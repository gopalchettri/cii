"""The paced, budgeted NVD client of ONE run. NVD allows 5 requests per 30 s without a key and 50 with one: a
pause before every request but the first keeps a little under that, and a run is capped at
NVD_MAX_REQUESTS_PER_RUN. The key travels as a header only: never in the address, never in a message, never
in a log line. The pause is injected so tests do not wait."""

import time
from collections.abc import Callable
from typing import Any, Final

import httpx

from app.core.constants import IntelLimits, IntelMessage, IntelSource, IntelUrl, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.bounded_parse import load_json
from app.services.external_intelligence.sources.http_download import read_bounded

_RETRYABLE: Final = frozenset(
    {403, 429, 500, 502, 503, 504}
)  # NVD answers 403 as well as 429 when a client is too fast


class NvdApiClient:
    def __init__(
        self,
        api_key: str,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._http = client or httpx.Client(timeout=IntelLimits.FETCH_TIMEOUT_SECONDS)
        self._own = client is None
        self._sleep = sleep
        self._headers = {"apiKey": api_key} if api_key else {}
        self._pause = (
            IntelLimits.NVD_SLEEP_KEYED_SECONDS if api_key else IntelLimits.NVD_SLEEP_UNKEYED_SECONDS
        )
        self._made = 0
        self._answered = 0
        self._stopped = False

    def close(self) -> None:
        if self._own:
            self._http.close()

    def get(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """The JSON answer, or None when the run must stop (budget spent, or NVD still limiting us after the
        back-offs). Stopping with no answer at all this run is a failure; with progress it is not."""
        for attempt in range(1, IntelLimits.FETCH_ATTEMPTS + 1):
            if self._stopped or self._made >= IntelLimits.NVD_MAX_REQUESTS_PER_RUN:
                self._stopped = True
                return None
            if self._made:
                self._sleep(self._pause)
            self._made += 1
            response = self._send(params)
            if response is not None and response[0] not in _RETRYABLE:
                return self._body(*response)
            if attempt < IntelLimits.FETCH_ATTEMPTS:
                self._sleep(IntelLimits.NVD_BACKOFF_SECONDS)
        self._stopped = True
        if not self._answered:
            raise IntelFetchFailed(IntelMessage.NOT_ANSWERED, url=IntelUrl.NVD_API, attempts=self._made)
        return None

    def _send(self, params: dict[str, Any]) -> tuple[int, bytes] | None:
        """The status and the body, the body read in chunks and refused past MAX_NVD_PAGE_BYTES.
        A redirect is never followed (the key travels in a header httpx would send to the new address): its
        status is refused by `_body` like any other that is not a success."""
        try:
            with self._http.stream(
                "GET", IntelUrl.NVD_API, params=params, headers=self._headers, follow_redirects=False
            ) as response:
                body = (
                    b""
                    if response.is_redirect
                    else read_bounded(response, IntelUrl.NVD_API, SourceDownload.MAX_NVD_PAGE_BYTES)
                )
                return response.status_code, body
        except httpx.TransportError:
            return None
        except httpx.RequestError:  # undecodable body...: a retry cannot change it
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.NIST_NVD) from None

    def _body(self, status: int, raw: bytes) -> dict[str, Any]:
        if not 200 <= status < 300:  # 400/404...: a retry cannot change it
            raise IntelFetchFailed(IntelMessage.REFUSED, url=IntelUrl.NVD_API, status=status)
        try:
            body = load_json(raw, IntelSource.NIST_NVD)
        except ValueError:
            body = None
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.NIST_NVD)
        self._answered += 1
        return body
