"""NIST NVD API 2.0: one VULNERABILITY_DETAIL record per KEV CVE, always partial. A run reads the CVEs changed
since its checkpoint (a time) in one window, then looks up the wanted CVEs not yet stored, in sorted order,
through a paced and budgeted API client."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx

from app.core.config import get_settings
from app.core.constants import IntelLimits, IntelMessage, IntelSource, IntelUrl, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord
from app.worker.external_intelligence.cancel_check import import_cancelled
from app.worker.external_intelligence.sources.http_download import load_json, network_reason, read_bounded
from app.worker.external_intelligence.sources.nvd_item_reader import NvdItemReader
from app.worker.external_intelligence.sources.text_guard import SourceTextGuard, limit_rejected

_RETRYABLE: Final = frozenset(
    {403, 429, 500, 502, 503, 504}
)  # NVD answers 403 as well as 429 when a client is too fast


class NvdApiClient:
    """One run's NVD client."""

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
        self._last_reason = ""  # why the last try got no usable answer

    def close(self) -> None:
        """Close the HTTP client this client made itself."""
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
            if response is not None:
                self._last_reason = f"HTTP {response[0]}"
            if attempt < IntelLimits.FETCH_ATTEMPTS:
                self._sleep(IntelLimits.NVD_BACKOFF_SECONDS)
        self._stopped = True
        if not self._answered:
            raise IntelFetchFailed(
                IntelMessage.NOT_ANSWERED, url=IntelUrl.NVD_API, attempts=self._made, reason=self._last_reason
            )
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
        except httpx.TransportError as error:
            self._last_reason = network_reason(error)
            return None
        except httpx.RequestError:  # undecodable body...: a retry cannot change it
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.NIST_NVD) from None

    def _body(self, status: int, raw: bytes) -> dict[str, Any]:
        """The parsed answer of a success; IntelFetchFailed for a refusal or an unexpected shape."""
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


_TIME = "%Y-%m-%dT%H:%M:%S.000+00:00"


class _Collected:
    """The records and rejections one run gathered, by CVE id (local to one call)."""

    def __init__(self) -> None:
        self.records: dict[str, IntelRecord] = {}
        self.rejected: list[RejectedRecord] = []


class NistNvdDetailsSource:
    """The NVD details source; a run is bounded and paced under NVD's limit (NvdApiClient)."""

    source_id = IntelSource.NIST_NVD

    def __init__(
        self,
        known_cves: Callable[[], set[str]],
        stored_cves: Callable[[], set[str]],
        *,
        api_key: Callable[[], str] | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._known_cves = known_cves
        self._stored_cves = stored_cves
        self._api_key = api_key or (lambda: get_settings().nvd_api_key.get_secret_value())
        self._client = client
        self._sleep = sleep
        self._clock = clock or (lambda: datetime.now(UTC))
        self._reader = NvdItemReader(SourceTextGuard(IntelSource.NIST_NVD))

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The records this run reached, or None when there is nothing to ask for; `more` when the budget or
        a rate limit cut the run short. The checkpoint moves only to the end of a window fully read."""
        wanted = {cve.upper() for cve in self._known_cves()}
        if not wanted:
            return None
        started, since = self._clock(), _parse_time(checkpoint)
        found, cut = _Collected(), False  # cut: the budget or a rate limit ended the run early
        api = NvdApiClient(self._api_key(), self._client, self._sleep)
        try:
            moved_to = started if since is None else self._read_changed(api, since, started, wanted, found)
            if moved_to is None:
                cut = True
            for cve in sorted(wanted - self._stored_cves() - found.records.keys()):
                # A cancelled import stops here like a rate limit: what was read is kept, the next goes on.
                body = None if import_cancelled() else api.get({"cveId": cve})
                if body is None:
                    cut = True
                    break
                self._collect(body["vulnerabilities"], wanted, found)
        finally:
            api.close()
        new_checkpoint = (moved_to or since or started).strftime(_TIME)
        return FetchResult(
            tuple(found.records.values()),
            limit_rejected(found.rejected),
            new_checkpoint,
            new_checkpoint,
            partial=True,
            more=cut,
        )

    def _read_changed(
        self, api: NvdApiClient, since: datetime, now: datetime, wanted: set[str], found: _Collected
    ) -> datetime | None:
        """Reads the wanted CVEs changed since `since`; the end of the window when all its pages were read."""
        end = min(now, since + timedelta(days=IntelLimits.NVD_MAX_WINDOW_DAYS))
        if end <= since:  # a checkpoint from the future (clock skew): nothing to ask yet
            return since
        index = 0
        while True:
            window = {"lastModStartDate": since.strftime(_TIME), "lastModEndDate": end.strftime(_TIME)}
            if import_cancelled():  # the window is not fully read: the checkpoint stays where it was
                return None
            body = api.get({**window, "startIndex": index, "resultsPerPage": IntelLimits.NVD_PAGE_SIZE})
            if body is None:
                return None
            items, total = body["vulnerabilities"], body.get("totalResults")
            self._collect(items, wanted, found)
            index += len(items)
            if not items or not isinstance(total, int) or index >= total:
                return end

    def _collect(self, items: list[Any], wanted: set[str], found: _Collected) -> None:
        """Read the wanted CVEs among `items` into `found`."""
        for item in items:
            cve = item.get("cve") if isinstance(item, dict) else None
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if isinstance(cve_id, str) and cve_id.upper() not in wanted:
                continue  # a window lists every CVE NVD changed: only ours are read
            made = self._reader.read_item(item)
            if isinstance(made, IntelRecord):
                found.records[made.external_id] = made
            else:
                found.rejected.append(made)


def _parse_time(checkpoint: str | None) -> datetime | None:
    """The saved checkpoint as a time; anything else (first run, a hand-edited value) starts a first pass."""
    try:
        return datetime.fromisoformat(checkpoint).astimezone(UTC) if checkpoint else None
    except ValueError:
        return None
