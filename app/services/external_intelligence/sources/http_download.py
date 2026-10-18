"""The one place a source downloads a file (a timeout, a size limit, bounded retries, a conditional request,
redirects only over https to allowed hosts) and parses it within SourceDownload.MAX_PARSED_BYTES."""

import gzip
import io
import json
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Final
from urllib.parse import urljoin

import httpx

from app.core.constants import IntelLimits, IntelMessage, SourceDownload, SourceHosts
from app.core.exceptions import IntelFetchFailed
from app.core.redaction import clipped_text, redact
from app.models.external_intelligence.fetch_result import DownloadedFile
from app.services.external_intelligence.sources.text_guard import on_host


def within_parse_limit(body: bytes, source: str) -> bytes:
    """`body` itself; IntelFetchFailed when it is too large to parse."""
    if len(body) > SourceDownload.MAX_PARSED_BYTES:
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=source)
    return body


def load_json(body: bytes, source: str) -> Any:
    """The parsed JSON of `body`; ValueError when it is not JSON, IntelFetchFailed when it is too large."""
    return json.loads(within_parse_limit(body, source))


class _CappedReader(io.RawIOBase):
    """Reads an unpacking stream and stops it for good once it has produced the limit."""

    def __init__(self, inner: io.BufferedIOBase, source: str) -> None:
        super().__init__()
        self._inner = inner
        self._source = source
        self._produced = 0

    def readable(self) -> bool:
        """Always readable."""
        return True

    def readinto(self, buffer: Any) -> int:
        """Read into `buffer`; IntelFetchFailed once the stream has produced more than the limit."""
        data = self._inner.read(len(buffer))
        self._produced += len(data)
        if self._produced > SourceDownload.MAX_PARSED_BYTES:
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=self._source)
        buffer[: len(data)] = data
        return len(data)


def open_gzip_text(body: bytes, source: str) -> io.TextIOWrapper:
    """The UTF-8 text inside gzip `body`, read lazily; IntelFetchFailed once it unpacks past the limit
    (also inside one endless line: the cap is on bytes, not on rows)."""
    unpacked = _CappedReader(gzip.GzipFile(fileobj=io.BytesIO(body)), source)  # type: ignore[arg-type]
    return io.TextIOWrapper(io.BufferedReader(unpacked), encoding="utf-8", newline="")


_RETRY_STATUSES: Final = frozenset({429, 500, 502, 503, 504})
_NOT_MODIFIED: Final = 304
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
_SECONDS = re.compile(r"[0-9]{1,3}")


class _TryAgain(Exception):
    """A try that may succeed later: how long to wait and why it failed."""

    def __init__(self, wait: float, reason: str) -> None:
        super().__init__()
        self.wait = wait
        self.reason = reason


class HttpDownloader:
    """Stateless: it holds an HTTP client only when one is given (tests give a mock transport, a batch gives
    one connection to reuse)."""

    def __init__(
        self, client: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        self._client = client
        self._sleep = sleep

    def download(self, url: str, max_bytes: int | None = None) -> bytes:
        """The body at `url` (at most `max_bytes`, else SourceDownload.MAX_BYTES). Timeouts, connection errors
        and 429/5xx are retried up to FETCH_ATTEMPTS with doubling back-off; any other bad status fails at
        once (a retry cannot change a 404)."""
        file = self._request(url, None, max_bytes)
        assert file is not None  # no validator was sent, so the answer cannot be "not modified"
        return file.body

    def download_if_changed(
        self, url: str, etag: str | None, max_bytes: int | None = None
    ) -> DownloadedFile | None:
        """The body and its validator, or None when the server says it is still `etag` (a conditional GET:
        nothing is transferred for an unchanged file)."""
        return self._request(url, etag, max_bytes)

    @contextmanager
    def batch(self) -> Iterator["HttpDownloader"]:
        """A downloader that reuses one connection for many files (the ICS advisories)."""
        if self._client is not None:
            yield self
            return
        with httpx.Client(timeout=IntelLimits.FETCH_TIMEOUT_SECONDS) as client:
            yield HttpDownloader(client, self._sleep)

    def _request(self, url: str, etag: str | None, max_bytes: int | None) -> DownloadedFile | None:
        """Try up to FETCH_ATTEMPTS times with back-off; IntelFetchFailed naming the last reason."""
        headers = {"If-None-Match": etag} if etag else {}
        limit = SourceDownload.MAX_BYTES if max_bytes is None else max_bytes
        reason = ""
        for attempt in range(1, IntelLimits.FETCH_ATTEMPTS + 1):
            try:
                return self._attempt(url, headers, limit)
            except _TryAgain as retry:
                reason = retry.reason
                if attempt < IntelLimits.FETCH_ATTEMPTS:
                    self._sleep(retry.wait or 2**attempt)
        raise IntelFetchFailed(
            IntelMessage.NOT_ANSWERED, url=url, attempts=IntelLimits.FETCH_ATTEMPTS, reason=reason
        )

    def _attempt(self, url: str, headers: dict[str, str], limit: int) -> DownloadedFile | None:
        """One try, on the batch's client or a fresh one."""
        if self._client is None:
            with httpx.Client(timeout=IntelLimits.FETCH_TIMEOUT_SECONDS) as client:
                return self._follow(client, url, headers, limit)
        return self._follow(self._client, url, headers, limit)

    def _follow(
        self, client: httpx.Client, url: str, headers: dict[str, str], limit: int
    ) -> DownloadedFile | None:
        """The answer at `url`, after at most MAX_REDIRECTS redirects that stay on the allowed hosts."""
        asked, status = url, 0
        for _ in range(SourceDownload.MAX_REDIRECTS + 1):
            try:
                with client.stream("GET", url, headers=headers, follow_redirects=False) as response:
                    if response.status_code not in _REDIRECT_STATUSES:
                        return self._answer(response, asked, headers, limit)
                    url, status = _redirect_target(response, asked), response.status_code
            except httpx.TransportError as error:
                raise _TryAgain(0, network_reason(error)) from None
            except httpx.RequestError:  # undecodable body, too many redirects...: no retry changes it
                raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=asked) from None
        raise IntelFetchFailed(IntelMessage.REFUSED, url=asked, status=status)

    @staticmethod
    def _answer(
        response: httpx.Response, url: str, headers: dict[str, str], limit: int
    ) -> DownloadedFile | None:
        """The file of a final answer: None for "not modified", _TryAgain for a busy server, else refused."""
        if response.status_code == _NOT_MODIFIED and headers:
            return None
        if response.status_code in _RETRY_STATUSES:
            raise _TryAgain(_retry_after(response), f"HTTP {response.status_code}")
        if not response.is_success:
            raise IntelFetchFailed(IntelMessage.REFUSED, url=url, status=response.status_code)
        return DownloadedFile(read_bounded(response, url, limit), response.headers.get("etag"))


def network_reason(error: Exception) -> str:
    """Why a try got no answer, safe to store and show: the error's kind and text, with secrets and internal
    host names masked (a proxy address can carry a password), clipped."""
    text = redact(f"{type(error).__name__}: {error}".removesuffix(": "))
    return clipped_text(text, IntelLimits.FAILURE_REASON_CHARS)


def _redirect_target(response: httpx.Response, asked: str) -> str:
    """Where a redirect leads, when that is https on the host asked or an allowed one; else the download is
    refused (with the redirect's own status)."""
    location = response.headers.get("location", "")
    target = urljoin(str(response.request.url), location)
    hosts = (httpx.URL(asked).host, *SourceHosts.REDIRECTS)
    if not (location and on_host(target, hosts)):
        raise IntelFetchFailed(IntelMessage.REFUSED, url=asked, status=response.status_code)
    return target


def read_bounded(response: httpx.Response, url: str, limit: int | None = None) -> bytes:
    """The body of `response` read in chunks; IntelFetchFailed once it passes `limit` (default
    SourceDownload.MAX_BYTES)."""
    cap = SourceDownload.MAX_BYTES if limit is None else limit
    body = bytearray()
    for chunk in response.iter_bytes(SourceDownload.CHUNK_BYTES):
        body += chunk
        if len(body) > cap:
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=url)
    return bytes(body)


def _retry_after(response: httpx.Response) -> float:
    """The seconds a busy server asks to wait (capped), or 0 for the default back-off."""
    value = response.headers.get("retry-after", "")
    return min(float(value), SourceDownload.MAX_RETRY_AFTER_SECONDS) if _SECONDS.fullmatch(value) else 0
