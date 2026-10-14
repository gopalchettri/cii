"""The one place a source downloads a file: a timeout, a size limit, bounded retries with back-off, a
conditional request, and an error that names the address that failed (never a secret: keys travel in headers
the sources own, not here).

Redirects are followed by hand: only over https, and only to the host asked or one of SourceHosts.REDIRECTS,
so a redirect cannot lead a source to a plain-http or a foreign host."""

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Final
from urllib.parse import urljoin

import httpx

from app.core.constants import IntelLimits, IntelMessage, SourceDownload, SourceHosts
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.downloaded_file import DownloadedFile
from app.services.external_intelligence.sources.text_guard import on_host

_RETRY_STATUSES: Final = frozenset({429, 500, 502, 503, 504})
_NOT_MODIFIED: Final = 304
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
_SECONDS = re.compile(r"[0-9]{1,3}")


class _TryAgain(Exception):  # an internal signal between the methods below
    def __init__(self, wait: float) -> None:
        super().__init__()
        self.wait = wait


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
        headers = {"If-None-Match": etag} if etag else {}
        limit = SourceDownload.MAX_BYTES if max_bytes is None else max_bytes
        for attempt in range(1, IntelLimits.FETCH_ATTEMPTS + 1):
            try:
                return self._attempt(url, headers, limit)
            except _TryAgain as retry:
                if attempt < IntelLimits.FETCH_ATTEMPTS:
                    self._sleep(retry.wait or 2**attempt)
        raise IntelFetchFailed(IntelMessage.NOT_ANSWERED, url=url, attempts=IntelLimits.FETCH_ATTEMPTS)

    def _attempt(self, url: str, headers: dict[str, str], limit: int) -> DownloadedFile | None:
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
            except httpx.TransportError:
                raise _TryAgain(0) from None
            except httpx.RequestError:  # undecodable body, too many redirects...: no retry changes it
                raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=asked) from None
        raise IntelFetchFailed(IntelMessage.REFUSED, url=asked, status=status)

    @staticmethod
    def _answer(
        response: httpx.Response, url: str, headers: dict[str, str], limit: int
    ) -> DownloadedFile | None:
        if response.status_code == _NOT_MODIFIED and headers:
            return None
        if response.status_code in _RETRY_STATUSES:
            raise _TryAgain(_retry_after(response))
        if not response.is_success:
            raise IntelFetchFailed(IntelMessage.REFUSED, url=url, status=response.status_code)
        return DownloadedFile(read_bounded(response, url, limit), response.headers.get("etag"))


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
