"""The one door through which source text reaches a stored record."""

import json
import re
import time
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Final
from urllib.parse import unquote_plus, urljoin, urlparse

import httpx
import structlog

from app.core.constants import (
    IntelLimits,
    IntelMessage,
    IntelRejection,
    IntelSource,
    LogEvent,
    SourceDownload,
    TextCleaning,
    TextSafety,
)
from app.core.exceptions import IntelFetchFailed
from app.core.redaction import clipped_text, redact
from app.domain.intel.safety import UntrustedTextSanitiser
from app.schemas.intel_records import DownloadedFile, RejectedRecord, content_hash_of

log = structlog.get_logger(__name__)

_LINK = re.compile(r"https?://[^\s<>\"'`\\{}|^]+")
_PLAIN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


class UnsafeSourceText(Exception):
    """A field reads as instructions to an AI."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SourceTextGuard:
    """Sanitises one source's texts; stateless apart from the source, so it may be shared."""

    def __init__(self, source: IntelSource, sanitiser: UntrustedTextSanitiser | None = None) -> None:
        self._source = source
        self._sanitiser = sanitiser or UntrustedTextSanitiser()

    def clean(self, text: Any, max_chars: int) -> str:
        """`text` as safe plain text of at most `max_chars`."""
        result = self._sanitiser.sanitise(text, max_chars)
        if result.unsafe:
            raise UnsafeSourceText(result.reason or "")
        return result.text

    def clean_sentences(self, text: Any, max_chars: int) -> str:
        """A description as safe plain text."""
        if not isinstance(text, str) or max_chars <= 0:
            return ""
        whole = self._sanitiser.sanitise(text, max_chars)
        if not whole.unsafe:
            return whole.text
        raw = " ".join(text[: max(TextCleaning.MIN_RAW_CHARS, max_chars * TextCleaning.RAW_FACTOR)].split())
        kept: list[str] = []
        reasons: list[str] = []
        for sentence in filter(None, _SENTENCE_END.split(raw)):
            result = self._sanitiser.sanitise(sentence, len(sentence))
            if result.unsafe:
                reasons.append(result.reason or "")
            elif result.text:
                kept.append(result.text)
        if reasons and not kept:
            raise UnsafeSourceText(reasons[0])
        if reasons:
            log.info(
                LogEvent.EXTERNAL_INTELLIGENCE_SENTENCES_REMOVED,
                source=self._source,
                removed=len(reasons),
                reason=reasons[0],
                raw_hash=content_hash_of(text),
            )
        return self.clean(" ".join(kept), max_chars)

    def clean_list(self, values: Any, max_chars: int, max_items: int = TextSafety.MAX_DATA_ITEMS) -> list[str]:
        """The non-empty cleaned texts of a list, each once, at most `max_items` of them."""
        items = values if isinstance(values, Sequence) and not isinstance(values, str) else []
        return list(dict.fromkeys(c for c in (self.clean(item, max_chars) for item in items) if c))[:max_items]

    def clean_link(self, url: Any, hosts: Sequence[str]) -> str:
        """`url` when it is a plain https address on one of `hosts` that does not itself read as instructions."""
        if not (isinstance(url, str) and len(url) <= TextSafety.MAX_URL_CHARS and _LINK.fullmatch(url)):
            return ""
        if not on_host(url, hosts):
            return ""
        return "" if self._sanitiser.sanitise(unquote_plus(url), len(url)).unsafe else url

    def screen_together(self, parts: Iterable[Any]) -> None:
        """Raises when the fields of one record, read together, are unsafe."""
        joined = " ".join(part for part in parts if isinstance(part, str))
        self.clean(joined, len(joined) + 1)

    def quarantine(self, external_id: Any, raw: Any, reason: str) -> RejectedRecord:
        """The rejection of a record with unsafe text, logged; its id only when it looks like one (T1059)."""
        raw_hash = content_hash_of(raw)
        log.warning(
            LogEvent.EXTERNAL_INTELLIGENCE_TEXT_QUARANTINED, source=self._source, reason=reason, raw_hash=raw_hash
        )
        plain_id = external_id if isinstance(external_id, str) and _PLAIN_ID.fullmatch(external_id) else ""
        return RejectedRecord(self._source, plain_id, IntelRejection.UNSAFE_TEXT, raw_hash)


def on_host(url: str, hosts: Sequence[str]) -> bool:
    """True for an https `url` whose host is one of `hosts` or a subdomain of one."""
    try:
        parts = urlparse(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.username is None
        and any(host == allowed or host.endswith("." + allowed) for allowed in hosts)
    )


def flat_strings(value: Any) -> Iterable[str]:
    """Every string inside nested lists and dicts."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from flat_strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from flat_strings(item)


def load_json(body: bytes, source: str) -> Any:
    """The parsed JSON of `body`; IntelFetchFailed when it is too large to parse, ValueError when not JSON."""
    if len(body) > SourceDownload.MAX_PARSED_BYTES:
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=source)
    return json.loads(body)


_RETRY_STATUSES: Final = frozenset({429, 500, 502, 503, 504})
_NOT_MODIFIED: Final = 304
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
_SECONDS = re.compile(r"[0-9]{1,3}")


class _TryAgain(Exception):
    def __init__(self, wait: float, reason: str) -> None:
        super().__init__()
        self.wait = wait
        self.reason = reason


class HttpDownloader:
    """Stateless: it holds an HTTP client only when one is given (tests give a mock transport)."""

    def __init__(self, client: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        self._client = client
        self._sleep = sleep

    def download_if_changed(self, url: str, etag: str | None, max_bytes: int | None = None) -> DownloadedFile | None:
        """The body (at most `max_bytes`) and its validator, or None when the server says it is still `etag`."""
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
        raise IntelFetchFailed(IntelMessage.NOT_ANSWERED, url=url, attempts=IntelLimits.FETCH_ATTEMPTS, reason=reason)

    def _attempt(self, url: str, headers: dict[str, str], limit: int) -> DownloadedFile | None:
        if self._client is None:
            with httpx.Client(timeout=IntelLimits.FETCH_TIMEOUT_SECONDS) as client:
                return self._follow(client, url, headers, limit)
        return self._follow(self._client, url, headers, limit)

    def _follow(self, client: httpx.Client, url: str, headers: dict[str, str], limit: int) -> DownloadedFile | None:
        asked, status = url, 0
        for _ in range(SourceDownload.MAX_REDIRECTS + 1):
            try:
                with client.stream("GET", url, headers=headers, follow_redirects=False) as response:
                    if response.status_code not in _REDIRECT_STATUSES:
                        return self._answer(response, asked, headers, limit)
                    url, status = _redirect_target(response, asked), response.status_code
            except httpx.TransportError as error:  # why it got no answer, safe to store and show
                reason = redact(f"{type(error).__name__}: {error}".removesuffix(": "))
                raise _TryAgain(0, clipped_text(reason, IntelLimits.FAILURE_REASON_CHARS)) from None
            except httpx.RequestError:  # undecodable body, too many redirects...: no retry changes it
                raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=asked) from None
        raise IntelFetchFailed(IntelMessage.REFUSED, url=asked, status=status)

    @staticmethod
    def _answer(response: httpx.Response, url: str, headers: dict[str, str], limit: int) -> DownloadedFile | None:
        if response.status_code == _NOT_MODIFIED and headers:
            return None
        if response.status_code in _RETRY_STATUSES:
            raise _TryAgain(_retry_after(response), f"HTTP {response.status_code}")
        if not response.is_success:
            raise IntelFetchFailed(IntelMessage.REFUSED, url=url, status=response.status_code)
        return DownloadedFile(read_bounded(response, url, limit), response.headers.get("etag"))


def _redirect_target(response: httpx.Response, asked: str) -> str:
    location = response.headers.get("location", "")
    target = urljoin(str(response.request.url), location)
    hosts = (httpx.URL(asked).host, "raw.githubusercontent.com")  # a host matches itself and its subdomains
    if not (location and on_host(target, hosts)):
        raise IntelFetchFailed(IntelMessage.REFUSED, url=asked, status=response.status_code)
    return target


def read_bounded(response: httpx.Response, url: str, limit: int | None = None) -> bytes:
    """The body of `response` read in chunks; IntelFetchFailed once it passes `limit` (default MAX_BYTES)."""
    cap = SourceDownload.MAX_BYTES if limit is None else limit
    body = bytearray()
    for chunk in response.iter_bytes(SourceDownload.CHUNK_BYTES):
        body += chunk
        if len(body) > cap:
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=url)
    return bytes(body)


def _retry_after(response: httpx.Response) -> float:
    value = response.headers.get("retry-after", "")
    return min(float(value), SourceDownload.MAX_RETRY_AFTER_SECONDS) if _SECONDS.fullmatch(value) else 0
