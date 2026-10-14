"""Every JSON or CSV text a source parses, and every gzip stream it reads, is bounded: a body that is too
large, or a stream that unpacks to too much (a gzip bomb), fails the source with IntelFetchFailed instead of
exhausting the worker's memory. The bound is SourceDownload.MAX_PARSED_BYTES, checked before a JSON parse and
while a stream unpacks."""

import gzip
import io
import json
from typing import Any

from app.core.constants import IntelMessage, SourceDownload
from app.core.exceptions import IntelFetchFailed


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
        return True

    def readinto(self, buffer: Any) -> int:
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
