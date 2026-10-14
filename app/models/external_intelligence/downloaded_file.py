"""A file read from a source's address."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DownloadedFile:
    body: bytes
    etag: str | None  # the server's validator for this body, to send back as If-None-Match next time
