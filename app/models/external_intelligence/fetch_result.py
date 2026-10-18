"""A file downloaded from a source's address, and what one source's download produced."""

from dataclasses import dataclass

from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord


@dataclass(frozen=True)
class DownloadedFile:
    """One downloaded body and its validator."""

    body: bytes
    etag: str | None  # the server's validator for this body, to send back as If-None-Match next time


@dataclass(frozen=True)
class FetchResult:
    """`checkpoint` is saved only after every record is committed."""

    records: tuple[IntelRecord, ...]
    rejected: tuple[RejectedRecord, ...]
    checkpoint: str  # the source's own version marker: KEV catalogueVersion, EPSS score date, ATT&CK release
    source_version: str
    # Incremental: the records are only part of the source, so one absent from this result is not gone and
    # nothing is retired; an empty result is progress, not a bad format.
    partial: bool = False
    more: bool = False  # the source has more to give now: due again at the next check, not tomorrow
