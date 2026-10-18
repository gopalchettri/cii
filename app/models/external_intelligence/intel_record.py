"""A normalized intelligence record: what a source said, where from, and a fingerprint of it. Frozen: a source
class builds it once and the store writes it as it is."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.constants import IntelKind, IntelLimits, IntelSource, IntelState


def content_hash_of(*parts: Any) -> str:
    """A stable SHA-256 of any JSON-able parts: the same content always gives the same hash."""
    text = json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IntelRecord:
    """One source record as stored."""

    source: IntelSource
    external_id: str  # the source's own id: T1059, CVE-2024-0001
    kind: IntelKind
    asset_type: str  # AssetType value: IT, OT or IT-OT (both)
    title: str
    text: str  # what the search indexes
    url: str
    source_version: str  # the source's release, catalogue version or score date
    modified: str | None = None  # the source's own modified time, when it gives one
    data: dict[str, Any] = field(default_factory=dict)  # kind-specific facts (cve, kev dates, epss, ...)

    @property
    def content_hash(self) -> str:
        """Over what the source said, never over when it was fetched: an unchanged record keeps its hash."""
        return content_hash_of(self.title, self.text, self.data, self.asset_type, self.modified)

    def as_doc(self, fetched_at: datetime) -> dict[str, Any]:
        """The record as the store writes it: valid, with its hash and parser version."""
        return {
            "source": self.source,
            "external_id": self.external_id,
            "kind": self.kind,
            "asset_type": self.asset_type,
            "title": self.title,
            "text": self.text,
            "url": self.url,
            "source_version": self.source_version,
            "modified": self.modified,
            "data": self.data,
            "content_hash": self.content_hash,
            "parser_version": IntelLimits.PARSER_VERSION,
            "fetched_at": fetched_at,
            "state": IntelState.VALID,
        }


@dataclass(frozen=True)
class RejectedRecord:
    """A malformed source record, kept with the reason and never indexed."""

    source: IntelSource
    external_id: str
    reason: str  # an IntelRejection value
    raw_hash: str  # of the raw payload, so the same bad record is stored once

    def as_doc(self, fetched_at: datetime) -> dict[str, Any]:
        """The rejection as the store writes it: quarantined and never current."""
        return {
            "source": self.source,
            "external_id": self.external_id,
            "content_hash": self.raw_hash,
            "reason": self.reason,
            "parser_version": IntelLimits.PARSER_VERSION,
            "fetched_at": fetched_at,
            "state": IntelState.QUARANTINED,
            "current": False,
        }


@dataclass(frozen=True)
class SaveCounts:
    """What saving a batch did: versions created, records already current, bad records newly quarantined."""

    new_versions: int
    unchanged: int
    quarantined: int

    def __add__(self, other: "SaveCounts") -> "SaveCounts":
        """The counts of both batches together."""
        return SaveCounts(
            self.new_versions + other.new_versions,
            self.unchanged + other.unchanged,
            self.quarantined + other.quarantined,
        )
