"""What cleaning one piece of untrusted source text gave."""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.core.constants import (
    AiOutage,
    EvidenceDecision,
    EvidenceRole,
    EvidenceSearchFailure,
    FeedStatus,
    IntelKind,
    IntelSource,
    IntelState,
)


@dataclass(frozen=True)
class SanitisedText:
    """`unsafe` text is returned EMPTY."""

    text: str
    unsafe: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class SwitchState:
    env_enabled: bool  # EXTERNAL_INTELLIGENCE_ENABLED: the master switch
    runtime_enabled: bool = True  # the admin's switch; on until an admin turns it off
    changed_at: datetime | None = None
    changed_by: str | None = None
    # False: its store could not be read and no value was kept, so it reads off in doubt (a writer that must
    # be sure then waits, never turning a story into an original card)
    known: bool = True

    @property
    def effective(self) -> bool:
        """On only when both are on: the run-time switch can turn intelligence off."""
        return self.env_enabled and self.runtime_enabled

    def as_doc(self) -> dict[str, Any]:
        """The state as the admin API and the audit show it."""
        return {
            "env_enabled": self.env_enabled,
            "runtime_enabled": self.runtime_enabled,
            "effective": self.effective,
            "changed_at": self.changed_at,
            "changed_by": self.changed_by,
        }


def content_hash_of(*parts: Any) -> str:
    """A stable SHA-256 of any JSON-able parts: the same content always gives the same hash."""
    text = json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IntelRecord:
    """One source record as stored."""

    source: IntelSource
    external_id: str  # the source's own id: T1059
    kind: IntelKind
    asset_type: str  # AssetType value: IT, OT or IT-OT (both)
    title: str
    text: str  # what the search indexes
    url: str
    source_version: str  # the source's release
    modified: str | None = None  # the source's own modified time, when it gives one
    data: dict[str, Any] = field(default_factory=dict)  # kind-specific facts (tactics, mitigations, ...)

    @property
    def content_hash(self) -> str:
        """Over what the source said, never over when it was fetched."""
        return content_hash_of(self.title, self.text, self.data, self.asset_type, self.modified)

    def as_doc(self, fetched_at: datetime) -> dict[str, Any]:
        """The record as the store writes it: valid, with its hash."""
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
            "fetched_at": fetched_at,
            "state": IntelState.VALID,
        }


@dataclass(frozen=True)
class RejectedRecord:
    """A malformed source record with the reason: never stored, never indexed."""

    source: IntelSource
    external_id: str
    reason: str  # an IntelRejection value
    raw_hash: str  # of the raw payload, as the log names it


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
    checkpoint: str  # the source's own version marker: the ATT&CK release
    source_version: str
    graph: tuple[dict[str, Any], ...] = ()  # the ATT&CK objects and relationships, as tsg_attack stores them
    raw_stix: tuple[dict[str, Any], ...] = ()  # the STIX objects the MITRE run reads (tsg_mitre_*_stix)


@dataclass(frozen=True)
class IntelHit:
    """One intelligence record found for a threat. `score` is the reranker's 0-100."""

    external_id: str
    kind: IntelKind
    title: str
    text: str
    url: str
    source: IntelSource
    asset_type: str
    score: float = 0.0
    # kind-specific facts
    data: dict[str, Any] = field(default_factory=dict)
    modified: str | None = None  # the source's own date for the record, when it gives one
    fetched_at: str | None = None  # when the refresh fetched it (ISO)


@dataclass(frozen=True)
class Evidence:
    """What the writer may use and the reader can open."""

    ref: str  # the source's own id (T0821): shown in the evidence panel, never in the story
    kind: IntelKind
    source: IntelSource
    title: str
    url: str
    score: float  # the reranker's 0-100
    facts: tuple[str, ...]  # plain sentences the writer may use: who did it before, what it causes, ...
    fetched_at: str | None = None
    role: EvidenceRole = EvidenceRole.CONTEXT  # what it proves: every entry is context
    # the source's own names for what reduces it (an ATT&CK technique's mitigations); the control search
    # reads them
    mitigations: tuple[str, ...] = ()
    modified: str | None = None  # the source's last change to the record
    nearest: bool = False  # under the threshold: the nearest record, used because none met it

    def as_doc(self) -> dict[str, Any]:
        """The entry as stored, its tuples as lists; `nearest` only when it is."""
        doc = asdict(self) | {"facts": list(self.facts), "mitigations": list(self.mitigations)}
        if not self.nearest:
            del doc["nearest"]
        return doc


@dataclass(frozen=True)
class Considered:
    """One candidate of a search and what became of it."""

    ref: str
    score: float
    decision: EvidenceDecision
    reason: str = ""  # an EvidenceReason, filled in: a short rule-based reason for an exclusion

    def as_doc(self) -> dict[str, Any]:
        """The row as stored."""
        return asdict(self)


@dataclass(frozen=True)
class EvidenceSearchRecord:
    """The audit of one threat's search."""

    query: str  # what was searched, so the search can be repeated
    asset_types: tuple[str, ...]  # the IT / OT filter applied before ranking
    snapshot_id: str | None  # None: no snapshot yet, so nothing was searched
    threshold: float
    considered: tuple[Considered, ...] = field(default_factory=tuple)
    failure: EvidenceSearchFailure | None = None  # the search could not be made: no evidence, run goes on
    # Rerank scores are 0-100 ranking scores whose scale differs per model and the threshold is cut on them:
    # the audit row is only readable next to the model that gave the scores.
    rerank_model: str = ""
    outage: AiOutage | None = None  # the AI outage that stopped the search: what the held-back path tells
    outage_message: str = ""  # that outage in its own words: a reranker wait is no gateway refusal

    def as_doc(self) -> dict[str, Any]:
        """The audit as stored, its tuples as lists."""
        doc = asdict(self) | {
            "asset_types": list(self.asset_types),
            "considered": [c.as_doc() for c in self.considered],
        }
        outage_keys = ("outage", "outage_message")
        return doc if self.outage else {key: value for key, value in doc.items() if key not in outage_keys}


@dataclass(frozen=True)
class EvidenceRequest:
    """One threat's evidence search."""

    text: str  # the threat's search text, already cut to EvidenceLimits.QUERY_MAX_CHARS
    asset_types: frozenset[str]  # the IT / OT filter: the asset's and the threat's systems' types


@dataclass(frozen=True)
class EvidenceResult:
    evidence: tuple[Evidence, ...]  # best first, at most EVIDENCE_KEPT_PER_THREAT
    search: EvidenceSearchRecord


@dataclass(frozen=True)
class EvidenceCorpus:
    """The searchable records and their search texts, with the checksum."""

    hits: tuple[IntelHit, ...]  # in a fixed (source, id) order, so an unchanged corpus gives the same rows
    search_texts: tuple[str, ...]  # one per hit: its text without indicators of compromise
    checksum: str  # over every current record, whatever the order they were read in
    source_versions: dict[str, str] = field(default_factory=dict)


class RefreshResult(StrEnum):
    REFRESHED = "refreshed"  # records were stored
    UNCHANGED = "unchanged"  # the source had nothing new
    FAILED = "failed"
    SKIPPED = "skipped"  # being refreshed by another worker
    CLAIM_LOST = "claim_lost"  # the claim was taken over mid-run: the run stopped


@dataclass(frozen=True)
class SourceRefresh:
    """What the refresh did to one source."""

    source: IntelSource
    result: RefreshResult
    new_versions: int = 0
    retired: int = 0
    error: str | None = None  # people-readable: a message text or an exception type
    graph_changed: bool = False  # it stored an ATT&CK graph that differs from the one stored before


@dataclass(frozen=True)
class RefreshSummary:
    """What one refresh did to every source it looked at."""

    sources: tuple[SourceRefresh, ...]
    index_rebuilt: bool  # the evidence index was rebuilt after the refresh
    index_error: dict[str, str] | None = None  # why it was not: {code, message} and an AI outage's reason
    graph_changed: bool = False  # a source stored a new or changed ATT&CK graph (the links follow every import)

    @property
    def failed(self) -> tuple[IntelSource, ...]:
        """The sources whose refresh failed."""
        return tuple(item.source for item in self.sources if item.result == RefreshResult.FAILED)


@dataclass(frozen=True)
class SourceHealth:
    """One source's row of `tsg_external_feed_status`."""

    source: IntelSource
    status: FeedStatus = FeedStatus.NEVER_RUN
    checkpoint: str | None = None  # the source's own version marker of the last committed refresh
    source_version: str | None = None
    records: int = 0  # current records of this source
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None  # an IntelMessage, filled in
    # set while a worker refreshes it; older than IntelLimits.CLAIM_STALE_SECONDS: the worker is dead
    claimed_at: datetime | None = None

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> "SourceHealth":
        """A tsg_external_feed_status source document as its SourceHealth."""
        source = IntelSource(doc["_id"])
        values = {name: doc.get(name, default) for name, default in cls(source).as_doc().items()}
        return cls(**{**values, "source": source, "status": FeedStatus(values["status"])})

    @property
    def is_pending(self) -> bool:
        """Never succeeded yet (not run, or only failed so far): waits for first data."""
        return self.last_success_at is None

    def as_doc(self) -> dict[str, Any]:
        """The row as the health report shows it."""
        return {
            "source": self.source,
            "status": self.status,
            "checkpoint": self.checkpoint,
            "source_version": self.source_version,
            "records": self.records,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "claimed_at": self.claimed_at,
        }


def refresh_success_fields(checkpoint: str, source_version: str, now: datetime, *, records: int) -> dict[str, Any]:
    """What a successful refresh records on its source: the new checkpoint, version and count."""
    return {
        "status": FeedStatus.OK,
        "checkpoint": checkpoint,
        "source_version": source_version,
        "records": records,
        "last_success_at": now,
        "last_error": None,
    }


def refresh_failure_fields(error: str, now: datetime) -> dict[str, Any]:
    """What a failed refresh records on its source."""
    return {"status": FeedStatus.FAILED, "last_attempt_at": now, "last_error": error[:500]}


def source_health_in_registry_order(docs: Iterable[dict[str, Any]]) -> list[SourceHealth]:
    """tsg_external_feed_status source documents as their SourceHealth, in registry order."""
    by_source = {doc["_id"]: SourceHealth.from_doc(doc) for doc in docs}
    return [by_source[source] for source in IntelSource if source in by_source]
