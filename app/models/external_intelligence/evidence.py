"""The evidence a scenario rests on (plain facts for the story, the source link for the proof) and the audit
of each search (every candidate with its score and decision), stored as they are (`as_doc`)."""

from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.constants import (
    AiOutage,
    Applicability,
    EvidenceDecision,
    EvidenceRole,
    EvidenceSearchFailure,
    IntelKind,
    IntelSource,
)


@dataclass(frozen=True)
class IntelHit:
    """One intelligence record found for a threat. `score` is the reranker's 0-100 (0 until reranked)."""

    external_id: str
    kind: IntelKind
    title: str
    text: str
    url: str
    source: IntelSource
    asset_type: str
    score: float = 0.0
    # kind-specific facts; a vulnerability's has epss and detail
    data: dict[str, Any] = field(default_factory=dict)
    modified: str | None = None  # the source's own date for the record, when it gives one
    fetched_at: str | None = None  # when the refresh fetched it (ISO)
    # the other sources whose records were joined into `data` (a KEV entry's EPSS score, NVD detail): a revoke
    # of either reaches the evidence it fed
    joined: tuple[IntelSource, ...] = ()


@dataclass(frozen=True)
class Evidence:
    """What the writer may use and the reader can open."""

    ref: str  # the source's own id (T0821, CVE-2024-0001): shown in the evidence panel, never in the story
    kind: IntelKind
    source: IntelSource
    title: str
    url: str
    score: float  # the reranker's 0-100
    facts: tuple[str, ...]  # plain sentences the writer may use: who did it before, what it causes, ...
    applicability: Applicability | None = None  # only for a vulnerability; None for a technique
    published: str | None = None  # when the source published the record
    fetched_at: str | None = None
    role: EvidenceRole = EvidenceRole.CONTEXT  # what it proves: direct (the asset's own product) or context
    # the source's own names for what reduces it (an ATT&CK technique's mitigations); the control search
    # reads them
    mitigations: tuple[str, ...] = ()
    modified: str | None = None  # the source's last change to the record (`published` is when it came out)
    joined: tuple[IntelSource, ...] = ()  # the sources its facts also rest on (IntelHit.joined)
    nearest: bool = False  # under the threshold: the nearest record, used because none met it

    def as_doc(self) -> dict[str, Any]:
        """The entry as stored, its tuples as lists; `nearest` only when it is."""
        doc = asdict(self) | {
            "facts": list(self.facts),
            "mitigations": list(self.mitigations),
            "joined": list(self.joined),
        }
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
    stale: bool = False  # the snapshot's sources have not refreshed within the age limit; still used
    failure: EvidenceSearchFailure | None = None  # the search could not be made: no evidence, run goes on
    # Rerank scores are 0-100 ranking scores whose scale differs per model and the threshold is cut on them:
    # the audit row is only readable next to the model that gave the scores.
    rerank_model: str = ""
    outage: AiOutage | None = None  # the AI outage that stopped the search: what the held-back path tells
    outage_message: str = ""  # that outage in its own words: a reranker wait is no gateway refusal

    def as_doc(self) -> dict[str, Any]:
        """The audit as stored, its tuples as lists; the outage fields only when the AI stopped the search."""
        doc = asdict(self) | {
            "asset_types": list(self.asset_types),
            "considered": [c.as_doc() for c in self.considered],
        }
        outage_keys = ("outage", "outage_message")
        return doc if self.outage else {key: value for key, value in doc.items() if key not in outage_keys}


@dataclass(frozen=True)
class EvidenceBatchSummary:
    """What one batch's evidence search did, for the batch's one audit row."""

    snapshot_id: str | None  # None: no snapshot (or intelligence off): nothing was searched
    source_versions: dict[str, str]
    threats_searched: int
    threats_with_evidence: int
    evidence_used: int
    stale: bool

    def as_doc(self) -> dict[str, Any]:
        """The summary as its audit row stores it."""
        return asdict(self)
