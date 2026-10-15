"""The evidence a scenario rests on, and the audit of how it was found.

`Evidence` is what the writer may use and what the reader can open: plain-language `facts` for the story, the
source link for the proof. `EvidenceSearchRecord` is the audit of one threat's search: the query, the filter,
the snapshot, every candidate considered with its score and the decision, so a reviewer can see why a record
was used or left out. All are frozen and JSON-able (`as_doc`), so they are stored as they are."""

from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.constants import (
    Applicability,
    EvidenceDecision,
    EvidenceRole,
    EvidenceScope,
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
    modified: str | None = None  # the source's own date for the record, when it gives one (G229)
    fetched_at: str | None = None  # when the refresh fetched it (ISO)


@dataclass(frozen=True)
class Evidence:
    ref: str  # the source's own id (T0821, CVE-2024-0001): shown in the evidence panel, never in the story
    kind: IntelKind
    source: IntelSource
    title: str
    url: str
    score: float  # the reranker's 0-100
    facts: tuple[str, ...]  # plain sentences the writer may use: who did it before, what it causes, ...
    applicability: Applicability | None = None  # only for a vulnerability; None for a technique
    # G229 (owner 2026-10-13): the source's own date for the record, when it was fetched, and what it proves.
    published: str | None = None
    fetched_at: str | None = None
    role: EvidenceRole = EvidenceRole.CONTEXT
    # G232: groups behind it attacked the deployment's country, its region, or neither (global); never proof
    # that this asset or its organisation was attacked.
    scope: EvidenceScope = EvidenceScope.GLOBAL
    # G234 (owner 2026-10-14: the feeds guide the controls): the source's own names for what reduces it, the
    # ones its facts say (an ATT&CK technique's mitigations); the control search reads them.
    mitigations: tuple[str, ...] = ()

    def as_doc(self) -> dict[str, Any]:
        return asdict(self) | {"facts": list(self.facts), "mitigations": list(self.mitigations)}


@dataclass(frozen=True)
class Considered:
    """One candidate of a search and what became of it."""

    ref: str
    score: float
    decision: EvidenceDecision
    reason: str = ""  # an EvidenceReason, filled in: a short rule-based reason for an exclusion

    def as_doc(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceSearchRecord:
    query: str  # what was searched, so the search can be repeated
    asset_types: tuple[str, ...]  # the IT / OT filter applied before ranking
    snapshot_id: str | None  # None: no snapshot yet, so nothing was searched
    threshold: float
    considered: tuple[Considered, ...] = field(default_factory=tuple)
    stale: bool = False  # the snapshot's sources have not refreshed within the age limit; still used
    failure: EvidenceSearchFailure | None = None  # the search could not be made: no evidence, run goes on

    def as_doc(self) -> dict[str, Any]:
        return asdict(self) | {
            "asset_types": list(self.asset_types),
            "considered": [c.as_doc() for c in self.considered],
        }


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
        return asdict(self)
