"""Fakes of the other groups' pieces for group C's tests: a finder that answers from a table and counts its
calls, a switch, and a refresher. The real classes replace the stubs at merge; these tests only rely on the
documented signatures. Also the admin service as the container builds it, with chosen parts in place."""

from collections.abc import Collection, Sequence
from datetime import datetime
from typing import Any

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiOutage,
    EvidenceDecision,
    EvidenceFact,
    EvidenceSearchFailure,
    IntelKind,
    IntelSource,
)
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.models.external_intelligence.evidence import (
    Considered,
    Evidence,
    EvidenceBatchSummary,
    EvidenceSearchRecord,
)
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.models.external_intelligence.refresh_summary import RefreshSummary
from app.models.external_intelligence.switch_state import SwitchState
from app.services.external_intelligence.external_intelligence_service import ExternalIntelligenceService

SNAPSHOT = "snap-1"
#: A fact as the real feeds build it (EvidenceFact.USED_BY): it names a group, so a story may cite it (G268).
NAMED_FACT = EvidenceFact.USED_BY.format(name="Sandworm Team", what="a threat group")
FACT = "Sandworm used a rogue firmware update to disable substation devices in a real attack."
TECHNIQUE = Evidence(
    ref="T0839",
    kind=IntelKind.TECHNIQUE,
    source=IntelSource.ATTACK_ICS,
    title="Module Firmware",
    url="https://attack.mitre.org/techniques/T0839/",
    score=91.0,
    facts=(FACT, "Defenders limit vendor remote access and monitor firmware changes.", NAMED_FACT),
)


class FakeFinder:
    """One technique for every request; `down` = the search service is unavailable; `raises` = a bug."""

    def __init__(self) -> None:
        self.calls: list[tuple[Sequence[EvidenceRequest], bool]] = []
        self.down = False
        self.outage: AiOutage | None = None  # with `down`: the AI outage that stopped the search
        self.raises = False
        self.evidence: tuple[Evidence, ...] = (TECHNIQUE,)

    def find_evidence(
        self, requests: Sequence[EvidenceRequest], *, stale: bool, approved: Collection[IntelSource]
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        self.calls.append((requests, stale))
        if self.raises:
            raise RuntimeError("a bug in the search")
        # as the real index: a record of a source no longer approved is never a candidate
        evidence = tuple(item for item in self.evidence if {item.source, *item.joined} <= set(approved))
        results = [self._result_of(request, stale, evidence) for request in requests]
        used = 0 if self.down else len(evidence) * len(requests)
        summary = EvidenceBatchSummary(
            SNAPSHOT,
            {"mitre_attack_ics": "r1"},
            len(requests),
            0 if self.down else len(requests),
            used,
            stale,
        )
        return results, summary

    def _result_of(
        self, request: EvidenceRequest, stale: bool, evidence: tuple[Evidence, ...]
    ) -> EvidenceResult:
        failure = EvidenceSearchFailure.UNAVAILABLE if self.down else None
        considered = () if self.down else (Considered("T0839", 91.0, EvidenceDecision.USED),)
        outage = self.outage if self.down else None
        search = EvidenceSearchRecord(
            request.text,
            tuple(sorted(request.asset_types)),
            SNAPSHOT,
            1.0,
            considered,
            stale,
            failure,
            "",
            outage,
        )
        return EvidenceResult(() if self.down else evidence, search)


class FakeSwitch(IntelligenceSwitch):
    """The real switch's is_on over a state the test sets; no store is read."""

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(feeds=None, env_enabled=True)  # type: ignore[arg-type]
        self.enabled = enabled
        self.known = True  # False: its store could not be read and no value was kept (it reads off)

    def state(self) -> SwitchState:
        return SwitchState(True, self.enabled and self.known, known=self.known)


class FakeRefresher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.index_error: dict[str, str] | None = None  # set: the index rebuild after the refresh failed

    def refresh_due_sources(self, now: datetime) -> RefreshSummary:
        self.calls.append(("due", None))
        return RefreshSummary((), self.index_error is None, self.index_error)

    def refresh_one_source(self, source: IntelSource, now: datetime) -> RefreshSummary:
        self.calls.append(("one", source))
        return RefreshSummary((), self.index_error is None, self.index_error)


def intelligence_service(**changed: Any) -> ExternalIntelligenceService:
    """The service over the app's own parts, with `changed` ones in their place; a part given is never built
    (the index keeper builds the AI models). Nothing is sent unless `send_admin_job` is given."""
    providers = {
        "settings": get_settings,
        "switch": container.get_intelligence_switch,
        "feeds": container.get_intel_feed_repository,
        "records": container.get_intel_record_repository,
        "snapshots": container.get_intel_snapshot_repository,
        "vectors": container.get_embedding_repository,
        "admin_jobs": container.get_admin_job_repository,
        "audit": container.get_audit_repository,
        "index_keeper": container.get_evidence_index_keeper,
        "send_admin_job": lambda: _not_sent,
    }
    parts = {name: changed[name] if name in changed else build() for name, build in providers.items()}
    return ExternalIntelligenceService(**parts)


def _not_sent(task: str, job_id: str) -> bool:
    """A job queue that is unreachable."""
    return False
