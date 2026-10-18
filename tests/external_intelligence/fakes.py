"""Fakes of the other groups' pieces for group C's tests: a finder that answers from a table and counts its
calls, a switch, and a refresher. The real classes replace the stubs at merge; these tests only rely on the
documented signatures."""

from collections.abc import Collection, Sequence
from datetime import datetime
from typing import Any

from app.core.constants import (
    EvidenceDecision,
    EvidenceFact,
    EvidenceSearchFailure,
    IntelKind,
    IntelSource,
)
from app.models.external_intelligence.evidence import (
    Considered,
    Evidence,
    EvidenceBatchSummary,
    EvidenceSearchRecord,
)
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.models.external_intelligence.switch_state import SwitchState
from app.services.external_intelligence.switch import ExternalIntelligenceSwitch

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
        search = EvidenceSearchRecord(
            request.text, tuple(sorted(request.asset_types)), SNAPSHOT, 1.0, considered, stale, failure
        )
        return EvidenceResult(() if self.down else evidence, search)


class FakeSwitch(ExternalIntelligenceSwitch):
    """The real switch's is_on over a state the test sets; no store is read."""

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(feeds=None)  # type: ignore[arg-type]
        self.enabled = enabled
        self.known = True  # False: its store could not be read and no value was kept (it reads off)

    def state(self) -> SwitchState:
        return SwitchState(True, self.enabled and self.known, known=self.known)


class FakeRefresher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def refresh_due_sources(self, now: datetime) -> None:
        self.calls.append(("due", None))

    def refresh_one_source(self, source: IntelSource, now: datetime) -> None:
        self.calls.append(("one", source))
