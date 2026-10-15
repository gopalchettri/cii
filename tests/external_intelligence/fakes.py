"""Fakes of the other groups' pieces for group C's tests: a finder that answers from a table and counts its
calls, a switch, and a refresher. The real classes replace the stubs at merge; these tests only rely on the
documented signatures."""

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.core.constants import (
    EvidenceDecision,
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
from app.models.external_intelligence.known_groups import KnownGroup

SNAPSHOT = "snap-1"
FACT = "Sandworm used a rogue firmware update to disable substation devices in a real attack."
TECHNIQUE = Evidence(
    ref="T0839",
    kind=IntelKind.TECHNIQUE,
    source=IntelSource.ATTACK_ICS,
    title="Module Firmware",
    url="https://attack.mitre.org/techniques/T0839/",
    score=91.0,
    facts=(FACT, "Defenders limit vendor remote access and monitor firmware changes."),
)


class FakeFinder:
    """One technique for every request; `down` = the search service is unavailable; `raises` = a bug."""

    def __init__(self) -> None:
        self.calls: list[tuple[Sequence[EvidenceRequest], bool]] = []
        self.down = False
        self.raises = False
        self.evidence: tuple[Evidence, ...] = (TECHNIQUE,)
        self.groups: tuple[KnownGroup, ...] = ()  # G230: the real groups it answers with
        self.nearest: Evidence | None = None  # G254: the closest candidate when no evidence passed

    def find_evidence(
        self, requests: Sequence[EvidenceRequest], *, stale: bool
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        self.calls.append((requests, stale))
        if self.raises:
            raise RuntimeError("a bug in the search")
        results = [self._result_of(request, stale) for request in requests]
        used = 0 if self.down else len(self.evidence) * len(requests)
        summary = EvidenceBatchSummary(
            SNAPSHOT,
            {"mitre_attack_ics": "r1"},
            len(requests),
            0 if self.down else len(requests),
            used,
            stale,
        )
        return results, summary

    def _result_of(self, request: EvidenceRequest, stale: bool) -> EvidenceResult:
        failure = EvidenceSearchFailure.UNAVAILABLE if self.down else None
        considered = () if self.down else (Considered("T0839", 91.0, EvidenceDecision.USED),)
        search = EvidenceSearchRecord(
            request.text, tuple(sorted(request.asset_types)), SNAPSHOT, 1.0, considered, stale, failure
        )
        evidence, groups = (() if self.down else self.evidence), (() if self.down else self.groups)
        return EvidenceResult(evidence, search, groups, None if self.down else self.nearest)


class FakeSwitch:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.reads = 0

    def is_enabled(self) -> bool:
        self.reads += 1
        return self.enabled


class FakeRefresher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def refresh_due_sources(self, now: datetime) -> None:
        self.calls.append(("due", None))

    def refresh_one_source(self, source: IntelSource, now: datetime) -> None:
        self.calls.append(("one", source))
