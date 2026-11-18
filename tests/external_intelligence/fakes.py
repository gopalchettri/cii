"""Fakes of the other groups' pieces for group C's tests: a finder that answers from a table and counts its
calls, a switch, and a refresher. The real classes replace the stubs at merge; these tests only rely on the
documented signatures. Also the admin module with chosen parts in place."""

from collections.abc import Sequence
from datetime import datetime
from types import ModuleType
from typing import Any

import pytest

from app.core.constants import AiOutage, EvidenceDecision, EvidenceFact, EvidenceSearchFailure, IntelKind, IntelSource
from app.domain.intel import admin
from app.domain.intel.switch import IntelligenceSwitch
from app.schemas.intel_records import (
    Considered,
    Evidence,
    EvidenceRequest,
    EvidenceResult,
    EvidenceSearchRecord,
    RefreshSummary,
    SwitchState,
)

SNAPSHOT = "snap-1"
#: A fact as the evidence search builds it (EvidenceFact.USED_BY): it names a group, so a story may cite it (G268).
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
        self.calls: list[Sequence[EvidenceRequest]] = []
        self.down = False
        self.outage: AiOutage | None = None  # with `down`: the AI outage that stopped the search
        self.raises = False
        self.evidence: tuple[Evidence, ...] = (TECHNIQUE,)

    def find_evidence(self, requests: Sequence[EvidenceRequest]) -> list[EvidenceResult]:
        self.calls.append(requests)
        if self.raises:
            raise RuntimeError("a bug in the search")
        return [self._result_of(request, self.evidence) for request in requests]

    def _result_of(self, request: EvidenceRequest, evidence: tuple[Evidence, ...]) -> EvidenceResult:
        failure = EvidenceSearchFailure.UNAVAILABLE if self.down else None
        considered = () if self.down else (Considered("T0839", 91.0, EvidenceDecision.USED),)
        outage = self.outage if self.down else None
        search = EvidenceSearchRecord(
            request.text, tuple(sorted(request.asset_types)), SNAPSHOT, 1.0, considered, failure, "", outage
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

    def refresh_all_sources(self, now: datetime) -> RefreshSummary:
        self.calls.append(("due", None))
        return RefreshSummary((), self.index_error is None, self.index_error)

    def refresh_one_source(self, source: IntelSource, now: datetime) -> RefreshSummary:
        self.calls.append(("one", source))
        return RefreshSummary((), self.index_error is None, self.index_error)


_GETTERS = {
    "settings": "get_settings",
    "switch": "get_intelligence_switch",
    "feeds": "get_intel_feed_repository",
    "snapshots": "get_intel_snapshot_repository",
    "admin_jobs": "get_admin_job_repository",
    "audit": "get_audit_repository",
    "index_keeper": "get_evidence_index_keeper",
}


def intelligence_service(monkeypatch: pytest.MonkeyPatch, **changed: Any) -> ModuleType:
    """The admin module over the app's own parts, with `changed` ones in their place; the index keeper is
    never built unless given (it builds the AI models). Nothing is sent unless `send_admin_job` is given."""
    monkeypatch.setattr(admin, "get_evidence_index_keeper", _no_keeper)
    monkeypatch.setattr(admin, "send_admin_job", changed.pop("send_admin_job", _not_sent))
    for name, part in changed.items():
        monkeypatch.setattr(admin, _GETTERS[name], lambda part=part: part)
    return admin


def _no_keeper() -> None:
    raise AssertionError("the test gave no index_keeper")


def _not_sent(task: str, job_id: str) -> bool:
    """A job queue that is unreachable."""
    return False
