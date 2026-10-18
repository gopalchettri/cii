"""The plan job's input completion (app/worker/plan_inputs.py, G262: a plan request makes no AI call) on
fakes: the control mapping (the scenarios it was asked for, one library control back; it can be made to wait,
as a busy AI does), the attacker search (the queries it got) and the library proposal (what was proposed)."""

import threading
from types import SimpleNamespace
from typing import Any

from app.core.constants import ControlMatch, ResolveOutcome
from app.models.controls import ControlMapping, MappedControl
from app.models.library import ProposedThreat, ThreatProposal
from app.worker.plan_inputs import PlanInputs
from tests.fakes import FakeRerankModel
from tests.test_threat_identity import LIBRARY as THREATS


class FakeMapper:
    def __init__(self) -> None:
        self.asked: list[str] = []
        self.release: threading.Event | None = None  # set: each mapping waits for it, as a busy AI makes it
        self.control = (1, "CII-CID-1")  # the library control (id, code) each mapping answers
        self.failure: Exception | None = None  # raised by the next mapping (an outage), then cleared

    def map_controls(self, scenario: dict[str, Any], context: Any, snapshot: Any) -> ControlMapping:
        self.asked.append(scenario["_id"])
        if self.release is not None:
            self.release.wait(30)
        if self.failure is not None:
            failure, self.failure = self.failure, None
            raise failure
        control_id, code = self.control
        control = MappedControl(control_id, code, "A control", None, "OT", 1, 87.4, ControlMatch.EXACT)
        return ControlMapping(items=(control,), query="the scenario and its risk")


class FakeSearch:
    """LibrarySearch's surface: the actors a query may rank, in library order; every query kept."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    def snapshot(self) -> Any:
        def find_actors(queries: list[str], top_k: int, allowed_ids: list[Any]) -> list[Any]:
            self.queries += queries
            actors = THREATS.actors
            return [[(a, 1.0) for a in actors if ids is None or a.actor_id in ids] for ids in allowed_ids]

        library = SimpleNamespace(threat_library=THREATS, stamp=())
        return SimpleNamespace(library=library, find_actors=find_actors)


def fake_plan_inputs(library: Any) -> tuple[PlanInputs, dict[str, Any]]:
    """PlanInputs on the fakes, and {mapper, search, proposals} to read what the plan job did."""
    proposals: list[ThreatProposal] = []

    def propose(operation_id: str, proposal: ThreatProposal) -> tuple[ProposedThreat, bool]:
        proposals.append(proposal)
        type_id = 1 if proposal.type_name == "Malware" else 900
        return ProposedThreat(type_id, 901, ResolveOutcome.CREATED_PENDING), True

    search, mapper = FakeSearch(), FakeMapper()
    inputs = PlanInputs(library, search, FakeRerankModel(), SimpleNamespace(propose_threat=propose))  # type: ignore[arg-type]
    inputs._mapper = mapper  # type: ignore[assignment]  # noqa: SLF001 — the fake in place of the reranker's
    return inputs, {"mapper": mapper, "search": search, "proposals": proposals}
