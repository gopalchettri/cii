"""The plan job's input completion (app/worker/remediation/plan_inputs.py: a plan request makes no AI call) on
fakes: the control mapping (the scenarios it was asked for, one library control back; it can be made to wait,
as a busy AI does), the attacker search (the queries it got) and the library proposal (what was proposed).
Also the remediation service and plan job built as the app builds them, with some parts swapped."""

import threading
from types import SimpleNamespace
from typing import Any

from app import container
from app.core.constants import ControlMatch, ResolveOutcome
from app.models.library.library import ProposedThreat, ThreatProposal
from app.models.scenario.controls import ControlMapping, MappedControl
from app.realtime.publisher import publish_remediation_status
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.worker.celery_app import send_job
from app.worker.remediation.plan_inputs import PlanInputs
from app.worker.remediation.remediation_plan_job import RemediationPlanJob
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
    """LibrarySearch's surface: the actors a query may rank, in library order, and the active controls; every
    query kept."""

    def __init__(self, controls: tuple[Any, ...]) -> None:
        self.queries: list[str] = []
        self.controls = controls

    def snapshot(self) -> Any:
        def find_actors(queries: list[str], top_k: int, allowed_ids: list[Any]) -> list[Any]:
            self.queries += queries
            actors = THREATS.actors
            return [[(a, 1.0) for a in actors if ids is None or a.actor_id in ids] for ids in allowed_ids]

        library = SimpleNamespace(threat_library=THREATS, control_library=self.controls, stamp=())
        return SimpleNamespace(library=library, find_actors=find_actors)


def fake_plan_inputs(controls: tuple[Any, ...] = ()) -> tuple[PlanInputs, dict[str, Any]]:
    """PlanInputs on the fakes (its search snapshot holding `controls`) and the app's repositories, and
    {mapper, search, proposals} to read what the plan job did."""
    proposals: list[ThreatProposal] = []

    def propose(operation_id: str, proposal: ThreatProposal) -> tuple[ProposedThreat, bool]:
        proposals.append(proposal)
        type_id = 1 if proposal.type_name == "Malware" else 900
        return ProposedThreat(type_id, 901, ResolveOutcome.CREATED_PENDING), True

    search, mapper = FakeSearch(controls), FakeMapper()
    inputs = PlanInputs(
        search=search,  # type: ignore[arg-type]
        rerank=FakeRerankModel(),
        threats=SimpleNamespace(propose_threat=propose),  # type: ignore[arg-type]
        scenarios=container.get_threat_scenario_repository(),
        sessions=container.get_threat_scenario_session_repository(),
        remediations=container.get_remediation_repository(),
        audit=container.get_audit_repository(),
    )
    inputs._mapper = mapper  # type: ignore[assignment]  # noqa: SLF001 — the fake in place of the reranker's
    return inputs, {"mapper": mapper, "search": search, "proposals": proposals}


def remediation_plan_service(**changed: Any) -> RemediationPlanService:
    """The remediation service on the app's own repositories and side effects, `changed` ones swapped in."""
    dependencies: dict[str, Any] = {
        "remediations": container.get_remediation_repository(),
        "scenarios": container.get_threat_scenario_repository(),
        "sessions": container.get_threat_scenario_session_repository(),
        "assets": container.get_asset_repository(),
        "library": container.get_library_cache(),
        "audit": container.get_audit_repository(),
        "send_job": send_job,
        "publish_remediation_status": publish_remediation_status,
    }
    return RemediationPlanService(**(dependencies | changed))


def remediation_plan_job(chat: Any, inputs: PlanInputs, **changed: Any) -> RemediationPlanJob:
    """The plan job on `chat`, `inputs` and the app's own repositories, `changed` ones swapped in."""
    dependencies: dict[str, Any] = {
        "remediations": container.get_remediation_repository(),
        "audit": container.get_audit_repository(),
    }
    return RemediationPlanJob(chat=chat, inputs=inputs, **(dependencies | changed))
