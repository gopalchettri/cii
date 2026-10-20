"""The remediation service and plan job as the app builds them, on the app's repositories, with the AI, the
library, the search and the library proposal faked; the samples and fixtures (api_key, world) the remediation
API tests share (import api_key_fixture and world_fixture to use the fixtures)."""

import contextlib
import threading
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    Collection,
    ControlMatch,
    LibraryRowKind,
    ResolveOutcome,
    StrideCategory,
    TaskName,
)
from app.models.library.library import (
    LibraryActor,
    LibraryControl,
    LibraryThreat,
    LibraryThreatType,
    LoadedLibraries,
    PendingLibraryRow,
    ProposedThreat,
    RejectedLibraryThreat,
    ThreatLibrary,
    ThreatProposal,
)
from app.models.scenario.controls import ControlMapping, MappedControl
from app.realtime.publisher import publish_remediation_status
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.worker import jobs
from app.worker.celery_app import send_job
from app.worker.remediation.remediation_plan_job import RemediationPlanJob
from tests.fakes import FakeChatModel

CREW = LibraryActor(3, "Organised crime group")
TAMPERING, ELEVATION = StrideCategory.TAMPERING, StrideCategory.ELEVATION_OF_PRIVILEGE
#: One live threat (Malware: Firmware tampering), a pending type and threat, a curator-rejected wording.
THREATS = ThreatLibrary(
    threats=(LibraryThreat(10, "Firmware tampering", 1, "Malware", (TAMPERING, ELEVATION), (CREW,)),),
    actors=(CREW,),
    types=(
        LibraryThreatType(1, "Malware", TAMPERING, (CREW,)),
        LibraryThreatType(2, "Phishing", StrideCategory.SPOOFING),
    ),
    category_ids=((1, "Spoofing"), (2, "Tampering")),
    pending=(
        PendingLibraryRow(LibraryRowKind.TYPE, 5, "Supply chain", None),
        PendingLibraryRow(LibraryRowKind.THREAT, 20, "Vendor implant", 5),
    ),
    curator_rejected=(RejectedLibraryThreat(30, "Rogue USB", 1),),
)
#: The active controls by id: CII-CID-2 (IT) and CII-CID-5 (OT) are twins (the same name and text).
CONTROLS = {
    1: LibraryControl(
        1, "CII-CID-1", "OT", "Integrity", "Firmware integrity verification", "Signed firmware."
    ),
    2: LibraryControl(2, "CII-CID-2", "IT", "Access", "Vendor remote-access approval", "Approves sessions."),
    5: LibraryControl(5, "CII-CID-5", "OT", "Access", "Vendor remote-access approval", "Approves sessions."),
}
#: A generated scenario's content as stored.
SCENARIO_CONTENT: dict[str, Any] = {
    "title": "Loss of control integrity",
    "statement": "A cybercriminal could push unsigned firmware to the RTU at Grid Control Centre.",
    "risk_statement": "Loss of trusted control could interrupt transmission.",
    "category": "Tampering",
    "threat": {"type": "Malicious code", "name": "Firmware tampering"},
    "actors": [{"id": 7, "name": "Cybercriminal", "role": "acting"}],
    "systems": [{"id": 321, "name": "SCADA server", "entry_point": True}],
    "route": {"status": "standalone"},
}


def plan_control(code: str) -> dict[str, Any]:
    """One recommended control as the plan AI writes it."""
    return {
        "control_type": "preventive",
        "control_name": "Firmware integrity verification",
        "description": "Stops unsigned firmware reaching the RTU.",
        "priority": "High",
        "control_code": code,
    }


def _plan_action(action_id: str, depends_on: tuple[str, ...], codes: tuple[str, ...]) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "action": f"Do {action_id}",
        "owner": "OT Security",
        "priority": "High",
        "dependencies": ", ".join(depends_on) or "None",
        "depends_on": list(depends_on),
        "duration_days": 10,
        "implements_controls": list(codes),
        "success_criteria": "Shown by the firmware policy and a signing test.",
    }


def plan_answer(*codes: str, **fields: Any) -> dict[str, Any]:
    """A plan answer recommending `codes`: A1 (10 days) implements them, A2 (10 days) waits for A1."""
    actions = [_plan_action("A1", (), codes), _plan_action("A2", ("A1",), ())]
    return {
        "title": "Firmware Integrity Hardening",
        "controls_to_be_implemented": {
            "control_coverage": "gaps",
            "controls": [plan_control(code) for code in codes],
        },
        "remediation_action_plan": actions,
        "action_plan": "A1, then A2 validates it.",
        "mitigation_owner": "OT Security",
        "applicable_to_all_subsystems": "Yes",
    } | fields


class FakeMapper:
    """ControlMapper's surface: the scenarios it was asked for, one library control back each time."""

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
    """LibrarySearch's surface: THREATS' actors a query may rank, in library order, and the active controls;
    every query kept."""

    def __init__(self, controls: tuple[LibraryControl, ...]) -> None:
        self.queries: list[str] = []
        self.controls = controls

    def snapshot(self) -> Any:
        def find_actors(queries: list[str], top_k: int, allowed_ids: list[Any]) -> list[Any]:
            self.queries += queries
            actors = THREATS.actors
            return [[(a, 1.0) for a in actors if ids is None or a.actor_id in ids] for ids in allowed_ids]

        library = SimpleNamespace(threat_library=THREATS, control_library=self.controls, stamp=())
        return SimpleNamespace(library=library, find_actors=find_actors)


def plan_job_fakes(controls: tuple[LibraryControl, ...] = ()) -> dict[str, Any]:
    """The plan job's faked parts, to read what it did: {mapper, search (holding `controls`), threats,
    proposals}; a proposal of type Malware gets type 1, any other the new type 900, each threat 901."""
    proposals: list[ThreatProposal] = []

    def propose(operation_id: str, proposal: ThreatProposal) -> tuple[ProposedThreat, bool]:
        proposals.append(proposal)
        type_id = 1 if proposal.type_name == "Malware" else 900
        return ProposedThreat(type_id, 901, ResolveOutcome.CREATED_PENDING), True

    return {
        "mapper": FakeMapper(),
        "search": FakeSearch(controls),
        "threats": SimpleNamespace(propose_threat=propose),
        "proposals": proposals,
    }


def fake_library(controls: tuple[LibraryControl, ...]) -> Any:
    """LibraryCache's surface: THREATS and `controls`, always current."""
    loaded = LoadedLibraries((), THREATS, controls)
    return SimpleNamespace(check_library_once=lambda: None, get_loaded_libraries=lambda: loaded)


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


def remediation_plan_job(chat: Any, fakes: dict[str, Any], **changed: Any) -> RemediationPlanJob:
    """The plan job on `chat`, the fakes' mapper, search and threats and the app's own repositories, `changed`
    ones swapped in."""
    dependencies: dict[str, Any] = {
        "remediations": container.get_remediation_repository(),
        "scenarios": container.get_threat_scenario_repository(),
        "sessions": container.get_threat_scenario_session_repository(),
        "threats": fakes["threats"],
        "audit": container.get_audit_repository(),
        "search": fakes["search"],
        "mapper": fakes["mapper"],
        "chat": chat,
    }
    return RemediationPlanJob(**(dependencies | changed))


def deliver(remediation_id: str, version: int = 1) -> None:
    """One delivery of the container's plan job, as tasks.py runs it; what it settles is on the record."""
    task: Any = SimpleNamespace(
        name=TaskName.WRITE_PLAN, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )
    write = container.get_remediation_plan_job().write_remediation_plan_version
    with contextlib.suppress(Exception):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(
            task, Collection.REMEDIATIONS, remediation_id, version, write, RemediationPlanJob.RECORD_FIELDS
        )


@pytest.fixture(scope="module", name="api_key")
def api_key_fixture() -> str:
    """An API client's key for this test module."""
    _, key = container.get_admin_service().create_api_client(f"plans-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture(name="world")
def world_fixture(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """The app's remediation service (`service`) on fake_library(CONTROLS), what it sends and publishes, and
    the plan job (`job`, the container's) on its chat and plan_job_fakes."""
    state: dict[str, Any] = {"chat": FakeChatModel(), "sent": [], "published": []}
    state |= plan_job_fakes(tuple(CONTROLS.values()))
    built = remediation_plan_service(
        library=fake_library(tuple(CONTROLS.values())),
        send_job=lambda *args: state["sent"].append(args),
        publish_remediation_status=state["published"].append,
    )
    state |= {"service": built, "job": remediation_plan_job(state["chat"], state)}
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_remediation_plan_service] = lambda: built
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.REMEDIATIONS, state["published"].append)
    monkeypatch.setattr(container, "get_remediation_plan_job", lambda: state["job"])
    yield state
    overrides.pop(container.get_remediation_plan_service, None)
