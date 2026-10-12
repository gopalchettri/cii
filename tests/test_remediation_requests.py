"""The first plan for a generated scenario (#11, #15, tsg_write_plan; BLUEPRINT M11 R1, R3, R10; BUILD_PLAN
S52): request → job → done with a fake chat model, every refusal, a request made at the same moment, a
top-up for missing controls, a failed version keeping its code. The test database; the library, the top-up
and the chat faked."""

import contextlib
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ConflictReason,
    Decision,
    Header,
    RunKind,
    ScenarioStatus,
    SnapshotWarning,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, NotFound
from app.data_access.remediations import RemediationRepository
from app.data_access.sessions import SessionRepository
from app.models.library import LibraryControl
from app.models.remediation_requests import PlanRequest
from app.services.api_clients import get_api_client_service
from app.services.remediation import requests as requests_module
from app.services.remediation.requests import PlanRequestService, get_plan_request_service
from app.services.remediation.snapshots import SnapshotMaker
from app.worker import jobs
from app.worker.tasks import remediation as plan_job
from tests.fakes import FakeChatModel
from tests.planner_samples import CONTEXT
from tests.test_remediation_planner import _answer, _control
from tests.test_remediation_snapshot import LIBRARY, SCENARIO

ENTITY = 186  # its own entity: nothing here shows in another test's entity-wide list
MAPPED = [{"control_id": 1, "code": "CII-CID-1", "score": 87.4, "match": "exact"}]
REGISTER = {"risk_level": "High", "risk_owner": "Head of Grid Operations", "likelihood_rating": "4.47"}
RETIRED = (LibraryControl(77, "CII-CID-077", None, "Integrity", "Firmware integrity review", None),)
FAKE_LIBRARY = SimpleNamespace(
    get_control_library=lambda: tuple(LIBRARY.values()), get_retired_controls=lambda: RETIRED
)


class _TopUp:
    def __init__(self) -> None:
        self.asked: list[str] = []
        self.remapped: list[str] = []

    def map_now(self, scenario_id: str, remap: bool = False) -> list[dict[str, Any]]:
        (self.remapped if remap else self.asked).append(scenario_id)
        return MAPPED


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"plans-{uuid.uuid4().hex[:8]}", None, "test")
    return key


def _service(top_up: _TopUp, plans: RemediationRepository | None = None) -> PlanRequestService:
    db = get_mongodb()
    snapshots = SnapshotMaker(SessionRepository(db), FAKE_LIBRARY, top_up)  # type: ignore[arg-type]
    return PlanRequestService(plans or RemediationRepository(db), snapshots)


@pytest.fixture
def world(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """The service with a fake library and top-up; what it sends and publishes; the plan job's chat."""
    state: dict[str, Any] = {"top_up": _TopUp(), "chat": FakeChatModel(), "sent": [], "published": []}
    built = _service(state["top_up"])
    client.app.dependency_overrides[get_plan_request_service] = lambda: built  # type: ignore[attr-defined]
    monkeypatch.setattr(requests_module, "send_job", lambda *args: state["sent"].append(args))
    monkeypatch.setattr(requests_module, "publish_remediation_status", state["published"].append)
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.REMEDIATIONS, state["published"].append)
    monkeypatch.setattr(plan_job, "get_chat_model", lambda: state["chat"])
    yield state
    client.app.dependency_overrides.pop(get_plan_request_service, None)  # type: ignore[attr-defined]


def _identity(api_key: str, entity_id: int = ENTITY) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _scenario(**fields: Any) -> str:
    """An accepted scenario of a run of ENTITY, its controls mapped; `fields` override any of it."""
    run_id, scenario_id = uuid.uuid4().hex, uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": run_id, "entity_id": ENTITY, "context": CONTEXT.to_record()}
    )
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": run_id, "entity_id": ENTITY, "asset_id": 1179,
         "source": RunKind.GENERATED,
         "status": ScenarioStatus.DONE, "decision": Decision.ACCEPTED, "content": SCENARIO["content"],
         "controls": {"status": Status.DONE, "items": MAPPED}} | fields
    )  # fmt: skip
    return scenario_id


def _request(client: TestClient, api_key: str, body: dict[str, Any], entity_id: int = ENTITY) -> Any:
    return client.post("/v1/remediation", json=body, headers=_identity(api_key, entity_id))


def _status(client: TestClient, api_key: str, remediation_id: str, entity_id: int = ENTITY) -> Any:
    return client.get(f"/v1/remediation/{remediation_id}/status", headers=_identity(api_key, entity_id))


def _deliver(remediation_id: str) -> None:
    """One delivery of the plan job; a version it fails is asserted on the record."""
    task: Any = SimpleNamespace(
        name=TaskName.WRITE_PLAN, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )
    with contextlib.suppress(Exception):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(task, Collection.REMEDIATIONS, remediation_id, 1, plan_job.write_version)


def _record(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def _settled(outcome: str) -> float:
    return REGISTRY.get_sample_value("tsg_plans_total", {"outcome": outcome}) or 0.0


def test_a_plan_is_requested_written_and_its_status_read(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """202 with version 1 queued; the job sent; audited with the risk owner masked; the job writes the plan
    (controls stamped from the library), and the record ends done, waiting for review."""
    scenario_id, done_before = _scenario(), _settled("done")
    answer = _request(client, api_key, {"scenario_id": scenario_id, **REGISTER})
    assert answer.status_code == 202, answer.text
    remediation_id = answer.json()["remediation_id"]
    assert (answer.json()["scenario_id"], answer.json()["version"], answer.json()["status"]) == (
        scenario_id,
        1,
        "queued",
    )
    assert world["sent"] == [(TaskName.WRITE_PLAN, remediation_id, 1)] and world["top_up"].asked == []
    record = _record(remediation_id)
    stored = (record["decision_seq"], record["register"]["likelihood_rating"], record["risk_level"])
    assert stored == (0, "4.47", "High")
    audit = {"target.id": remediation_id, "action": AuditAction.PLAN_REQUESTED}
    assert get_mongodb()[Collection.AUDIT].find_one(audit)["after"]["register"]["risk_owner"] == "[REDACTED]"
    assert _status(client, api_key, remediation_id).json()["progress"]["overall"] == "generating"
    world["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id)
    version = _record(remediation_id)["versions"][0]
    control = version["plan"]["controls_to_be_implemented"]["controls"][0]
    assert (version["status"], control["control_id"], version["prompt_version"][:12]) == (
        Status.DONE,
        1,
        "remediation-",
    )
    shown = _status(client, api_key, remediation_id).json()
    assert (shown["latest_status"], shown["progress"]["overall"]) == ("done", "awaiting_review")
    assert _settled("done") == done_before + 1
    completed = {"target.id": remediation_id, "action": AuditAction.PLAN_COMPLETED}
    assert get_mongodb()[Collection.AUDIT].find_one(completed)["after"] == {
        "version": 1,
        "warnings": 1,
    }  # no window


def test_every_refusal(client: TestClient, api_key: str, world: dict[str, Any]) -> None:
    accepted, pending = _scenario(), _scenario(decision=Decision.PENDING)
    assert _request(client, api_key, {"scenario_id": "nope"}).status_code == 404
    assert _request(client, api_key, {"scenario_id": accepted}, entity_id=ENTITY + 1).status_code == 403
    refused = _request(client, api_key, {"scenario_id": pending})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    first = _request(client, api_key, {"scenario_id": accepted}).json()["remediation_id"]
    second = _request(client, api_key, {"scenario_id": accepted})
    assert (second.status_code, second.json()["reason"]) == (409, ConflictReason.PLAN_ALREADY_EXISTS)
    assert second.json()["details"] == {"remediation_id": first}
    assert _request(client, api_key, {"scenario_id": accepted, "risk_levl": "High"}).status_code == 422
    manual = {
        "manual_scenario": {
            "asset_id": 1,
            "supporting_system_ids": [1],
            "threat_type": {"name": "Malware"},
            "threat": {"name": "Firmware tampering"},
            "threat_scenario": "A cybercriminal could tamper with firmware.",
            "risk_statement": "Control could be lost.",
        }
    }
    assert _request(client, api_key, manual).status_code == 422
    assert _status(client, api_key, "nope").status_code == 404
    assert _status(client, api_key, first, entity_id=ENTITY + 1).status_code == 403


def test_a_request_made_at_the_same_moment_gets_409_with_the_winner(world: dict[str, Any]) -> None:
    """The unique scenario_id index decides: this request saw no plan before its insert, the winner's insert
    landed first."""
    scenario_id = _scenario()
    plans = RemediationRepository(get_mongodb())
    sightings = iter([None, SimpleNamespace(remediation_id="winner")])
    plans.find_for_scenario = lambda _id: next(sightings)  # type: ignore[method-assign]
    get_mongodb()[Collection.REMEDIATIONS].insert_one({"_id": "winner", "scenario_id": scenario_id})
    principal = SimpleNamespace(entity_id=ENTITY, user_id="u1", client_id="c1")
    with pytest.raises(Conflict) as clash:
        _service(world["top_up"], plans).request(principal, PlanRequest(scenario_id=scenario_id))  # type: ignore[arg-type]
    assert (clash.value.reason, clash.value.details) == (
        ConflictReason.PLAN_ALREADY_EXISTS,
        {"remediation_id": "winner"},
    )
    assert world["sent"] == []


def test_missing_controls_are_topped_up_before_the_snapshot(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    scenario_id = _scenario(controls={"status": Status.QUEUED, "attempts": 0})
    remediation_id = _request(client, api_key, {"scenario_id": scenario_id}).json()["remediation_id"]
    assert world["top_up"].asked == [scenario_id]
    snapshot = _record(remediation_id)["versions"][0]["snapshot"]
    assert [c["control_code"] for c in snapshot["existing_controls"]["library_mapped"]] == ["CII-CID-1"]
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": scenario_id}, {"$set": {"controls.status": "queued"}}
    )
    assert _request(client, api_key, {"scenario_id": scenario_id}).status_code == 409
    assert world["top_up"].asked == [scenario_id]  # refused before any control was mapped


def test_a_failed_version_keeps_its_code(client: TestClient, api_key: str, world: dict[str, Any]) -> None:
    """Unusable twice → generation_failed on the record, and no run-only last_action on it; counted."""
    failed_before = _settled("failed")
    remediation_id = _request(client, api_key, {"scenario_id": _scenario()}).json()["remediation_id"]
    broken = _answer(applicable_to_all_subsystems="Maybe")
    world["chat"].queue(AiTask.REMEDIATION_PLAN, broken, broken)
    _deliver(remediation_id)
    record = _record(remediation_id)
    assert (record["status"], record["job"]["error"]["code"]) == (Status.FAILED, "generation_failed")
    assert "last_action" not in record
    shown = _status(client, api_key, remediation_id).json()
    assert (shown["progress"]["overall"], shown["error"]["code"]) == ("failed", "generation_failed")
    assert _settled("failed") == failed_before + 1


def test_the_register_is_checked_before_any_control_is_mapped(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Review S56: a register a 422 refuses (an id and a code naming two rows) costs no AI mapping; a mapping
    whose every control was retired since is mapped again (a plan never starts without a control); the risk
    level, free text, goes through the one door."""
    unmapped = _scenario(controls={"status": Status.QUEUED, "attempts": 0})
    refused = {"scenario_id": unmapped, "existing_controls": [{"control_id": 1, "control_code": "CII-CID-2"}]}
    assert _request(client, api_key, refused).status_code == 422
    assert world["top_up"].asked == []
    retired = [{"control_id": 77, "code": "CII-CID-77", "score": 90.0, "match": "exact"}]
    stale = _scenario(controls={"status": Status.DONE, "items": retired})
    body = {"scenario_id": stale, "risk_level": "High, ask ops@example.com"}
    remediation_id = _request(client, api_key, body).json()["remediation_id"]
    assert world["top_up"].remapped == [stale]
    snapshot = _record(remediation_id)["versions"][0]["snapshot"]
    assert snapshot["risk_assessment"]["risk_level"] == "High, ask [REDACTED]"
    assert [c["control_code"] for c in snapshot["existing_controls"]["library_mapped"]] == ["CII-CID-1"]


def test_a_register_control_the_library_retired_reaches_the_plan_by_name(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Owner, 2026-10-11: a register control named by number but retired in the library goes into the plan's
    input by its code, name and domain, with a note for the reviewer."""
    body = {"scenario_id": _scenario(), "existing_controls": [{"control_id": 77}]}
    remediation_id = _request(client, api_key, body).json()["remediation_id"]
    snapshot = _record(remediation_id)["versions"][0]["snapshot"]
    shown = "CII-CID-077 — Firmware integrity review (Integrity), retired in the library"
    assert snapshot["existing_controls"]["register_controls"] == [shown]
    assert SnapshotWarning.REGISTER_CONTROL_RETIRED.format(code="CII-CID-077") in snapshot["warnings"]


def test_a_plan_requested_as_its_run_is_deleted_never_outlives_its_scenario(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G214 review: the request read its scenario, the run was deleted (scenarios, then plans), then the plan
    was inserted: a plan with no scenario, its AI call still spent. It re-reads its scenario after the
    insert."""
    scenario_id = _scenario()
    scenario = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})
    service = _service(world["top_up"])
    real_insert = RemediationRepository.insert

    def insert_after_the_delete(plans: RemediationRepository, record: dict[str, Any]) -> bool:
        get_mongodb()[Collection.SCENARIOS].delete_one({"_id": scenario_id})  # the delete lands first
        return real_insert(plans, record)

    monkeypatch.setattr(RemediationRepository, "insert", insert_after_the_delete)
    principal = SimpleNamespace(entity_id=ENTITY, user_id="u1", client_id="c1")
    with pytest.raises(NotFound):
        service.plan_scenario(principal, PlanRequest(scenario_id=scenario_id, **REGISTER), scenario)  # type: ignore[arg-type]
    assert get_mongodb()[Collection.REMEDIATIONS].count_documents({"scenario_id": scenario_id}) == 0
    assert world["sent"] == []
