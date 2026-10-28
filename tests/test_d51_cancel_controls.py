"""Cancel and delete leave a plan's controls to the plan. A run cancel stops only the run's own controls
(never a hand-written scenario's, never a plan job's live claim); a plan cancel stops the hand-written
controls only it maps and hands a generated scenario's claim back to the run as the run's cancel left it, as
the plan job's own give-back does; the cancel's later writes never touch a next set queued meanwhile; a
delete refused for plans names them; a plan job stopped meanwhile proposes nothing to the library. Records
written straight into the test MongoDB."""

import random
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    AiTask,
    Collection,
    ConflictReason,
    Decision,
    Header,
    JobKind,
    Remediation,
    RunActionKind,
    RunActionOutcome,
    RunKind,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.lease_signal import raise_if_lease_lost
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.data_access.service_mapper.mapping_repository import MappingRepository
from app.services.jobs.job_service import JobService
from app.worker import jobs
from app.worker.remediation import remediation_plan_job
from tests.plan_addresses import generated, plan_url
from tests.plan_job_fakes import (  # noqa: F401 — api_key_fixture and world_fixture are fixtures
    SCENARIO_CONTENT,
    api_key_fixture,
    deliver,
    plan_answer,
    world_fixture,
)
from tests.planner_samples import CONTEXT

NOW = datetime.now(UTC)
PLAN_CLAIM = f"plan-job{Remediation.CONTROLS_CLAIM_SUFFIX}"
WHO = {"user_id": "u1", "client_id": "c1"}


@pytest.fixture
def entity() -> int:
    """An organisation of this test alone: other tests' runs never show in its list."""
    return random.randint(10_000_000, 99_999_999)  # noqa: S311 — test data, not security


@pytest.fixture
def published(client: TestClient) -> Iterator[dict[str, list[str]]]:
    """The job routes with every live update kept here: the runs' and the plans' ids told."""
    told: dict[str, list[str]] = {"sessions": [], "plans": []}
    service = JobService(
        container.get_work_control_repository(),
        container.get_threat_scenario_session_repository(),
        container.get_audit_repository(),
        publish_session_status=told["sessions"].append,
        publish_remediation_status=told["plans"].append,
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_job_service] = lambda: service
    yield told
    overrides.pop(container.get_job_service, None)


def _who(api_key: str, entity_id: int) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "T",
    }


def _run(entity_id: int, status: Status, **fields: Any) -> str:
    """A run of `entity_id` at epoch 1 with its frozen asset context."""
    run_id = uuid.uuid4().hex
    record = {
        "_id": run_id, "entity_id": entity_id, "asset_id": 1179, "status": status, "step": "scenarios",
        "context": CONTEXT.to_record(), "counts": {}, "user_id": "u1", "created_at": NOW, "updated_at": NOW,
        "job": {"task": TaskName.WRITE_SCENARIOS, "epoch": 1, "task_id": "t1", "attempts": 1, "due_at": NOW,
                "lease_until": NOW + timedelta(minutes=2)},
    }  # fmt: skip
    get_mongodb()[Collection.SESSIONS].insert_one(record | fields)
    return run_id


def _scenario(run_id: str, entity_id: int, state: Status, **fields: Any) -> str:
    """An accepted written scenario of the run, its controls in `state`."""
    scenario_id = uuid.uuid4().hex
    record = {
        "_id": scenario_id, "session_id": run_id, "entity_id": entity_id, "asset_id": 1179,
        "path_id": scenario_id, "version": 1, "source": RunKind.GENERATED, "status": ScenarioStatus.DONE,
        "decision": Decision.ACCEPTED, "superseded_by": None, "content": SCENARIO_CONTENT, "created_at": NOW,
        "controls": {"status": state, "attempts": 0, "queued_at": NOW - timedelta(hours=1)},
    }  # fmt: skip
    get_mongodb()[Collection.SCENARIOS].insert_one(record | fields)
    return scenario_id


def _plan(entity_id: int, run_id: str, scenario_id: str, status: Status) -> str:
    plan_id = uuid.uuid4().hex
    get_mongodb()[Collection.REMEDIATIONS].insert_one(
        {"_id": plan_id, "entity_id": entity_id, "scenario_id": scenario_id, "session_id": run_id,
         "asset_id": 1179, "status": status, "decision": "pending", "created_at": NOW,
         "job": {"epoch": 1, "error": None, "due_at": NOW, "attempts": 1}, "updated_at": NOW}
    )  # fmt: skip
    return plan_id


def _controls(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]


def _work_control(sessions: Any) -> WorkControlRepository:
    """A job control whose tsg_sessions writes go through `sessions` (a proxy of the real collection)."""
    scenarios = ThreatScenarioRepository()
    runs = ThreatScenarioSessionRepository(sessions, scenarios=scenarios)
    return WorkControlRepository(runs, scenarios, RemediationRepository(), MappingRepository())


def _requested_plan(client: TestClient, api_key: str, entity_id: int, **scenario: Any) -> tuple[str, str]:
    """(a plan's id, its scenario's id): the plan requested for an accepted scenario of a new run, not written
    yet; `scenario` fields set on the card after the request (e.g. a hand-written source)."""
    scenario_id = _scenario(_run(entity_id, Status.DONE), entity_id, Status.QUEUED)
    answer = client.post("/v1/remediation", json=generated(scenario_id), headers=_who(api_key, entity_id))
    assert answer.status_code == 202, answer.text
    if scenario:
        get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": scenario})
    return answer.json()["remediation_id"], scenario_id


# --- a run cancel stops only the run's own controls


def test_a_run_cancel_leaves_a_plans_controls_to_the_plan(entity: int) -> None:
    """A finished run's cancel stops its own waiting controls, never a plan job's live claim nor a
    hand-written scenario's (only its plan maps them): the plan job's save still lands."""
    run_id = _run(entity, Status.DONE)
    held, own = _scenario(run_id, entity, Status.QUEUED), _scenario(run_id, entity, Status.QUEUED)
    hand_written = _scenario(run_id, entity, Status.QUEUED, source=RunKind.MANUAL)
    scenarios = container.get_threat_scenario_repository()
    claimed = scenarios.claim_scenario_controls_by_id(held, PLAN_CLAIM)
    assert claimed is not None
    records = container.get_work_control_repository()
    assert records.cancel_scenario_session(run_id, entity, WHO) == (False, 1)
    states = [_controls(card)["status"] for card in (held, hand_written, own)]
    assert states == [Status.RUNNING, Status.QUEUED, Status.CANCELLED]
    mapping = {"items": [{"control_id": 1}]}
    attempts = claimed["controls"]["attempts"]
    assert scenarios.update_scenario_controls(held, PLAN_CLAIM, attempts, Status.DONE, mapping=mapping)


@pytest.mark.parametrize("owner", ["plan_claim", "hand_written"])
def test_a_run_whose_only_controls_are_a_plans_has_nothing_to_cancel(
    client: TestClient, api_key: str, entity: int, owner: str
) -> None:
    """Before: 200 with the controls stopped, then the plan mapped them anyway."""
    if owner == "plan_claim":
        run_id = _run(entity, Status.DONE)
        scenario_id = _scenario(run_id, entity, Status.QUEUED)
        assert container.get_threat_scenario_repository().claim_scenario_controls_by_id(
            scenario_id, PLAN_CLAIM
        )
    else:
        run_id = _run(entity, Status.DONE, kind=RunKind.MANUAL)
        scenario_id = _scenario(run_id, entity, Status.QUEUED, source=RunKind.MANUAL)
    before = _controls(scenario_id)["status"]
    refused = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.NOTHING_TO_CANCEL)
    assert _controls(scenario_id)["status"] == before


def test_a_hand_written_run_is_listed_through_its_plan_alone(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Its controls are its plan's: the list shows the plan being written, not the run as matching controls
    (whose cancel would find nothing to stop)."""
    run_id = _run(entity, Status.DONE, kind=RunKind.MANUAL)
    scenario_id = _scenario(run_id, entity, Status.QUEUED, source=RunKind.MANUAL)
    container.get_threat_scenario_session_repository().update_scenario_session_counts(run_id)
    plan_id = _plan(entity, run_id, scenario_id, Status.QUEUED)
    listed = client.get("/v1/jobs", headers=_who(api_key, entity)).json()
    assert [(job["kind"], job["remediation_id"]) for job in listed["jobs"]] == [
        (JobKind.REMEDIATION, plan_id)
    ]
    assert listed["total"] == 1


def test_a_hand_written_run_whose_plan_failed_before_mapping_can_be_deleted(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Its waiting controls are its plan's work: with no plan being written, nothing maps them, and a delete
    that counted them answered cancel_first though no cancel could ever stop them."""
    run_id = _run(entity, Status.DONE, kind=RunKind.MANUAL)
    scenario_id = _scenario(run_id, entity, Status.QUEUED, source=RunKind.MANUAL)
    _plan(entity, run_id, scenario_id, Status.FAILED)
    deleted = client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity))
    assert deleted.status_code == 200, deleted.text


# --- the cancel's later writes leave a next set queued meanwhile alone


def test_a_next_set_queued_right_after_a_cancel_keeps_its_running_summary(entity: int) -> None:
    """The stopped next set's summary ends cancelled only at the stopped job's epoch: a next set queued
    between the stop and that write keeps its own summary running."""
    summary = {"outcome": RunActionOutcome.RUNNING, "requested": 6, "delivered": None, "epoch": 1}
    run_id = _run(entity, Status.RUNNING, last_action={"kind": RunActionKind.NEXT_SET}, last_next_set=summary)
    sessions = get_mongodb()[Collection.SESSIONS]

    class NextSetQueuedAfterTheStop:
        def __getattr__(self, name: str) -> Any:
            return getattr(sessions, name)

        def find_one_and_update(self, *args: Any, **kwargs: Any) -> Any:
            stopped = sessions.find_one_and_update(*args, **kwargs)
            next_set = {"status": Status.QUEUED, "job.epoch": 2, "last_next_set": summary | {"epoch": 2}}
            sessions.update_one({"_id": run_id}, {"$set": next_set, "$unset": {"cancelled": ""}})
            return stopped

    _work_control(NextSetQueuedAfterTheStop()).cancel_scenario_session(run_id, entity, WHO)
    assert sessions.find_one({"_id": run_id})["last_next_set"]["outcome"] == RunActionOutcome.RUNNING


def test_a_next_set_queued_during_a_finished_runs_cancel_is_never_stamped(
    entity: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cancel stamp lands on a session still finished: a next set queued after the controls stopped is
    neither marked cancelled nor loses its controls delivery."""
    run_id = _run(entity, Status.DONE)
    _scenario(run_id, entity, Status.QUEUED)
    sessions = get_mongodb()[Collection.SESSIONS]
    records = _work_control(sessions)
    recount = records._sessions.update_scenario_session_counts
    delivery = {"task_id": None, "until": NOW + timedelta(minutes=10)}

    def next_set_queued_meanwhile(session_id: str, *args: Any) -> dict[str, int]:
        queued = {"status": Status.QUEUED, "job.epoch": 2, "controls_delivery": delivery}
        sessions.update_one({"_id": run_id}, {"$set": queued, "$unset": {"cancelled": ""}})
        return recount(session_id, *args)

    monkeypatch.setattr(records._sessions, "update_scenario_session_counts", next_set_queued_meanwhile)
    assert records.cancel_scenario_session(run_id, entity, WHO) == (False, 1)
    stored = sessions.find_one({"_id": run_id})
    assert "cancelled" not in stored and "controls_delivery" in stored


# --- a plan cancel stops the hand-written controls only it maps


def test_a_hand_written_plans_cancel_stops_the_controls_only_it_maps(
    client: TestClient, api_key: str, entity: int, published: dict[str, list[str]]
) -> None:
    """Before: they waited for ever, the run listed as matching controls and its delete refused."""
    run_id = _run(entity, Status.DONE, kind=RunKind.MANUAL)
    scenario_id = _scenario(run_id, entity, Status.QUEUED, source=RunKind.MANUAL)
    plan_id = _plan(entity, run_id, scenario_id, Status.QUEUED)
    container.get_threat_scenario_session_repository().update_scenario_session_counts(run_id)
    cancelled = client.post(plan_url(plan_id, "cancel"), headers=_who(api_key, entity))
    assert cancelled.status_code == 200, cancelled.text
    controls = _controls(scenario_id)
    assert (controls["status"], controls.get("lease_until")) == (Status.CANCELLED, None)
    counts = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})["counts"]
    assert (counts["controls_waiting"], counts["controls_cancelled"]) == (0, 1)
    assert published == {"sessions": [run_id], "plans": [plan_id]}
    assert client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).status_code == 200


def test_a_stopped_plan_job_gives_a_hand_written_scenarios_controls_back_cancelled(
    client: TestClient,
    api_key: str,
    entity: int,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan stopped while its job maps a hand-written scenario's controls (or between the job's claim and
    its controls claim): they read cancelled, never failed as "could not be matched"."""
    monkeypatch.setattr(jobs.Lease, "RENEW_EVERY_SECONDS", 0.02)
    remediation_id, scenario_id = _requested_plan(client, api_key, entity, source=RunKind.MANUAL)

    def map_until_stopped(*_args: Any) -> None:
        plans = get_mongodb()[Collection.REMEDIATIONS]
        plans.update_one({"_id": remediation_id}, {"$set": {"status": Status.CANCELLED}})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:  # every AI call checks the signal first
            raise_if_lease_lost()
            time.sleep(0.01)

    monkeypatch.setattr(world["mapper"], "map_controls", map_until_stopped)
    deliver(remediation_id)
    controls = _controls(scenario_id)
    assert (controls["status"], controls.get("error")) == (Status.CANCELLED, None)


# --- a plan's claim on a generated scenario goes back to its run as the run's cancel left it


def _run_with_a_plans_live_claim(entity_id: int) -> tuple[str, str, str, str]:
    """(a finished run, its own waiting card, its card a plan job maps now under a live claim, that plan)."""
    run_id = _run(entity_id, Status.DONE)
    own, held = _scenario(run_id, entity_id, Status.QUEUED), _scenario(run_id, entity_id, Status.QUEUED)
    assert container.get_threat_scenario_repository().claim_scenario_controls_by_id(held, PLAN_CLAIM)
    return run_id, own, held, _plan(entity_id, run_id, held, Status.RUNNING)


def test_a_plan_cancel_after_its_runs_cancel_gives_the_claim_back_cancelled(
    client: TestClient, api_key: str, entity: int
) -> None:
    """The run cancel left the card a plan job maps to the plan; the plan's cancel hands it back as the run's
    cancel left it: cancelled, and the run deletes at once. Before: the delete answered cancel_first naming
    no plan while the run cancel answered nothing_to_cancel, then the job gave the card back queued for the
    background to map."""
    run_id, own, held, plan_id = _run_with_a_plans_live_claim(entity)
    headers = _who(api_key, entity)
    assert client.post(f"/v1/sessions/{run_id}/cancel", headers=headers).status_code == 200
    assert client.post(plan_url(plan_id, "cancel"), headers=headers).status_code == 200
    for card in (own, held):
        controls = _controls(card)
        assert (controls["status"], controls.get("lease_until")) == (Status.CANCELLED, None)
    deleted = client.delete(f"/v1/sessions/{run_id}", headers=headers)
    assert deleted.status_code == 200, deleted.text


def test_a_plan_cancel_gives_the_claim_back_queued_to_a_run_not_cancelled(
    client: TestClient, api_key: str, entity: int
) -> None:
    """The card waits for the run's own mapping again: the delete names no plan, and the run's cancel stops
    it. Before: it stayed running under the cancelled plan's claim, out of the run cancel's reach."""
    run_id, _, held, plan_id = _run_with_a_plans_live_claim(entity)
    headers = _who(api_key, entity)
    assert client.post(plan_url(plan_id, "cancel"), headers=headers).status_code == 200
    controls = _controls(held)
    assert (controls["status"], controls.get("lease_until")) == (Status.QUEUED, None)
    refused = client.delete(f"/v1/sessions/{run_id}", headers=headers)
    assert (refused.status_code, refused.json()["details"]) == (409, {"plans_to_cancel": []})
    assert client.post(f"/v1/sessions/{run_id}/cancel", headers=headers).status_code == 200
    assert _controls(held)["status"] == Status.CANCELLED
    assert client.delete(f"/v1/sessions/{run_id}", headers=headers).status_code == 200


def test_a_plan_job_fault_gives_a_cancelled_runs_controls_back_cancelled(
    client: TestClient,
    api_key: str,
    entity: int,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The run was cancelled before its plan's job claimed the card: a fault while mapping gives it back as
    the run's cancel left it. Before: queued again, so the sweep sent the cancelled run's mapping."""
    remediation_id, scenario_id = _requested_plan(client, api_key, entity)
    run_id = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["session_id"]
    assert client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity)).status_code == 200

    def mapper_fault(*_args: Any) -> None:
        raise RuntimeError("mapper fault")

    monkeypatch.setattr(world["mapper"], "map_controls", mapper_fault)
    deliver(remediation_id)
    controls = _controls(scenario_id)
    assert controls["task_id"].endswith(Remediation.CONTROLS_CLAIM_SUFFIX)  # the plan job claimed it
    assert (controls["status"], controls.get("lease_until"), controls.get("error")) == (
        Status.CANCELLED,
        None,
        None,
    )


# --- a delete refused for plans names them


def test_a_delete_refused_for_plans_names_each_plan_to_cancel(
    client: TestClient, api_key: str, entity: int
) -> None:
    """A run cancel never stops a plan: the 409 names the plans being written and their scenarios, so the
    caller can cancel each on its own route (before: a loop between cancel and delete)."""
    planning = _run(entity, Status.DONE)
    scenario_id = _scenario(planning, entity, Status.DONE)
    plan_id = _plan(entity, planning, scenario_id, Status.QUEUED)
    refused = client.delete(f"/v1/sessions/{planning}", headers=_who(api_key, entity))
    body = refused.json()
    assert (refused.status_code, body["reason"]) == (409, ConflictReason.CANCEL_FIRST)
    assert body["details"] == {"plans_to_cancel": [{"remediation_id": plan_id, "scenario_id": scenario_id}]}
    assert plan_id in body["detail"] and "treatment-plan/cancel" in body["detail"]
    working = _run(entity, Status.RUNNING)
    refused = client.delete(f"/v1/sessions/{working}", headers=_who(api_key, entity))
    assert refused.json()["details"] == {"plans_to_cancel": []}


# --- a plan job stopped meanwhile proposes nothing


def test_a_plan_cancelled_and_its_run_deleted_meanwhile_proposes_nothing_to_the_library(
    client: TestClient,
    api_key: str,
    entity: int,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan cancelled and its run deleted while the job picks the attacker: the job checks it still holds
    its lease before the proposal, so no library row, operation record or audit is left for a deleted run."""
    pending = {"actors": True, "proposal": True, "by": WHO}
    mapped = {"status": Status.DONE, "items": [{"control_id": 1, "code": "CII-CID-1", "match": "given"}]}
    remediation_id, scenario_id = _requested_plan(
        client, api_key, entity, source=RunKind.MANUAL, pending=pending, controls=mapped
    )
    run_id = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["session_id"]
    pick_attacker = remediation_plan_job.pick_manual_attacker

    def cancelled_and_deleted_meanwhile(*args: Any) -> list[dict[str, Any]]:
        records = container.get_work_control_repository()
        assert records.cancel_remediation_plan(remediation_id, entity, WHO)
        assert records.delete_scenario_session(run_id, entity) is not None
        return pick_attacker(*args)

    monkeypatch.setattr(remediation_plan_job, "pick_manual_attacker", cancelled_and_deleted_meanwhile)
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    assert world["proposals"] == []  # the proposal is what writes the library row, its record and audit
