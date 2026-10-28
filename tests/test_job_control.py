"""G214 (owner 2026-10-12): an organisation reviews its own work queued or running, cancels a run or a
remediation plan (stop now, keep what is done) and deletes a run for good. Its normal API key and entity:
never another organisation's. Runs, scenarios and plans are written straight into the test MongoDB."""

import random
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    ActionStatus,
    AiOutage,
    AuditAction,
    Collection,
    ConflictReason,
    Controls,
    Header,
    JobControl,
    JobKind,
    RunActionOutcome,
    RunOverall,
    ScenarioStatus,
    SessionState,
    Status,
    Step,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, LeaseLost, NotFound
from app.data_access.jobs.job_repository import JobLease, JobRepository
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.data_access.service_mapper.mapping_repository import MappingRepository
from app.domain.scenario.review import cancel_stamp_seen
from app.models.admin.api_clients import Principal
from app.services.jobs.job_service import JobService
from tests.plan_addresses import plan_url
from tests.service_builders import threat_scenario_service

NOW = datetime.now(UTC)


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = container.get_admin_service().create_api_client(f"jobs-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def entity() -> int:
    """An organisation of this test alone: other tests' runs never show in its list."""
    return random.randint(10_000_000, 99_999_999)  # noqa: S311 — test data, not security


@pytest.fixture(autouse=True)
def told(client: TestClient) -> Iterator[list[str]]:
    """The job routes with no live update sent; the plans whose watchers were told."""
    plans: list[str] = []
    service = JobService(
        container.get_work_control_repository(),
        container.get_threat_scenario_session_repository(),
        container.get_audit_repository(),
        publish_session_status=lambda _: None,
        publish_remediation_status=plans.append,
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_job_service] = lambda: service
    yield plans
    overrides.pop(container.get_job_service, None)


@pytest.fixture
def sent(client: TestClient) -> Iterator[list[Any]]:
    """The scenario routes with their jobs kept here instead of sent, and no live update."""
    jobs: list[Any] = []
    service = threat_scenario_service(
        send_job=lambda *job: jobs.append(job), publish_session_status=lambda _: None
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_threat_scenario_service] = lambda: service
    yield jobs
    overrides.pop(container.get_threat_scenario_service, None)


def _work_control(remediations: RemediationRepository | None = None) -> WorkControlRepository:
    """A job control of the test's own on the test database, so a test can patch it."""
    scenarios = ThreatScenarioRepository()
    sessions = ThreatScenarioSessionRepository(scenarios=scenarios)
    return WorkControlRepository(
        sessions, scenarios, remediations or RemediationRepository(), MappingRepository()
    )


def _who(api_key: str, entity_id: int) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "T",
    }


def _run(entity_id: int, status: Status, task: TaskName = TaskName.WRITE_SCENARIOS, **fields: Any) -> str:
    record_id = uuid.uuid4().hex
    record = {
        "_id": record_id, "entity_id": entity_id, "asset_id": 1207, "status": status, "step": Step.SCENARIOS,
        "counts": {"planned": 16, "written": 6, "remaining": 10}, "user_id": "u1", "created_at": NOW,
        "job": {"task": task, "epoch": 1, "task_id": "t1", "attempts": 1, "due_at": NOW,
                "lease_until": NOW + timedelta(minutes=2)},
        "updated_at": NOW,
    }  # fmt: skip
    get_mongodb()[Collection.SESSIONS].insert_one(record | fields)
    return record_id


def _scenario(run_id: str, state: Status, **fields: Any) -> str:
    """A written scenario of the run (of its entity), its controls in `state` since an hour ago."""
    scenario_id = uuid.uuid4().hex
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id}, {"entity_id": 1}) or {}
    record = {
        "_id": scenario_id, "session_id": run_id, "entity_id": run.get("entity_id"),
        "path_id": uuid.uuid4().hex, "version": 1,
        "source": "generated", "status": ScenarioStatus.DONE, "decision": "pending", "superseded_by": None,
        "content": {"title": scenario_id}, "created_at": NOW,
        "controls": {"status": state, "queued_at": NOW - timedelta(hours=1),
                     "last_attempt_at": NOW - timedelta(hours=1)},
    }  # fmt: skip
    get_mongodb()[Collection.SCENARIOS].insert_one(record | fields)
    return scenario_id


def _plan(entity_id: int, run_id: str, status: Status) -> str:
    plan_id = uuid.uuid4().hex
    get_mongodb()[Collection.REMEDIATIONS].insert_one(
        {"_id": plan_id, "entity_id": entity_id, "scenario_id": uuid.uuid4().hex, "session_id": run_id,
         "asset_id": 1207, "status": status, "decision": "pending", "created_at": NOW,
         "job": {"epoch": 1, "error": None, "due_at": NOW, "attempts": 1}, "updated_at": NOW}
    )  # fmt: skip
    return plan_id


def _controls(scenario_id: str) -> str:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]["status"]


def test_the_list_shows_my_work_queued_or_running_oldest_first_and_never_another_organisations(
    client: TestClient, api_key: str, entity: int
) -> None:
    """One line per piece of work: finding threats, writing scenarios, matching controls (a finished run whose
    scenarios' controls are still being matched), writing a remediation plan."""
    controls = _run(
        entity, Status.DONE, counts={"controls_waiting": 2}, created_at=NOW - timedelta(minutes=9)
    )
    threats = _run(entity, Status.QUEUED, TaskName.FIND_THREATS, created_at=NOW - timedelta(minutes=5))
    writing = _run(entity, Status.RUNNING, created_at=NOW - timedelta(minutes=3))
    plan = _plan(entity, writing, Status.RUNNING)
    _run(entity, Status.DONE)  # finished: not work in progress
    _run(entity + 1, Status.RUNNING)  # another organisation's
    listed = client.get("/v1/jobs", headers=_who(api_key, entity)).json()
    assert listed["total"] == 4
    assert [(job["kind"], job["session_id"]) for job in listed["jobs"]] == [
        (JobKind.CONTROLS, controls),
        (JobKind.THREATS, threats),
        (JobKind.SCENARIOS, writing),
        (JobKind.REMEDIATION, writing),
    ]
    assert listed["jobs"][2]["progress"] == {
        "planned": 16,
        "written": 6,
        "remaining": 10,
        "controls_waiting": 0,
    }
    assert listed["jobs"][3]["remediation_id"] == plan
    assert all(job["retrying"] is None for job in listed["jobs"])


def test_the_list_says_why_a_job_waits_out_an_ai_outage(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Owner 2026-10-20: a run or a plan given back after an AI outage is listed with its retry notice."""
    notice = {"reason": AiOutage.TIMED_OUT, "message": "The AI service timed out.", "attempt": 1,
              "max_attempts": 5, "retry_at": NOW}  # fmt: skip
    run = _run(entity, Status.QUEUED, TaskName.FIND_THREATS, step=Step.THREATS)
    get_mongodb()[Collection.SESSIONS].update_one({"_id": run}, {"$set": {"job.retry": notice}})
    plan = _plan(entity, run, Status.QUEUED)
    get_mongodb()[Collection.REMEDIATIONS].update_one({"_id": plan}, {"$set": {"job.retry": notice}})
    listed = client.get("/v1/jobs", headers=_who(api_key, entity)).json()["jobs"]
    by_kind = {job["kind"]: job["retrying"] for job in listed}
    assert by_kind[JobKind.THREATS]["reason"] == by_kind[JobKind.REMEDIATION]["reason"] == AiOutage.TIMED_OUT
    assert (by_kind[JobKind.THREATS]["stage"], by_kind[JobKind.REMEDIATION]["stage"]) == (Step.THREATS, None)


def test_a_cancelled_run_is_never_claimed_resent_or_retried_and_its_worker_stops(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Stop now, keep what is done: the job's next save fails (its worker stops), the claim and the reaper
    never take it again, its controls stop and are never swept again, the asset is free, the board says
    who."""
    run_id = _run(entity, Status.RUNNING)
    waiting = _scenario(run_id, Status.QUEUED)
    failed = _scenario(run_id, Status.FAILED, controls={"status": Status.FAILED, "attempts": 1})
    spent = _scenario(
        run_id, Status.FAILED, controls={"status": Status.FAILED, "attempts": Controls.MAX_ATTEMPTS}
    )
    sessions = get_mongodb()[Collection.SESSIONS]
    lease = JobLease(sessions, run_id, 1, "t1", 1)
    response = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    assert response.status_code == 200
    board = response.json()
    assert (board["session_status"], board["progress"]["overall"]) == (
        SessionState.CANCELLED,
        RunOverall.CANCELLED,
    )
    stopped_by = board["progress"]["error_message"]["scenarios"]
    assert re.fullmatch(r"Cancelled by user u1 at \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\.", stopped_by)
    with pytest.raises(LeaseLost):
        lease.update_job({"counts.written": 7})  # the worker's next save
    assert JobRepository(sessions).claim_job(run_id, 1, TaskName.WRITE_SCENARIOS, "t2") is None
    sessions.update_one({"_id": run_id}, {"$set": {"job.lease_until": NOW - timedelta(hours=1)}})
    reaper = JobRepository(sessions)
    assert run_id not in {r["_id"] for r in reaper.list_expired_jobs(datetime.now(UTC))}
    assert run_id not in {r["_id"] for r in reaper.list_unsent_jobs(datetime.now(UTC))}
    assert (_controls(waiting), _controls(failed), _controls(spent)) == (
        Status.CANCELLED,
        Status.CANCELLED,
        Status.FAILED,  # every attempt used: nothing left to stop
    )
    assert run_id not in container.get_work_control_repository().sweep_stalled_controls()
    assert container.get_threat_scenario_session_repository().claim_controls_delivery(run_id, "t3") is None
    stored = sessions.find_one({"_id": run_id})
    assert "active" not in stored and stored["cancelled"]["user_id"] == "u1"
    audits = get_mongodb()[Collection.AUDIT].find({"target.id": run_id, "action": AuditAction.RUN_CANCELLED})
    assert len(list(audits)) == 1


def test_a_scenario_saved_in_flight_after_a_cancel_never_has_its_controls_matched(
    client: TestClient, api_key: str, entity: int
) -> None:
    """A scenario saved as the cancel landed (its writer checked its lease a moment before), its controls
    queued just now: the sweep's next round stops them, whatever their age (review: a stray waited 15 minutes,
    listed as work and refusing the delete)."""
    run_id = _run(entity, Status.RUNNING)
    client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    late = _scenario(
        run_id, Status.QUEUED, controls={"status": Status.QUEUED, "queued_at": datetime.now(UTC)}
    )
    assert run_id not in container.get_work_control_repository().sweep_stalled_controls()
    assert _controls(late) == Status.CANCELLED
    counts = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})["counts"]
    assert (counts["controls_waiting"], counts["controls_cancelled"]) == (0, 1)  # the board and list follow


def test_nothing_to_cancel_another_organisations_run_and_an_unknown_one(
    client: TestClient, api_key: str, entity: int
) -> None:
    finished = _run(entity, Status.DONE)
    refused = client.post(f"/v1/sessions/{finished}/cancel", headers=_who(api_key, entity))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.NOTHING_TO_CANCEL)
    theirs = _run(entity + 1, Status.RUNNING)
    assert client.post(f"/v1/sessions/{theirs}/cancel", headers=_who(api_key, entity)).status_code == 403
    assert (
        client.post(f"/v1/sessions/{uuid.uuid4().hex}/cancel", headers=_who(api_key, entity)).status_code
        == 404
    )


def test_a_finished_run_whose_controls_are_still_matched_stops_only_its_controls(
    client: TestClient, api_key: str, entity: int
) -> None:
    run_id = _run(entity, Status.DONE, counts={"controls_waiting": 1})
    waiting = _scenario(run_id, Status.QUEUED)
    assert client.get("/v1/jobs", headers=_who(api_key, entity)).json()["total"] == 1
    board = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity)).json()
    assert board["session_status"] == SessionState.COMPLETED and _controls(waiting) == Status.CANCELLED
    assert board["progress"]["controls"] == "CANCELLED"
    assert client.get("/v1/jobs", headers=_who(api_key, entity)).json()["total"] == 0  # no longer listed


def test_a_cancelled_run_resumes_whole_with_the_next_set(
    client: TestClient, api_key: str, entity: int, sent: list[Any]
) -> None:
    """Restarting is deliberate: a next set takes it up again, its stopped controls with it."""
    path = {"path_id": "p1", "rank": 1, "selected": True, "served": None, "attempts": 0, "abandoned": False}
    run_id = _run(entity, Status.RUNNING, plan={"paths": [path]})
    stopped = _scenario(run_id, Status.QUEUED)
    client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    resumed = client.post(f"/v1/sessions/{run_id}/scenarios/next-set", headers=_who(api_key, entity))
    assert resumed.status_code == 202
    assert sorted(task for task, _, _ in sent) == [TaskName.MAP_CONTROLS, TaskName.WRITE_SCENARIOS]
    stored = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert stored["status"] == Status.QUEUED and "cancelled" not in stored
    assert _controls(stopped) == Status.QUEUED and stored["counts"]["controls_waiting"] == 1


def test_a_deleted_run_is_gone_for_good_with_its_scenarios_and_plans_and_audited(
    client: TestClient, api_key: str, entity: int
) -> None:
    run_id = _run(entity, Status.DONE)
    scenarios = [_scenario(run_id, Status.DONE), _scenario(run_id, Status.CANCELLED)]
    _plan(entity, run_id, Status.DONE)
    response = client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity))
    assert response.json() == {"session_id": run_id, "scenarios": 2, "remediation_plans": 1}
    db = get_mongodb()
    assert db[Collection.SESSIONS].find_one({"_id": run_id}) is None
    assert db[Collection.SCENARIOS].count_documents({"_id": {"$in": scenarios}}) == 0
    assert db[Collection.REMEDIATIONS].count_documents({"session_id": run_id}) == 0
    assert (
        db[Collection.AUDIT].count_documents({"target.id": run_id, "action": AuditAction.SESSION_DELETED})
        == 1
    )


def test_nothing_is_ever_deleted_under_a_worker(client: TestClient, api_key: str, entity: int) -> None:
    """While its job, a scenario's controls or one of its plans is queued or running: cancel first."""
    working = _run(entity, Status.RUNNING)
    controls = _run(entity, Status.DONE)
    _scenario(controls, Status.RUNNING)
    planning = _run(entity, Status.DONE)
    _plan(entity, planning, Status.QUEUED)
    for run_id in (working, controls, planning):
        refused = client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity))
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.CANCEL_FIRST), run_id
        assert "deleting_at" not in get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})  # unmarked
    client.post(f"/v1/sessions/{working}/cancel", headers=_who(api_key, entity))
    assert client.delete(f"/v1/sessions/{working}", headers=_who(api_key, entity)).status_code == 200
    theirs = _run(entity + 1, Status.DONE)
    assert client.delete(f"/v1/sessions/{theirs}", headers=_who(api_key, entity)).status_code == 403


def test_a_remediation_plan_being_written_can_be_cancelled(
    client: TestClient, api_key: str, entity: int
) -> None:
    plan_id = _plan(entity, "run", Status.RUNNING)
    url = plan_url(plan_id, "cancel")  # v1's address: the plan's run and scenario
    response = client.post(url, headers=_who(api_key, entity))
    assert response.json() == {"remediation_id": plan_id, "status": Status.CANCELLED}
    stored = get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": plan_id})
    assert stored["status"] == Status.CANCELLED and "active" not in stored
    again = client.post(url, headers=_who(api_key, entity))
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.NOTHING_TO_CANCEL)
    assert client.post(url, headers=_who(api_key, entity + 1)).status_code == 403


def test_a_delivery_mapping_the_run_stops_at_the_cancel(
    client: TestClient, api_key: str, entity: int
) -> None:
    """The cancel ends the run's controls delivery lease: a delivery mapping it stops after the scenario in
    hand, never claiming one saved later (review)."""
    sessions = container.get_threat_scenario_session_repository()
    for status in (Status.RUNNING, Status.DONE):  # a job at work; a finished run still matching controls
        run_id = _run(entity, status)
        _scenario(run_id, Status.QUEUED)
        assert sessions.claim_controls_delivery(run_id, "mapping") is not None
        assert client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity)).status_code == 200
        assert not sessions.update_controls_delivery(run_id, "mapping"), status


def test_a_deleted_runs_scenario_saved_meanwhile_goes_with_it(entity: int) -> None:
    """A scenario whose run is gone is never queued again for ever: the sweep removes it."""
    gone = uuid.uuid4().hex
    stray = _scenario(gone, Status.QUEUED, entity_id=entity)
    assert gone not in container.get_work_control_repository().sweep_stalled_controls()
    assert get_mongodb()[Collection.SCENARIOS].find_one({"_id": stray}) is None


def test_a_deleted_runs_failure_and_blocked_cards_go_too_and_a_live_runs_stay(entity: int) -> None:
    """A failure or blocked card saved after its run was deleted has no controls waiting: the sweep still
    removes it, never a card of a run that exists."""
    gone, live = uuid.uuid4().hex, _run(entity, Status.DONE)
    cards = {
        run_id: [
            _scenario(run_id, Status.QUEUED, entity_id=entity, status=status, controls=None)
            for status in (ScenarioStatus.FAILED, ScenarioStatus.BLOCKED)
        ]
        for run_id in (gone, live)
    }
    container.get_work_control_repository().sweep_stalled_controls()
    left = {
        found["_id"]
        for found in get_mongodb()[Collection.SCENARIOS].find({"session_id": {"$in": [gone, live]}})
    }
    assert left == set(cards[live])


def test_a_delete_cut_short_is_finished_by_calling_it_again(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Children first, the run last: an outage between the steps leaves the run there to be found again."""
    run_id = _run(entity, Status.DONE)
    _scenario(run_id, Status.DONE)
    _plan(entity, run_id, Status.DONE)
    plans = get_mongodb()[Collection.REMEDIATIONS]

    class Down:  # MongoDB goes away as the plans are deleted; every read before works
        def __getattr__(self, name: str) -> Any:
            return getattr(plans, name)

        def delete_many(self, _: dict[str, Any]) -> None:
            raise ConnectionError("MongoDB went away")

    records = _work_control(RemediationRepository(Down()))  # type: ignore[arg-type]
    with pytest.raises(ConnectionError):
        records.delete_scenario_session(run_id, entity)
    response = client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity))
    assert response.json() == {"session_id": run_id, "scenarios": 0, "remediation_plans": 1}
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id}) is None


def test_a_replaced_versions_old_controls_never_count_as_work(
    client: TestClient, api_key: str, entity: int
) -> None:
    """A version replaced while its controls waited is never mapped (MAPPED_VERSIONS): it neither refuses the
    delete nor gives a finished run something to cancel (review)."""
    run_id = _run(entity, Status.DONE)
    _scenario(run_id, Status.QUEUED, superseded_by="newer")
    refused = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.NOTHING_TO_CANCEL)
    assert client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).status_code == 200


def test_a_run_cancelled_before_its_plan_says_start_a_new_run(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Cancelled while finding threats: no plan, so nothing to decide or resume (review: next set answered a
    misleading nothing_left)."""
    run_id = _run(entity, Status.RUNNING, TaskName.FIND_THREATS, step=Step.THREATS)
    client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    refused = client.post(f"/v1/sessions/{run_id}/scenarios/next-set", headers=_who(api_key, entity))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_CANCELLED)


def test_a_cut_list_still_says_how_many_there_are(
    client: TestClient, api_key: str, entity: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(JobControl, "LIST_MAX", 2)
    oldest = [
        _run(entity, Status.QUEUED, created_at=NOW - timedelta(minutes=minutes)) for minutes in (3, 2, 1)
    ]
    listed = client.get("/v1/jobs", headers=_who(api_key, entity)).json()
    assert ([job["session_id"] for job in listed["jobs"]], listed["total"]) == (oldest[:2], 3)


def test_the_job_list_reads_through_its_indexes(entity: int) -> None:
    """Every poll of the list: two indexed reads of the entity's runs, never a walk over every run it made
    (here 40 finished ones, one at work, one still matching controls)."""
    for _ in range(40):
        _run(entity, Status.DONE)
    _run(entity, Status.RUNNING)
    _run(entity, Status.DONE, counts={"controls_waiting": 1})
    sessions, working = get_mongodb()[Collection.SESSIONS], [Status.QUEUED, Status.RUNNING]
    reads = (
        ({"entity_id": entity, "status": {"$in": working}}, "entity_id_1_status_1_created_at_1"),
        (
            {"entity_id": entity, "status": {"$nin": working}, "counts.controls_waiting": {"$gt": 0}},
            "controls_waiting_by_entity",
        ),
    )
    for query, index in reads:
        explained = sessions.find(query).sort("created_at", 1).explain()
        assert explained["executionStats"]["totalDocsExamined"] == 1, query
        assert index in str(explained["queryPlanner"]["winningPlan"]), query


def test_a_cancelled_next_set_reads_cancelled_after_any_later_action(
    client: TestClient, api_key: str, entity: int
) -> None:
    """Its summary said "running" for ever, and "failed" once another action started (review)."""
    summary = {"outcome": "running", "requested": 6, "delivered": None}
    run_id = _run(entity, Status.RUNNING, last_action={"kind": "next_set"}, last_next_set=summary)
    client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    stored = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert stored["last_next_set"]["outcome"] == RunActionOutcome.CANCELLED


def test_a_finished_runs_stopped_controls_resume_with_a_next_set(
    client: TestClient, api_key: str, entity: int, sent: list[Any]
) -> None:
    """Nothing left to write: a next set resumes only its stopped controls, sent at once (review: they could
    never be resumed but by rewriting scenarios)."""
    path = {"path_id": "p1", "rank": 1, "selected": True, "served": "s1", "attempts": 1, "abandoned": False}
    stale = {"threats_s": 93.7, "scenarios_s": 130.7, "controls_s": 111.0}  # the run's first times
    run_id = _run(entity, Status.DONE, plan={"paths": [path]}, timings=stale)
    stopped = _scenario(run_id, Status.QUEUED)
    outage = {"code": "unavailable", "message": "The AI service is down.", "reason": AiOutage.DOWN}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": stopped}, {"$set": {"controls.error": outage}})
    client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity))
    resumed = client.post(f"/v1/sessions/{run_id}/scenarios/next-set", headers=_who(api_key, entity))
    # G268: v1's 202 shape; only stopped controls resumed, so the current epoch and mapping_controls.
    assert resumed.status_code == 202, resumed.text
    assert {key: resumed.json()[key] for key in ("session_id", "status", "epoch")} == {
        "session_id": run_id, "status": ActionStatus.MAPPING_CONTROLS, "epoch": 1,
    }  # fmt: skip
    assert sent == [(TaskName.MAP_CONTROLS, run_id, 0)] and _controls(stopped) == Status.QUEUED
    # Resumed on purpose: the outage from before the cancel no longer says why they wait.
    assert get_mongodb()[Collection.SCENARIOS].find_one({"_id": stopped})["controls"].get("error") is None
    board = client.get(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).json()
    assert board["progress"]["controls"] == "RUNNING" and board["progress"]["error_message"] == {}
    # Owner 2026-10-28: the resume is the latest action; it found and wrote nothing, so no earlier time stays.
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert run["timings"] == {"threats_s": 0.0, "scenarios_s": 0.0}
    assert board["progress"]["timings"] == {"threats": 0.0, "scenarios": 0.0, "controls": None}


def test_a_deleted_runs_plan_watchers_are_told(
    client: TestClient, api_key: str, entity: int, told: list[str]
) -> None:
    run_id = _run(entity, Status.DONE)
    plan_id = _plan(entity, run_id, Status.DONE)
    assert client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).status_code == 200
    assert told == [plan_id]


def test_a_run_gone_under_a_reader_is_a_404_never_a_500() -> None:
    """A plan request or a job that reads a run deleted meanwhile (review: KeyError, a 500)."""
    with pytest.raises(NotFound):
        container.get_threat_scenario_session_repository().get_scenario_session_context(uuid.uuid4().hex)


def test_a_next_set_racing_a_delete_is_told_the_run_is_being_deleted(
    client: TestClient, api_key: str, entity: int, monkeypatch: pytest.MonkeyPatch, sent: list[Any]
) -> None:
    """Owner 2026-10-12: a next set clicked as the run is deleted got 202, then its run vanished. The delete
    marks the run first; a next set landing between that mark and the end gets 409 run_being_deleted, and
    nothing is queued or sent."""
    service = client.app.dependency_overrides[container.get_threat_scenario_service]()  # type: ignore[attr-defined]
    path = {"path_id": "p1", "rank": 1, "selected": True, "served": None, "attempts": 0, "abandoned": False}
    run_id = _run(entity, Status.DONE, plan={"paths": [path]})
    principal = Principal(client_id="c1", user_id="u2", entity_id=entity, tenant_id="T")
    raced: list[BaseException] = []
    work_left = WorkControlRepository._work_left

    def next_set_lands_meanwhile(records: WorkControlRepository, session_id: str, entity_id: int) -> bool:
        try:
            run = service.get_threat_scenario_session_status(run_id, entity)
            service.write_next_threat_scenario_set(principal, run)
        except Conflict as exc:
            raced.append(exc)
        return work_left(records, session_id, entity_id)

    monkeypatch.setattr(WorkControlRepository, "_work_left", next_set_lands_meanwhile)
    assert client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).status_code == 200
    assert [getattr(exc, "reason", None) for exc in raced] == [ConflictReason.RUN_BEING_DELETED]
    assert sent == []


def test_a_run_whose_delete_was_cut_short_starts_nothing_more(
    client: TestClient, api_key: str, entity: int, sent: list[Any]
) -> None:
    """Not even its stopped controls (nothing left to write): they stay stopped until the delete ends."""
    path = {"path_id": "p1", "rank": 1, "selected": True, "served": "s1", "attempts": 1, "abandoned": False}
    run_id = _run(entity, Status.DONE, plan={"paths": [path]}, deleting_at=NOW)
    stopped = _scenario(run_id, Status.CANCELLED)
    refused = client.post(f"/v1/sessions/{run_id}/scenarios/next-set", headers=_who(api_key, entity))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    assert _controls(stopped) == Status.CANCELLED and sent == []
    assert client.delete(f"/v1/sessions/{run_id}", headers=_who(api_key, entity)).status_code == 200


def test_a_cancel_landing_during_a_resume_stands(entity: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: the resume re-queued the controls, then cleared the run's cancel stamp whatever happened in
    between, so a cancel clicked meanwhile was undone."""
    earlier = {"user_id": "u1", "at": NOW - timedelta(hours=1)}
    run_id = _run(entity, Status.DONE, cancelled=earlier)
    stopped = _scenario(run_id, Status.CANCELLED)
    records = _work_control()
    being_deleted = records._sessions.is_being_deleted

    def cancel_lands_meanwhile(session_id: str) -> bool:
        records.cancel_scenario_session(run_id, entity, {"user_id": "u9"})
        return being_deleted(session_id)

    monkeypatch.setattr(records._sessions, "is_being_deleted", cancel_lands_meanwhile)
    assert records.resume_scenario_controls(run_id, earlier["at"]) == 0
    stored = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert stored["cancelled"]["user_id"] == "u9" and _controls(stopped) == Status.CANCELLED


def test_a_cancel_landing_after_the_caller_read_the_run_stands(entity: int) -> None:
    """D8: the resume read the cancel stamp itself, so a cancel landing between the caller's status read and
    the resume passed as the one the caller saw and was undone. The guard now uses the stamp it saw."""
    earlier = {"user_id": "u1", "at": NOW - timedelta(hours=1)}
    run_id = _run(entity, Status.DONE, cancelled=earlier)
    stopped, waiting = _scenario(run_id, Status.CANCELLED), _scenario(run_id, Status.QUEUED)
    seen = container.get_threat_scenario_service().get_threat_scenario_session_status(run_id, entity)
    records = container.get_work_control_repository()
    records.cancel_scenario_session(run_id, entity, {"user_id": "u9"})
    assert records.resume_scenario_controls(run_id, cancel_stamp_seen(seen)) == 0
    stored = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert stored["cancelled"]["user_id"] == "u9"
    assert _controls(stopped) == _controls(waiting) == Status.CANCELLED


def test_a_plan_jobs_live_claim_on_a_cancelled_run_survives_the_sweep(entity: int) -> None:
    """A plan for an accepted scenario of a cancelled run maps its controls on purpose: the sweep never stops
    a live lease, so the plan job's save still lands."""
    run_id = _run(entity, Status.CANCELLED)
    scenario_id = _scenario(run_id, Status.CANCELLED, controls={"status": Status.CANCELLED, "attempts": 1})
    scenarios = container.get_threat_scenario_repository()
    claimed = scenarios.claim_scenario_controls_by_id(scenario_id, "plan-job:plan")
    assert claimed is not None
    container.get_work_control_repository().sweep_stalled_controls()
    assert _controls(scenario_id) == Status.RUNNING
    attempts = claimed["controls"]["attempts"]
    mapping = {"items": [{"control_id": 1}]}
    assert scenarios.update_scenario_controls(
        scenario_id, "plan-job:plan", attempts, Status.DONE, mapping=mapping
    )


def test_a_sweep_landing_during_a_resume_keeps_the_resume(
    entity: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resume takes the run out of cancelled before it queues the controls again, so a sweep landing in
    between never stops them as a cancelled run's."""
    earlier = {"user_id": "u1", "at": NOW - timedelta(hours=1)}
    run_id = _run(entity, Status.CANCELLED, cancelled=earlier)
    stopped = _scenario(run_id, Status.CANCELLED)
    records = _work_control()
    being_deleted = records._sessions.is_being_deleted

    def sweep_lands_meanwhile(session_id: str) -> bool:
        records.sweep_stalled_controls()
        return being_deleted(session_id)

    monkeypatch.setattr(records._sessions, "is_being_deleted", sweep_lands_meanwhile)
    assert records.resume_scenario_controls(run_id, earlier["at"]) == 1
    stored = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})
    assert stored["status"] == Status.DONE and "cancelled" not in stored
    assert _controls(stopped) == Status.QUEUED


def test_a_resume_landing_after_the_sweep_read_the_run_keeps_its_requeued_controls(
    entity: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review: the sweep stopped every waiting card of a run it read cancelled, so a card a resume queued
    again after that read was stopped again. It stops only the cards it read waiting."""
    earlier = {"user_id": "u1", "at": NOW - timedelta(hours=1)}
    run_id = _run(entity, Status.CANCELLED, cancelled=earlier)
    stopped = _scenario(run_id, Status.CANCELLED)
    late = _scenario(
        run_id, Status.QUEUED, controls={"status": Status.QUEUED, "queued_at": datetime.now(UTC)}
    )
    records = _work_control()
    read_states = records._sessions.list

    def resume_lands_meanwhile(**query: Any) -> list[dict[str, Any]]:
        states = read_states(**query)
        assert records.resume_scenario_controls(run_id, earlier["at"]) == 1
        return states

    monkeypatch.setattr(records._sessions, "list", resume_lands_meanwhile)
    records.settle_stopped_scenario_sessions()
    assert (_controls(stopped), _controls(late)) == (Status.QUEUED, Status.CANCELLED)
