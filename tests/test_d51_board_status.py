"""The run's board and a job's stored error say what is true: a failed run still matching controls is in
progress, a finished run whose controls were cancelled reads cancelled, a job given up as job_abandoned says
why, and a path an AI outage cost keeps the run waiting for its regenerate."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app import container
from app.core.constants import (
    AbandonReason,
    AiOutage,
    AiTask,
    Collection,
    Controls,
    ErrorCode,
    Generation,
    Lease,
    LogEvent,
    ScenarioStatus,
    Status,
    Step,
    TaskName,
    UnselectedReason,
)
from app.core.constants import RunOverall as Overall
from app.core.constants import SessionState as Session
from app.core.constants import StageState as S
from app.core.database import get_mongodb
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.domain.scenario.plan import plan_counts
from app.domain.scenario.results import build_board
from app.domain.service_mapper.views import mapping_status
from app.models.scenario.views import session_status_from_record
from app.worker import jobs, reaper
from tests.fakes import FakeChatModel
from tests.test_control_mapping import _controls_of, _waiting_scenario
from tests.test_job_control import _run as _stored_run
from tests.test_job_control import _scenario, _who, api_key, entity, told  # noqa: F401 - fixtures by name
from tests.test_next_set_rules import _RULE, _path
from tests.test_outage_paths_rewritten import busy_for_and_blocked
from tests.test_run_board import _FAILED, _SET, _run, _written
from tests.test_worker import _insert_job, _records
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _on_last_try,
    _queued_run,
    _write_batch,
    chat,
    sent,
)

LONG_AGO = datetime.now(UTC) - timedelta(hours=2)


# A failed run whose earlier scenarios' controls are still matched.


def test_a_failed_run_reads_in_progress_until_its_controls_are_matched() -> None:
    """`error` is terminal for a client: it comes once nothing of the run is still being matched."""
    failed = _written(Status.FAILED, **_SET) | {"job": _FAILED}
    matching = build_board(_run(**failed | {"counts": _SET | {"controls_waiting": 2}}))
    progress = matching.progress
    assert (progress.scenarios, progress.controls, progress.overall, matching.session_status) == (
        S.ERROR,
        S.RUNNING,
        Overall.IN_PROGRESS,
        Session.FAILED,
    )
    assert matching.error is not None and matching.error.code == "unavailable"
    assert build_board(_run(**failed)).progress.overall == Overall.ERROR  # its controls are done


# A finished run whose controls were cancelled.


def test_a_finished_run_whose_controls_were_cancelled_reads_cancelled() -> None:
    board = build_board(_run(**_written(planned=6, written=6, accepted=6, controls_cancelled=1)))
    progress = board.progress
    assert (progress.controls, progress.overall, board.session_status) == (
        S.CANCELLED,
        Overall.CANCELLED,
        Session.COMPLETED,
    )


def test_a_finished_run_whose_controls_were_cancelled_reads_cancelled_beside_failed_controls() -> None:
    """A cancel leaves controls that failed for good as they are: the stage reads error, overall cancelled."""
    counts = {"planned": 6, "written": 6, "accepted": 6, "controls_failed": 1, "controls_cancelled": 2}
    board = build_board(_run(**_written(**counts)))
    progress = board.progress
    assert (progress.controls, progress.overall, board.session_status) == (
        S.ERROR,
        Overall.CANCELLED,
        Session.COMPLETED,
    )


def test_cancelling_a_finished_runs_controls_answers_cancelled_when_one_failed_for_good(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    entity: int,  # noqa: F811 - the imported fixture
) -> None:
    """The cancel stops the waiting controls only; the answer still says the run's controls were stopped."""
    run_id = _stored_run(entity, Status.DONE, counts={"planned": 3, "remaining": 0, "controls_waiting": 2})
    failed_for_good = {"status": Status.FAILED, "attempts": Controls.MAX_ATTEMPTS}
    _scenario(run_id, Status.FAILED, decision="accepted", controls=failed_for_good)
    for _ in range(2):
        _scenario(run_id, Status.QUEUED, decision="accepted")
    board = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity)).json()
    progress = board["progress"]
    assert (board["session_status"], progress["controls"], progress["overall"]) == (
        Session.COMPLETED,
        S.ERROR,
        Overall.CANCELLED,
    )


def test_cancelling_a_finished_runs_controls_answers_cancelled(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    entity: int,  # noqa: F811 - the imported fixture
) -> None:
    """The cancel's own answer: the run stays completed, and overall says its controls were stopped."""
    run_id = _stored_run(entity, Status.DONE, counts={"planned": 1, "remaining": 0, "controls_waiting": 1})
    _scenario(run_id, Status.QUEUED, decision="accepted")
    board = client.post(f"/v1/sessions/{run_id}/cancel", headers=_who(api_key, entity)).json()
    progress = board["progress"]
    assert (board["session_status"], progress["controls"], progress["overall"]) == (
        Session.COMPLETED,
        S.CANCELLED,
        Overall.CANCELLED,
    )


# Why a job was given up (job_abandoned).


@pytest.fixture
def reaper_alone(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The reaper on this test's records only, its re-sends accepted and its live updates kept here."""
    for collection in jobs.JOB_COLLECTIONS:
        get_mongodb()[collection].delete_many({})
    published: list[str] = []
    for collection in list(jobs.JOB_COLLECTIONS):
        monkeypatch.setitem(jobs.JOB_COLLECTIONS, collection, published.append)
    monkeypatch.setattr(reaper, "send_job", lambda *_args, **_priority: True)
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    return published


def _mapping_running_out_of_attempts() -> str:
    """A service mapping whose worker stopped on its last attempt."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    job = {"task": TaskName.MAP_SERVICES, "epoch": 1, "attempts": Lease.MAX_ATTEMPTS, "due_at": LONG_AGO,
           "lease_until": LONG_AGO, "task_id": "gone"}  # fmt: skip
    get_mongodb()[Collection.SERVICE_MAPPINGS].insert_one(
        {"_id": record_id, "tenant_id": "t1", "entity_id": 86, "generation": 1, "status": Status.RUNNING,
         "created_at": now, "updated_at": now, "job": job}
    )  # fmt: skip
    return record_id


@pytest.mark.usefixtures("reaper_alone")
def test_the_reaper_stores_why_it_gave_each_job_up() -> None:
    """Its worker stopped on every attempt, or it was sent again and again and never started: the stored
    error says which (error.reason), as the job.failed line does; the run and the mapping show it."""
    worn_out = _insert_job(Status.RUNNING, attempts=Lease.MAX_ATTEMPTS, lease_until=LONG_AGO, task_id="gone")
    never_started = _insert_job(Status.QUEUED, due_at=LONG_AGO, resends=Lease.MAX_ATTEMPTS)
    mapping = _mapping_running_out_of_attempts()
    with capture_logs() as logs:
        reaper.reap_jobs()
    stored = {record_id: _records().find_one({"_id": record_id})["job"]["error"] for record_id in
              (worn_out, never_started)}  # fmt: skip
    assert {key: (error["code"], error.get("reason")) for key, error in stored.items()} == {
        worn_out: (ErrorCode.JOB_ABANDONED, AbandonReason.WORKER_STOPPED),
        never_started: (ErrorCode.JOB_ABANDONED, AbandonReason.NEVER_STARTED),
    }
    lines = {line["record_id"]: line["reason"] for line in logs if line["event"] == LogEvent.JOB_FAILED}
    shown_in_logs = [lines[key] for key in (worn_out, never_started, mapping)]
    assert shown_in_logs == ["abandoned", "never_started", "abandoned"]
    board = build_board(session_status_from_record(_records().find_one({"_id": worn_out})))
    assert board.error is not None and board.error.reason == AbandonReason.WORKER_STOPPED
    assert board.progress.error_reason is None  # an AI outage's reason only
    shown = mapping_status(get_mongodb()[Collection.SERVICE_MAPPINGS].find_one({"_id": mapping}), 5)
    assert shown.error is not None and shown.error.reason == AbandonReason.WORKER_STOPPED


def test_a_stale_admin_job_says_whether_it_ever_started() -> None:
    """Never started (still queued) or its worker stopped (running): failed by the reaper's pass or by the
    next request of its kind, which takes its place."""
    admin_jobs = AdminJobRepository()
    queued, running, replaced = (uuid.uuid4().hex for _ in range(3))
    kinds = ("d51_queued", "d51_running", "d51_replaced")
    admin_jobs.collection.delete_many({"kind": {"$in": kinds}})

    def stale_job(job_id: str, kind: str, status: Status) -> None:
        started = {"started_at": LONG_AGO} if status == Status.RUNNING else {}
        admin_jobs.create({"_id": job_id, "kind": kind, "status": status, "active": True,
                           "created_at": LONG_AGO, **started})  # fmt: skip

    stale_job(queued, kinds[0], Status.QUEUED)
    stale_job(running, kinds[1], Status.RUNNING)
    try:
        failed = {job["_id"]: job["error"] for job in admin_jobs.fail_stale_admin_jobs(datetime.now(UTC))}
        assert (failed[queued].get("reason"), failed[running].get("reason")) == (
            AbandonReason.NEVER_STARTED,
            AbandonReason.WORKER_STOPPED,
        )
        assert admin_jobs.get(None, _id=queued)["error"] == failed[queued] | {"code": ErrorCode.JOB_ABANDONED}
        stale_job(replaced, kinds[2], Status.QUEUED)
        new_job = {"_id": uuid.uuid4().hex, "kind": kinds[2], "status": Status.QUEUED,
                   "created_at": datetime.now(UTC)}  # fmt: skip
        assert admin_jobs.create_admin_job(new_job) == new_job["_id"]
        assert admin_jobs.get(None, _id=replaced)["error"].get("reason") == AbandonReason.NEVER_STARTED
    finally:
        admin_jobs.collection.delete_many({"kind": {"$in": kinds}})


def test_controls_given_up_after_their_last_attempt_say_their_worker_stopped() -> None:
    expired = datetime.now(UTC) - timedelta(seconds=1)
    run_id, scenario_id = _waiting_scenario(
        status=Status.RUNNING, lease_until=expired, attempts=Controls.MAX_ATTEMPTS
    )
    assert run_id in container.get_threat_scenario_repository().fail_abandoned_controls(datetime.now(UTC))
    error = _controls_of(scenario_id)["error"]
    assert (error["code"], error.get("reason")) == (ErrorCode.JOB_ABANDONED, AbandonReason.WORKER_STOPPED)


# A path given up after its last AI outage: its card can still be regenerated.


def test_the_plan_counts_a_path_an_ai_outage_cost_as_an_outage_card() -> None:
    """Given up for an AI outage and not written: regenerable (a replaced one too). A store or evidence
    outage (unavailable, no AI reason) and a rule failure are given up for good."""
    outage = {"abandoned": True, "attempts": Generation.MAX_PATH_ATTEMPTS}
    replaced = {"selected": False, "replaced_by": "p9",
                "unselected_reason": UnselectedReason.REPLACED_AFTER_FAILURE}  # fmt: skip
    paths = [
        _path("p1", 1, **outage, abandoned_reason=AiOutage.BUSY),
        _path("p2", 2, **outage, abandoned_reason=AiOutage.TIMED_OUT, **replaced),
        _path("p3", 3, **outage, abandoned_reason=ErrorCode.UNAVAILABLE),
        _path("p4", 4, **_RULE),
        _path("p5", 5, **outage, abandoned_reason=AiOutage.DOWN, served="s5"),  # a late save won
    ]
    assert plan_counts(paths)["outage_cards"] == 2


def test_a_run_holding_an_outage_card_waits_for_its_regenerate() -> None:
    board = build_board(_run(**_written(planned=6, written=5, accepted=5, abandoned=1, outage_cards=1)))
    count = board.progress.scenario_count
    assert (board.progress.overall, count.remaining, count.complete) == (Overall.AWAITING_REVIEW, 0, False)


@pytest.mark.usefixtures("sent")
def test_a_path_given_up_after_its_last_ai_outage_keeps_the_run_awaiting_its_regenerate(
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """Through the write job: the path's give-up names the AI outage, as its card does, and the run is not
    complete while that card can still be written."""
    chat.responders[AiTask.WRITE_SCENARIO] = busy_for_and_blocked("Threat 2", "Blocked threat")
    record_id = _queued_run(["Threat 1", "Threat 2", "Blocked threat"])
    tried = {"step": Step.SCENARIOS, "plan.paths.1.attempts": Generation.MAX_PATH_ATTEMPTS - 1}
    _records().update_one({"_id": record_id}, {"$set": tried})
    _write_batch(_on_last_try(record_id))
    run = _records().find_one({"_id": record_id})
    reasons = [path.get("abandoned_reason") for path in run["plan"]["paths"]]
    assert reasons[:2] == [None, AiOutage.BUSY] and reasons[2] not in AiOutage
    assert (run["status"], run["counts"]["remaining"], run["counts"]["outage_cards"]) == (Status.DONE, 0, 1)
    written = {"session_id": record_id, "status": ScenarioStatus.DONE}
    get_mongodb()[Collection.SCENARIOS].update_many(written, {"$set": {"decision": "accepted"}})
    container.get_threat_scenario_session_repository().update_scenario_session_counts(record_id)
    progress = build_board(session_status_from_record(_records().find_one({"_id": record_id}))).progress
    assert (progress.overall, progress.scenario_count.complete) == (Overall.AWAITING_REVIEW, False)
