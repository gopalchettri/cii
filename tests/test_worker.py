"""Leased jobs: one owner at a time, fenced writes, outage retries, the reaper, worker start-up rules."""

import contextvars
import logging
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import structlog
from celery import states
from celery.exceptions import Ignore, Retry
from prometheus_client import REGISTRY
from pymongo.errors import AutoReconnect
from redis.exceptions import ReadOnlyError
from structlog.testing import capture_logs

from app import ai, container
from app.ai.profiles import CHAT_MODEL_PROFILES
from app.core import metrics, readiness
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    AiTask,
    Collection,
    ErrorCode,
    ErrorMessage,
    Lease,
    LogEvent,
    Queue,
    SqlOperationStatus,
    Status,
    StoredProcedure,
    TaskName,
    Worker,
)
from app.core.database import get_mongodb, get_redis_client
from app.core.exceptions import JobFailed, LeaseLost, Unavailable, WaitingForAnotherJob
from app.core.lease_signal import raise_if_lease_lost
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.jobs.job_repository import JobLease, JobRepository, ended_job_fields
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.scenario.results import build_board
from app.domain.shared.parallel import raise_most_retryable
from app.models.scenario.views import session_status_from_record
from app.worker import celery_app, heartbeat, jobs, lifecycle, reaper
from app.worker.celery_app import BrokerUnavailable, count_waiting_messages, send_job
from app.worker.scenario.tasks import find_threats


class RetryRequested(Exception):
    def __init__(self, countdown: int) -> None:
        super().__init__(countdown)
        self.countdown = countdown


def _records() -> Any:
    return get_mongodb()[Collection.SESSIONS]


def _insert_job(status: Status = Status.QUEUED, **job: Any) -> str:
    record_id = uuid.uuid4().hex
    now = datetime.now(UTC)
    job = {"task": TaskName.FIND_THREATS, "epoch": 1, "attempts": 0, "due_at": now, **job}
    _records().insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 103, "status": status, "updated_at": now, "job": job}
    )
    return record_id


def _task(task_id: str = "task-1", name: str = TaskName.FIND_THREATS) -> Any:
    """What run_leased_job uses of a Celery task: its name, its delivery id, and retry (Celery raises it)."""
    return SimpleNamespace(
        name=name,
        request=SimpleNamespace(id=task_id),
        retry=lambda countdown, exc, **_options: RetryRequested(countdown),
    )


def _claim(record_id: str, delivery: str, epoch: int = 1, task: str = TaskName.FIND_THREATS) -> Any:
    return JobRepository(_records()).claim_job(record_id, epoch, task, delivery)


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    announced: list[str] = []
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, announced.append)
    return announced


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    sends: list[tuple] = []
    monkeypatch.setattr(jobs, "send_job", lambda *args, **_priority: sends.append(args))
    monkeypatch.setattr(reaper, "send_job", lambda *args, **_priority: sends.append(args))
    return sends


def test_a_job_has_one_owner_and_a_stale_epoch_claims_nothing() -> None:
    record_id = _insert_job()
    lease = _claim(record_id, "delivery-a")
    assert lease is not None and lease.attempts == 1
    assert _claim(record_id, "delivery-b") is None  # duplicate delivery
    assert _claim(record_id, "delivery-c", epoch=2) is None  # not this job's epoch


def test_only_the_owner_of_the_current_epoch_can_change_a_plan_path() -> None:
    """S24: a path's state (served, attempts, abandoned) is written through the lease's fence, so a delivery
    whose job was replaced by a newer epoch, or taken over by another delivery, changes nothing."""
    record_id = _insert_job()
    paths = [
        {"path_id": "p1", "served": None, "attempts": 0},
        {"path_id": "p2", "served": None, "attempts": 0},
    ]
    _records().update_one({"_id": record_id}, {"$set": {"plan.paths": paths}})
    lease = _claim(record_id, "writer-1")
    lease.update_job({"plan.paths.$[p].served": "s1", "plan.paths.$[p].attempts": 1}, [{"p.path_id": "p1"}])
    _records().update_one({"_id": record_id}, {"$set": {"job.epoch": 2}})  # e.g. a regenerate replaced it
    with pytest.raises(LeaseLost):
        lease.update_job({"plan.paths.$[p].served": "late"}, [{"p.path_id": "p2"}])
    stored = _records().find_one({"_id": record_id})["plan"]["paths"]
    assert [(path["served"], path["attempts"]) for path in stored] == [("s1", 1), (None, 0)]


def test_a_late_message_for_an_earlier_stage_cannot_run_that_stage_again(sent: list[tuple]) -> None:
    record_id = _insert_job()
    jobs.hand_over(_claim(record_id, "threats-1"), TaskName.WRITE_SCENARIOS, {"plan": "frozen"})
    assert _claim(record_id, "threats-late-copy") is None  # the record now waits for the next stage
    assert _claim(record_id, "scenarios-1", task=TaskName.WRITE_SCENARIOS) is not None
    assert sent == [(TaskName.WRITE_SCENARIOS, record_id, 1)]


def test_after_the_lease_expires_a_new_owner_takes_over_and_the_old_one_cannot_write() -> None:
    record_id = _insert_job()
    first = _claim(record_id, "delivery-a")
    assert first is not None
    _records().update_one({"_id": record_id}, {"$set": {"job.lease_until": datetime.now(UTC) - timedelta(1)}})
    second = _claim(record_id, "delivery-b")
    assert second is not None and second.attempts == 2
    with pytest.raises(LeaseLost):
        first.update_job({"plan": "stale work"})
    assert "plan" not in _records().find_one({"_id": record_id})


def test_a_redelivered_copy_with_the_same_task_id_shuts_the_hung_copy_out() -> None:
    """Celery reuses the task id on a retry or a redelivery: a hung copy and the copy that claimed the job
    again after its lease ran out share task id and epoch, so only the newer claim's attempts let it write."""
    record_id = _insert_job()
    hung = _claim(record_id, "task-1")
    _records().update_one({"_id": record_id}, {"$set": {"job.lease_until": datetime.now(UTC) - timedelta(1)}})
    again = _claim(record_id, "task-1")
    assert hung is not None and again is not None and again.attempts == hung.attempts + 1
    assert not hung.renew()
    with pytest.raises(LeaseLost):
        hung.update_job({"plan": "stale work"} | ended_job_fields(Status.DONE))
    again.update_job({"plan": "fresh work"} | ended_job_fields(Status.DONE))
    stored = _records().find_one({"_id": record_id})
    assert (stored["status"], stored["plan"]) == (Status.DONE, "fresh work")


def test_a_delivery_that_takes_over_a_job_reuses_the_ai_answers_the_job_already_got(
    monkeypatch: pytest.MonkeyPatch, published: list[str]
) -> None:
    """The reaper's re-send is a new message with a new task id: the claim binds the job (record, epoch,
    stage), so the delivery that takes over after a lost lease reads back the gate answer the first one got;
    a new epoch of the record asks again."""
    model = "litellm_proxy/kimi-k2.5"
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    chat = ai.ChatModel([(model, CHAT_MODEL_PROFILES[model])], "http://ai.invalid", "key", records)
    calls: list[int] = []
    reply = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))], usage=None)
    monkeypatch.setattr(litellm, "completion", lambda **_: calls.append(1) or reply)
    record_id = _insert_job()

    def ask_the_gate(_lease: JobLease) -> None:
        chat.ask_for_checked_json(AiTask.RELEVANCE_GATE, "s", "gate", lambda _: [], reuse_earlier_answer=True)

    def deliver(task_id: str, epoch: int = 1) -> None:
        with structlog.contextvars.bound_contextvars(task_id=task_id):  # as start_job_clock binds it
            jobs.run_leased_job(_task(task_id), Collection.SESSIONS, record_id, epoch, ask_the_gate)

    deliver("first")
    _records().update_one({"_id": record_id}, {"$set": {"job.lease_until": datetime.now(UTC) - timedelta(1)}})
    deliver("resent")
    assert len(calls) == 1
    _records().update_one({"_id": record_id}, {"$set": {"status": Status.QUEUED, "job.epoch": 2}})
    deliver("next-run", epoch=2)
    assert len(calls) == 2


def test_an_outage_gives_the_job_back_and_retries_after_the_first_delay(published: list[str]) -> None:
    record_id = _insert_job()

    def work(_lease: JobLease) -> None:
        raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    with pytest.raises(RetryRequested) as retry:
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    record = _records().find_one({"_id": record_id})
    assert retry.value.countdown == Lease.RETRY_DELAYS_SECONDS[0]
    assert record["status"] == Status.QUEUED and record["job"]["due_at"] > datetime.now(UTC)
    assert published == [record_id, record_id]  # running, then queued again


def test_an_ai_outage_leaves_a_retry_notice_until_the_next_try_starts(
    published: list[str], sent: list[tuple]
) -> None:
    """The status tells the UI why a stage waits and which try comes when; the claim of that try clears it,
    so a running retry never shows the old outage."""
    record_id = _insert_job()

    def busy(_lease: JobLease) -> None:
        raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)

    with pytest.raises(RetryRequested):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, busy)
    job = _records().find_one({"_id": record_id})["job"]
    assert job["retry"] == {
        "reason": AiOutage.BUSY,
        "message": AI_OUTAGE_MESSAGES[AiOutage.BUSY],
        "attempt": 1,
        "max_attempts": Lease.MAX_ATTEMPTS,
        "retry_at": job["due_at"],
    }
    # Read as the status endpoint and its live updates read it: through the status fields.
    sessions = ThreatScenarioSessionRepository(scenarios=ThreatScenarioRepository())
    notice = build_board(session_status_from_record(sessions.get("status", _id=record_id))).progress.retrying
    assert notice is not None and (notice.reason, notice.attempt) == (AiOutage.BUSY, 1)
    _records().update_one(
        {"_id": record_id}, {"$set": {"job.due_at": datetime.now(UTC)}}
    )  # its back-off ended
    shown_while_retrying: list[Any] = []

    def retry_runs(lease: JobLease) -> None:
        status = session_status_from_record(sessions.get("status", _id=record_id))
        shown_while_retrying.append(build_board(status).progress.retrying)
        jobs.hand_over(lease, TaskName.WRITE_SCENARIOS)

    jobs.run_leased_job(_task("task-2"), Collection.SESSIONS, record_id, 1, retry_runs)
    assert shown_while_retrying == [None]
    assert _records().find_one({"_id": record_id})["job"]["retry"] is None


def test_a_job_waiting_for_another_job_looks_again_soon_and_counts_as_waiting(published: list[str]) -> None:
    """A plan waiting for its scenario's controls polled every 120 s, so it started up to 2 minutes late. Then
    each 15 s look was an outage retry: counted as `retry`, warned as job.retry_scheduled, its notice claiming
    a store outage, so a 2-minute wait read as 8 outage retries and 8 near-zero job times."""
    record_id = _insert_job(retry={"reason": AiOutage.BUSY, "attempt": 1})  # an earlier outage's notice
    resent: list[dict[str, Any]] = []
    task = SimpleNamespace(
        name=TaskName.FIND_THREATS, request=SimpleNamespace(id="waits"), retry=lambda **o: resent.append(o)
    )

    def controls_being_mapped(_lease: JobLease) -> None:
        raise WaitingForAnotherJob("controls being mapped")

    with capture_logs() as logs, pytest.raises(jobs.JobWaiting) as waiting:
        jobs.run_leased_job(task, Collection.SESSIONS, record_id, 1, controls_being_mapped)
    [options] = resent
    assert (options["countdown"], options["throw"]) == (Lease.RETRY_DELAYS_SECONDS[0], False)
    job = _records().find_one({"_id": record_id})["job"]
    assert (job["attempts"], job["retry"]) == (0, None)  # no attempt used, no outage claimed
    levels = {line["event"]: line["log_level"] for line in logs}
    assert levels[LogEvent.JOB_WAITING] == "info" and LogEvent.JOB_RETRY_SCHEDULED not in levels
    waits, retries = ({"task": TaskName.FIND_THREATS, "outcome": outcome} for outcome in ("waiting", "retry"))
    durations = {"task": TaskName.FIND_THREATS}
    before = (_job_samples("tsg_jobs_total", waits), _job_samples("tsg_jobs_total", retries))
    runs_before = _job_samples("tsg_job_seconds_count", durations)
    # As Celery ends the delivery: IGNORED, its result the JobWaiting raised.
    lifecycle.start_job_clock("waits", task)
    lifecycle.record_job_outcome("waits", task, state=states.IGNORED, retval=waiting.value)
    assert _job_samples("tsg_jobs_total", waits) == before[0] + 1
    assert _job_samples("tsg_jobs_total", retries) == before[1]
    assert _job_samples("tsg_job_seconds_count", durations) == runs_before  # a look is no job's run time


def test_a_job_meeting_a_young_pending_sql_operation_is_retried_not_failed(published: list[str]) -> None:
    """A SQL Server write an earlier attempt left pending only means waiting: the job backs off until the
    record is older than SqlOperations.PENDING_SECONDS and its replay may run."""
    record_id, operation_id = _insert_job(), f"propose:{uuid.uuid4().hex}"
    pending = {"status": SqlOperationStatus.PENDING, "started_at": datetime.now(UTC), "parameters": {}}
    get_mongodb()[Collection.SQL_OPERATIONS].insert_one({"_id": operation_id, **pending})
    sql = SqlOperationRepository(SimpleNamespace(execute_procedure=lambda *_args, **_kwargs: []))  # type: ignore[arg-type]

    def propose(_lease: JobLease) -> None:
        sql.run_sql_operation(operation_id, StoredProcedure.RESOLVE_THREAT, {})

    with pytest.raises(RetryRequested):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, propose)
    assert _records().find_one({"_id": record_id})["status"] == Status.QUEUED


def test_a_mongo_outage_while_claiming_is_retried_after_the_first_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mongo_down(*_args: object) -> None:
        raise AutoReconnect("connection lost")

    monkeypatch.setattr(JobRepository, "claim_job", mongo_down)
    with pytest.raises(RetryRequested) as retry:
        jobs.run_leased_job(_task(), Collection.SESSIONS, uuid.uuid4().hex, 1, lambda _lease: None)
    assert retry.value.countdown == Lease.RETRY_DELAYS_SECONDS[0]


def test_the_last_attempt_fails_the_job_with_the_outage_message(published: list[str]) -> None:
    record_id = _insert_job(attempts=Lease.MAX_ATTEMPTS - 1)

    def work(_lease: JobLease) -> None:
        raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    with pytest.raises(Unavailable):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.FAILED
    assert record["job"]["error"] == {"code": ErrorCode.UNAVAILABLE, "message": ErrorMessage.AI_UNREACHABLE}


def test_the_last_attempt_the_ai_timed_out_names_the_outage_and_leaves_no_notice(
    published: list[str],
) -> None:
    waiting = {"reason": AiOutage.TIMED_OUT, "attempt": Lease.MAX_ATTEMPTS - 1}
    record_id = _insert_job(attempts=Lease.MAX_ATTEMPTS - 1, retry=waiting)
    timed_out = AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT]

    def work(_lease: JobLease) -> None:
        raise Unavailable(timed_out, reason=AiOutage.TIMED_OUT)

    with pytest.raises(Unavailable):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    job = _records().find_one({"_id": record_id})["job"]
    assert job["error"] == {"code": ErrorCode.UNAVAILABLE, "message": timed_out, "reason": AiOutage.TIMED_OUT}
    assert job["retry"] is None


def test_an_unexpected_error_fails_the_job_and_a_success_finishes_it(published: list[str]) -> None:
    broken, good = _insert_job(), _insert_job()

    def explode(_lease: JobLease) -> None:
        raise KeyError("bug")

    with pytest.raises(KeyError):
        jobs.run_leased_job(_task(), Collection.SESSIONS, broken, 1, explode)
    jobs.run_leased_job(
        _task(),
        Collection.SESSIONS,
        good,
        1,
        lambda lease: lease.update_job({"plan": "ok"} | ended_job_fields(Status.DONE)),
    )
    # The run's id, not a request id: a background job has none, and its log lines carry record_id.
    assert _records().find_one({"_id": broken})["job"]["error"] == {
        "code": ErrorCode.INTERNAL_ERROR,
        "message": ErrorMessage.JOB_UNEXPECTED.format(record_id=broken),
    }
    assert _records().find_one({"_id": good})["status"] == Status.DONE


def test_the_reaper_requeues_abandons_and_resends_each_once(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reaper scans every job record: earlier tests' records older than Lease.REQUEUE_QUEUED_AFTER_SECONDS
    # would be re-sent too, so this test starts with only its own, in every collection the reaper reads.
    # (Before 2026-10-11 it cleared only the runs: plan jobs a remediation test dated 09:00 UTC that day made
    # it fail from 09:02 on, depending on the clock.)
    for collection in jobs.JOB_COLLECTIONS:
        get_mongodb()[collection].delete_many({})
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    notice = {
        "reason": AiOutage.BUSY,
        "message": "busy",
        "attempt": 1,
        "max_attempts": 5,
        "retry_at": long_ago,
    }
    expired = _insert_job(Status.RUNNING, attempts=1, lease_until=long_ago, task_id="gone", retry=notice)
    worn_out = _insert_job(Status.RUNNING, attempts=Lease.MAX_ATTEMPTS, lease_until=long_ago, task_id="gone")
    never_sent = _insert_job(Status.QUEUED, due_at=long_ago, retry=notice)
    failures_before = _job_failures()
    priorities: list[int] = []
    monkeypatch.setattr(
        reaper, "send_job", lambda *args, priority: (sent.append(args), priorities.append(priority))
    )
    reaper.reap_jobs()
    reaper.reap_jobs()  # a second pass right after must not send anything again
    requeued = _records().find_one({"_id": expired})
    # Its worker was lost: an earlier outage's notice no longer says why it waits; a resend keeps its own.
    assert requeued["status"] == Status.QUEUED and requeued["job"]["retry"] is None
    assert _records().find_one({"_id": never_sent})["job"]["retry"]["reason"] == AiOutage.BUSY
    abandoned = _records().find_one({"_id": worn_out})
    assert abandoned["job"]["error"]["code"] == ErrorCode.JOB_ABANDONED
    assert abandoned["active"] is False and abandoned["finished_at"] is not None  # the asset is free again
    assert sorted(record_id for _, record_id, _ in sent) == sorted([expired, never_sent])
    assert priorities == [Worker.NEXT_STAGE_PRIORITY] * 2  # both ahead of new work: they waited already
    # The abandoned run counts as a job failure (JobsFailing): its dead worker never recorded an outcome.
    assert _job_failures() == failures_before + 1


def test_a_worker_makes_every_index_its_reaper_scans_at_start_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each of the reaper's two scans reads one index; without them it scans whole collections."""
    made: list[object] = []
    monkeypatch.setattr(container, "create_all_indexes", made.append)
    for gateway in ("get_chat_model", "get_embedding_model", "get_rerank_model"):
        monkeypatch.setattr(container, gateway, lambda: None)
    lifecycle._prepare_stores_and_models()
    assert made == [jobs.JOB_COLLECTIONS]


def test_a_worker_pool_that_forks_is_refused() -> None:
    with pytest.raises(SystemExit, match="prefork"):
        lifecycle.prepare_worker(SimpleNamespace(pool_cls="prefork"))


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_a_worker_whose_ai_model_has_no_profile_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_profile() -> None:
        raise ValueError("No profile for AI model 'typo'")

    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", _free_port())
    monkeypatch.setattr(container, "get_chat_model", no_profile)
    with pytest.raises(SystemExit, match="typo"):
        lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))


def test_the_worker_serves_its_ai_metrics_for_prometheus(monkeypatch: pytest.MonkeyPatch) -> None:
    free_port = _free_port()
    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", free_port)
    lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))
    metrics.AI_CALLS.labels(AiTask.EMBED, "worker-test-model", "ok").inc()
    with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/metrics", timeout=5) as response:  # noqa: S310
        assert 'tsg_ai_calls_total{model="worker-test-model"' in response.read().decode()


def _worker_starting(pool: str, *queues: str) -> Any:
    """What Celery passes to worker_init / worker_ready: the pool, the queues chosen with -Q, the name."""
    consume_from = dict.fromkeys(queues)
    amqp = SimpleNamespace(queues=SimpleNamespace(consume_from=consume_from))
    hostname = f"celery@test-{uuid.uuid4().hex}"
    return SimpleNamespace(pool_cls=pool, hostname=hostname, app=SimpleNamespace(amqp=amqp))


def _online(queue: str) -> int:
    return readiness.count_online_workers([queue])[queue]


def _stamps(queue: str) -> dict[str, float]:
    return dict(get_redis_client().zrange(Worker.HEARTBEAT_KEY.format(queue=queue), 0, -1, withscores=True))


def test_a_ready_worker_is_counted_on_its_queues_until_it_shuts_down() -> None:
    ready = _worker_starting("threads", Queue.THREATS)
    lifecycle.start_heartbeat(ready)
    try:
        deadline = time.monotonic() + 5  # the heartbeat thread beats as soon as it starts
        while ready.hostname not in _stamps(Queue.THREATS) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.hostname in _stamps(Queue.THREATS)
        assert _online(Queue.THREATS) >= 1
    finally:
        lifecycle.stop_heartbeat()
    assert ready.hostname not in _stamps(Queue.THREATS)


def test_any_redis_error_leaves_the_heartbeat_beating(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read-only replica after a failover is not a ConnectionError: it must not end the thread."""
    monkeypatch.setattr(Worker, "HEARTBEAT_SECONDS", 0.01)
    beats: list[int] = []
    second_beat = threading.Event()

    def flaky_beat(_self: object) -> None:
        beats.append(1)
        if len(beats) == 1:
            raise ReadOnlyError("You can't write against a read only replica.")
        second_beat.set()

    monkeypatch.setattr(heartbeat.WorkerHeartbeat, "beat", flaky_beat)
    beating = heartbeat.WorkerHeartbeat([Queue.THREATS], f"celery@flaky-{uuid.uuid4().hex}")
    beating.start()
    try:
        assert second_beat.wait(5), "the heartbeat stopped after one Redis error"
    finally:
        beating.stop()


def test_a_worker_silent_for_a_minute_is_not_counted_and_its_stamp_is_dropped() -> None:
    key = Worker.HEARTBEAT_KEY.format(queue=Queue.SCENARIOS)
    silent = f"celery@silent-{uuid.uuid4().hex}"
    get_redis_client().zadd(key, {silent: time.time() - Worker.ONLINE_WITHIN_SECONDS - 1})
    before = _online(Queue.SCENARIOS)
    alive = heartbeat.WorkerHeartbeat([Queue.SCENARIOS], f"celery@alive-{uuid.uuid4().hex}")
    alive.beat()
    try:
        assert _online(Queue.SCENARIOS) == before + 1  # the silent one never counted
        assert silent not in _stamps(Queue.SCENARIOS)  # and the next beat cleaned it up
    finally:
        alive.stop()


def test_two_workers_on_one_laptop_write_different_log_files() -> None:
    """Before: every worker appended to logs/worker.log, so a second worker interleaved half-lines."""
    assert lifecycle.log_file_role("dev@laptop") == "worker-dev"
    assert lifecycle.log_file_role("dev2@laptop") == "worker-dev2"
    assert lifecycle.log_file_role("a b/c@laptop") == "worker-a_b_c"  # always a plain file name


def test_a_worker_that_cannot_open_its_log_file_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: the OSError escaped worker_init, Celery only logged it, and the worker ran without metrics."""

    def log_dir_unusable(*_: object) -> None:
        raise PermissionError("logs is read-only")

    monkeypatch.setattr(lifecycle, "configure_logging", log_dir_unusable)
    with pytest.raises(SystemExit, match="read-only"):
        lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))


def test_every_job_outcome_series_starts_at_zero_when_the_worker_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: a task's failure series first appeared at 1, which Prometheus reads as no increase, so the
    first failure after a restart never fired JobsFailing."""
    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", _free_port())
    lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))
    for task in TaskName:
        for outcome in metrics.JOB_OUTCOMES:
            assert REGISTRY.get_sample_value("tsg_jobs_total", {"task": task, "outcome": outcome}) is not None


def _last_reaper_pass() -> float:
    return metrics.REAPER_LAST_PASS.collect()[0].samples[0].value


def test_no_process_but_the_reaper_s_worker_exports_its_last_pass() -> None:
    """Before: every process that loads the metrics exported 0 (the API, every worker, Flower), so right
    after a start the newest pass read 0 until Prometheus reached the maintenance worker (alert pending)."""
    code = (
        "import app.main, app.worker.lifecycle; from prometheus_client import generate_latest; "
        "print(b'tsg_reaper_last_pass' in generate_latest())"
    )
    run = [sys.executable, "-c", code]
    result = subprocess.run(run, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    assert result.stdout.strip().splitlines()[-1:] == ["False"], result.stdout + result.stderr


def test_the_probe_app_loads_no_worker_code() -> None:
    """Every startup and liveness probe imports it: app.worker would load the AI clients each time."""
    run = [sys.executable, "-c", "import sys, app.probe; print(*sys.modules)"]
    result = subprocess.run(run, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    loaded = result.stdout.split()
    assert "app.probe" in loaded, result.stderr
    assert [name for name in loaded if name.startswith(("app.worker", "litellm"))] == []


def test_only_the_worker_that_runs_the_reaper_starts_on_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: ReaperNotRunning read a rise in tsg_jobs_total, and the first pass after a start comes before
    Prometheus' first scrape, so every start showed it (and the beat tile DOWN) for a minute. The worker that
    runs the reaper is on time from its own start; no other worker stands in for it."""
    metrics.REAPER_LAST_PASS.set(0)
    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", _free_port())
    lifecycle.prepare_worker(_worker_starting("threads", Queue.THREATS, Queue.SCENARIOS))
    assert _last_reaper_pass() == 0
    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", _free_port())
    before = time.time()
    lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))
    assert before <= _last_reaper_pass() <= time.time()


def test_each_reaper_pass_records_when_it_ended_and_a_failed_one_does_not(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    metrics.REAPER_LAST_PASS.set(0)
    before = time.time()
    reaper.reap_jobs()
    assert before <= _last_reaper_pass() <= time.time()

    def mongodb_down(*_: object) -> list:
        raise AutoReconnect("MongoDB is down")

    metrics.REAPER_LAST_PASS.set(0)
    monkeypatch.setattr(JobRepository, "list_expired_jobs", mongodb_down)
    with pytest.raises(AutoReconnect):
        reaper.reap_jobs()
    assert _last_reaper_pass() == 0  # a pass that did not end is not on time


def test_celery_keeps_the_log_level_cii_log_level_chose() -> None:
    """Before: Celery set up logging after worker_init and reset the root level to its own --loglevel."""
    root = logging.getLogger()
    level, already = root.level, celery_app.log.already_setup
    root.setLevel(logging.INFO)
    try:
        celery_app.log.already_setup = False
        celery_app.log.setup(loglevel="WARNING")
        assert root.level == logging.INFO
    finally:
        root.setLevel(level)
        celery_app.log.already_setup = already


def _job_failures() -> float:
    labels = {"task": TaskName.FIND_THREATS, "outcome": "failure"}
    return REGISTRY.get_sample_value("tsg_jobs_total", labels) or 0.0


def test_a_job_the_reaper_failed_cannot_be_finished_by_its_old_owner(
    published: list[str], sent: list[tuple]
) -> None:
    """Before: the write fence did not check the status, so a slow owner could turn a job the reaper had
    already failed (job_abandoned) into done, with the stale error still on it."""
    _records().delete_many({})
    record_id = _insert_job()
    slow_owner = _claim(record_id, "slow-owner")
    assert slow_owner is not None
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    _records().update_one(
        {"_id": record_id}, {"$set": {"job.lease_until": long_ago, "job.attempts": Lease.MAX_ATTEMPTS}}
    )
    reaper.reap_jobs()
    with pytest.raises(LeaseLost):
        slow_owner.update_job({"plan": "late work"} | ended_job_fields(Status.DONE))
    assert not slow_owner.renew()
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.FAILED and "plan" not in record


def test_a_duplicate_message_cannot_run_a_job_before_its_back_off_ends() -> None:
    """Before: claim ignored due_at, so a duplicate delivery took a job straight after an outage gave it back,
    and the 15/30/60 s back-off could burn every attempt in seconds."""
    record_id = _insert_job()
    first = _claim(record_id, "first")
    assert first is not None
    first.update_job(
        {
            "status": Status.QUEUED,
            "job.due_at": datetime.now(UTC) + timedelta(seconds=60),
            "job.lease_until": None,
        }
    )
    assert _claim(record_id, "duplicate") is None
    almost_due = datetime.now(UTC) + timedelta(seconds=Lease.CLOCK_SKEW_SECONDS - 1)
    _records().update_one({"_id": record_id}, {"$set": {"job.due_at": almost_due}})
    assert _claim(record_id, "retry") is not None  # another pod's clock may run a little ahead


def test_a_delivery_that_cannot_claim_its_job_logs_why() -> None:
    """UAT, 2026-10-24: job.not_claimed said only that a delivery was dropped, so the clocks (not_due) could
    not be told from a worker reading another database (missing) without guessing."""
    jobs_ = JobRepository(_records())

    def why(record_id: str, epoch: int = 1, task: str = TaskName.FIND_THREATS) -> dict[str, Any]:
        return jobs_.why_not_claimed(record_id, epoch, task)

    assert why("no-such-record") == {"reason": "missing"}
    queued = _insert_job(due_at=datetime.now(UTC) + timedelta(seconds=376))
    assert why(queued, epoch=2) == {"reason": "other_epoch", "job_epoch": 1}
    assert why(queued, task=TaskName.WRITE_SCENARIOS) == {
        "reason": "other_task",
        "job_task": TaskName.FIND_THREATS,
    }
    not_due = why(queued)
    assert not_due["reason"] == "not_due" and 370 < not_due["due_in_seconds"] <= 376
    running = _insert_job(Status.RUNNING, worker="celery@worker-threats", lease_until=datetime.now(UTC))
    assert why(running) == {"reason": "leased", "worker": "celery@worker-threats"}
    assert why(_insert_job(Status.FAILED)) == {"reason": "status_failed"}
    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(_task("early"), Collection.SESSIONS, queued, 1, lambda _lease: None)
    [line] = [line for line in logs if line["event"] == LogEvent.JOB_NOT_CLAIMED]
    assert line["reason"] == "not_due" and line["due_in_seconds"] > 370 and line["sent_again"] is False


def test_a_delivery_that_comes_before_its_job_is_due_is_sent_again_for_then() -> None:
    """Celery runs a retry's countdown on the receiving pod's clock, not MongoDB's, so a retry could come
    early: it was dropped and the job waited minutes for the reaper. Sent again, it uses no attempt. An early
    first send is a duplicate (a reaper re-send): only dropped, so it never follows the job's retries."""
    resent: list[dict[str, Any]] = []
    soon = _insert_job(due_at=datetime.now(UTC) + timedelta(seconds=40))
    for retries in (0, 1):
        request = SimpleNamespace(id="early", retries=retries)
        task = SimpleNamespace(
            name=TaskName.FIND_THREATS, request=request, retry=lambda **options: resent.append(options)
        )
        with pytest.raises(Ignore):
            jobs.run_leased_job(task, Collection.SESSIONS, soon, 1, lambda _lease: None)
        assert len(resent) == retries
    [options] = resent
    assert options["throw"] is False and 40 <= options["countdown"] <= 41
    assert options["priority"] == Worker.NEXT_STAGE_PRIORITY
    job = _records().find_one({"_id": soon})["job"]
    assert (job["attempts"], job.get("task_id")) == (0, None)


def test_a_run_s_next_stage_is_taken_before_new_work_already_waiting() -> None:
    """A stage handed over goes ahead of runs that have not started, so a started run finishes first."""
    with celery_app.connection_for_write() as connection:
        channel = connection.default_channel
        channel.queue_purge(Queue.SCENARIOS)
        new_run, started_run = _insert_job(), _insert_job()
        try:
            send_job(TaskName.WRITE_SCENARIOS, new_run, 1)
            jobs.hand_over(_claim(started_run, "threats-1"), TaskName.WRITE_SCENARIOS)
            taken = [channel.basic_get(Queue.SCENARIOS, no_ack=True).decode()[0][0] for _ in range(2)]
        finally:
            channel.queue_purge(Queue.SCENARIOS)
    assert taken == [started_run, new_run]


def test_a_retried_job_is_taken_before_new_work_already_waiting(published: list[str]) -> None:
    """Celery's retry copies its message's priority, so a retry waited behind the whole backlog."""

    def outage(_lease: JobLease) -> None:
        raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    delivery = {"exchange": Queue.THREATS, "routing_key": Queue.THREATS, "priority": Worker.NEW_WORK_PRIORITY}
    with celery_app.connection_for_write() as connection:
        channel = connection.default_channel
        channel.queue_purge(Queue.THREATS)
        new_run, retried_run = _insert_job(), _insert_job()
        try:
            send_job(TaskName.FIND_THREATS, new_run, 1)
            find_threats.push_request(
                id="first-try", args=[retried_run, 1], delivery_info=delivery, called_directly=False
            )
            try:
                with pytest.raises(Retry):
                    jobs.run_leased_job(find_threats, Collection.SESSIONS, retried_run, 1, outage)
            finally:
                find_threats.pop_request()
            taken = [channel.basic_get(Queue.THREATS, no_ack=True).decode()[0][0] for _ in range(2)]
        finally:
            channel.queue_purge(Queue.THREATS)
    assert taken == [retried_run, new_run]


def test_a_claimed_job_records_how_long_it_waited_after_it_was_due(published: list[str]) -> None:
    def waits() -> float:
        return _job_samples("tsg_job_queue_wait_seconds_count", {"task": TaskName.FIND_THREATS})

    def over_a_minute() -> float:
        labels = {"task": TaskName.FIND_THREATS, "le": "60.0"}
        return waits() - _job_samples("tsg_job_queue_wait_seconds_bucket", labels)

    before, slow_before = waits(), over_a_minute()
    late = _insert_job(due_at=datetime.now(UTC) - timedelta(seconds=90))
    jobs.run_leased_job(_task(), Collection.SESSIONS, late, 1, lambda _lease: None)
    assert (waits(), over_a_minute()) == (before + 1, slow_before + 1)


#: Routed ahead of their build step (BLUEPRINT §15, Steps 11-14): no module defines them yet, and nothing
#: sends them. Remove each one here when its task is built.
NOT_BUILT_YET: set[TaskName] = set()


def test_every_task_is_registered_and_routed() -> None:
    """A task module missing from TASK_MODULES is never registered, so its messages are refused; a task with
    no route goes to the default queue, which may have no worker. Both checked against the routes (J6)."""
    celery_app.loader.import_default_modules()  # what a worker does at start: imports TASK_MODULES
    registered = {name for name in celery_app.tasks if not name.startswith("celery.")}
    assert registered == set(celery_app.conf.task_routes) - NOT_BUILT_YET


def _job_samples(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_a_delivery_that_finds_its_job_taken_is_ignored_not_counted(published: list[str]) -> None:
    """Before: a duplicate delivery (a reaper re-send, a broker redelivery) returned normally, Celery called
    it SUCCESS, and tsg_jobs_total counted deliveries instead of jobs (and tsg_job_seconds near-zero runs)."""
    record_id = _insert_job()
    assert _claim(record_id, "first-delivery") is not None
    with pytest.raises(Ignore):
        jobs.run_leased_job(_task("duplicate"), Collection.SESSIONS, record_id, 1, lambda _lease: None)
    task = SimpleNamespace(name=TaskName.FIND_THREATS)
    success = {"task": TaskName.FIND_THREATS, "outcome": "success"}
    ignored = {"task": TaskName.FIND_THREATS, "outcome": "ignored"}
    durations = {"task": TaskName.FIND_THREATS}
    before = [_job_samples("tsg_jobs_total", success), _job_samples("tsg_jobs_total", ignored)]
    runs_before = _job_samples("tsg_job_seconds_count", durations)
    lifecycle.start_job_clock("duplicate", task)
    lifecycle.record_job_outcome("duplicate", task, state=states.IGNORED)
    assert [_job_samples("tsg_jobs_total", success), _job_samples("tsg_jobs_total", ignored)] == before
    assert _job_samples("tsg_job_seconds_count", durations) == runs_before
    assert "duplicate" not in lifecycle._job_started


def test_a_job_waiting_behind_others_is_not_sent_again(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a job still waiting in a busy queue was re-sent every 2 minutes: the backlog grew by copies
    (QueueBacklog fired early) and each copy became an empty extra delivery."""
    _records().delete_many({})
    waiting = _insert_job(Status.QUEUED, due_at=datetime.now(UTC) - timedelta(minutes=3))
    sizes: dict[str, int] = {Queue.THREATS: 3}
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda queue: sizes.get(queue, 0))
    reaper.reap_jobs()
    assert sent == []  # its message is still in line

    def broker_down(_queue: str) -> int:
        raise BrokerUnavailable("broker down")

    monkeypatch.setattr(reaper, "count_waiting_messages", broker_down)
    reaper.reap_jobs()
    assert sent == []  # cannot tell, and a send would fail too
    sizes[Queue.THREATS] = 0  # the line cleared and the job is still queued: its message was lost
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda queue: sizes.get(queue, 0))
    reaper.reap_jobs()
    assert [record_id for _, record_id, _ in sent] == [waiting]


def test_the_waiting_message_count_reads_the_broker_queue() -> None:
    """The real kombu path, key prefix and each priority's list included, against the test broker database."""
    queue = f"tsg_test_{uuid.uuid4().hex[:8]}"
    assert count_waiting_messages(queue) == 0
    celery_app.send_task(TaskName.REAP, queue=queue, priority=Worker.NEXT_STAGE_PRIORITY)
    celery_app.send_task(TaskName.REAP, queue=queue, priority=Worker.NEW_WORK_PRIORITY)
    try:
        assert count_waiting_messages(queue) == 2
    finally:
        with celery_app.connection_for_write() as connection:
            connection.default_channel.queue_purge(queue)


def test_one_broken_record_does_not_stop_the_reaper_for_the_others(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a record missing a field ended the whole pass with a KeyError, so no other job was repaired
    again until someone fixed that record by hand."""
    _records().delete_many({})
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    broken = _insert_job(Status.QUEUED, due_at=long_ago)
    _records().update_one({"_id": broken}, {"$unset": {"job.task": ""}})
    lost = _insert_job(Status.QUEUED, due_at=long_ago)
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    reaper.reap_jobs()
    assert [record_id for _, record_id, _ in sent] == [lost]


def test_beat_writes_its_own_log_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: beat logged to its window only, so a schedule it could not send never reached Grafana."""
    roles: list[str | None] = []
    monkeypatch.setattr(lifecycle, "configure_logging", lambda _settings, role=None: roles.append(role))
    lifecycle.prepare_beat()
    assert roles == ["beat"]


def test_no_task_has_a_celery_retry_limit() -> None:
    """Before: retry(max_retries=None) meant "the task's default", 3, so a job's 4th outage raised the error
    instead of retrying: counted as a failure while its record still said queued. Lease.MAX_ATTEMPTS, on the
    record, is the only limit."""
    celery_app.loader.import_default_modules()
    tasks = [task for name, task in celery_app.tasks.items() if not name.startswith("celery.")]
    assert tasks and all(task.max_retries is None for task in tasks)


def test_a_job_queued_too_long_is_sent_again_whatever_its_queue_holds(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a lost job was re-sent only when its queue was empty, so a steady backlog hid it for hours."""
    _records().delete_many({})
    lost = _insert_job(
        Status.QUEUED, due_at=datetime.now(UTC) - timedelta(seconds=Lease.RESEND_ANYWAY_AFTER_SECONDS + 60)
    )
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 3)
    reaper.reap_jobs()
    assert [record_id for _, record_id, _ in sent] == [lost]
    assert _records().find_one({"_id": lost})["job"]["resends"] == 0  # its queue was busy: not counted


def test_a_job_waiting_in_a_long_backlog_is_sent_again_never_failed_as_never_started(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: each re-send into a busy queue counted toward the sends that fail a job as never started, so
    a job only waiting in a long backlog was failed after ~75 minutes."""
    _records().delete_many({})
    waiting = _insert_job(
        Status.QUEUED,
        due_at=datetime.now(UTC) - timedelta(seconds=Lease.RESEND_ANYWAY_AFTER_SECONDS + 60),
        resends=Lease.MAX_ATTEMPTS - 1,
    )
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 3)
    for _ in range(3):
        reaper.reap_jobs()
        _records().update_one(
            {"_id": waiting}, {"$set": {"job.due_at": datetime.now(UTC) - timedelta(hours=1)}}
        )
    record = _records().find_one({"_id": waiting})
    assert record["status"] == Status.QUEUED and record["job"]["resends"] == Lease.MAX_ATTEMPTS - 1
    assert [record_id for _, record_id, _ in sent] == [waiting] * 3
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    reaper.reap_jobs()  # its queue is empty and it is still queued: this send counts
    assert _records().find_one({"_id": waiting})["job"]["resends"] == Lease.MAX_ATTEMPTS


def test_a_job_sent_again_and_again_but_never_started_is_failed_and_counted(
    published: list[str], sent: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a job no worker ever claimed (its task not registered) was re-sent every 2 minutes for ever,
    with the run stuck in queued and no alert."""
    _records().delete_many({})
    stuck = _insert_job(
        Status.QUEUED, due_at=datetime.now(UTC) - timedelta(minutes=3), resends=Lease.MAX_ATTEMPTS
    )
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    failures = {"task": TaskName.FIND_THREATS, "outcome": "failure"}
    before = _job_samples("tsg_jobs_total", failures)
    with capture_logs() as logs:
        reaper.reap_jobs()
    [failed] = [line for line in logs if line["event"] == LogEvent.JOB_FAILED]
    # The job's own task and module, not the reaper's: the dashboard groups failed jobs by them.
    assert (failed["task"], failed["module"], failed["code"], failed["reason"]) == (
        TaskName.FIND_THREATS,
        "threat_scenarios",
        ErrorCode.JOB_ABANDONED,
        "never_started",
    )
    record = _records().find_one({"_id": stuck})
    assert sent == [] and record["status"] == Status.FAILED
    assert record["job"]["error"]["code"] == ErrorCode.JOB_ABANDONED and published == [stuck]
    assert record["active"] is False and record["finished_at"] is not None
    assert _job_samples("tsg_jobs_total", failures) == before + 1
    # A claim starts the count again: a job that once reached a worker is not given up for old re-sends.
    retried = _insert_job(resends=3)
    assert _claim(retried, "delivery") is not None
    assert _records().find_one({"_id": retried})["job"]["resends"] == 0


def test_a_job_running_past_its_time_limit_stops_renewing_its_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung job (a deadlock, an endless loop) stops renewing, so the reaper takes it over, and makes no more
    AI calls meanwhile."""
    monkeypatch.setattr(jobs.Lease, "RENEW_EVERY_SECONDS", 0.02)
    monkeypatch.setattr(jobs.Lease, "MAX_JOB_SECONDS", 0.1)
    renewals: list[int] = []
    lease = SimpleNamespace(record_id="hung", renew=lambda: renewals.append(1) or True)
    with jobs.keep_lease_alive(lease):  # type: ignore[arg-type]
        time.sleep(0.4)
        renewed = len(renewals)
        time.sleep(0.2)
        assert len(renewals) == renewed  # stopped: the lease now runs out and the reaper takes the job
        with pytest.raises(LeaseLost):
            raise_if_lease_lost()
    assert 0 < renewed < 10


def test_a_finished_job_frees_its_asset_and_says_when_it_ended(published: list[str]) -> None:
    """Every end of a job sets active false and finished_at: otherwise the unique "one active run per asset"
    index would block the asset for good after its first run."""
    record_id = _insert_job()
    finish = lambda lease: lease.update_job(ended_job_fields(Status.DONE))  # noqa: E731
    jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, finish)
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.DONE and record["active"] is False and record["finished_at"] is not None


@pytest.mark.parametrize(
    ("error", "code", "reason"),
    [
        (JobFailed(ErrorCode.PLAN_REFUSED, "no room"), ErrorCode.PLAN_REFUSED, None),
        (KeyError("bug"), ErrorCode.INTERNAL_ERROR, None),
        (Unavailable("timed out", reason=AiOutage.TIMED_OUT), ErrorCode.UNAVAILABLE, AiOutage.TIMED_OUT),
    ],
)
def test_every_failed_job_writes_one_job_failed_line_with_its_code_and_reason(
    published: list[str], error: Exception, code: ErrorCode, reason: AiOutage | None
) -> None:
    """Owner, 2026-10-23: the dashboard's "Failed jobs" table reads these lines. Before, an outage on the last
    try wrote none, and a bug's line had no code; a bug still writes its traceback on a line of its own."""
    record_id = _insert_job(attempts=Lease.MAX_ATTEMPTS - 1)

    def work(_lease: JobLease) -> None:
        raise error

    with capture_logs() as logs, pytest.raises(type(error)):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    failed = [line for line in logs if line["event"] == LogEvent.JOB_FAILED]
    assert [(line["record_id"], line["code"], line.get("reason")) for line in failed] == [
        (record_id, code, reason)
    ]
    bugs = [line for line in logs if line["event"] == LogEvent.JOB_UNEXPECTED_ERROR]
    assert len(bugs) == (code == ErrorCode.INTERNAL_ERROR)


def test_a_job_failed_by_its_own_rule_keeps_its_code_and_is_not_retried(published: list[str]) -> None:
    """Before: a job's own final error (e.g. plan_refused) could only end as internal_error."""
    record_id = _insert_job()

    def refuse(_lease: JobLease) -> None:
        raise JobFailed(ErrorCode.PLAN_REFUSED, "SYS2 has too little room in the landscape.")

    with pytest.raises(JobFailed):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, refuse)
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.FAILED and record["active"] is False and record["finished_at"]
    assert record["job"]["error"] == {
        "code": ErrorCode.PLAN_REFUSED,
        "message": "SYS2 has too little room in the landscape.",
    }
    assert published == [record_id, record_id]  # running, then failed
    assert JobFailed in celery_app.tasks[TaskName.REAP].throws  # logged without a traceback


def test_a_job_whose_lease_is_lost_makes_no_more_ai_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """G214 cross-check: a run cancelled while it found threats (about 100 AI calls before its next save) kept
    calling the AI until that save failed. The renewal that finds the lease lost now stops every next call,
    in the job's pool threads too; outside the job nothing is checked."""
    monkeypatch.setattr(jobs.Lease, "RENEW_EVERY_SECONDS", 0.02)
    lease = SimpleNamespace(record_id="cancelled-run", renew=lambda: False)
    with jobs.keep_lease_alive(lease):  # type: ignore[arg-type]
        deadline = time.monotonic() + 5
        with pytest.raises(LeaseLost):
            while time.monotonic() < deadline:
                raise_if_lease_lost()
                time.sleep(0.01)
        errors: list[BaseException] = []

        def in_a_pool_thread() -> None:
            try:
                raise_if_lease_lost()
            except LeaseLost as exc:
                errors.append(exc)

        thread = threading.Thread(target=contextvars.copy_context().run, args=(in_a_pool_thread,))
        thread.start()
        thread.join()
        assert len(errors) == 1
    raise_if_lease_lost()  # the job is over: nothing to stop


def test_an_outage_that_names_the_ai_is_raised_before_one_that_names_none() -> None:
    """The retry notice then says which AI outage the batch met (owner 2026-10-20)."""
    timed_out = Unavailable(AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT], reason=AiOutage.TIMED_OUT)
    with pytest.raises(Unavailable) as raised:
        raise_most_retryable([RuntimeError("bug"), Unavailable("evidence search"), timed_out])
    assert raised.value is timed_out


def test_a_lost_lease_is_raised_before_any_outage() -> None:
    """Once the job is not this delivery's, an outage of another call must not retry it."""
    with pytest.raises(LeaseLost):
        raise_most_retryable([Unavailable("busy"), LeaseLost("run")])


@pytest.mark.parametrize("ending", ["lease lost", "unusable answer", "outage", "waiting", "unexpected error"])
def test_a_job_its_owner_cancelled_ends_quietly(published: list[str], ending: str) -> None:
    """G214 cross-check: a job cancelled while it ran counted as a success (its lost lease returned), or, when
    an answer came back unusable or an outage struck, as a failure (feeding the failure alert) or a retry. It
    now ends with no outcome (Ignore), the record untouched, and an info line, not a stall warning."""
    record_id = _insert_job()

    def work(lease: JobLease) -> None:
        _records().update_one({"_id": record_id}, {"$set": {"status": Status.CANCELLED}})
        if ending == "lease lost":
            lease.update_job({"plan": "late work"})
        raise {
            "unusable answer": JobFailed(ErrorCode.GENERATION_FAILED, "unusable"),
            "outage": Unavailable(ErrorMessage.AI_UNREACHABLE),
            "waiting": WaitingForAnotherJob("controls being mapped"),
            "unexpected error": KeyError("x"),
        }[ending]

    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.CANCELLED and "error" not in record["job"] and "plan" not in record
    events = [entry["event"] for entry in logs]
    assert "job.stopped_by_owner" in events and "job.lease_lost" not in events
    assert "job.retry_scheduled" not in events


def test_a_job_another_delivery_took_over_still_warns() -> None:
    record_id = _insert_job()

    def taken_over(lease: JobLease) -> None:
        _records().update_one({"_id": record_id}, {"$set": {"job.task_id": "another-delivery"}})
        lease.update_job({"plan": "late work"})

    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, taken_over)
    assert "job.lease_lost" in [entry["event"] for entry in logs]
