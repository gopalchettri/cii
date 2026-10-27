"""Leased-job runtime: a stalled job stops renewing while a working one keeps its lease, a job thread that
ignores its lost lease restarts its worker, a stopping worker hands its jobs back, and waits for another job
or for the shared library build end."""

import contextvars
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from celery import signals
from celery.exceptions import Ignore
from structlog.testing import capture_logs

from app.core.constants import (
    AiLimits,
    Collection,
    ErrorCode,
    Lease,
    LogEvent,
    Queue,
    Status,
    TaskName,
    Worker,
)
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, LeaseLost, WaitingForAnotherJob
from app.core.lease_signal import lease_lost_signal, raise_if_lease_lost
from app.core.logging import current_request_id
from app.data_access.jobs.job_repository import JobLease, JobRepository
from app.search.service import _SnapshotKeeper
from app.worker import heartbeat, jobs, lease_renewal, lifecycle
from app.worker.lease_renewal import keep_lease_alive
from tests.test_deploy import _all_deployments

#: The queues whose tasks run under run_leased_job: their workers hand jobs back when they stop.
LEASED_QUEUES = {Queue.THREATS, Queue.SCENARIOS, Queue.REMEDIATION, Queue.SERVICEMAPPER}


def _records() -> Any:
    return get_mongodb()[Collection.SESSIONS]


def _insert_job(**job: Any) -> str:
    record_id = uuid.uuid4().hex
    now = datetime.now(UTC)
    job = {"task": TaskName.FIND_THREATS, "epoch": 1, "attempts": 0, "due_at": now, **job}
    record = {"_id": record_id, "entity_id": 86, "asset_id": 103, "status": Status.QUEUED, "updated_at": now}
    _records().insert_one({**record, "job": job})
    return record_id


def _claim(record_id: str, delivery: str) -> JobLease | None:
    return JobRepository(_records()).claim_job(record_id, 1, TaskName.FIND_THREATS, delivery)


def _waiting_task(resent: list[dict[str, Any]]) -> Any:
    """A Celery task as run_leased_job uses it, recording the re-sends of a waiting job."""
    return SimpleNamespace(
        name=TaskName.FIND_THREATS, request=SimpleNamespace(id="waits"), retry=lambda **o: resent.append(o)
    )


def _controls_being_mapped(_lease: JobLease) -> None:
    raise WaitingForAnotherJob("controls being mapped")


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    announced: list[str] = []
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, announced.append)
    return announced


@pytest.fixture
def fresh_hung_mark(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """This test's own "worker hung" mark, so no other test sees it set."""
    hung = threading.Event()
    monkeypatch.setattr(heartbeat, "_hung", hung, raising=False)
    return hung


def test_a_job_that_keeps_working_keeps_its_lease_past_the_run_time_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job still making AI calls after Lease.MAX_JOB_SECONDS lost its lease and was re-run by the reaper as
    "stopped responding", up to 5 times, then failed: only a job that stops looking stops renewing."""
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.02)
    monkeypatch.setattr(Lease, "MAX_JOB_SECONDS", 0.1)
    monkeypatch.setattr(Lease, "STALL_SECONDS", 0.3, raising=False)
    renewals: list[int] = []
    lease = SimpleNamespace(record_id="long", renew=lambda: renewals.append(1) or True)
    with keep_lease_alive(lease):  # type: ignore[arg-type]
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline:
            raise_if_lease_lost()  # as each AI call and wait does
            time.sleep(0.02)
        renewed = len(renewals)
        time.sleep(0.1)
        raise_if_lease_lost()
        assert len(renewals) > renewed  # still renewing at six times the run-time cap


def test_a_job_that_stops_looking_stops_renewing_and_says_it_stalled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.02)
    monkeypatch.setattr(Lease, "STALL_SECONDS", 0.1, raising=False)
    renewals: list[int] = []
    lease = SimpleNamespace(record_id="stalled", renew=lambda: renewals.append(1) or True)
    with capture_logs() as logs, keep_lease_alive(lease):  # type: ignore[arg-type]
        time.sleep(0.4)
        renewed = len(renewals)
        time.sleep(0.2)
        assert len(renewals) == renewed  # stopped: the lease runs out and the reaper takes the job over
        with pytest.raises(LeaseLost):
            raise_if_lease_lost()
    assert [line["record_id"] for line in logs if line["event"] == LogEvent.JOB_STALLED] == ["stalled"]


def test_a_check_in_one_of_the_jobs_pool_threads_counts_as_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    """A job waiting on its pool threads checks nothing itself; their AI calls are its progress."""
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.02)
    monkeypatch.setattr(Lease, "STALL_SECONDS", 0.15, raising=False)
    lease = SimpleNamespace(record_id="parallel", renew=lambda: True)

    def pool_thread_calls_the_ai() -> None:
        for _ in range(25):
            raise_if_lease_lost()
            time.sleep(0.02)

    with keep_lease_alive(lease):  # type: ignore[arg-type]
        thread = threading.Thread(target=contextvars.copy_context().run, args=(pool_thread_calls_the_ai,))
        thread.start()
        thread.join()
        raise_if_lease_lost()  # 0.5 s with no check of its own, more than the stall cap: still its job


def test_a_job_thread_running_long_after_losing_its_lease_restarts_its_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fresh_hung_mark: threading.Event
) -> None:
    """Python cannot kill a thread: one that ignores its lost lease held its worker slot until the pod
    restarted for some other reason. Now the liveness file stops being touched, so the probe restarts it."""
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.01)
    monkeypatch.setattr(Lease, "HUNG_AFTER_SECONDS", 0.05, raising=False)
    monkeypatch.setattr(Worker, "HEARTBEAT_SECONDS", 0.01)
    alive_file = tmp_path / "alive"
    monkeypatch.setattr(Worker, "LIVENESS_FILE", str(alive_file))
    monkeypatch.setattr(heartbeat.WorkerHeartbeat, "beat", lambda _self: None)
    with capture_logs() as logs:
        with keep_lease_alive(SimpleNamespace(record_id="hung-job", renew=lambda: False)):  # type: ignore[arg-type]
            time.sleep(0.3)  # never checks its signal, as a thread stuck in a call with no timeout
        beating = heartbeat.WorkerHeartbeat([Queue.THREATS], "celery@hung-test")
        beating.start()
        time.sleep(0.1)
        beating.stop()
    assert not alive_file.exists()  # the probe sees the file age and restarts the container
    hung = [line for line in logs if line["event"] == LogEvent.WORKER_JOB_HUNG]
    assert [(line["record_id"], line["log_level"]) for line in hung] == [("hung-job", "error")]


def test_a_job_that_stops_at_its_lost_lease_leaves_its_worker_alive(
    monkeypatch: pytest.MonkeyPatch, fresh_hung_mark: threading.Event
) -> None:
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.01)
    monkeypatch.setattr(Lease, "HUNG_AFTER_SECONDS", 0.05, raising=False)
    lease = SimpleNamespace(record_id="cancelled", renew=lambda: False)
    with keep_lease_alive(lease), pytest.raises(LeaseLost):  # type: ignore[arg-type]
        for _ in range(500):
            raise_if_lease_lost()
            time.sleep(0.01)
    time.sleep(0.1)
    assert not fresh_hung_mark.is_set()


def test_a_stopping_worker_gives_its_running_job_back_without_using_an_attempt(
    monkeypatch: pytest.MonkeyPatch, published: list[str]
) -> None:
    """A deploy stopped a worker mid-job: the job waited for its lease to run out, then the reaper re-ran it
    with one of its 5 attempts used, as if the worker had crashed."""
    record_id = _insert_job()
    sends: list[tuple[tuple, dict, str | None]] = []
    fake_send = lambda *args, **options: sends.append((args, options, current_request_id())) or True  # noqa: E731
    monkeypatch.setattr(lease_renewal, "send_job", fake_send, raising=False)
    task = SimpleNamespace(name=TaskName.FIND_THREATS, request=SimpleNamespace(id="stopping"))

    def work_while_the_worker_stops(lease: JobLease) -> None:
        assert lease.attempts == 1
        stopping = threading.Thread(target=lease_renewal.hand_back_running_jobs)  # as the shutdown thread
        stopping.start()
        stopping.join(5)
        lease.update_job({"plan": "late"})  # the old delivery's next write

    with structlog.contextvars.bound_contextvars(request_id="req-stop"), pytest.raises(Ignore):
        jobs.run_leased_job(task, Collection.SESSIONS, record_id, 1, work_while_the_worker_stops)
    job = _records().find_one({"_id": record_id})
    assert job["status"] == Status.QUEUED and "plan" not in job
    fields = ("attempts", "task_id", "worker", "lease_until")
    assert [job["job"][field] for field in fields] == [0, None, None, None]
    sent_again = ((TaskName.FIND_THREATS, record_id, 1), {"priority": Worker.NEXT_STAGE_PRIORITY})
    assert sends == [(*sent_again, "req-stop")]  # under the job's own request id
    taken = _claim(record_id, "twin")
    assert taken is not None and taken.attempts == 1  # the same attempt again, not the next one
    lease_renewal.hand_back_running_jobs()  # the job ended: nothing is held, nothing sent
    assert len(sends) == 1


def test_a_stalled_job_is_not_handed_back_with_its_attempt_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A job that hangs on every try must still run out of attempts, even when each hang restarts its pod."""
    record_id = _insert_job()
    lease = _claim(record_id, "stalled")
    assert lease is not None
    sends: list[tuple] = []
    monkeypatch.setattr(lease_renewal, "send_job", lambda *args, **_options: sends.append(args) or True)
    with (
        lease_lost_signal(record_id) as lost,
        lease_renewal.handed_back_at_shutdown(TaskName.FIND_THREATS, lease),
    ):
        lost.set()  # its renewer gave up: no lease check for Lease.STALL_SECONDS
        lease_renewal.hand_back_running_jobs()
    job = _records().find_one({"_id": record_id})
    assert (job["status"], job["job"]["attempts"], sends) == (Status.RUNNING, 1, [])  # the reaper takes it


def test_a_worker_told_to_stop_hands_its_jobs_back_before_its_pod_is_killed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[tuple] = []
    monkeypatch.setattr(lifecycle, "start_thread_without_lease", lambda *args: started.append(args))
    signals.worker_shutting_down.send(sender="celery@w", sig="SIGTERM", how="Warm", exitcode=0)
    assert started == [("hand-back", lease_renewal.hand_back_running_jobs, Worker.HAND_BACK_AFTER_SECONDS)]
    for deployment in _all_deployments():
        spec = deployment["spec"]["template"]["spec"]
        command = spec["containers"][0].get("command") or []
        queues = set(command[command.index("-Q") + 1].split(",")) if "-Q" in command else set()
        if queues & LEASED_QUEUES:  # handed back with time left to write and send before the kill
            assert spec["terminationGracePeriodSeconds"] >= Worker.HAND_BACK_AFTER_SECONDS + 20, deployment


def test_a_job_waiting_too_long_for_another_job_is_failed(published: list[str]) -> None:
    """A plan waiting for a scenario's controls that never got mapped was re-sent every 15 s for ever."""
    since = datetime.now(UTC) - timedelta(seconds=Lease.MAX_WAIT_SECONDS + 60)
    record_id = _insert_job(waiting_since=since)
    resent: list[dict[str, Any]] = []
    with pytest.raises(JobFailed) as failed:
        jobs.run_leased_job(_waiting_task(resent), Collection.SESSIONS, record_id, 1, _controls_being_mapped)
    record = _records().find_one({"_id": record_id})
    assert record["status"] == Status.FAILED and resent == []
    assert record["job"]["error"]["code"] == failed.value.code == ErrorCode.JOB_ABANDONED
    assert str(Lease.MAX_WAIT_SECONDS // 60 + 1) in record["job"]["error"]["message"]
    assert published == [record_id, record_id]  # running, then failed


def test_a_waiting_job_keeps_the_time_it_started_waiting_until_its_next_stage(
    monkeypatch: pytest.MonkeyPatch, published: list[str]
) -> None:
    record_id = _insert_job()
    resent: list[dict[str, Any]] = []
    with pytest.raises(jobs.JobWaiting):
        jobs.run_leased_job(_waiting_task(resent), Collection.SESSIONS, record_id, 1, _controls_being_mapped)
    first = _records().find_one({"_id": record_id})["job"]["waiting_since"]
    assert first is not None
    _records().update_one({"_id": record_id}, {"$set": {"job.due_at": datetime.now(UTC)}})  # looks again
    with pytest.raises(jobs.JobWaiting):
        jobs.run_leased_job(_waiting_task(resent), Collection.SESSIONS, record_id, 1, _controls_being_mapped)
    assert _records().find_one({"_id": record_id})["job"]["waiting_since"] == first
    _records().update_one({"_id": record_id}, {"$set": {"job.due_at": datetime.now(UTC)}})
    lease = _claim(record_id, "next-stage")
    assert lease is not None
    monkeypatch.setattr(jobs, "send_job", lambda *_args, **_options: True)
    jobs.hand_over(lease, TaskName.WRITE_SCENARIOS)
    assert _records().find_one({"_id": record_id})["job"]["waiting_since"] is None  # the next stage's clock


def test_a_job_waiting_on_the_shared_library_build_sees_its_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    """The job that started the first library build ran it in its own thread, and every other job waited on
    it with no lease check: a cancelled job sat there until the build ended."""
    monkeypatch.setattr(AiLimits, "LEASE_CHECK_SECONDS", 0.02)
    library = object()
    released = threading.Event()

    def build(built: object) -> Any:
        assert released.wait(5)
        return SimpleNamespace(library=built)

    keeper = _SnapshotKeeper(SimpleNamespace(get_loaded_libraries=lambda: library), build)  # type: ignore[arg-type]
    release_later = threading.Timer(1.5, released.set)
    release_later.start()
    try:
        with lease_lost_signal("cancelled-run") as lost:
            lost.set()
            asked = time.monotonic()
            with pytest.raises(LeaseLost):
                keeper.get(wait=False)
            assert time.monotonic() - asked < 1.0  # not after the build
    finally:
        release_later.join()
    assert keeper.get(wait=False).library is library  # the build went on for every other caller
