"""The reaper: a refused send never counts toward "never started", its lines carry the dead job's own
delivery, a lost worker is a warning, beat gives its passes room, and its send lets a new delivery run it."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from structlog.testing import capture_logs

from app.core.constants import Collection, Lease, LogEvent, Status, TaskName, Worker
from app.core.database import get_mongodb
from app.data_access.jobs.job_repository import JobLease
from app.worker import jobs, reaper
from app.worker.celery_app import REQUEST_ID_HEADER, BrokerUnavailable, celery_app


def _sessions() -> Any:
    return get_mongodb()[Collection.SESSIONS]


def _long_ago() -> datetime:
    return datetime.now(UTC) - timedelta(hours=1)


def _insert_job(status: Status, **job: Any) -> str:
    """A run record whose job is due (or whose lease ended) an hour ago."""
    record_id = uuid.uuid4().hex
    job = {
        "task": TaskName.FIND_THREATS,
        "epoch": 1,
        "attempts": 0,
        "due_at": _long_ago(),
        "resends": 0,
        **job,
    }
    _sessions().insert_one(
        {"_id": record_id, "entity_id": 86, "status": status, "updated_at": _long_ago(), "job": job}
    )
    return record_id


@pytest.fixture(autouse=True)
def only_these_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every job collection empty (the reaper scans them all), no announcement sent, every queue empty."""
    for collection in jobs.JOB_COLLECTIONS:
        get_mongodb()[collection].delete_many({})
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _record_id: None)
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Every message the broker takes, with its task name."""
    messages: list[dict[str, Any]] = []
    monkeypatch.setattr(
        celery_app, "send_task", lambda name, **message: messages.append({"name": name, **message})
    )
    return messages


def test_a_send_the_broker_refuses_never_counts_toward_never_started(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: the re-send was counted before it was sent, so while the broker was down a healthy queued job
    was failed as never started after Lease.MAX_ATTEMPTS passes."""
    waiting = _insert_job(Status.QUEUED)

    def refused(*_args: Any, **_message: Any) -> None:
        raise BrokerUnavailable("down")

    monkeypatch.setattr(celery_app, "send_task", refused)
    for _ in range(Lease.MAX_ATTEMPTS + 1):
        reaper.reap_jobs()
        _sessions().update_one({"_id": waiting}, {"$set": {"job.due_at": _long_ago()}})
    record = _sessions().find_one({"_id": waiting})
    assert (record["status"], record["job"]["resends"]) == (Status.QUEUED, 0)
    taken: list[str] = []
    monkeypatch.setattr(celery_app, "send_task", lambda name, **_message: taken.append(name))
    reaper.reap_jobs()
    record = _sessions().find_one({"_id": waiting})
    assert taken == [TaskName.FIND_THREATS] and record["job"]["resends"] == 1  # a send the broker took counts
    assert record["updated_at"] > datetime.now(UTC) - timedelta(minutes=1)  # the re-send write moves it


def test_beat_gives_the_reaper_and_the_controls_sweep_three_intervals_before_a_pass_expires() -> None:
    """Before: a pass expired after one interval, so a worker clock ahead of beat's dropped each one."""
    schedule = celery_app.conf.beat_schedule
    for task in (TaskName.REAP, TaskName.RETRY_CONTROLS):
        assert schedule[task]["options"]["expires"] == 3 * schedule[task]["schedule"]


def test_the_reapers_lines_carry_the_dead_jobs_own_delivery_and_a_lost_worker_is_a_warning(
    sent: list[dict[str, Any]],
) -> None:
    """Before: a requeue line carried the reaper's own task id and worker, named the count `attempts`, and a
    dead worker's requeue was only info."""
    dead = _insert_job(
        Status.RUNNING,
        attempts=1,
        epoch=3,
        lease_until=_long_ago(),
        task_id="dead-delivery",
        worker="worker@pod-1",
        request_id="request-1",
    )
    never_claimed = _insert_job(Status.QUEUED)
    reapers_own = {"task_id": "reaper-delivery", "worker": "beat@pod-2"}
    with (
        structlog.contextvars.bound_contextvars(**reapers_own),
        capture_logs(processors=[structlog.contextvars.merge_contextvars]) as logs,
    ):
        reaper.reap_jobs()
    requeued = {line["record_id"]: line for line in logs if line["event"] == LogEvent.JOB_REQUEUED}
    fields = ("task_id", "worker", "epoch", "request_id", "attempt", "log_level")
    assert {field: requeued[dead].get(field) for field in fields} == {
        "task_id": "dead-delivery",
        "worker": "worker@pod-1",
        "epoch": 3,
        "request_id": "request-1",
        "attempt": 1,
        "log_level": "warning",
    }
    assert "attempts" not in requeued[dead]
    assert (requeued[never_claimed]["task_id"], requeued[never_claimed]["worker"]) == (None, None)
    assert len(sent) == 2


def test_the_reapers_send_lets_a_new_delivery_take_over_a_dead_workers_job(
    sent: list[dict[str, Any]],
) -> None:
    """The reaper's own message (task, record, epoch, priority and the job's API request id) is what a new
    delivery claims and runs."""
    dead = _insert_job(
        Status.RUNNING,
        attempts=1,
        epoch=3,
        lease_until=_long_ago(),
        task_id="dead-delivery",
        request_id="req-77",
    )
    reaper.reap_jobs()
    [message] = sent
    record_id, epoch = message["args"]
    assert (message["name"], record_id, epoch) == (TaskName.FIND_THREATS, dead, 3)
    assert message["priority"] == Worker.NEXT_STAGE_PRIORITY
    assert message["headers"] == {REQUEST_ID_HEADER: "req-77"}  # the new delivery's job.started names it
    delivery = SimpleNamespace(name=message["name"], request=SimpleNamespace(id="new-delivery", retries=0))
    ran: list[JobLease] = []
    jobs.run_leased_job(delivery, Collection.SESSIONS, record_id, epoch, ran.append)  # type: ignore[arg-type]
    record = _sessions().find_one({"_id": dead})
    assert [lease.attempts for lease in ran] == [2]
    assert (record["status"], record["job"]["task_id"]) == (Status.RUNNING, "new-delivery")
