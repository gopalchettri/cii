"""One clock for every pod (app/core/clock.py): UAT, 2026-10-24, the pods' clocks disagreed by up to 76 s and
every run failed "The job was sent 5 times and never started". Each test makes this process a pod whose own
clock is behind MongoDB's, as the threats worker's was, and checks that it still agrees with pods whose clocks
are right (the test's own datetime.now / time.time)."""

import math
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pymongo.errors import AutoReconnect
from structlog.testing import capture_logs

from app.core import clock, metrics
from app.core.constants import Clock, Collection, LogEvent, Queue, Status, TaskName, Worker
from app.core.database import get_mongodb, get_redis_client
from app.data_access.jobs.job_repository import JobRepository
from app.worker import heartbeat


def _pod_behind(monkeypatch: pytest.MonkeyPatch, seconds: float, *, corrected: bool) -> None:
    """This process as a pod whose own clock is `seconds` behind MongoDB's. corrected: it measures its offset
    against MongoDB (the fix); else it trusts its own clock, as every pod did before."""
    real = clock._local_epoch
    monkeypatch.setattr(clock, "_local_epoch", lambda: real() - seconds)
    pod = clock.StoreClock()
    if not corrected:
        pod._next_check = math.inf  # never asks MongoDB
    monkeypatch.setattr(clock, "_clock", pod)


def _jobs() -> JobRepository:
    return JobRepository(get_mongodb()[Collection.SESSIONS])


def _queued_now(due_ago_seconds: float = 0) -> str:
    """A job queued by a pod whose clock is right (the API, or the reaper re-sending it), due that long
    ago."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    due_at = now - timedelta(seconds=due_ago_seconds)
    job = {"task": TaskName.FIND_THREATS, "epoch": 1, "attempts": 0, "due_at": due_at}
    get_mongodb()[Collection.SESSIONS].insert_one(
        {
            "_id": record_id,
            "entity_id": 86,
            "asset_id": 103,
            "status": Status.QUEUED,
            "updated_at": now,
            "job": job,
        }
    )
    return record_id


def test_a_worker_76_s_behind_takes_a_job_another_pod_queued_now(monkeypatch: pytest.MonkeyPatch) -> None:
    """The UAT failure itself: on its own clock the worker saw the job due 76 s ahead and dropped it, at every
    re-send. On MongoDB's clock the job is due at once."""
    record_id = _queued_now()
    _pod_behind(monkeypatch, 76, corrected=False)
    assert _jobs().claim_job(record_id, 1, TaskName.FIND_THREATS, "before") is None
    why = _jobs().why_not_claimed(record_id, 1, TaskName.FIND_THREATS)
    assert why["reason"] == "not_due" and 70 < why["due_in_seconds"] < 80
    _pod_behind(monkeypatch, 76, corrected=True)
    assert _jobs().claim_job(record_id, 1, TaskName.FIND_THREATS, "after") is not None


def test_the_reaper_never_takes_a_running_job_from_a_worker_whose_clock_is_behind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lease is written by the worker and read by the reaper on another pod. On a clock 100 s behind, a
    fresh 120 s lease looked to the reaper like 20 s, so its next pass would take a job that was still
    running."""
    next_reaper_pass = datetime.now(UTC) + timedelta(seconds=30)
    for corrected, taken in ((False, True), (True, False)):
        record_id = _queued_now(due_ago_seconds=300)  # long due: even the worker's own clock lets it claim
        _pod_behind(monkeypatch, 100, corrected=corrected)
        assert _jobs().claim_job(record_id, 1, TaskName.FIND_THREATS, f"worker-{corrected}") is not None
        expired = {record["_id"] for record in _jobs().list_expired_jobs(next_reaper_pass)}
        assert (record_id in expired) is taken, corrected


def test_a_worker_70_s_behind_still_counts_as_online(monkeypatch: pytest.MonkeyPatch) -> None:
    """The /ready heartbeat: a worker stamps its time, an API pod counts stamps of the last 60 s by its own
    clock. A worker 70 s behind looked silent, so its queue had no worker."""
    key = Worker.HEARTBEAT_KEY.format(queue=Queue.THREATS)
    for corrected, counted in ((False, False), (True, True)):
        name = f"celery@behind-{uuid.uuid4().hex}"
        _pod_behind(monkeypatch, 70, corrected=corrected)
        worker = heartbeat.WorkerHeartbeat([Queue.THREATS], name)
        worker.beat()
        try:
            stamp = get_redis_client().zscore(key, name)
            assert (stamp >= time.time() - Worker.ONLINE_WITHIN_SECONDS) is counted, corrected
        finally:
            worker.stop()


class _MongoClock:
    """MongoDB answering `hello` with its time, or failing."""

    def __init__(self, server_epoch: float) -> None:
        self.server_epoch: float | None = server_epoch

    def command(self, name: str) -> dict[str, Any]:
        assert name == "hello"
        if self.server_epoch is None:
            raise AutoReconnect("MongoDB is down")
        return {"localTime": datetime.fromtimestamp(self.server_epoch, UTC)}


def test_the_offset_is_mongodbs_clock_minus_the_pods_with_half_the_round_trip_each_way(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = iter([1_000.0, 1_000.02, 1_000.5, 2_000.0, 2_000.0, 2_000.0, 3_000.0, 3_000.0])
    monkeypatch.setattr(clock, "_local_epoch", lambda: next(local))
    mongo = _MongoClock(1_076.01)  # read halfway through a 20 ms round trip: MongoDB is 76 s ahead
    monkeypatch.setattr(clock, "get_mongodb", lambda: mongo)
    pod = clock.StoreClock()
    with capture_logs() as logs:
        assert pod.epoch_seconds() == pytest.approx(1_076.5, abs=1e-6)
        assert Clock.CHECK_EVERY_SECONDS - 1 < pod._next_check - time.monotonic() <= Clock.CHECK_EVERY_SECONDS
        assert metrics.CLOCK_OFFSET._value.get() == pytest.approx(76.0, abs=1e-6)
        pod._next_check = 0.0  # a minute later: measured again, still off, not logged again
        mongo.server_epoch = 2_080.0
        assert pod.epoch_seconds() == pytest.approx(2_080.0)
        pod._next_check = 0.0  # MongoDB down: the last offset stands
        mongo.server_epoch = None
        assert pod.epoch_seconds() == pytest.approx(3_080.0)
    assert [line["offset_seconds"] for line in logs if line["event"] == LogEvent.CLOCK_OFF] == [76.0]


def test_utc_now_is_the_same_instant_as_epoch_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    pod = clock.StoreClock()
    pod._offset, pod._next_check = 76.0, math.inf
    monkeypatch.setattr(clock, "_clock", pod)
    assert abs(clock.utc_now().timestamp() - clock.epoch_seconds()) < 0.01
    assert abs(clock.epoch_seconds() - time.time() - 76.0) < 0.01
