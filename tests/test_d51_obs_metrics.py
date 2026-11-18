"""Job metrics: each names its task's module, an expired timer message and a hung job are counted, and the
reaper's clocks report only what really happened (its starts apart from its finished passes)."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from celery import states
from celery.contrib.testing.mocks import TaskMessage
from celery.worker.request import Request
from celery.worker.state import revoked as revoked_tasks
from prometheus_client import REGISTRY
from pymongo.errors import AutoReconnect
from structlog.testing import capture_logs

from app.core import metrics
from app.core.constants import Collection, LogEvent, Queue, TaskName, module_of
from app.crud.jobs import JobRepository
from app.worker import celery_app, jobs, lifecycle
from tests.test_worker import _free_port, _insert_job, _records, _task, _worker_starting

JOB_METRICS = ("tsg_jobs_total", "tsg_job_seconds_count", "tsg_job_queue_wait_seconds_count")


def _sample(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _gauge_value(name: str) -> float:
    """The value of one of the reaper's gauges (exported or not), 0 when it does not exist."""
    gauge = getattr(metrics, name, None)
    return gauge.collect()[0].samples[0].value if gauge is not None else 0.0


def test_job_metrics_name_the_module_of_their_task(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: tsg_jobs_total, tsg_job_seconds and tsg_job_queue_wait_seconds named the task only, so no
    panel or alert could group jobs by product module as the log lines and admin rows do."""
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _record_id: None)
    task, module = TaskName.FIND_THREATS, "threat_scenarios"
    before = [_sample(name, task=task, module=module, **extra) for name, extra in _job_series()]
    lifecycle.start_job_clock("module-1", _task("module-1"))
    lifecycle.record_job_outcome("module-1", _task("module-1"), state=states.SUCCESS)
    late = _insert_job(due_at=datetime.now(UTC) - timedelta(seconds=30))
    jobs.run_leased_job(_task("module-2"), Collection.SESSIONS, late, 1, lambda _lease: None)
    after = [_sample(name, task=task, module=module, **extra) for name, extra in _job_series()]
    assert after == [count + 1 for count in before]
    for family in REGISTRY.collect():
        for sample in family.samples:
            if sample.name in JOB_METRICS:
                assert sample.labels.get("module") == module_of(sample.labels["task"]), sample


def _job_series() -> list[tuple[str, dict[str, str]]]:
    return [(JOB_METRICS[0], {"outcome": "success"}), (JOB_METRICS[1], {}), (JOB_METRICS[2], {})]


def _delivery(expires: datetime) -> Request:
    """A tsg_reap message as a worker receives it from beat, with its expiry."""
    task = celery_app.tasks[TaskName.REAP]
    message = TaskMessage(TaskName.REAP, expires=expires.isoformat())
    return Request(message, app=celery_app, task=task)


def test_a_timer_message_dropped_as_expired_is_counted() -> None:
    """Before: Celery dropped a beat message that reached a worker after its expiry (beat's clock behind, or
    its worker stuck) with one info line: no metric, no alert, and the reaper or sweep silently never ran."""
    expired = {"task": TaskName.REAP, "module": "maintenance", "outcome": "expired"}
    metrics.start_job_counters([TaskName.REAP])
    assert REGISTRY.get_sample_value("tsg_jobs_total", expired) is not None  # at 0 from start-up
    before = _sample("tsg_jobs_total", **expired)
    late = _delivery(datetime.now(UTC) - timedelta(seconds=5))
    with capture_logs() as logs:
        assert late.revoked()
    assert _sample("tsg_jobs_total", **expired) == before + 1
    [line] = [line for line in logs if line["event"] == LogEvent.JOB_FINISHED]
    assert (line["outcome"], line["task"], line["task_id"], line["log_level"]) == (
        "expired",
        TaskName.REAP,
        late.id,
        "warning",
    )
    on_time = _delivery(datetime.now(UTC) + timedelta(minutes=3))
    revoked_tasks.add(on_time.id)  # revoked by id, not expired: no timer message lost to a clock
    try:
        assert on_time.revoked()
    finally:
        revoked_tasks.discard(on_time.id)
        revoked_tasks.discard(late.id)
    assert _sample("tsg_jobs_total", **expired) == before + 1


def test_a_failing_reaper_pass_still_records_that_it_started(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: only a finished pass was recorded, so passes that fail (MongoDB down) or hang read as beat not
    sending the reaper, and ReaperNotRunning sent the operator to the wrong pod."""

    def mongodb_down(*_: object) -> list:
        raise AutoReconnect("MongoDB is down")

    monkeypatch.setattr(jobs, "count_waiting_messages", lambda _queue: 0)
    monkeypatch.setattr(JobRepository, "list_expired_jobs", mongodb_down)
    metrics.REAPER_LAST_PASS.set(0)
    started = time.time()
    with pytest.raises(AutoReconnect):
        jobs.reap_jobs()
    assert started <= _gauge_value("REAPER_LAST_START") <= time.time()
    assert _gauge_value("REAPER_LAST_PASS") == 0


def test_a_worker_start_reports_no_reaper_pass_it_has_not_made(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: the reaper's worker reported a pass at its start. One restarted pod (a deploy, an eviction)
    then hid a dead beat from ReaperNotRunning and the beat tile for 10 minutes, and a pod restarting more
    often kept the alert silent for ever. ReaperNotRunning and the beat tile read the start gauge."""
    metrics.REAPER_LAST_START.set(0)
    metrics.REAPER_LAST_PASS.set(0)
    monkeypatch.setattr(lifecycle.settings, "worker_metrics_port", _free_port())
    lifecycle.prepare_worker(_worker_starting("threads", Queue.MAINTENANCE))
    assert (_gauge_value("REAPER_LAST_START"), _gauge_value("REAPER_LAST_PASS")) == (0, 0)


def test_the_reaper_counts_jobs_now_and_drops_an_ended_one_to_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """tsg_jobs_current feeds the "Jobs now" panel, whose empty state says no job waits or runs: a queued and a
    retrying job are counted, and once they end their kind reads 0, never a job that is gone."""
    monkeypatch.setattr(jobs, "count_waiting_messages", lambda _queue: 1)
    kind = f"probe-{uuid.uuid4().hex}"
    _insert_job(task=kind)
    _insert_job(task=kind, retry={"message": "MongoDB is down"})
    jobs.reap_jobs()
    assert [_jobs_now(kind, status) for status in ("queued", "retrying")] == [1, 1]
    _records().delete_many({"job.task": kind})
    jobs.reap_jobs()
    assert [_jobs_now(kind, status) for status in ("queued", "retrying")] == [0, 0]


def _jobs_now(kind: str, status: str) -> float | None:
    return REGISTRY.get_sample_value("tsg_jobs_current", {"kind": kind, "status": status})
