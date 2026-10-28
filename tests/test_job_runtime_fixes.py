"""Worker runtime: liveness without Redis, redacted error text in logs, the lease renewer's context and
retries, the job's epoch on its lines, and a start-up failure that says why."""

import json
import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from pymongo.errors import AutoReconnect
from redis.exceptions import ReadOnlyError
from structlog.testing import capture_logs

from app.core.constants import Lease, LogEvent, Queue, TaskName, Worker
from app.core.exceptions import Unavailable
from app.core.logging import _json_formatter
from app.worker import heartbeat, jobs, lifecycle
from app.worker.lease_renewal import keep_lease_alive


class RetryRequested(Exception):
    """What the fake task's retry returns, carrying its countdown."""

    def __init__(self, countdown: int) -> None:
        super().__init__(countdown)
        self.countdown = countdown


def test_the_liveness_file_is_touched_even_when_redis_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The pod's liveness probe reads the file's age: a Redis outage must not make a live worker look dead."""
    alive_file = tmp_path / "alive"
    monkeypatch.setattr(Worker, "LIVENESS_FILE", str(alive_file))

    def failing_beat(_self: object) -> None:
        raise ReadOnlyError("You can't write against a read only replica.")

    monkeypatch.setattr(heartbeat.WorkerHeartbeat, "beat", failing_beat)
    beating = heartbeat.WorkerHeartbeat([Queue.THREATS], "celery@liveness-test")
    with capture_logs() as logs:
        beating.start()
        try:
            for _ in range(500):
                if alive_file.exists() and logs:
                    break
                threading.Event().wait(0.01)
        finally:
            beating.stop()
    assert alive_file.exists() and logs[0]["event"] == LogEvent.WORKER_HEARTBEAT_FAILED


def test_a_secret_in_an_exception_message_is_redacted_but_other_fields_are_not() -> None:
    formatter = _json_formatter()
    try:
        raise ValueError("connect failed: password=hunter2-fake")
    except ValueError:
        record = logging.LogRecord(
            "celery.app.trace", logging.ERROR, __file__, 1, "boom", None, sys.exc_info()
        )
    line = json.loads(formatter.format(record))
    assert "hunter2-fake" not in line["exception"] and "[REDACTED]" in line["exception"]
    fields = {"event": "x", "error": "token=abc123secret", "worker": "celery@node.local"}
    ours = logging.makeLogRecord({"msg": fields, "_logger": None, "_name": "error"})  # as structlog sends it
    line = json.loads(formatter.format(ours))
    assert line["error"] == "[REDACTED]" and line["worker"] == "celery@node.local"


def test_the_lease_renewer_logs_with_the_jobs_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.01)
    seen: dict[str, Any] = {}
    renewed = threading.Event()

    def renew() -> bool:
        seen.update(structlog.contextvars.get_contextvars())
        renewed.set()
        return True

    lease = SimpleNamespace(record_id="r", renew=renew)
    with (
        structlog.contextvars.bound_contextvars(task="t", module="m", request_id="req-1"),
        keep_lease_alive(lease),  # type: ignore[arg-type]
    ):
        assert renewed.wait(5)
    assert {key: seen.get(key) for key in ("task", "module", "request_id")} == {
        "task": "t",
        "module": "m",
        "request_id": "req-1",
    }


def test_the_lease_renewer_keeps_renewing_after_a_mongo_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.01)
    calls: list[int] = []
    renewed_again = threading.Event()

    def renew() -> bool:
        calls.append(1)
        if len(calls) == 1:
            raise AutoReconnect("primary stepped down")
        renewed_again.set()
        return True

    with keep_lease_alive(SimpleNamespace(record_id="r", renew=renew)):  # type: ignore[arg-type]
        assert renewed_again.wait(5)


@pytest.mark.parametrize("attempt", [1, 2, 3, 4])
def test_the_retry_delay_follows_the_back_off_by_attempt(
    monkeypatch: pytest.MonkeyPatch, attempt: int
) -> None:
    monkeypatch.setattr(jobs, "_give_back", lambda *_args: True)
    task = SimpleNamespace(retry=lambda countdown, exc, **_options: RetryRequested(countdown))
    lease = SimpleNamespace(attempts=attempt, record_id="r")
    with pytest.raises(RetryRequested) as retry:
        jobs._retry_or_fail(task, lease, Unavailable("down"), lambda _record_id: None)  # type: ignore[arg-type]
    assert retry.value.countdown == Lease.RETRY_DELAYS_SECONDS[attempt - 1]


def test_the_job_clock_binds_the_epoch() -> None:
    task = SimpleNamespace(name=TaskName.MAP_SERVICES, request=SimpleNamespace(hostname="w"))
    lifecycle.start_job_clock("task-epoch", task, args=("mapping-1", 3))  # type: ignore[arg-type]
    assert structlog.contextvars.get_contextvars()["epoch"] == 3


def test_a_worker_that_cannot_start_logs_why_before_it_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture_logs() as logs, pytest.raises(SystemExit):
        lifecycle.prepare_worker(SimpleNamespace(pool_cls=dict))  # an unsupported pool, no exception
    assert [(line["event"], line["log_level"], line["exc_info"]) for line in logs] == [
        (LogEvent.WORKER_START_FAILED, "error", False)
    ]
    assert "--pool=threads" in logs[0]["message"] and "reason" not in logs[0]  # free text, not a reason code

    def bad_log_dir(*_args: object) -> None:
        raise OSError("no such directory")

    monkeypatch.setattr(lifecycle, "configure_logging", bad_log_dir)
    with capture_logs() as logs, pytest.raises(SystemExit):
        lifecycle.prepare_beat()
    assert [(line["event"], line["exc_info"]) for line in logs] == [(LogEvent.WORKER_START_FAILED, True)]
