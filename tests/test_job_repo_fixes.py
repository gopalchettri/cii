"""Leased jobs: the request id rides on the record, the reaper's indexes, an unsaved failure, the attempts
cap on a redelivery, and a queued job that names no old delivery."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from celery.exceptions import Ignore
from pymongo.errors import AutoReconnect
from structlog.testing import capture_logs

from app.core.constants import Collection, ErrorCode, ErrorMessage, Lease, LogEvent, Status, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, Unavailable
from app.data_access.jobs.job_repository import JobLease, JobRepository, new_job
from app.worker import celery_app, jobs
from app.worker.celery_app import REQUEST_ID_HEADER


class RetryRequested(Exception):
    """Stands in for Celery's Retry."""


def _records() -> Any:
    """The sessions collection, a job collection."""
    return get_mongodb()[Collection.SESSIONS]


def _insert(status: Status = Status.QUEUED, **job: Any) -> str:
    """A job record with `job` over a fresh queued job; its id."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    record = {"_id": record_id, "entity_id": 86, "asset_id": 103, "status": status, "updated_at": now}
    _records().insert_one(record | {"job": new_job(TaskName.FIND_THREATS, 1, now) | job})
    return record_id


def _task() -> Any:
    """What run_leased_job uses of a Celery task, no request id header."""
    return SimpleNamespace(
        name=TaskName.FIND_THREATS,
        request=SimpleNamespace(id="task-1"),
        retry=lambda **_options: RetryRequested(),
    )


@pytest.fixture(autouse=True)
def nothing_published(monkeypatch: pytest.MonkeyPatch) -> None:
    """Status announcements are not under test."""
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _record_id: None)


def test_a_delivery_without_header_runs_under_the_jobs_request_id_and_passes_it_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    structlog.contextvars.bind_contextvars(request_id="req-42")
    record_id = _insert()  # made inside the API request
    structlog.contextvars.clear_contextvars()  # a reaper re-send: no header
    sent_headers: list[dict[str, str]] = []
    monkeypatch.setattr(celery_app, "send_task", lambda *_a, headers, **_k: sent_headers.append(headers))
    seen: list[Any] = []

    def work(lease: JobLease) -> None:
        seen.append(structlog.contextvars.get_contextvars().get("request_id"))
        jobs.hand_over(lease, TaskName.WRITE_SCENARIOS)

    jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    assert seen == ["req-42"]
    assert sent_headers == [{REQUEST_ID_HEADER: "req-42"}]


def test_the_reapers_failed_jobs_count_has_an_index() -> None:
    JobRepository(_records()).create_indexes()
    keys = [index["key"] for index in _records().index_information().values()]
    assert [("status", 1), ("finished_at", 1)] in keys


@pytest.mark.parametrize(
    ("attempts_before", "error"),
    [(0, JobFailed(ErrorCode.INTERNAL_ERROR, "bad")), (Lease.MAX_ATTEMPTS - 1, Unavailable("down"))],
)
def test_a_failure_mongodb_could_not_save_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, attempts_before: int, error: Exception
) -> None:
    record_id = _insert(attempts=attempts_before)

    def work(lease: JobLease) -> None:
        monkeypatch.setattr(lease, "update_job", _mongo_down)
        raise error

    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    events = [line["event"] for line in logs]
    assert LogEvent.JOB_FAILED not in events
    not_saved = next(line for line in logs if line["event"] == LogEvent.JOB_FAILURE_NOT_SAVED)
    assert not_saved["code"] and not_saved["message"]
    assert _records().find_one({"_id": record_id})["status"] == Status.RUNNING


def test_mongodb_down_while_giving_a_job_back_still_retries_it(monkeypatch: pytest.MonkeyPatch) -> None:
    record_id = _insert()

    def work(lease: JobLease) -> None:
        monkeypatch.setattr(lease, "update_job", _mongo_down)
        raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    with capture_logs() as logs, pytest.raises(RetryRequested):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, work)
    assert LogEvent.JOB_FAILED not in [line["event"] for line in logs]


def test_a_redelivery_cannot_take_an_expired_job_past_its_last_attempt() -> None:
    expired = {"task_id": "old", "lease_until": datetime.now(UTC) - timedelta(minutes=1)}
    spent = _insert(Status.RUNNING, attempts=Lease.MAX_ATTEMPTS, **expired)
    left = _insert(Status.RUNNING, attempts=Lease.MAX_ATTEMPTS - 1, **expired)
    jobs_repo = JobRepository(_records())
    assert jobs_repo.claim_job(spent, 1, TaskName.FIND_THREATS, "new") is None
    assert jobs_repo.claim_job(left, 1, TaskName.FIND_THREATS, "new") is not None


def test_a_queued_job_names_no_earlier_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, "send_job", lambda *_args, **_priority: None)
    handed = _insert()
    lease = JobRepository(_records()).claim_job(handed, 1, TaskName.FIND_THREATS, "task-1", worker="w1")
    assert lease is not None
    jobs.hand_over(lease, TaskName.WRITE_SCENARIOS)
    expired = {"task_id": "t", "worker": "w", "lease_until": datetime.now(UTC) - timedelta(minutes=1)}
    requeued = _insert(Status.RUNNING, **expired)
    record = _records().find_one({"_id": requeued})
    assert JobRepository(_records()).requeue_or_fail_expired_job(record, datetime.now(UTC))
    for record_id in (handed, requeued):
        job = _records().find_one({"_id": record_id})["job"]
        assert (job["task_id"], job.get("worker")) == (None, None)


def _mongo_down(*_args: Any, **_kwargs: Any) -> None:
    """MongoDB unreachable for a write."""
    raise AutoReconnect("down")
