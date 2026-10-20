"""Leased background jobs: one owner per job at a time, and retries after outages (the reaper that repairs
abandoned jobs is app/worker/reaper.py).

A job lives on its MongoDB record (`status`, `job.*`; read and written by
app/data_access/jobs/job_repository.py). A delivery claims it with a time-limited lease, renews the lease
while it works, and writes only while it still owns it. If the worker dies, the lease runs out and the
reaper hands the job to another delivery."""

import contextlib
import threading
import time
from collections.abc import Callable, Generator, Iterable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn, Protocol

import structlog
from celery import Task
from celery.exceptions import Ignore

from app.ai.common import outage_reason
from app.core.constants import (
    AiOutage,
    Collection,
    ErrorCode,
    ErrorMessage,
    Lease,
    LogEvent,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import (
    MONGO_UNAVAILABLE_ERRORS,
    TEMPORARY_ERRORS,
    AppError,
    JobFailed,
    LeaseLost,
    WaitingForAnotherJob,
)
from app.core.lease_signal import lease_lost_signal
from app.data_access.jobs.job_repository import JobLease, JobRepository, failed_job_fields
from app.realtime.publisher import publish_mapping_status, publish_remediation_status, publish_session_status
from app.worker.celery_app import send_job

log = structlog.get_logger(__name__)


#: Every collection whose records carry a leased job, and how a change to one of them is announced.
JOB_COLLECTIONS: dict[Collection, Callable[[str], None]] = {
    Collection.SERVICE_MAPPINGS: publish_mapping_status,
    Collection.SESSIONS: publish_session_status,
    Collection.REMEDIATIONS: publish_remediation_status,
}


def hand_over(lease: JobLease, next_task: TaskName, changes: dict[str, Any] | None = None) -> None:
    """End this stage and queue the next one on the same record (same epoch), then send it."""
    lease.update_job(
        {
            **(changes or {}),
            "status": Status.QUEUED,
            "job.task": next_task,
            "job.due_at": datetime.now(UTC),
            "job.attempts": 0,
            "job.lease_until": None,
            "job.retry": None,
        }
    )
    send_job(next_task, lease.record_id, lease.epoch)


class RenewableLease(Protocol):
    """A lease keep_lease_alive renews: a run's job lease, or one scenario's control lease."""

    record_id: str

    def renew(self) -> bool: ...


@contextmanager
def keep_lease_alive(lease: RenewableLease) -> Generator[None, None, None]:
    """Renew the lease every Lease.RENEW_EVERY_SECONDS while the work runs, from a background thread, for at
    most Lease.MAX_JOB_SECONDS: a hung job then loses its lease to the reaper, which counts the attempt. A
    renewal that finds the lease lost (a cancel), or the time limit, sets the job's signal: its next AI call
    raises LeaseLost (core/lease_signal.py), as its next fenced write does."""
    stopped = threading.Event()
    deadline = time.monotonic() + Lease.MAX_JOB_SECONDS

    def renew_until_stopped(lost: threading.Event) -> None:
        while not stopped.wait(Lease.RENEW_EVERY_SECONDS):
            if time.monotonic() >= deadline:
                log.warning(LogEvent.JOB_TOO_LONG, record_id=lease.record_id, seconds=Lease.MAX_JOB_SECONDS)
                lost.set()  # no more AI calls; its writes fail (LeaseLost) once the reaper takes the job over
                return
            try:
                if not lease.renew():
                    lost.set()  # no more AI calls; the work's next fenced write raises LeaseLost too
                    return
            except Exception:  # noqa: BLE001 — a store blip must not end renewing; the next round retries
                log.warning(LogEvent.JOB_LEASE_RENEW_FAILED, record_id=lease.record_id, exc_info=True)

    with lease_lost_signal(lease.record_id) as lost:
        renewer = threading.Thread(
            target=renew_until_stopped, args=(lost,), name=f"lease-{lease.record_id}", daemon=True
        )
        renewer.start()
        try:
            yield
        finally:
            stopped.set()
            renewer.join()


def describe_outage(error: Exception) -> str:
    if isinstance(error, AppError):
        return error.detail
    if isinstance(error, MONGO_UNAVAILABLE_ERRORS):
        return ErrorMessage.MONGO_UNREACHABLE
    return ErrorMessage.REDIS_UNREACHABLE


def outage_error(exc: Exception) -> dict[str, str]:
    """An outage as a stored error: unavailable, its message, and which AI outage it was when the AI's."""
    error = {"code": ErrorCode.UNAVAILABLE, "message": describe_outage(exc)}
    if reason := outage_reason(exc):
        error["reason"] = reason
    return error


def job_error_of(exc: Exception) -> dict[str, str]:
    """The failure as an admin job record shows it: an app error's or a job failure's own code and message,
    else only the exception's type (its text may carry a provider's or a driver's details)."""
    if isinstance(exc, AppError):
        reason = outage_reason(exc)
        return {"code": exc.code, "message": exc.detail} | ({"reason": reason} if reason else {})
    if isinstance(exc, JobFailed):
        return {"code": exc.code, "message": exc.message}
    return {"code": ErrorCode.INTERNAL_ERROR, "message": type(exc).__name__}


def _fail_if_still_owned(
    lease: JobLease, code: ErrorCode, message: str, reason: AiOutage | None = None
) -> bool:
    """False when the job is no longer this delivery's (nothing written). Best effort: if MongoDB is down too,
    the record stays running and the reaper settles it later (True: still this delivery's as far as known)."""
    error = {"code": code, "message": message} | ({"reason": reason} if reason else {})
    try:
        lease.update_job(failed_job_fields(lease.collection, error))
    except LeaseLost:
        return False
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.JOB_FAILED, record_id=lease.record_id, settled_by="reaper", exc_info=True)
    return True


def run_leased_job(
    task: Task,
    collection: Collection,
    record_id: str,
    epoch: int,
    work: Callable[[JobLease], None],
    fields: Iterable[str] = (),
) -> None:
    """The life of one delivery: claim the record → do the work under a live lease → on a temporary outage
    give the job back and retry after Lease.RETRY_DELAYS_SECONDS, up to Lease.MAX_ATTEMPTS → otherwise mark it
    failed with a clear error. The lease carries the record's `fields` the work reads. Every status change is
    announced to the record's subscribers."""
    publish = JOB_COLLECTIONS[collection]
    lease = _claim_or_ignore(task, collection, record_id, epoch, fields)
    structlog.contextvars.bind_contextvars(record_id=record_id, attempt=lease.attempts)
    publish(record_id)
    try:
        with keep_lease_alive(lease):
            work(lease)
    except LeaseLost:
        _end_lost_delivery(collection, record_id)
    except TEMPORARY_ERRORS as exc:
        if not _retry_or_fail(task, lease, exc, publish):
            _end_lost_delivery(collection, record_id)
        raise
    except JobFailed as failure:  # the job's own final error: failed with its code, never retried
        _fail_or_end(lease, collection, failure.code, failure.message)
        log.warning(LogEvent.JOB_FAILED, record_id=record_id, code=failure.code)
        publish(record_id)
        raise
    except Exception:
        log.exception(LogEvent.JOB_FAILED, record_id=record_id)
        message = ErrorMessage.JOB_UNEXPECTED.format(record_id=record_id)
        _fail_or_end(lease, collection, ErrorCode.INTERNAL_ERROR, message)
        publish(record_id)
        raise
    publish(record_id)


def _fail_or_end(lease: JobLease, collection: Collection, code: ErrorCode, message: str) -> None:
    """The job failed with `code` while it is still this delivery's; else this delivery just ends."""
    if not _fail_if_still_owned(lease, code, message):
        _end_lost_delivery(collection, lease.record_id)


def _end_lost_delivery(collection: Collection, record_id: str) -> NoReturn:
    """This delivery no longer owns its job: its owner cancelled or deleted it (G214, a normal end: info), or
    another delivery took it over (a warning: it stalled). Ignore: a delivery's end is not the job's outcome,
    so it counts as neither a success nor a failure (lifecycle.py counts jobs)."""
    try:
        status = JobRepository(get_mongodb()[collection]).get_job_status(record_id)
    except MONGO_UNAVAILABLE_ERRORS:
        status = Status.RUNNING  # unknown: reported as a lost lease
    if status is None or status == Status.CANCELLED:
        log.info(LogEvent.JOB_STOPPED_BY_OWNER, record_id=record_id, status=status or "deleted")
    else:
        log.warning(LogEvent.JOB_LEASE_LOST, record_id=record_id)
    raise Ignore


def _claim_or_ignore(
    task: Task, collection: Collection, record_id: str, epoch: int, fields: Iterable[str]
) -> JobLease:
    """This delivery's lease on the job. A MongoDB outage retries the delivery; a job another delivery owns
    (or finished) raises Ignore."""
    try:
        jobs = JobRepository(get_mongodb()[collection])
        lease = jobs.claim_job(record_id, epoch, task.name, task.request.id, fields)
    except MONGO_UNAVAILABLE_ERRORS as exc:
        # Nothing is owned yet, so nothing to give back: the same message simply comes again after the first
        # back-off instead of waiting for the reaper.
        raise _retry_later(task, exc, Lease.RETRY_DELAYS_SECONDS[0]) from exc
    if lease is None:
        log.info(LogEvent.JOB_NOT_CLAIMED, record_id=record_id, epoch=epoch)
        # This delivery did nothing. Ignore acknowledges the message and keeps it out of the job outcomes,
        # which count jobs, not deliveries (app/worker/lifecycle.py).
        raise Ignore
    return lease


def _retry_or_fail(task: Task, lease: JobLease, exc: Exception, publish: Callable[[str], None]) -> bool:
    """A store or AI outage: give the job back and retry after the next back-off delay, or, on the last
    attempt, fail it with the outage message. Raises Celery's Retry; returns True after failing the job, False
    when it is no longer this delivery's (cancelled meanwhile: nothing to retry or fail)."""
    # ponytail: a wait uses no attempt and the longest back-off (about one control lease), whoever waits
    waiting, backoff = isinstance(exc, WaitingForAnotherJob), Lease.RETRY_DELAYS_SECONDS
    if waiting or lease.attempts < Lease.MAX_ATTEMPTS:
        delay = backoff[-1] if waiting else backoff[min(lease.attempts, len(backoff)) - 1]
        # If MongoDB is down too, giving it back fails and the record stays running with a live lease: the
        # retry finds it still owned and exits, and the reaper re-queues it once the lease runs out.
        given_back = True
        with contextlib.suppress(*MONGO_UNAVAILABLE_ERRORS):
            due_at = datetime.now(UTC) + timedelta(seconds=delay)
            try:
                lease.update_job(
                    {
                        "status": Status.QUEUED,
                        "job.due_at": due_at,
                        "job.lease_until": None,
                        "job.retry": _retry_notice(lease, exc, due_at),
                    }
                    | ({"job.attempts": lease.attempts - 1} if waiting else {})
                )
            except LeaseLost:
                given_back = False
        if not given_back:
            return False
        log.warning(
            LogEvent.JOB_RETRY_SCHEDULED,
            record_id=lease.record_id,
            delay_seconds=delay,
            error=str(exc),
            reason=outage_reason(exc),
        )
        publish(lease.record_id)
        raise _retry_later(task, exc, delay) from exc
    if not _fail_if_still_owned(lease, ErrorCode.UNAVAILABLE, describe_outage(exc), outage_reason(exc)):
        return False
    publish(lease.record_id)
    return True


def _retry_notice(lease: JobLease, exc: Exception, retry_at: datetime) -> dict[str, Any]:
    """What the status shows until the stage ends (a RetryNotice but its stage): why it waits, which try comes
    when."""
    return {
        "reason": outage_reason(exc),
        "message": describe_outage(exc),
        "attempt": lease.attempts,
        "max_attempts": Lease.MAX_ATTEMPTS,
        "retry_at": retry_at,
    }


def _retry_later(task: Task, exc: Exception, delay: int) -> Exception:
    """Celery's own retry, with no limit of its own (task_annotations in app/worker/celery_app.py). Its count
    is per message and also grows with the retries of an unclaimed delivery (MongoDB down at claim), so any
    Celery limit could end an owned job early: counted as a failure while the record still waited to run. The
    real limit is Lease.MAX_ATTEMPTS, counted on the record; an unclaimed delivery waits for MongoDB, 15 s
    apart."""
    return task.retry(countdown=delay, exc=exc)
