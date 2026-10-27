"""Leased background jobs: one owner per job at a time, and retries after outages (the reaper that repairs
abandoned jobs is app/worker/reaper.py).

A job lives on its MongoDB record (`status`, `job.*`; read and written by
app/data_access/jobs/job_repository.py). A delivery claims it with a time-limited lease, renews the lease
while it works, and writes only while it still owns it. If the worker dies, the lease runs out and the
reaper hands the job to another delivery."""

import contextlib
import math
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any, NoReturn

import structlog
from celery import Task
from celery.exceptions import Ignore

from app.ai.common import outage_reason
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    AiOutage,
    Collection,
    ErrorCode,
    ErrorMessage,
    Lease,
    LogEvent,
    Status,
    TaskName,
    Worker,
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
from app.data_access.jobs.job_repository import JobLease, JobRepository, failed_job_fields, retry_notice
from app.realtime.publisher import publish_mapping_status, publish_remediation_status, publish_session_status
from app.worker.celery_app import send_job
from app.worker.lease_renewal import keep_lease_alive

log = structlog.get_logger(__name__)


#: Every collection whose records carry a leased job, and how a change to one of them is announced.
JOB_COLLECTIONS: dict[Collection, Callable[[str], None]] = {
    Collection.SERVICE_MAPPINGS: publish_mapping_status,
    Collection.SESSIONS: publish_session_status,
    Collection.REMEDIATIONS: publish_remediation_status,
}


class JobWaiting(Ignore):
    """Ends a delivery whose job waits for another job: the job is sent again for later, and the delivery
    counts as `waiting` (lifecycle.py), never as a retry."""


def hand_over(lease: JobLease, next_task: TaskName, changes: dict[str, Any] | None = None) -> None:
    """End this stage and queue the next one on the same record (same epoch), sent ahead of new work."""
    lease.update_job(
        {
            **(changes or {}),
            "status": Status.QUEUED,
            "job.task": next_task,
            "job.task_id": None,
            "job.worker": None,
            "job.due_at": utc_now(),
            "job.attempts": 0,
            "job.lease_until": None,
            "job.retry": None,
        }
    )
    send_job(next_task, lease.record_id, lease.epoch, priority=Worker.NEXT_STAGE_PRIORITY)


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
    """False when the job is no longer this delivery's (nothing written). Else the job's one job.failed line.
    If MongoDB is down too, nothing failed: the record stays running, the reaper re-queues it once the lease
    runs out, and this delivery ends as Ignore (neither a success nor a failure)."""
    error = {"code": code, "message": message} | ({"reason": reason} if reason else {})
    try:
        lease.update_job(failed_job_fields(lease.collection, error))
    except LeaseLost:
        return False
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.JOB_FAILURE_NOT_SAVED, record_id=lease.record_id, **error, exc_info=True)
        raise Ignore from None
    log.warning(LogEvent.JOB_FAILED, record_id=lease.record_id, **error)
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
    give the job back and retry after Lease.RETRY_DELAYS_SECONDS, up to Lease.MAX_ATTEMPTS; waiting for
    another job, look again soon → otherwise mark it failed with a clear error. The lease carries the record's
    `fields` the work reads. Every status change is announced to the record's subscribers."""
    publish = JOB_COLLECTIONS[collection]
    lease = _claim_or_ignore(task, collection, record_id, epoch, fields)
    # A waiting job's look reads queued: nothing changed. ponytail: one that then runs is announced only at
    # its end; its streams see it running at their next re-read (Realtime.RECHECK_SECONDS)
    if not lease.record["job"].get("waiting"):
        publish(record_id)
    try:
        with keep_lease_alive(lease):
            work(lease)
    except LeaseLost:
        _end_lost_delivery(collection, record_id)
    except WaitingForAnotherJob as exc:
        _wait_for_other_job(task, lease, exc, collection)
    except TEMPORARY_ERRORS as exc:
        if not _retry_or_fail(task, lease, exc, publish):
            _end_lost_delivery(collection, record_id)
        raise
    except JobFailed as failure:  # the job's own final error: failed with its code, never retried
        _fail_or_end(lease, collection, failure.code, failure.message)
        publish(record_id)
        raise
    except Exception:
        log.exception(LogEvent.JOB_UNEXPECTED_ERROR, record_id=record_id)  # the bug, with its traceback
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
    """This delivery's lease on the job, its wait since due counted and its log lines bound to the job. A
    MongoDB outage retries the delivery; one that comes shortly before its job is due is sent again for then;
    a job another delivery owns (or finished) raises Ignore."""
    try:
        jobs = JobRepository(get_mongodb()[collection])
        worker, retries = getattr(task.request, "hostname", "") or "", getattr(task.request, "retries", 0)
        lease = jobs.claim_job(record_id, epoch, task.name, task.request.id, fields, worker, retries)
    except MONGO_UNAVAILABLE_ERRORS as exc:
        # The claim may be saved though its answer was lost: this retry (a higher retry count) takes its own
        # claim back after the first back-off, never waiting for the reaper (job_repository._claimable).
        raise _retry_later(task, exc, Lease.RETRY_DELAYS_SECONDS[0]) from exc
    if lease is None:
        why = jobs.why_not_claimed(record_id, epoch, task.name)  # not due, missing, another epoch...
        # A first send that comes early is a duplicate (the job's own retry comes): dropped, never re-sent.
        early = (
            why["reason"] == "not_due"
            and 0 < why["due_in_seconds"] <= Lease.RESEND_EARLY_WITHIN_SECONDS
            and task.request.retries > 0
        )
        log.info(LogEvent.JOB_NOT_CLAIMED, record_id=record_id, epoch=epoch, sent_again=early, **why)
        if early:
            # Celery ran the countdown on this pod's clock, not MongoDB's. Nothing is written, so no attempt
            # is used; early again only on a pod whose clock is over 6 s ahead of this one's: it cannot loop.
            countdown = math.ceil(why["due_in_seconds"]) + 1
            task.retry(countdown=countdown, throw=False, priority=Worker.NEXT_STAGE_PRIORITY)
        # Ignore: this delivery did nothing, and job outcomes count jobs, not deliveries (lifecycle.py).
        raise Ignore
    if due_at := lease.record["job"].get("due_at"):
        waited = (utc_now() - due_at).total_seconds()
        metrics.record_queue_wait(task.name, waited)
    structlog.contextvars.bind_contextvars(  # the job (record, epoch, stage): a re-send finds its AI answers
        record_id=record_id, epoch=epoch, task=task.name, attempt=lease.attempts
    )
    if request_id := lease.record["job"].get("request_id"):
        structlog.contextvars.bind_contextvars(request_id=request_id)  # also for a re-send without header
    return lease


def _retry_or_fail(task: Task, lease: JobLease, exc: Exception, publish: Callable[[str], None]) -> bool:
    """A store or AI outage: give the job back and retry after the next back-off delay, or, on the last
    attempt, fail it with the outage message. Raises Celery's Retry; returns True after failing the job, False
    when it is no longer this delivery's (cancelled meanwhile: nothing to retry or fail)."""
    if lease.attempts < Lease.MAX_ATTEMPTS:
        backoff = Lease.RETRY_DELAYS_SECONDS
        delay = backoff[min(lease.attempts, len(backoff)) - 1]
        due_at = utc_now() + timedelta(seconds=delay)
        notice = retry_notice(outage_reason(exc), describe_outage(exc), lease.attempts, due_at)
        if not _give_back(lease, due_at, {"job.retry": notice}):
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


def _wait_for_other_job(
    task: Task, lease: JobLease, exc: WaitingForAnotherJob, collection: Collection
) -> NoReturn:
    """Another job holds what this one needs, a normal step and not an outage: give the job back with no
    attempt used and no retry notice, marked waiting (it reads queued, and its looks are not announced),
    and look again after the first back-off delay. Raises JobWaiting, or ends the delivery when the job is
    no longer its own."""
    # ponytail: polls at the first back-off (cheap); wake waiters if many ever wait
    delay = Lease.RETRY_DELAYS_SECONDS[0]
    due_at = utc_now() + timedelta(seconds=delay)
    waiting = {"job.attempts": lease.attempts - 1, "job.retry": None, "job.waiting": True}
    if not _give_back(lease, due_at, waiting):
        _end_lost_delivery(collection, lease.record_id)
    log.info(LogEvent.JOB_WAITING, record_id=lease.record_id, delay_seconds=delay, message=str(exc))
    if not lease.record["job"].get("waiting"):  # only the wait's start is news
        JOB_COLLECTIONS[collection](lease.record_id)
    task.retry(countdown=delay, throw=False, priority=Worker.NEXT_STAGE_PRIORITY)
    raise JobWaiting from exc


def _give_back(lease: JobLease, due_at: datetime, changes: dict[str, Any]) -> bool:
    """The job queued again for `due_at` with `changes`; False when it is no longer this delivery's. If
    MongoDB is down too, the record stays running with a live lease: this delivery's own retry takes it
    back (job_repository._claimable), while any other delivery finds it still owned and exits."""
    queued = {"status": Status.QUEUED, "job.due_at": due_at, "job.lease_until": None}
    with contextlib.suppress(*MONGO_UNAVAILABLE_ERRORS):
        try:
            lease.update_job(queued | changes)
        except LeaseLost:
            return False
    return True


def _retry_later(task: Task, exc: Exception, delay: int) -> Exception:
    """Celery's own retry, with no limit of its own (task_annotations in app/worker/celery_app.py). Its count
    is per message and also grows with the retries of an unclaimed delivery (MongoDB down at claim), so any
    Celery limit could end an owned job early: counted as a failure while the record still waited to run. The
    real limit is Lease.MAX_ATTEMPTS, counted on the record; an unclaimed delivery waits for MongoDB, 15 s
    apart. Sent ahead of new work: Celery would copy the message's own priority, behind the whole backlog."""
    return task.retry(countdown=delay, exc=exc, priority=Worker.NEXT_STAGE_PRIORITY)
