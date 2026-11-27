"""Leased jobs on MongoDB records: claim, work under a renewed lease, retry outages, else fail clearly; and
the reaper, which every minute requeues or fails jobs whose lease ran out and re-sends jobs left queued."""

import contextlib
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any, NoReturn

import structlog
from celery import Task
from celery.exceptions import Ignore

from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    ADMIN_JOB_TASKS,
    AbandonReason,
    AiOutage,
    Collection,
    ErrorCode,
    ErrorMessage,
    Lease,
    LogEvent,
    Status,
    TaskName,
    Worker,
    module_of,
)
from app.core.database import get_mongodb
from app.core.exceptions import (
    MONGO_UNAVAILABLE_ERRORS,
    REDIS_UNAVAILABLE_ERRORS,
    TEMPORARY_ERRORS,
    AppError,
    JobFailed,
    LeaseLost,
    WaitingForAnotherJob,
    outage_reason,
)
from app.crud.admin_jobs import AdminJobRepository
from app.crud.jobs import JobLease, JobRepository, failed_job_fields, retry_notice
from app.realtime.publisher import publish_mapping_status, publish_remediation_status, publish_session_status
from app.worker.celery_app import BrokerUnavailable, celery_app, count_waiting_messages, queue_of, send_job
from app.worker.lease_renewal import handing_back, keep_lease_alive

log = structlog.get_logger(__name__)


#: Every collection whose records carry a leased job, and how a change to one of them is announced.
JOB_COLLECTIONS: dict[Collection, Callable[[str], None]] = {
    Collection.SERVICE_MAPPINGS: publish_mapping_status,
    Collection.SESSIONS: publish_session_status,
    Collection.REMEDIATIONS: publish_remediation_status,
}


class JobWaiting(Ignore):
    """Ends a delivery whose job waits for another job; counted as `waiting`, never as a retry."""


def hand_over(lease: JobLease, next_task: TaskName, changes: dict[str, Any] | None = None) -> None:
    """End this stage and queue the next one on the same record (same epoch), sent ahead of new work."""
    cleared = dict.fromkeys(("job.task_id", "job.worker", "job.lease_until", "job.retry", "job.waiting_since"))
    next_stage = {"status": Status.QUEUED, "job.task": next_task, "job.due_at": utc_now(), "job.attempts": 0}
    lease.update_job({**(changes or {}), **next_stage, **cleared})
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


def _fail(lease: JobLease, code: ErrorCode, message: str, reason: AiOutage | AbandonReason | None = None) -> None:
    error = {"code": code, "message": message} | ({"reason": reason} if reason else {})
    try:
        lease.update_job(failed_job_fields(lease.collection, error))
    except LeaseLost:
        _end_lost_delivery(lease.collection, lease.record_id)
    except MONGO_UNAVAILABLE_ERRORS:
        # The record stays running: the reaper re-queues it once the lease runs out.
        log.warning(LogEvent.JOB_FAILURE_NOT_SAVED, record_id=lease.record_id, **error, exc_info=True)
        raise Ignore from None
    log.warning(LogEvent.JOB_FAILED, record_id=lease.record_id, **error)


def run_leased_job(
    task: Task,
    collection: Collection,
    record_id: str,
    epoch: int,
    work: Callable[[JobLease], None],
    fields: Iterable[str] = (),
) -> None:
    """One delivery: claim, work under a live lease, retry outages up to Lease.MAX_ATTEMPTS, else fail."""
    publish = JOB_COLLECTIONS[collection]
    lease = _claim_or_ignore(task, collection, record_id, epoch, fields)
    # A waiting job's look reads queued: nothing changed. ponytail: one that then runs is announced only at
    # its end; its streams see it running at their next re-read (Realtime.RECHECK_SECONDS)
    if not lease.record["job"].get("waiting"):
        publish(record_id)
    try:
        with keep_lease_alive(record_id, lease.renew, lambda: give_job_back(task.name, lease)):
            work(lease)
    except LeaseLost:
        _end_lost_delivery(collection, record_id)
    except WaitingForAnotherJob as exc:
        _wait_for_other_job(task, lease, exc, collection)
    except TEMPORARY_ERRORS as exc:
        _retry_or_fail(task, lease, exc, publish)
        raise
    except JobFailed as failure:  # the job's own final error: failed with its code, never retried
        _fail(lease, failure.code, failure.message)
        publish(record_id)
        raise
    except AppError as exc:  # a known failure: failed in its own words, not "Unexpected" (owner 2026-11-27)
        log.error(LogEvent.JOB_KNOWN_ERROR, record_id=record_id, code=exc.code, message=str(exc.__cause__ or exc))
        _fail(lease, exc.code, exc.detail, outage_reason(exc))
        publish(record_id)
        raise
    except Exception:
        log.exception(LogEvent.JOB_UNEXPECTED_ERROR, record_id=record_id)
        _fail(lease, ErrorCode.INTERNAL_ERROR, ErrorMessage.JOB_UNEXPECTED.format(record_id=record_id))
        publish(record_id)
        raise
    publish(record_id)


def give_job_back(task: str, lease: JobLease) -> bool:
    """Queue the job again now with this delivery's attempt returned; LeaseLost once it is not ours."""
    cleared = dict.fromkeys(("job.lease_until", "job.task_id", "job.worker", "job.retry"))
    lease.update_job({"status": Status.QUEUED, "job.due_at": utc_now(), "job.attempts": lease.attempts - 1, **cleared})
    log.info(LogEvent.JOB_HANDED_BACK, record_id=lease.record_id, attempt=lease.attempts)
    send_job(TaskName(task), lease.record_id, lease.epoch, priority=Worker.NEXT_STAGE_PRIORITY)
    return True


def _end_lost_delivery(collection: str, record_id: str) -> NoReturn:
    try:
        status = JobRepository(get_mongodb()[collection]).get_job_status(record_id)
    except MONGO_UNAVAILABLE_ERRORS:
        status = Status.RUNNING  # unknown: reported as a lost lease
    if status is None or status == Status.CANCELLED:
        log.info(LogEvent.JOB_STOPPED_BY_OWNER, record_id=record_id, status=status or "deleted")
    elif handing_back.is_set():
        log.info(LogEvent.JOB_STOPPED_HANDED_BACK, record_id=record_id, status=status)
    else:
        log.warning(LogEvent.JOB_LEASE_LOST, record_id=record_id)
    raise Ignore


def _claim_or_ignore(task: Task, collection: Collection, record_id: str, epoch: int, fields: Iterable[str]) -> JobLease:
    try:
        worker = getattr(task.request, "hostname", "") or ""
        lease = JobRepository(get_mongodb()[collection]).claim_job(
            record_id, epoch, task.name, task.request.id, fields, worker
        )
    except MONGO_UNAVAILABLE_ERRORS as exc:
        # A claim saved with its answer lost waits for the reaper: this retry finds the job running.
        raise task.retry(countdown=Lease.RETRY_DELAYS_SECONDS[0], exc=exc, priority=Worker.NEXT_STAGE_PRIORITY) from exc
    if lease is None:  # a duplicate, stale or early delivery; an early retry is re-sent by the reaper
        log.info(LogEvent.JOB_NOT_CLAIMED, record_id=record_id, epoch=epoch)
        raise Ignore
    if due_at := lease.record["job"].get("due_at"):
        metrics.record_queue_wait(task.name, (utc_now() - due_at).total_seconds())
    structlog.contextvars.bind_contextvars(
        record_id=record_id, epoch=epoch, task=task.name, attempt=lease.attempts, **lease.origin
    )
    return lease


def _retry_or_fail(task: Task, lease: JobLease, exc: Exception, publish: Callable[[str], None]) -> None:
    if lease.attempts >= Lease.MAX_ATTEMPTS:
        _fail(lease, ErrorCode.UNAVAILABLE, describe_outage(exc), outage_reason(exc))
        publish(lease.record_id)
        return
    delay = Lease.RETRY_DELAYS_SECONDS[min(lease.attempts, len(Lease.RETRY_DELAYS_SECONDS)) - 1]
    due_at = utc_now() + timedelta(seconds=delay)
    notice = retry_notice(outage_reason(exc), describe_outage(exc), lease.attempts, due_at)
    if not _give_back(lease, due_at, {"job.retry": notice}):
        _end_lost_delivery(lease.collection, lease.record_id)
    log.warning(
        LogEvent.JOB_RETRY_SCHEDULED,
        record_id=lease.record_id,
        delay_seconds=delay,
        message=str(exc),
        reason=outage_reason(exc),
    )
    publish(lease.record_id)
    raise task.retry(countdown=delay, exc=exc, priority=Worker.NEXT_STAGE_PRIORITY) from exc


def _wait_for_other_job(task: Task, lease: JobLease, exc: WaitingForAnotherJob, collection: Collection) -> NoReturn:
    now = utc_now()
    since = lease.record["job"].get("waiting_since") or now
    if (waited := now - since) >= timedelta(seconds=Lease.MAX_WAIT_SECONDS):
        message = ErrorMessage.JOB_WAITED_TOO_LONG.format(minutes=round(waited.total_seconds() / 60))
        _fail(lease, ErrorCode.JOB_ABANDONED, message, AbandonReason.WAITED_TOO_LONG)
        JOB_COLLECTIONS[collection](lease.record_id)
        raise JobFailed(ErrorCode.JOB_ABANDONED, message) from exc
    # ponytail: polls at the first back-off (cheap); wake waiters if many ever wait
    delay = Lease.RETRY_DELAYS_SECONDS[0]
    waiting: dict[str, Any] = {"job.attempts": lease.attempts - 1, "job.retry": None, "job.waiting": True}
    waiting["job.waiting_since"] = since
    if not _give_back(lease, now + timedelta(seconds=delay), waiting):
        _end_lost_delivery(collection, lease.record_id)
    log.info(LogEvent.JOB_WAITING, record_id=lease.record_id, delay_seconds=delay, message=str(exc))
    if not lease.record["job"].get("waiting"):  # only the wait's start is news
        JOB_COLLECTIONS[collection](lease.record_id)
    task.retry(countdown=delay, throw=False, priority=Worker.NEXT_STAGE_PRIORITY)
    raise JobWaiting from exc


def _give_back(lease: JobLease, due_at: datetime, changes: dict[str, Any]) -> bool:
    queued = {"status": Status.QUEUED, "job.due_at": due_at, "job.lease_until": None}
    with contextlib.suppress(*MONGO_UNAVAILABLE_ERRORS):
        try:
            lease.update_job(queued | changes)
        except LeaseLost:
            return False
    return True


@celery_app.task(name=TaskName.REAP)
def reap_jobs() -> None:
    """Every minute: requeue or fail jobs whose lease ran out, and re-send jobs left queued."""
    metrics.record_reaper_time(metrics.REAPER_LAST_START)  # a pass that fails or hangs still started
    now = utc_now()
    stale_queued = now - timedelta(seconds=Lease.REQUEUE_QUEUED_AFTER_SECONDS)
    queue_is_empty = _queue_sizes_read_once()
    for collection, publish in JOB_COLLECTIONS.items():
        jobs = JobRepository(get_mongodb()[collection])
        for record in jobs.list_expired_jobs(now):
            _isolated(_settle_expired_job, jobs, record, now, publish)
        for record in jobs.list_unsent_jobs(stale_queued):
            _isolated(_resend_if_lost, jobs, record, now, queue_is_empty, publish)
    admin_jobs = AdminJobRepository()
    for job in admin_jobs.fail_stale_admin_jobs(now):  # its own task and module: the dashboard groups by them
        task = ADMIN_JOB_TASKS.get(job.get("kind", ""), job.get("kind") or "unknown")
        metrics.count_job(task, "failure")
        log.warning(LogEvent.JOB_FAILED, task=task, module=module_of(task), record_id=job["_id"], **job["error"])
    try:
        _count_jobs_now(admin_jobs, now)
    except Exception:  # noqa: BLE001 — a count for Grafana never fails the reaper's repairs
        log.warning(LogEvent.JOB_REAP_FAILED, step="count_jobs_now", exc_info=True)
    metrics.record_reaper_time(metrics.REAPER_LAST_PASS)


def _count_jobs_now(admin_jobs: AdminJobRepository, now: datetime) -> None:
    # tsg_jobs_current: queued, retrying and running jobs, and failures of the last 24 h; an ended one drops to 0
    since = now - timedelta(hours=24)
    counts: dict[tuple[str, str], int] = {}
    for collection in JOB_COLLECTIONS:
        counts |= JobRepository(get_mongodb()[collection]).count_jobs_by_task(since)
    counts |= admin_jobs.count_admin_jobs_by_kind(since)
    for labels in _jobs_now_labels | counts.keys():
        metrics.JOBS_NOW.labels(*labels).set(counts.get(labels, 0))
    _jobs_now_labels.update(counts)


_jobs_now_labels: set[tuple[str, str]] = set()  # every (kind, status) ever set, so an ended one drops to 0


def _isolated(repair: Callable[..., None], jobs: JobRepository, record: dict[str, Any], *args: Any) -> None:
    try:
        repair(jobs, record, *args)
    except MONGO_UNAVAILABLE_ERRORS:
        raise
    except Exception:  # noqa: BLE001 — logged with its record; the pass goes on
        log.exception(LogEvent.JOB_REAP_FAILED, record_id=record.get("_id"))


def _queue_sizes_read_once() -> Callable[[str], bool]:
    sizes: dict[str, int | None] = {}

    def queue_is_empty(queue: str) -> bool:
        if queue not in sizes:
            try:
                sizes[queue] = count_waiting_messages(queue)
            except (BrokerUnavailable, *REDIS_UNAVAILABLE_ERRORS):
                log.warning(LogEvent.JOB_QUEUE_SIZE_UNKNOWN, queue=queue, exc_info=True)
                sizes[queue] = None
        return sizes[queue] == 0

    return queue_is_empty


def _settle_expired_job(
    jobs: JobRepository, record: dict[str, Any], now: datetime, publish: Callable[[str], None]
) -> None:
    job = record["job"]
    attempts = job.get("attempts", 0)
    if attempts < Lease.MAX_ATTEMPTS:
        if not jobs.requeue_or_fail_expired_job(record, now):
            return  # its worker renewed or finished in between
        _job_log(record).warning(LogEvent.JOB_REQUEUED, reason="lease_expired", attempt=attempts)
        _send_again(record)
    else:
        error = _abandoned(ErrorMessage.JOB_ABANDONED.format(attempts=attempts), AbandonReason.WORKER_STOPPED)
        if not jobs.requeue_or_fail_expired_job(record, now, error):
            return
        metrics.count_job(job["task"], "failure")  # the worker died mid-job: no task outcome was recorded
        _job_log(record).warning(LogEvent.JOB_FAILED, attempt=attempts, **error)
    publish(record["_id"])


def _resend_if_lost(
    jobs: JobRepository,
    record: dict[str, Any],
    now: datetime,
    queue_is_empty: Callable[[str], bool],
    publish: Callable[[str], None],
) -> None:
    job = record["job"]
    queue_empty = queue_is_empty(queue_of(job["task"]))
    if not queue_empty and job["due_at"] >= now - timedelta(seconds=Lease.RESEND_ANYWAY_AFTER_SECONDS):
        return
    resends = job.get("resends", 0)
    if resends >= Lease.MAX_ATTEMPTS:
        error = _abandoned(ErrorMessage.JOB_NEVER_STARTED.format(sends=resends), AbandonReason.NEVER_STARTED)
        if jobs.resend_or_fail_unsent_job(record, now, error=error):
            metrics.count_job(job["task"], "failure")
            _job_log(record).warning(LogEvent.JOB_FAILED, resends=resends, **error)
            publish(record["_id"])
        return
    # Moving due_at forward first means one re-send per REQUEUE_QUEUED_AFTER_SECONDS, never one per minute.
    if not jobs.resend_or_fail_unsent_job(record, now):
        return
    _job_log(record).info(LogEvent.JOB_REQUEUED, reason="never_picked_up", resends=resends)
    if _send_again(record) and queue_empty:  # a broker outage never fails a healthy job as never started
        jobs.count_resend(record, now)


def _abandoned(message: str, reason: AbandonReason) -> dict[str, str]:
    return {"code": ErrorCode.JOB_ABANDONED, "message": message, "reason": reason}


def _send_again(record: dict[str, Any]) -> bool:
    job = record["job"]
    request = {"request_id": job["request_id"]} if job.get("request_id") else {}
    with structlog.contextvars.bound_contextvars(**request):
        return send_job(job["task"], record["_id"], job["epoch"], priority=Worker.NEXT_STAGE_PRIORITY)


def _job_log(record: dict[str, Any]) -> Any:
    job = record["job"]
    fields = {name: job.get(name) for name in ("task_id", "worker", "epoch", "request_id")}
    return log.bind(task=job["task"], module=module_of(job["task"]), record_id=record["_id"], **fields)
