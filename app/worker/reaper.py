"""The reaper: every minute it repairs jobs no delivery is working on. A lease that ran out (its worker died)
is queued again, or failed after Lease.MAX_ATTEMPTS; a job left queued while its queue is empty (its message
never reached the broker, or was lost) is sent again. Every write applies only if the record did not change
since it was read, so two reapers never send the same job twice."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core import metrics
from app.core.constants import ErrorCode, ErrorMessage, Lease, LogEvent, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, REDIS_UNAVAILABLE_ERRORS
from app.data_access.job_records import JobRecords
from app.worker.celery_app import BrokerUnavailable, celery_app, count_waiting_messages, queue_of, send_job
from app.worker.jobs import JOB_COLLECTIONS

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.REAP)
def reap_jobs() -> None:
    """Every minute: give back jobs whose worker stopped renewing the lease (or fail them after
    Lease.MAX_ATTEMPTS), and re-send jobs left queued (a send that never reached the broker)."""
    now = datetime.now(UTC)
    stale_queued = now - timedelta(seconds=Lease.REQUEUE_QUEUED_AFTER_SECONDS)
    queue_is_empty = _queue_sizes_read_once()
    for collection, publish in JOB_COLLECTIONS.items():
        records = JobRecords(get_mongodb()[collection])
        for record in records.find_expired_leases(now):
            _isolated(_settle_expired_job, records, record, now, publish)
        for record in records.find_unsent(stale_queued):
            _isolated(_resend_if_lost, records, record, now, queue_is_empty, publish)


def _isolated(repair: Callable[..., None], records: JobRecords, record: dict[str, Any], *args: Any) -> None:
    """One bad record (a field missing or of the wrong type) is logged and skipped, so it never stops the
    other jobs' repairs. A MongoDB outage still ends the pass (the next one runs in a minute)."""
    try:
        repair(records, record, *args)
    except MONGO_UNAVAILABLE_ERRORS:
        raise
    except Exception:  # noqa: BLE001 — logged with its record; the pass goes on
        log.exception(LogEvent.JOB_REAP_FAILED, record_id=record.get("_id"))


def _resend_if_lost(
    records: JobRecords,
    record: dict[str, Any],
    now: datetime,
    queue_is_empty: Callable[[str], bool],
    publish: Callable[[str], None],
) -> None:
    """Re-send a job still queued 2 min on: lost, or only waiting behind other jobs."""
    # A message waiting in its queue would make a re-send a duplicate (a bigger backlog, an empty extra
    # delivery), so it is sent again only when its queue is empty, or after Lease.RESEND_ANYWAY_AFTER_SECONDS
    # whatever the queue holds. Only a send into an empty queue counts toward "never started": a job merely
    # waiting in a long backlog is never failed for it.
    queue_empty = queue_is_empty(queue_of(record["job"]["task"]))
    waited_long = record["job"]["due_at"] < now - timedelta(seconds=Lease.RESEND_ANYWAY_AFTER_SECONDS)
    if waited_long or queue_empty:
        _resend_queued_job(records, record, now, publish, counted=queue_empty)


def _queue_sizes_read_once() -> Callable[[str], bool]:
    """Whether a queue is empty, each queue read at most once per reaper pass. A queue the broker cannot
    report counts as not empty: a re-send would fail just the same."""
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
    records: JobRecords, record: dict[str, Any], now: datetime, publish: Callable[[str], None]
) -> None:
    job = record["job"]
    attempts = job.get("attempts", 0)
    if attempts >= Lease.MAX_ATTEMPTS:
        error = {
            "code": ErrorCode.JOB_ABANDONED,
            "message": ErrorMessage.JOB_ABANDONED.format(attempts=attempts),
        }
        if not records.fail_expired(record, error, now):
            return  # its worker renewed or finished in between
        # Counted as a job failure: the worker died mid-job, so no task outcome was ever recorded, and
        # JobsFailing would otherwise never hear of this run.
        metrics.JOBS.labels(job["task"], "failure").inc()
        log.warning(LogEvent.JOB_FAILED, record_id=record["_id"], reason="abandoned", attempts=attempts)
    else:
        if not records.requeue_expired(record, now):
            return  # its worker renewed or finished in between
        log.info(LogEvent.JOB_REQUEUED, record_id=record["_id"], reason="lease_expired", attempts=attempts)
        send_job(job["task"], record["_id"], job["epoch"])
    publish(record["_id"])


def _resend_queued_job(
    records: JobRecords,
    record: dict[str, Any],
    now: datetime,
    publish: Callable[[str], None],
    *,
    counted: bool,
) -> None:
    """Send a queued job again (`counted`: one more send toward Lease.MAX_ATTEMPTS), or fail it once it was
    sent that often and never started."""
    job = record["job"]
    sends = job.get("resends", 0)
    if sends >= Lease.MAX_ATTEMPTS:
        # Never claimed after so many sends (its task is not registered, or its message is always refused):
        # failed, counted and announced, instead of re-sent every 2 minutes for ever with no alert.
        error = {
            "code": ErrorCode.JOB_ABANDONED,
            "message": ErrorMessage.JOB_NEVER_STARTED.format(sends=sends),
        }
        if records.fail_unsent(record, error, now):
            metrics.JOBS.labels(job["task"], "failure").inc()
            log.warning(LogEvent.JOB_FAILED, record_id=record["_id"], reason="never_started", sends=sends)
            publish(record["_id"])
        return
    # Moving due_at forward first means one re-send per REQUEUE_QUEUED_AFTER_SECONDS, never one per minute.
    if records.push_due_forward(record, now, counted=counted):
        log.info(
            LogEvent.JOB_REQUEUED, record_id=record["_id"], reason="never_picked_up", sends=sends + counted
        )
        send_job(job["task"], record["_id"], job["epoch"])
