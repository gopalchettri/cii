"""The reaper: every minute it repairs jobs no delivery is working on. A lease that ran out (its worker died)
is queued again, or failed after Lease.MAX_ATTEMPTS; a job left queued while its queue is empty (its message
never reached the broker, or was lost) is sent again. Every write applies only if the record did not change
since it was read, so two reapers never send the same job twice."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core import metrics
from app.core.constants import ADMIN_JOB_TASKS, ErrorCode, ErrorMessage, Lease, LogEvent, TaskName, module_of
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, REDIS_UNAVAILABLE_ERRORS
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.jobs.job_repository import JobRepository
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
        jobs = JobRepository(get_mongodb()[collection])
        for record in jobs.list_expired_jobs(now):
            _isolated(_settle_expired_job, jobs, record, now, publish)
        for record in jobs.list_unsent_jobs(stale_queued):
            _isolated(_resend_if_lost, jobs, record, now, queue_is_empty, publish)
    admin_jobs = AdminJobRepository()
    for job in admin_jobs.fail_stale_admin_jobs(now):  # never left "running" until the next request
        _announce_abandoned_admin_job(job)
    try:
        _count_jobs_now(admin_jobs, now)
    except Exception:  # noqa: BLE001 — a count for Grafana never fails the reaper's repairs
        log.warning(LogEvent.JOB_REAP_FAILED, step="count_jobs_now", exc_info=True)


def _announce_abandoned_admin_job(job: dict[str, Any]) -> None:
    """One job.failed line under the job's own task and module, not the reaper's (the dashboard groups failed
    jobs by task), counted as a failure: its worker died, so no task outcome was ever recorded."""
    task = ADMIN_JOB_TASKS.get(job.get("kind", ""), job.get("kind") or "unknown")
    metrics.JOBS.labels(task, "failure").inc()
    log.warning(
        LogEvent.JOB_FAILED,
        task=task,
        module=module_of(task),
        record_id=job["_id"],
        reason="abandoned",
        **job["error"],
    )


def _count_jobs_now(admin_jobs: AdminJobRepository, now: datetime) -> None:
    """tsg_jobs_current for Grafana: every kind's queued, retrying and running jobs, and its failures of the
    last 24 h. A kind with none is set to 0, so a panel never keeps showing a job that ended."""
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
    """One bad record (a field missing or of the wrong type) is logged and skipped, so it never stops the
    other jobs' repairs. A MongoDB outage still ends the pass (the next one runs in a minute)."""
    try:
        repair(jobs, record, *args)
    except MONGO_UNAVAILABLE_ERRORS:
        raise
    except Exception:  # noqa: BLE001 — logged with its record; the pass goes on
        log.exception(LogEvent.JOB_REAP_FAILED, record_id=record.get("_id"))


def _resend_if_lost(
    jobs: JobRepository,
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
        _resend_queued_job(jobs, record, now, publish, counted=queue_empty)


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
    jobs: JobRepository, record: dict[str, Any], now: datetime, publish: Callable[[str], None]
) -> None:
    job = record["job"]
    attempts = job.get("attempts", 0)
    # The job's own task and module, not the reaper's: the dashboard groups failed jobs by them.
    job_log = log.bind(task=job["task"], module=module_of(job["task"]), record_id=record["_id"])
    if attempts >= Lease.MAX_ATTEMPTS:
        error = {
            "code": ErrorCode.JOB_ABANDONED,
            "message": ErrorMessage.JOB_ABANDONED.format(attempts=attempts),
        }
        if not jobs.requeue_or_fail_expired_job(record, now, error):
            return  # its worker renewed or finished in between
        # Counted as a job failure: the worker died mid-job, so no task outcome was ever recorded, and
        # JobsFailing would otherwise never hear of this run.
        metrics.JOBS.labels(job["task"], "failure").inc()
        job_log.warning(LogEvent.JOB_FAILED, reason="abandoned", attempts=attempts, **error)
    else:
        if not jobs.requeue_or_fail_expired_job(record, now):
            return  # its worker renewed or finished in between
        job_log.info(LogEvent.JOB_REQUEUED, reason="lease_expired", attempts=attempts)
        send_job(job["task"], record["_id"], job["epoch"])
    publish(record["_id"])


def _resend_queued_job(
    jobs: JobRepository,
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
    # The job's own task and module, not the reaper's: the dashboard groups failed jobs by them.
    job_log = log.bind(task=job["task"], module=module_of(job["task"]), record_id=record["_id"])
    if sends >= Lease.MAX_ATTEMPTS:
        # Never claimed after so many sends (its task is not registered, or its message is always refused):
        # failed, counted and announced, instead of re-sent every 2 minutes for ever with no alert.
        error = {
            "code": ErrorCode.JOB_ABANDONED,
            "message": ErrorMessage.JOB_NEVER_STARTED.format(sends=sends),
        }
        if jobs.resend_or_fail_unsent_job(record, now, counted=False, error=error):
            metrics.JOBS.labels(job["task"], "failure").inc()
            job_log.warning(LogEvent.JOB_FAILED, reason="never_started", sends=sends, **error)
            publish(record["_id"])
        return
    # Moving due_at forward first means one re-send per REQUEUE_QUEUED_AFTER_SECONDS, never one per minute.
    if jobs.resend_or_fail_unsent_job(record, now, counted=counted):
        job_log.info(LogEvent.JOB_REQUEUED, reason="never_picked_up", sends=sends + counted)
        send_job(job["task"], record["_id"], job["epoch"])
