"""The intelligence refresh job: beat's scheduled check of the due sources, skipped while the switch is off,
or an admin's refresh recorded on its job. A failed source keeps its last good data."""

from collections.abc import Callable

import structlog

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import ErrorCode, IntelRefreshMessage, IntelSource, IntelWorkEvent, TaskName
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.worker.celery_app import celery_app, current_worker
from app.worker.external_intelligence.cancel_check import import_cancel_check
from app.worker.external_intelligence.refresh_sources import SourceRefresher
from app.worker.jobs import job_error_of

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.REFRESH_EXTERNAL_INTELLIGENCE)
def refresh_external_intelligence(job_id: str | None = None) -> None:
    """Celery task: without `job_id` refresh the due sources (the scheduled check); with it, run that job."""
    from app import container

    if job_id is None:
        if container.get_intelligence_switch().is_on():
            container.get_source_refresher().refresh_due_sources(utc_now())
        else:
            log.info(IntelWorkEvent.REFRESH_SKIPPED)
        return
    run_refresh_job(job_id, container.get_admin_job_repository(), container.get_source_refresher)


def run_refresh_job(job_id: str, jobs: AdminJobRepository, refresher: Callable[[], SourceRefresher]) -> None:
    """Run an admin's refresh of its one source, or of the due ones, and record how it went on the job.
    The run-time switch was checked when the job was queued, so only the env master switch is checked here
    (the worker's cached run-time switch can lag a change by a minute). A late or repeated message finds the
    job no longer active and does nothing; a failure is recorded, then raised."""
    now = utc_now()
    if not jobs.update_admin_job_running(job_id, now, **current_worker()):
        return
    record = jobs.get(("source",), _id=job_id) or {}
    source = IntelSource(record["source"]) if record.get("source") else None
    try:
        if not get_settings().external_intelligence_enabled:
            error = {"code": ErrorCode.CONFLICT, "message": IntelRefreshMessage.SWITCH_OFF.value}
            jobs.update_admin_job_finished(job_id, utc_now(), error=error)
            return
        with import_cancel_check(lambda: jobs.is_admin_job_active(job_id)):  # its cancel stops it early
            if source is None:
                summary = refresher().refresh_due_sources(now)
            else:
                summary = refresher().refresh_one_source(source, now)
    except Exception as exc:
        log.warning(IntelWorkEvent.REFRESH_JOB_FAILED, job_id=job_id, exc_info=True)
        jobs.update_admin_job_finished(job_id, utc_now(), error=job_error_of(exc))
        raise
    # Done: the data refresh stands; an index the AI could not rebuild is told beside it (with its reason).
    index_error = {"index_error": summary.index_error} if summary.index_error else {}
    jobs.update_admin_job_finished(job_id, utc_now(), result={"source": source} | index_error)
