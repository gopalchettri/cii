"""The intelligence refresh job: beat's scheduled check of the due sources, or an admin's refresh recorded on
its job. Skipped while the switch is off; a failed source keeps its last good data."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.constants import ErrorCode, IntelRefreshMessage, IntelSource, IntelWorkEvent, TaskName
from app.core.exceptions import AppError
from app.data_access.admin.repository import AdminJobRepository, admin_jobs
from app.worker.celery_app import celery_app
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.REFRESH_EXTERNAL_INTELLIGENCE)
def refresh_external_intelligence(job_id: str | None = None) -> None:
    """Celery task: without `job_id` refresh the due sources (the scheduled check); with it, run that job."""
    access = get_intel_access()
    if job_id is None:
        if access.is_on():
            access.refresher().refresh_due_sources(datetime.now(UTC))
        else:
            log.info(IntelWorkEvent.REFRESH_SKIPPED)
        return
    run_refresh_job(job_id, admin_jobs, access)


def run_refresh_job(job_id: str, jobs: AdminJobRepository, access: IntelAccess) -> None:
    """Run an admin's refresh of its one source, or of the due ones, and record how it went on the job.
    A late or repeated message finds the job no longer active and does nothing; a failure is recorded, then
    raised."""
    now = datetime.now(UTC)
    if not jobs.update_admin_job_running(job_id, now):
        return
    record = jobs.get(("source",), _id=job_id) or {}
    source = IntelSource(record["source"]) if record.get("source") else None
    try:
        if not access.is_on():
            error = {"code": ErrorCode.CONFLICT, "message": IntelRefreshMessage.SWITCH_OFF.value}
            jobs.update_admin_job_finished(job_id, datetime.now(UTC), error=error)
            return
        if source is None:
            access.refresher().refresh_due_sources(now)
        else:
            access.refresher().refresh_one_source(source, now)
    except Exception as exc:
        log.warning(IntelWorkEvent.REFRESH_JOB_FAILED, job_id=job_id, exc_info=True)
        jobs.update_admin_job_finished(job_id, datetime.now(UTC), error=_job_error(exc))
        raise
    jobs.update_admin_job_finished(job_id, datetime.now(UTC), result={"source": source})


def _job_error(exc: Exception) -> dict[str, Any]:
    """The failure as the job record shows it: an app error's own code and message, else only the exception's
    type (its text may carry a provider's or a driver's details)."""
    if isinstance(exc, AppError):
        return {"code": exc.code, "message": exc.detail}
    return {"code": ErrorCode.INTERNAL_ERROR, "message": type(exc).__name__}
