"""Background job of the intelligence sources (maintenance queue). Beat sends it every
IntelLimits.CHECK_EVERY_SECONDS (only while the master switch is on): it refreshes the sources that are
due. An admin's refresh (#job kind intel_refresh) sends it with the job id: it refreshes the one source
named, or the due ones, and its job record says how it went. Skipped when the switch is off; nothing on a
scenario's path waits for it, and a failed source keeps its last good data (SourceRefresher)."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.constants import ErrorCode, IntelRefreshMessage, IntelSource, IntelWorkEvent, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import AppError
from app.data_access.admin_jobs import AdminJobRecords
from app.worker.celery_app import celery_app
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.REFRESH_EXTERNAL_INTELLIGENCE)
def refresh_external_intelligence(job_id: str | None = None) -> None:
    """Without `job_id`: the scheduled check. With it: an admin's refresh, recorded on its job."""
    access = get_intel_access()
    if job_id is None:
        if access.is_on():
            access.refresher().refresh_due_sources(datetime.now(UTC))
        else:
            log.info(IntelWorkEvent.REFRESH_SKIPPED)
        return
    run_refresh_job(job_id, AdminJobRecords(get_mongodb()), access)


def run_refresh_job(job_id: str, jobs: AdminJobRecords, access: IntelAccess) -> None:
    """An admin's refresh. A late or repeated message finds the job no longer active and does nothing. A
    failure is recorded on the job, then raised (counted like any failed job)."""
    now = datetime.now(UTC)
    if not jobs.mark_running(job_id, now):
        return
    record = jobs.read(job_id) or {}
    source = IntelSource(record["source"]) if record.get("source") else None
    try:
        if not access.is_on():
            error = {"code": ErrorCode.CONFLICT, "message": IntelRefreshMessage.SWITCH_OFF.value}
            jobs.end(job_id, datetime.now(UTC), error=error)
            return
        _refresh(access, source, now)
    except Exception as exc:
        log.warning(IntelWorkEvent.REFRESH_JOB_FAILED, job_id=job_id, exc_info=True)
        jobs.end(job_id, datetime.now(UTC), error=_error_of(exc))
        raise
    jobs.end(job_id, datetime.now(UTC), result={"source": source})


def _refresh(access: IntelAccess, source: IntelSource | None, now: datetime) -> None:
    refresher = access.refresher()
    if source is None:
        refresher.refresh_due_sources(now)
    else:
        refresher.refresh_one_source(source, now)


def _error_of(exc: Exception) -> dict[str, Any]:
    """The failure as the job record shows it: an app error's own code and message (written for people), else
    only the exception's type (its text may carry a provider's or a driver's details)."""
    if isinstance(exc, AppError):
        return {"code": exc.code, "message": exc.detail}
    return {"code": ErrorCode.INTERNAL_ERROR, "message": type(exc).__name__}
