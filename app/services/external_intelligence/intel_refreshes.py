"""An intelligence refresh on request (admin job kind intel_refresh): one at a time, a stale one replaced, an
unreachable queue failing the job at once; the worker runs it and its job record says how it went."""

import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    AdminJobKind,
    AdminJobMessage,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ErrorCode,
    IntelRefreshMessage,
    IntelSource,
    Status,
    TaskName,
)
from app.core.exceptions import Conflict, Invalid, NotFound, Unavailable
from app.core.singletons import singleton
from app.data_access.admin.repository import AdminJobRepository, admin_jobs, audit_records
from app.data_access.external_intelligence.repository import IntelFeedRepository, intel_feeds
from app.services.audit import admin_actor, audit_target
from app.services.external_intelligence.switch import (
    ExternalIntelligenceSwitch,
    get_external_intelligence_switch,
)
from app.worker.celery_app import send_admin_job

_KIND = AdminJobKind.INTEL_REFRESH


class IntelRefreshes:
    """Starts and reads the admin's refresh jobs."""

    def __init__(
        self, jobs: AdminJobRepository, feeds: IntelFeedRepository, switch: ExternalIntelligenceSwitch
    ) -> None:
        self._jobs, self._feeds, self._switch = jobs, feeds, switch

    def start(self, requested_by: str, source: IntelSource | None = None) -> dict[str, Any]:
        """Queue a refresh and return its id. 409 while the switch is off; 422 for a source not approved; 409
        job_in_progress (details.job_id: the active one) while one is queued or running; 503 when the job
        queue is unreachable (the job is then failed, never left queued)."""
        if not self._switch.is_enabled():
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        if source is not None and not self._feeds.count(_id=source, approved=True):
            raise Invalid(IntelRefreshMessage.SOURCE_NOT_APPROVED.format(source=source))
        now, job_id = datetime.now(UTC), uuid.uuid4().hex
        job: dict[str, Any] = {
            "_id": job_id,
            "kind": _KIND,
            "status": Status.QUEUED,
            "requested_by": requested_by,
            "source": source,
        }
        active_id = self._jobs.create_admin_job(job | {"created_at": now})
        if active_id != job_id:
            raise Conflict(
                IntelRefreshMessage.IN_PROGRESS,
                reason=ConflictReason.JOB_IN_PROGRESS,
                details={"job_id": active_id},
            )
        self._send(job_id)
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        after = {"kind": _KIND, "source": source}
        audit_records.create_audit_record(
            AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after=after
        )
        return {"job_id": job_id, "status": Status.QUEUED}

    def read(self, job_id: str) -> dict[str, Any]:
        """One refresh job as the API shows it; 404 for any other job."""
        record = self._jobs.get_admin_job(job_id, _KIND)
        if record is None:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}

    def _send(self, job_id: str) -> None:
        """Queue the job's message. Any failure to queue it fails the job, then is raised, so it never blocks
        the next."""
        try:
            sent = send_admin_job(TaskName.REFRESH_EXTERNAL_INTELLIGENCE, job_id)
        except Exception:
            self._not_sent(job_id)
            raise
        if not sent:
            self._not_sent(job_id)
            raise Unavailable(IntelRefreshMessage.NOT_SENT)

    def _not_sent(self, job_id: str) -> None:
        """Fail a job whose message could not be queued."""
        error = {"code": ErrorCode.UNAVAILABLE, "message": IntelRefreshMessage.NOT_SENT.value}
        self._jobs.update_admin_job_finished(job_id, datetime.now(UTC), error=error)


@singleton
def get_intel_refreshes() -> IntelRefreshes:
    """The process's IntelRefreshes."""
    return IntelRefreshes(admin_jobs, intel_feeds, get_external_intelligence_switch())
