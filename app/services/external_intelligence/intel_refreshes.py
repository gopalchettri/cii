"""An intelligence refresh on request (admin job kind intel_refresh), as the embeddings build is: one at
a time, a stale one replaced, an unreachable queue failing the job at once. The worker runs it
(app/worker/external_intelligence/refresh_task.py) and its job record says how it went."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.core.constants import (
    AdminJobKind,
    AdminJobMessage,
    AdminJobs,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ErrorCode,
    IntelRefreshMessage,
    IntelSource,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, Invalid, NotFound, Unavailable
from app.core.singletons import singleton
from app.data_access.admin_jobs import AdminJobRecords
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.services.audit import admin_actor, audit_target, record_audit
from app.worker.celery_app import send_admin_job

_KIND = AdminJobKind.INTEL_REFRESH


class IntelRefreshes:
    def __init__(self, jobs: AdminJobRecords, feeds: FeedStatusStore) -> None:
        self._jobs, self._feeds = jobs, feeds

    def start(self, requested_by: str, source: IntelSource | None = None) -> dict[str, Any]:
        """The queued refresh's id. 422 for a source not approved; 409 job_in_progress (details.job_id: the
        active one) while a refresh is queued or running; 503 when the job queue is unreachable (the job is
        then failed, never left queued)."""
        if not get_settings().external_intelligence_enabled:
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        if source is not None and not self._feeds.is_source_approved(source):
            raise Invalid(IntelRefreshMessage.SOURCE_NOT_APPROVED.format(source=source))
        now, job_id = datetime.now(UTC), uuid.uuid4().hex
        job: dict[str, Any] = {
            "_id": job_id,
            "kind": _KIND,
            "status": Status.QUEUED,
            "requested_by": requested_by,
        }
        job |= {"source": source}
        taken, active_id = self._take_the_slot(job | {"created_at": now}, now)
        if not taken:
            raise Conflict(
                IntelRefreshMessage.IN_PROGRESS,
                reason=ConflictReason.JOB_IN_PROGRESS,
                details={"job_id": active_id},
            )
        self._send(job_id)
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        after = {"kind": _KIND, "source": source}
        record_audit(AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after=after)
        return {"job_id": job_id, "status": Status.QUEUED}

    def read(self, job_id: str) -> dict[str, Any]:
        record = self._jobs.read(job_id)
        if record is None or record.get("kind") != _KIND:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}

    def _send(self, job_id: str) -> None:
        try:
            sent = send_admin_job(TaskName.REFRESH_EXTERNAL_INTELLIGENCE, job_id)
        except Exception:
            self._not_sent(job_id)  # any failure to queue it: a refresh no worker will run must not block
            raise
        if not sent:
            self._not_sent(job_id)
            raise Unavailable(IntelRefreshMessage.NOT_SENT)

    def _not_sent(self, job_id: str) -> None:
        error = {"code": ErrorCode.UNAVAILABLE, "message": IntelRefreshMessage.NOT_SENT.value}
        self._jobs.end(job_id, datetime.now(UTC), error=error)

    def _take_the_slot(self, job: dict[str, Any], now: datetime) -> tuple[bool, str | None]:
        """(True, None) when `job` is now the active refresh; else (False, the active one's id). One still
        unfinished after AdminJobs.STALE_AFTER_SECONDS (its worker died) is failed and replaced."""
        stale_before = now - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        if self._jobs.insert_active(job) or (
            self._jobs.end_stale(_KIND, stale_before, error, now) and self._jobs.insert_active(job)
        ):
            return True, None
        active = self._jobs.find_active(_KIND)
        if active is None and self._jobs.insert_active(job):  # the active one finished in between
            return True, None
        return False, active["_id"] if active else None


@singleton
def get_intel_refreshes() -> IntelRefreshes:
    db = get_mongodb()
    return IntelRefreshes(AdminJobRecords(db), FeedStatusStore(db))
