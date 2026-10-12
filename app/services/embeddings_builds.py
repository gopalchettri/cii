"""Embeddings build on request (#18, #19): the library's vectors made now instead of at the next 30-minute
build, for every library at once (one that did not change costs no AI call). One build at a time; its job
record says how it went (app/worker/tasks/library_indexes.py runs it)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.constants import (
    AdminJobKind,
    AdminJobMessage,
    AdminJobs,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ErrorCode,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, NotFound, Unavailable
from app.core.singletons import singleton
from app.data_access.admin_jobs import AdminJobRecords
from app.services.audit import admin_actor, audit_target, record_audit
from app.worker.celery_app import send_admin_job

_KIND = AdminJobKind.EMBEDDINGS_BUILD


class EmbeddingsBuilds:
    def __init__(self, jobs: AdminJobRecords) -> None:
        self._jobs = jobs

    def start(self, requested_by: str) -> dict[str, Any]:
        """The queued build's id. 409 job_in_progress (details.job_id: the active build) while one is queued
        or running; 503 when the job queue is unreachable (the job is then failed, never left queued)."""
        now = datetime.now(UTC)
        job_id = uuid.uuid4().hex
        job = {"_id": job_id, "kind": _KIND, "status": Status.QUEUED, "requested_by": requested_by}
        taken, active_id = self._take_the_slot(job | {"created_at": now}, now)
        if not taken:
            details = {"job_id": active_id}
            raise Conflict(
                AdminJobMessage.IN_PROGRESS, reason=ConflictReason.JOB_IN_PROGRESS, details=details
            )
        try:
            sent = send_admin_job(TaskName.BUILD_LIBRARY_INDEXES, job_id)
        except Exception:
            self._not_sent(job_id)  # any failure to queue it: a build no worker will run must not block
            raise
        if not sent:
            self._not_sent(job_id)
            raise Unavailable(AdminJobMessage.NOT_SENT)
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        record_audit(AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after={"kind": _KIND})
        return {"job_id": job_id, "status": Status.QUEUED}

    def read(self, job_id: str) -> dict[str, Any]:
        record = self._jobs.read(job_id)
        if record is None:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}

    def _not_sent(self, job_id: str) -> None:
        error = {"code": ErrorCode.UNAVAILABLE, "message": AdminJobMessage.NOT_SENT}
        self._jobs.end(job_id, datetime.now(UTC), error=error)

    def _take_the_slot(self, job: dict[str, Any], now: datetime) -> tuple[bool, str | None]:
        """(True, None) when `job` is now the active build; else (False, the active build's id). A build still
        unfinished after AdminJobs.STALE_AFTER_SECONDS (its worker died, its message was lost) is failed and
        replaced, so it can never block every later build."""
        stale_before = now - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        if self._jobs.insert_active(job) or (
            self._jobs.end_stale(_KIND, stale_before, error, now) and self._jobs.insert_active(job)
        ):
            return True, None
        active = self._jobs.find_active(_KIND)
        if active is None and self._jobs.insert_active(job):  # the active build finished in between
            return True, None
        return False, active["_id"] if active else None


@singleton
def get_embeddings_builds() -> EmbeddingsBuilds:
    return EmbeddingsBuilds(AdminJobRecords(get_mongodb()))
