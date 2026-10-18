"""Embeddings build on request (#18, #19): the library's vectors made now instead of at the next 30-minute
build, for every library at once (one that did not change costs no AI call). One build at a time; its job
record says how it went (app/worker/tasks/library_indexes.py runs it)."""

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
    Status,
    TaskName,
)
from app.core.exceptions import Conflict, NotFound, Unavailable
from app.core.singletons import singleton
from app.data_access.admin.repository import AdminJobRepository, admin_jobs, audit_records
from app.services.audit import admin_actor, audit_target
from app.worker.celery_app import send_admin_job

_KIND = AdminJobKind.EMBEDDINGS_BUILD


class EmbeddingsBuilds:
    def __init__(self, jobs: AdminJobRepository) -> None:
        self._jobs = jobs

    def start(self, requested_by: str) -> dict[str, Any]:
        """The queued build's id. 409 job_in_progress (details.job_id: the active build) while one is queued
        or running; 503 when the job queue is unreachable. Any failure to queue it fails the job, then is
        raised, so a build no worker will run never blocks the next."""
        now = datetime.now(UTC)
        job_id = uuid.uuid4().hex
        job = {"_id": job_id, "kind": _KIND, "status": Status.QUEUED, "requested_by": requested_by}
        active_id = self._jobs.create_admin_job(job | {"created_at": now})
        if active_id != job_id:
            details = {"job_id": active_id}
            raise Conflict(
                AdminJobMessage.IN_PROGRESS, reason=ConflictReason.JOB_IN_PROGRESS, details=details
            )
        try:
            sent = send_admin_job(TaskName.BUILD_LIBRARY_INDEXES, job_id)
        except Exception:
            self._not_sent(job_id)
            raise
        if not sent:
            self._not_sent(job_id)
            raise Unavailable(AdminJobMessage.NOT_SENT)
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        audit_records.create_audit_record(
            AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after={"kind": _KIND}
        )
        return {"job_id": job_id, "status": Status.QUEUED}

    def read(self, job_id: str) -> dict[str, Any]:
        """One build job as the API shows it; 404 for any other job."""
        record = self._jobs.get_admin_job(job_id, _KIND)
        if record is None:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}

    def _not_sent(self, job_id: str) -> None:
        error = {"code": ErrorCode.UNAVAILABLE, "message": AdminJobMessage.NOT_SENT}
        self._jobs.update_admin_job_finished(job_id, datetime.now(UTC), error=error)


@singleton
def get_embeddings_builds() -> EmbeddingsBuilds:
    return EmbeddingsBuilds(admin_jobs)
