"""tsg_admin_jobs: the admin jobs (an embeddings build, an intelligence refresh, a control-links preparation),
one active per kind."""

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any, Final

import structlog
from pymongo.collection import Collection as MongoCollection

from app.core.constants import (
    ADMIN_JOB_TASKS,
    AbandonReason,
    AdminJobMessage,
    AdminJobs,
    Collection,
    ErrorCode,
    Lease,
    LogEvent,
    Status,
    module_of,
)
from app.core.exceptions import DuplicateRecord
from app.core.singletons import singleton
from app.crud.base import MongoRepository, Record

log = structlog.get_logger(__name__)
_ABANDONED_ERROR: Final = {
    "code": ErrorCode.JOB_ABANDONED,
    "message": AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS),
}


class AdminJobRepository(MongoRepository):
    """tsg_admin_jobs: one active job per kind; an ended job loses `active` and stays as history."""

    def __init__(self, collection: str | MongoCollection = Collection.ADMIN_JOBS) -> None:
        unique_active = {"keys": "kind", "unique": True, "partialFilterExpression": {"active": True}}
        super().__init__(
            collection,
            indexes=[unique_active | {"name": "one_active_per_kind"}],
            ttl=[("created_at", int(timedelta(days=AdminJobs.KEEP_DAYS).total_seconds()))],
            field_lists={"without_active_flag": {"active": 0}},
            schema_version=1,
        )

    def create_admin_job(self, job: Record) -> str | None:
        """Create `job` as its kind's active job (failing an abandoned one); else the active job's id."""
        for _ in range(2):  # the second try after an abandoned job failed, or the active one finished
            try:
                self.create(job | {"active": True})
                return job["_id"]
            except DuplicateRecord:
                if not self.fail_stale_admin_jobs(job["created_at"], kind=job["kind"]):
                    active = self.get(("_id",), kind=job["kind"], active=True)
                    if active is not None:
                        return active["_id"]
        return None

    def get_admin_job(self, job_id: str, kind: str) -> Record | None:
        """The job with this id and kind, without its active flag."""
        return self.get("without_active_flag", _id=job_id, kind=kind)

    def update_admin_job_running(
        self, job_id: str, now: datetime, task_id: str | None = None, worker: str | None = None
    ) -> bool:
        """Mark a queued job running with its first heartbeat; False when it is no longer queued."""
        changes = {"status": Status.RUNNING, "started_at": now, "task_id": task_id, "worker": worker}
        return self.update(changes | _heartbeat(now), _id=job_id, active=True, status=Status.QUEUED) > 0

    def renew_admin_job(self, job_id: str, now: datetime) -> bool:
        """Stamp a running job's heartbeat; False once it ended."""
        return self.update(_heartbeat(now), _id=job_id, active=True, status=Status.RUNNING) > 0

    def update_admin_job_finished(
        self, job_id: str, now: datetime, *, result: Record | None = None, error: Record | None = None
    ) -> bool:
        """End an active job, done or failed (with its job.failed line), once; False when no longer active."""
        which = {"_id": job_id, "active": True}
        if error is None:
            return self._finish(which, Status.DONE, now, result=result)
        if not self._finish(which, Status.FAILED, now, error=error, result=result):
            return False
        kind = (self.get(("kind",), _id=job_id) or {}).get("kind") or "unknown"
        task = ADMIN_JOB_TASKS.get(kind, kind)
        log.warning(LogEvent.JOB_FAILED, task=task, module=module_of(task), record_id=job_id, **error)
        return True

    def list_recent_admin_jobs(
        self, since: datetime, statuses: Iterable[str] = (), kind: str | None = None, limit: int = 100
    ) -> list[Record]:
        """Admin jobs created since `since`, newest first, for GET /v1/admin/jobs."""
        where: dict[str, Any] = {"created_at": {"$gte": since}}
        if statuses:
            where["status"] = {"$in": list(statuses)}
        if kind:
            where["kind"] = kind
        return list(self.collection.find(where, {"active": 0}).sort("created_at", -1).limit(limit))

    def count_admin_jobs_by_kind(self, failed_since: datetime) -> dict[tuple[str, str], int]:
        """{(kind, status): count} of the admin jobs queued, running, and failed since `failed_since`."""
        live_or_failed = [
            {"status": {"$in": [Status.QUEUED, Status.RUNNING]}},
            {"status": Status.FAILED, "finished_at": {"$gte": failed_since}},
        ]
        pipeline: list[dict[str, Any]] = [
            {"$match": {"$or": live_or_failed}},
            {"$group": {"_id": {"kind": "$kind", "status": "$status"}, "count": {"$sum": 1}}},
        ]
        return {
            (row["_id"].get("kind") or "unknown", row["_id"]["status"]): row["count"]
            for row in self.collection.aggregate(pipeline)
        }

    def fail_stale_admin_jobs(self, now: datetime, **where: Any) -> list[Record]:
        """Fail every abandoned job of `where`: its heartbeat ran out, or it has none after an hour."""
        never_started_before = now - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        stale = {
            "active": True,
            "$or": [{"lease_until": {"$lt": now}}, {"lease_until": None, "created_at": {"$lt": never_started_before}}],
        } | where
        failed = []
        for job in self.collection.find(stale, {"_id": 1, "kind": 1, "status": 1}):
            started = job.get("status") != Status.QUEUED
            reason = AbandonReason.WORKER_STOPPED if started else AbandonReason.NEVER_STARTED
            error = _ABANDONED_ERROR | {"reason": reason}
            if self._finish(stale | {"_id": job["_id"]}, Status.FAILED, now, error=error):
                failed.append({"_id": job["_id"], "kind": job.get("kind"), "error": error})
        return failed

    def get_any_admin_job(self, job_id: str) -> Record | None:
        """The job with this id, whatever its kind, without its active flag."""
        return self.get("without_active_flag", _id=job_id)

    def is_admin_job_active(self, job_id: str) -> bool:
        """Whether the job is still queued or running."""
        return self.get(("_id",), _id=job_id, active=True) is not None

    def cancel_admin_job(self, job_id: str, now: datetime, cancelled_by: str) -> bool:
        """End a queued or running job as cancelled; False when it had already ended."""
        return self._finish({"_id": job_id, "active": True}, Status.CANCELLED, now, cancelled_by=cancelled_by)

    def _finish(self, which: Record, status: Status, now: datetime, **fields: Any) -> bool:
        ended = {"$set": {"status": status, "finished_at": now, **fields}, "$unset": {"active": ""}}
        return self.collection.update_one(which, ended).matched_count > 0


@singleton
def get_admin_job_repository() -> AdminJobRepository:
    return AdminJobRepository()


def _heartbeat(now: datetime) -> Record:
    return {"lease_until": now + timedelta(seconds=Lease.SECONDS)}
