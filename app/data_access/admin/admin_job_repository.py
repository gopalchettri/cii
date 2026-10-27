"""tsg_admin_jobs: the admin jobs (an embeddings build, an intelligence refresh), one active per kind."""

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

import structlog
from pymongo.collection import Collection as MongoCollection

from app.core.constants import (
    ADMIN_JOB_TASKS,
    AdminJobKind,
    AdminJobMessage,
    AdminJobs,
    Collection,
    ErrorCode,
    LogEvent,
    Status,
    module_of,
)
from app.core.exceptions import DuplicateRecord
from app.data_access.base import MongoRepository, Record

log = structlog.get_logger(__name__)
_DAY_SECONDS = int(timedelta(days=1).total_seconds())


class AdminJobRepository(MongoRepository):
    """tsg_admin_jobs: one active job per kind (a unique index over the `active` records); an ended job loses
    `active` and stays as history."""

    def __init__(self, collection: str | MongoCollection = Collection.ADMIN_JOBS) -> None:
        """tsg_admin_jobs with its one-active-per-kind index and its expiry."""
        super().__init__(
            collection,
            indexes=[
                {
                    "keys": "kind",
                    "unique": True,
                    "partialFilterExpression": {"active": True},
                    "name": "one_active_per_kind",
                }
            ],
            ttl=[("created_at", AdminJobs.KEEP_DAYS * _DAY_SECONDS)],
            field_lists={"without_active_flag": {"active": 0}},
            schema_version=1,
        )

    def create_admin_job(self, job: Record) -> str | None:
        """Creates `job` (with its created_at) as the active job of its kind in tsg_admin_jobs and returns its
        id; else the id of the active job of that kind. One still unfinished AdminJobs.STALE_AFTER_SECONDS
        after its creation, or its start once running (its worker died, its message was lost), is failed and
        replaced."""
        stale_before = job["created_at"] - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        stale = {"kind": job["kind"], **_abandoned_before(stale_before)}
        if self._create_active(job) or (
            self._finish(stale, Status.FAILED, job["created_at"], error=error) and self._create_active(job)
        ):
            return job["_id"]
        active = self.get(("_id",), kind=job["kind"], active=True)
        if active is None and self._create_active(job):  # the active job finished in between
            return job["_id"]
        return active["_id"] if active else None

    def get_admin_job(self, job_id: str, kind: AdminJobKind) -> Record | None:
        """The tsg_admin_jobs job with this id and kind, without its active flag; None for any other job."""
        return self.get("without_active_flag", _id=job_id, kind=kind)

    def update_admin_job_running(
        self, job_id: str, now: datetime, task_id: str | None = None, worker: str | None = None
    ) -> bool:
        """Marks a queued tsg_admin_jobs job running; False when it is no longer queued (a late or repeated
        message, so a redelivered copy never runs a second build)."""
        changes = {"status": Status.RUNNING, "started_at": now, "task_id": task_id, "worker": worker}
        return self.update(changes, _id=job_id, active=True, status=Status.QUEUED) > 0

    def update_admin_job_finished(
        self, job_id: str, now: datetime, *, result: Record | None = None, error: Record | None = None
    ) -> bool:
        """Ends an active tsg_admin_jobs job, done with its result or failed with its error and its
        job.failed line, once; False when it was no longer active (taken over as abandoned: it keeps its
        outcome)."""
        which = {"_id": job_id, "active": True}
        if error is None:
            return self._finish(which, Status.DONE, now, result=result)
        if not self._finish(which, Status.FAILED, now, error=error):
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
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "$or": [
                        {"status": {"$in": [Status.QUEUED, Status.RUNNING]}},
                        {"status": Status.FAILED, "finished_at": {"$gte": failed_since}},
                    ]
                }
            },
            {"$group": {"_id": {"kind": "$kind", "status": "$status"}, "count": {"$sum": 1}}},
        ]
        return {
            (row["_id"].get("kind") or "unknown", row["_id"]["status"]): row["count"]
            for row in self.collection.aggregate(pipeline)
        }

    def fail_stale_admin_jobs(self, now: datetime) -> list[Record]:
        """Fails every job still active AdminJobs.STALE_AFTER_SECONDS after its creation, or its start once
        running (its worker died or its message was lost), so none stays "running" until the next request of
        its kind; each one's id, kind and the error saved."""
        stale = _abandoned_before(now - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS))
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        jobs = list(self.collection.find(stale, {"_id": 1, "kind": 1}))
        return [
            job | {"error": error}
            for job in jobs
            if self._finish(stale | {"_id": job["_id"]}, Status.FAILED, now, error=error)
        ]

    def get_any_admin_job(self, job_id: str) -> Record | None:
        """The tsg_admin_jobs job with this id, whatever its kind, without its active flag."""
        return self.get("without_active_flag", _id=job_id)

    def is_admin_job_active(self, job_id: str) -> bool:
        """Whether the job is still queued or running: a cancelled one is not, so its worker stops early."""
        return self.get(("_id",), _id=job_id, active=True) is not None

    def cancel_admin_job(self, job_id: str, now: datetime, cancelled_by: str) -> bool:
        """Ends a queued or running job as cancelled; False when it had already ended. A queued one never
        starts (its worker finds it no longer queued); a running one cannot record its outcome over this."""
        return self._finish({"_id": job_id, "active": True}, Status.CANCELLED, now, cancelled_by=cancelled_by)

    def _create_active(self, job: Record) -> bool:
        """Inserts `job` as active; False when a job of its kind is still active."""
        try:
            self.create(job | {"active": True})
        except DuplicateRecord:
            return False
        return True

    def _finish(self, which: Record, status: Status, now: datetime, **fields: Any) -> bool:
        """Ends the active job `which` matches; True when there was one."""
        ended = {"$set": {"status": status, "finished_at": now, **fields}, "$unset": {"active": ""}}
        return self.collection.update_one(which, ended).matched_count > 0


def _abandoned_before(cutoff: datetime) -> Record:
    """The active jobs started before `cutoff`, or never started and created before it."""
    return {
        "active": True,
        "$or": [{"started_at": {"$lt": cutoff}}, {"started_at": None, "created_at": {"$lt": cutoff}}],
    }
