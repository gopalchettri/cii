"""tsg_admin_jobs: the admin jobs (an embeddings build, an intelligence refresh), one active per kind."""

from datetime import datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.constants import AdminJobKind, AdminJobMessage, AdminJobs, Collection, ErrorCode, Status
from app.core.exceptions import DuplicateRecord
from app.data_access.base import MongoRepository, Record

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
        after its creation (its worker died, its message was lost) is failed and replaced."""
        stale_before = job["created_at"] - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        stale = {"kind": job["kind"], "active": True, "created_at": {"$lt": stale_before}}
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

    def update_admin_job_running(self, job_id: str, now: datetime) -> bool:
        """Marks a queued tsg_admin_jobs job running; False when it is no longer queued (a late or repeated
        message, so a redelivered copy never runs a second build)."""
        changes = {"status": Status.RUNNING, "started_at": now}
        return self.update(changes, _id=job_id, active=True, status=Status.QUEUED) > 0

    def update_admin_job_finished(
        self, job_id: str, now: datetime, *, result: Record | None = None, error: Record | None = None
    ) -> bool:
        """Ends an active tsg_admin_jobs job, done with its result or failed with its error, once; False when
        it was no longer active (taken over as abandoned: it keeps the outcome it already has)."""
        which = {"_id": job_id, "active": True}
        if error is not None:
            return self._finish(which, Status.FAILED, now, error=error)
        return self._finish(which, Status.DONE, now, result=result)

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
