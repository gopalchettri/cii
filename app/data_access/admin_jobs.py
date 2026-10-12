"""tsg_admin_jobs: one record per admin job (#18 embeddings build), kept AdminJobs.KEEP_DAYS.

A record is `active` while queued or running; a unique index over the active records allows one of each kind
at a time, so two requests at the same moment can never start two builds. Done or failed: `active` is removed
and the record stays as its history: {_id, kind, status, requested_by, created_at, started_at, finished_at,
result, error}."""

from datetime import datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import AdminJobs, Collection, Status
from app.core.database import expire_documents_after

Doc = dict[str, Any]


class AdminJobRecords:
    def __init__(self, db: Database) -> None:
        self._jobs = db[Collection.ADMIN_JOBS]

    def ensure_indexes(self) -> None:
        self._jobs.create_index(
            "kind", unique=True, partialFilterExpression={"active": True}, name="one_active_per_kind"
        )
        keep = int(timedelta(days=AdminJobs.KEEP_DAYS).total_seconds())
        expire_documents_after(self._jobs, "created_at", keep)

    def insert_active(self, job: Doc) -> bool:
        """False when a job of the same kind is still active: nothing written."""
        try:
            self._jobs.insert_one(job | {"active": True})
        except DuplicateKeyError:
            return False
        return True

    def read(self, job_id: str) -> Doc | None:
        return self._jobs.find_one({"_id": job_id}, {"active": 0})

    def find_active(self, kind: str) -> Doc | None:
        return self._jobs.find_one({"kind": kind, "active": True}, {"_id": 1})

    def end_stale(self, kind: str, created_before: datetime, error: Doc, now: datetime) -> bool:
        """Fails the active job of `kind` made before `created_before` (abandoned); True if there was one."""
        stale = {"kind": kind, "active": True, "created_at": {"$lt": created_before}}
        return self._end(stale, Status.FAILED, now, error=error) is not None

    def mark_running(self, job_id: str, now: datetime) -> bool:
        """False when the job is no longer active (done, failed or taken over): a late or repeated message."""
        changed = self._jobs.find_one_and_update(
            {"_id": job_id, "active": True}, {"$set": {"status": Status.RUNNING, "started_at": now}}
        )
        return changed is not None

    def end(self, job_id: str, now: datetime, *, result: Doc | None = None, error: Doc | None = None) -> bool:
        """Done with its result, or failed with its error. False when it was no longer active (taken over as
        abandoned): nothing written, so the record keeps the outcome it already has."""
        which = {"_id": job_id, "active": True}
        if error is not None:
            return self._end(which, Status.FAILED, now, error=error) is not None
        return self._end(which, Status.DONE, now, result=result) is not None

    def _end(self, which: Doc, status: Status, now: datetime, **fields: Any) -> Doc | None:
        """Only an active job ends, once: a job taken over keeps the failure that took it over."""
        return self._jobs.find_one_and_update(
            which,
            {"$set": {"status": status, "finished_at": now, **fields}, "$unset": {"active": ""}},
            return_document=ReturnDocument.AFTER,
        )
