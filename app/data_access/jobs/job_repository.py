"""The leased job carried by tsg_sessions and tsg_remediations records (`status`, `job.*`): the claim, fenced
updates and the reaper's settling updates (the owner's cancel, resume and delete:
work_control_repository.py)."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.collection import Collection as MongoCollection

from app.core.constants import (
    Collection,
    Lease,
    RunActionOutcome,
    Status,
    TaskName,
)
from app.core.exceptions import LeaseLost

_CLOCK_SKEW = timedelta(seconds=Lease.CLOCK_SKEW_SECONDS)


def new_job(task: TaskName, epoch: int, now: datetime, **fields: Any) -> dict[str, Any]:
    """A queued job, due now, never claimed; `fields` add the task's own inputs."""
    return {
        "task": task,
        "epoch": epoch,
        "task_id": None,
        "attempts": 0,
        "due_at": now,
        "lease_until": None,
        "resends": 0,
        "error": None,
        **fields,
    }


def ended_job_fields(status: Status, now: datetime | None = None) -> dict[str, Any]:
    """A job's last fields on every path that ends one: `active` false frees the asset, the lease ends, and
    no retry notice is left."""
    return {
        "status": status,
        "active": False,
        "finished_at": now or datetime.now(UTC),
        "job.lease_until": None,
        "job.retry": None,
    }


def failed_job_fields(collection: str, error: dict[str, str], now: datetime | None = None) -> dict[str, Any]:
    """A failed job's fields; a scenario session's last action fails with it, so it never still reads
    "running"."""
    failed = {**ended_job_fields(Status.FAILED, now), "job.error": error}
    if collection == Collection.SESSIONS:
        failed["last_action.outcome"] = RunActionOutcome.FAILED
    return failed


class JobLease:
    """One delivery's claim on one job record; every update is fenced on task id, epoch, attempts and
    running. `record` holds the fields the claim read for the job."""

    def __init__(
        self,
        records: MongoCollection,
        record_id: str,
        epoch: int,
        task_id: str,
        attempts: int,
        record: dict[str, Any] | None = None,
    ) -> None:
        self._records = records
        self.collection = records.name
        self.record_id = record_id
        self.epoch = epoch
        self.task_id = task_id
        self.attempts = attempts
        self.record = record or {}

    @property
    def fence(self) -> dict[str, Any]:
        """The filter that matches the job record only while this delivery owns it."""
        # Running too: once the reaper settles the record, a slow old owner can no longer finish it.
        # Attempts too: Celery reuses the task id on a retry or a redelivery, so a hung delivery and a copy
        # that claimed the job again after its lease ran out share task id and epoch; only the newer claim's
        # count matches.
        return {
            "_id": self.record_id,
            "status": Status.RUNNING,
            "job.task_id": self.task_id,
            "job.epoch": self.epoch,
            "job.attempts": self.attempts,
        }

    def update_job(self, changes: dict[str, Any], array_filters: list[dict[str, Any]] | None = None) -> None:
        """Write `changes` to the job record while this delivery owns it, else raise LeaseLost;
        `array_filters` pick the list items a change names, e.g. [{"p.path_id": path_id}]."""
        update = {"$set": {**changes, "updated_at": datetime.now(UTC)}}
        if self._records.update_one(self.fence, update, array_filters=array_filters).matched_count != 1:
            raise LeaseLost(self.record_id)

    def renew_job(self) -> bool:
        """Extend the job's lease while the work goes on; False once it is lost."""
        try:
            self.update_job({"job.lease_until": datetime.now(UTC) + timedelta(seconds=Lease.SECONDS)})
        except LeaseLost:
            return False
        return True

    renew = renew_job  # ponytail: keep_lease_alive renews job and controls leases through one `renew`


class JobRepository:
    """The job lease of one job collection (tsg_sessions or tsg_remediations): claim, the reaper's two index
    reads, and its settling updates that apply only when nothing changed since the read."""

    def __init__(self, records: MongoCollection) -> None:
        self._records = records

    def create_indexes(self) -> None:
        """The reaper's two scans, each one index read."""
        self._records.create_index([("status", 1), ("job.lease_until", 1)])
        self._records.create_index([("status", 1), ("job.due_at", 1)])

    def claim_job(
        self, record_id: str, epoch: int, task: str, task_id: str, fields: Iterable[str] = ()
    ) -> JobLease | None:
        """Claim the job if it is due (queued) or abandoned (running, lease expired) for this task and epoch,
        returning its lease with `fields` of the record; None for a duplicate, stale or early delivery."""
        now = datetime.now(UTC)
        claimed = self._records.find_one_and_update(
            {
                "_id": record_id,
                "job.epoch": epoch,
                "job.task": task,
                "$or": [
                    # Due only, so a duplicate message never runs a job before its back-off ends; the skew
                    # allows for another pod's clock.
                    {"status": Status.QUEUED, "job.due_at": {"$lte": now + _CLOCK_SKEW}},
                    {"status": Status.RUNNING, "job.lease_until": {"$lt": now}},
                ],
            },
            {
                "$set": {
                    "status": Status.RUNNING,
                    "job.task_id": task_id,
                    "job.lease_until": now + timedelta(seconds=Lease.SECONDS),
                    "job.resends": 0,  # it reached a worker: the reaper's re-send count starts again
                    "updated_at": now,
                },
                "$inc": {"job.attempts": 1},
            },
            projection=dict.fromkeys(("job.attempts", *fields), 1),
            return_document=ReturnDocument.AFTER,
        )
        if claimed is None:
            return None
        return JobLease(self._records, record_id, epoch, task_id, claimed["job"]["attempts"], claimed)

    def get_job_status(self, record_id: str) -> str | None:
        """The job record's status now; None once it is gone."""
        found = self._records.find_one({"_id": record_id}, {"status": 1})
        return None if found is None else found.get("status")

    def list_expired_jobs(self, now: datetime) -> Iterable[dict[str, Any]]:
        """Running jobs whose lease ran out."""
        return self._records.find({"status": Status.RUNNING, "job.lease_until": {"$lt": now}}, {"job": 1})

    def list_unsent_jobs(self, queued_before: datetime) -> Iterable[dict[str, Any]]:
        """Queued jobs due before `queued_before` that no worker claimed."""
        return self._records.find({"status": Status.QUEUED, "job.due_at": {"$lt": queued_before}}, {"job": 1})

    def requeue_or_fail_expired_job(
        self, record: dict[str, Any], now: datetime, error: dict[str, str] | None = None
    ) -> bool:
        """Queue an expired job again, due now (or fail it with `error`), only while it is running with the
        lease the reaper read; False when its worker renewed or finished in between."""
        changes = (
            {"status": Status.QUEUED, "job.due_at": now}
            if error is None
            else failed_job_fields(self._records.name, error, now)
        )
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.RUNNING,
            "job.lease_until": record["job"]["lease_until"],
        }
        update = {"$set": {**changes, "job.lease_until": None, "updated_at": now}}
        return bool(self._records.update_one(unchanged_since_read, update).modified_count)

    def resend_or_fail_unsent_job(
        self, record: dict[str, Any], now: datetime, *, counted: bool, error: dict[str, str] | None = None
    ) -> bool:
        """Move a queued job's due_at to now, counting the re-send when `counted` (or fail it with `error`),
        only while it is queued with the due_at the reaper read."""
        update = (
            {"$set": {"job.due_at": now}, "$inc": {"job.resends": int(counted)}}
            if error is None
            else {"$set": {**failed_job_fields(self._records.name, error, now), "updated_at": now}}
        )
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.QUEUED,
            "job.due_at": record["job"]["due_at"],
        }
        return bool(self._records.update_one(unchanged_since_read, update).modified_count)
