"""The leased job on tsg_sessions, tsg_remediations and tsg_service_mappings records (`status`, `job.*`)."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from typing import Any

from pymongo import ReturnDocument
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Collection, ErrorMessage, Lease, RunActionOutcome, Status, TaskName
from app.core.exceptions import LeaseLost
from app.core.logging import current_job_origin, current_request_id
from app.crud.base import build_index

#: What a claim reads of every job (a plan's run is session_id; a run's or mapping's own id stands in).
_CLAIM_FIELDS: tuple[str, ...] = ("job.attempts", "job.due_at", "job.origin", "job.request_id", "job.waiting")
_CLAIM_FIELDS += ("job.waiting_since", "session_id")
_JOB_FIELDS = dict.fromkeys(("status", "entity_id", "created_at", "updated_at", "finished_at", "job"), 1)


def new_job(task: TaskName, epoch: int, now: datetime, **fields: Any) -> dict[str, Any]:
    """A queued job, due now, with the API request and origin that made it and the task's own `fields`."""
    return {
        "task": task,
        "epoch": epoch,
        "request_id": current_request_id(),
        "origin": current_job_origin(),
        "task_id": None,
        "attempts": 0,
        "due_at": now,
        "lease_until": None,
        "resends": 0,
        "error": None,
        **fields,
    }


def ended_job_fields(status: Status, now: datetime | None = None) -> dict[str, Any]:
    """A job's last fields: the lease ends and no retry notice is left."""
    return {"status": status, "finished_at": now or utc_now(), "job.lease_until": None, "job.retry": None}


def retry_notice(reason: str | None, message: str, attempt: int | str, retry_at: datetime) -> dict[str, Any]:
    """The job.retry notice a status shows until the next try is claimed."""
    return {
        "reason": reason,
        "message": message,
        "attempt": attempt,
        "max_attempts": Lease.MAX_ATTEMPTS,
        "retry_at": retry_at,
    }


def failed_job_fields(collection: str, error: dict[str, str], now: datetime | None = None) -> dict[str, Any]:
    """A failed job's fields; a run's last action fails with it."""
    failed = {**ended_job_fields(Status.FAILED, now), "job.error": error}
    if collection == Collection.SESSIONS:
        failed["last_action.outcome"] = RunActionOutcome.FAILED
    return failed


@dataclass
class JobLease:
    """One delivery's claim on one job record; `record` holds the fields the claim read."""

    records: MongoCollection
    record_id: str
    epoch: int
    task_id: str
    attempts: int
    record: dict[str, Any] = field(default_factory=dict)

    @property
    def collection(self) -> str:
        """The job record's collection name."""
        return self.records.name

    @property
    def origin(self) -> dict[str, Any]:
        """Who the job works for: its request, API call, caller and session."""
        job = self.record.get("job") or {}
        found = {"request_id": job.get("request_id"), "session_id": self.record.get("session_id") or self.record_id}
        return {name: value for name, value in (found | (job.get("origin") or {})).items() if value is not None}

    @property
    def fence(self) -> dict[str, Any]:
        """The filter that matches the job record only while this delivery owns it."""
        # Attempts too: a redelivery shares task id and epoch; only the newer claim's count matches.
        return {
            "_id": self.record_id,
            "status": Status.RUNNING,
            "job.task_id": self.task_id,
            "job.epoch": self.epoch,
            "job.attempts": self.attempts,
        }

    def update_job(
        self,
        changes: dict[str, Any],
        array_filters: list[dict[str, Any]] | None = None,
        operators: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Write `changes` (plus `operators`) while this delivery owns the job, else raise LeaseLost."""
        waited = {"job.waiting": None} if (self.record.get("job") or {}).get("waiting") else {}
        update = {**(operators or {}), "$set": {**waited, **changes, "updated_at": utc_now()}}
        if self.records.update_one(self.fence, update, array_filters=array_filters).matched_count != 1:
            raise LeaseLost(self.record_id)

    def renew_job(self) -> bool:
        """Extend the job's lease; False once it is lost."""
        try:
            self.update_job({"job.lease_until": utc_now() + timedelta(seconds=Lease.SECONDS)})
        except LeaseLost:
            return False
        return True

    renew = renew_job  # ponytail: keep_lease_alive renews job and controls leases through one `renew`


class JobRepository:
    """The job lease of one job collection: claim, the reaper's reads and its settling updates."""

    def __init__(self, records: MongoCollection) -> None:
        self._records = records

    def create_indexes(self) -> None:
        """The reaper's scans, its failed-jobs count and GET /v1/admin/jobs's newest-first list."""
        for keys in (
            [("status", 1), ("job.lease_until", 1)],
            [("updated_at", -1)],
            [("status", 1), ("job.due_at", 1)],
            [("status", 1), ("finished_at", 1)],
        ):
            build_index(self._records, keys, partial(self._records.create_index, keys))

    def claim_job(
        self, record_id: str, epoch: int, task: str, task_id: str, fields: Iterable[str] = (), worker: str = ""
    ) -> JobLease | None:
        """Claim a queued, due job of this task and epoch; None for a duplicate, stale or early delivery."""
        now = utc_now()
        claimed = self._records.find_one_and_update(
            # Due only: a duplicate never runs a job inside its back-off (the skew allows for pod clocks).
            {
                "_id": record_id,
                "job.epoch": epoch,
                "job.task": task,
                "status": Status.QUEUED,
                "job.due_at": {"$lte": now + timedelta(seconds=Lease.CLOCK_SKEW_SECONDS)},
            },
            {
                "$set": {
                    "status": Status.RUNNING,
                    "job.task_id": task_id,
                    "job.worker": worker,
                    "job.started_at": now,
                    "job.lease_until": now + timedelta(seconds=Lease.SECONDS),
                    "job.resends": 0,
                    "job.retry": None,
                    "updated_at": now,
                },
                "$inc": {"job.attempts": 1},
            },
            projection=dict.fromkeys((*_CLAIM_FIELDS, *fields), 1),
            return_document=ReturnDocument.AFTER,
        )
        if claimed is None:
            return None
        return JobLease(self._records, record_id, epoch, task_id, claimed["job"]["attempts"], claimed)

    def list_recent_jobs(
        self, since: datetime, statuses: Iterable[str] = (), task: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """The jobs changed since `since`, newest first, for GET /v1/admin/jobs."""
        where: dict[str, Any] = {"job": {"$exists": True}, "updated_at": {"$gte": since}}
        if statuses:
            where["status"] = {"$in": list(statuses)}
        if task:
            where["job.task"] = task
        return list(self._records.find(where, _JOB_FIELDS).sort("updated_at", -1).limit(limit))

    def count_jobs_by_task(self, failed_since: datetime) -> dict[tuple[str, str], int]:
        """{(task, status): count} of the jobs queued, retrying, running, and failed since `failed_since`."""
        live_or_failed = [
            {"status": {"$in": [Status.QUEUED, Status.RUNNING]}},
            {"status": Status.FAILED, "finished_at": {"$gte": failed_since}},
        ]
        retrying = {"$and": [{"$eq": ["$status", Status.QUEUED]}, {"$ifNull": ["$job.retry", False]}]}
        status = {"$cond": [retrying, "retrying", "$status"]}
        pipeline: list[dict[str, Any]] = [
            {"$match": {"job": {"$exists": True}, "$or": live_or_failed}},
            {"$group": {"_id": {"task": "$job.task", "status": status}, "count": {"$sum": 1}}},
        ]
        return {
            (row["_id"].get("task") or "unknown", row["_id"]["status"]): row["count"]
            for row in self._records.aggregate(pipeline)
        }

    def get_job_record(self, record_id: str) -> dict[str, Any] | None:
        """The record's status and job fields; None for no such job."""
        return self._records.find_one({"_id": record_id, "job": {"$exists": True}}, _JOB_FIELDS)

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
        """Queue an expired job again (or fail it with `error`) while it holds the lease the reaper read."""
        changes = (
            {"status": Status.QUEUED, "job.due_at": now, "job.retry": None, "job.task_id": None, "job.worker": None}
            if error is None
            else failed_job_fields(self._records.name, error, now)
        )
        unchanged = {"_id": record["_id"], "status": Status.RUNNING, "job.lease_until": record["job"]["lease_until"]}
        update = {"$set": {**changes, "job.lease_until": None, "updated_at": now}}
        return bool(self._records.update_one(unchanged, update).modified_count)

    def resend_or_fail_unsent_job(
        self, record: dict[str, Any], now: datetime, *, error: dict[str, str] | None = None
    ) -> bool:
        """Move a queued job's due_at to now (or fail it) while it has the due_at the reaper read."""
        changes = {"job.due_at": now} if error is None else failed_job_fields(self._records.name, error, now)
        unchanged = {"_id": record["_id"], "status": Status.QUEUED, "job.due_at": record["job"]["due_at"]}
        return bool(self._records.update_one(unchanged, {"$set": {**changes, "updated_at": now}}).modified_count)

    def note_unsent_job(self, record_id: str, task: str, epoch: int, retry_at: datetime) -> None:
        """Show a refused send on the queued job's status until its claim."""
        notice = retry_notice(None, ErrorMessage.REDIS_UNREACHABLE, "$job.attempts", retry_at)
        unclaimed = {"_id": record_id, "status": Status.QUEUED, "job.task": task, "job.epoch": epoch}
        self._records.update_one(unclaimed, [{"$set": {"job.retry": notice, "updated_at": utc_now()}}])

    def count_resend(self, record: dict[str, Any], resent_at: datetime) -> None:
        """Count a re-send the broker took, while the job still waits with that due_at."""
        still_waiting = {"_id": record["_id"], "status": Status.QUEUED, "job.due_at": resent_at}
        self._records.update_one(still_waiting, {"$inc": {"job.resends": 1}})
