"""The leased job carried by tsg_sessions and tsg_remediations records (`status`, `job.*`): the claim, fenced
updates and the reaper's settling updates (the owner's cancel, resume and delete:
work_control_repository.py)."""

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import (
    Collection,
    ErrorMessage,
    Lease,
    RunActionOutcome,
    Status,
    TaskName,
)
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, LeaseLost
from app.core.logging import current_request_id

_CLOCK_SKEW = timedelta(seconds=Lease.CLOCK_SKEW_SECONDS)
#: What a claim reads of every job: its lease carries them, with the task's own fields.
_CLAIM_FIELDS = ("job.attempts", "job.due_at", "job.lease_until", "job.request_id", "job.waiting")


def new_job(task: TaskName, epoch: int, now: datetime, **fields: Any) -> dict[str, Any]:
    """A queued job, due now, never claimed, with the id of the API request that made it (each stage logs
    it); `fields` add the task's own inputs."""
    return {
        "task": task,
        "epoch": epoch,
        "request_id": current_request_id(),
        "task_id": None,
        "attempts": 0,
        "due_at": now,
        "lease_until": None,
        "resends": 0,
        "error": None,
        **fields,
    }


def ended_job_fields(status: Status, now: datetime | None = None) -> dict[str, Any]:
    """A job's last fields on every path that ends one: the lease ends and no retry notice is left."""
    return {
        "status": status,
        "finished_at": now or utc_now(),
        "job.lease_until": None,
        "job.retry": None,
    }


def retry_notice(reason: str | None, message: str, attempt: int | str, retry_at: datetime) -> dict[str, Any]:
    """The job.retry notice a status shows until the next try is claimed (a RetryNotice but its stage): why
    the job waits, which try failed (or an update pipeline's field path), when the next one comes."""
    return {
        "reason": reason,
        "message": message,
        "attempt": attempt,
        "max_attempts": Lease.MAX_ATTEMPTS,
        "retry_at": retry_at,
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
        `array_filters` pick the list items a change names, e.g. [{"p.path_id": path_id}]. A job claimed while
        it waited for another job reads queued until this first write after its wait (job.waiting cleared)."""
        waited = {"job.waiting": None} if (self.record.get("job") or {}).get("waiting") else {}
        update = {"$set": {**waited, **changes, "updated_at": utc_now()}}
        if self._records.update_one(self.fence, update, array_filters=array_filters).matched_count != 1:
            raise LeaseLost(self.record_id)

    def renew_job(self) -> bool:
        """Extend the job's lease while the work goes on; False once it is lost."""
        try:
            self.update_job({"job.lease_until": utc_now() + timedelta(seconds=Lease.SECONDS)})
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
        """The reaper's two scans and its failed-jobs count, each one index read, and GET /v1/admin/jobs's
        newest-first list."""
        self._records.create_index([("status", 1), ("job.lease_until", 1)])
        self._records.create_index([("updated_at", -1)])
        self._records.create_index([("status", 1), ("job.due_at", 1)])
        self._records.create_index([("status", 1), ("finished_at", 1)])

    def claim_job(
        self,
        record_id: str,
        epoch: int,
        task: str,
        task_id: str,
        fields: Iterable[str] = (),
        worker: str = "",
        retries: int = 0,
    ) -> JobLease | None:
        """Claim the job if it is due (queued), abandoned (running, lease expired) or this delivery's own lost
        claim (`retries`: its Celery retry count) for this task and epoch, returning its lease with `fields`
        and _CLAIM_FIELDS as they were before the claim (job.attempts counted; a running job's job.due_at is
        when it was last held, see _as_claimed); None for a duplicate, stale or early delivery."""
        now = utc_now()
        claimed = self._records.find_one_and_update(
            _claimable(record_id, epoch, task, now, task_id, retries),
            {
                "$set": {
                    "status": Status.RUNNING,
                    "job.task_id": task_id,
                    "job.task_retries": retries,  # its own retry may take back a claim whose answer was lost
                    "job.worker": worker,  # which worker runs it, since when: GET /v1/admin/jobs shows both
                    "job.started_at": now,
                    "job.lease_until": now + timedelta(seconds=Lease.SECONDS),
                    "job.resends": 0,  # it reached a worker: the reaper's re-send count starts again
                    "job.retry": None,  # the next try runs: the last try's outage notice no longer applies
                    "updated_at": now,
                },
                "$inc": {"job.attempts": 1},
            },
            projection=dict.fromkeys((*_CLAIM_FIELDS, *fields), 1),
            return_document=ReturnDocument.BEFORE,  # the old lease's end; the $set changes no field read
        )
        if claimed is None:
            return None
        _as_claimed(claimed["job"], now)
        return JobLease(self._records, record_id, epoch, task_id, claimed["job"]["attempts"], claimed)

    def why_not_claimed(self, record_id: str, epoch: int, task: str) -> dict[str, Any]:
        """Why a delivery could not claim its job, for the job.not_claimed log line: the record is missing
        (this worker reads another database?), another epoch or task, a live lease, another status, or not
        due yet."""
        try:
            record = self._records.find_one({"_id": record_id}, {"status": 1, "job": 1})
        except MONGO_UNAVAILABLE_ERRORS:
            return {"reason": "unknown"}  # only a log line: the delivery is dropped either way
        if record is None:
            return {"reason": "missing"}
        job, status = record.get("job") or {}, record.get("status")
        if job.get("epoch") != epoch:
            return {"reason": "other_epoch", "job_epoch": job.get("epoch")}
        if job.get("task") != task:
            return {"reason": "other_task", "job_task": job.get("task")}
        if status == Status.QUEUED and job.get("due_at"):
            return {
                "reason": "not_due",
                "due_in_seconds": round((job["due_at"] - utc_now()).total_seconds(), 1),
            }
        if status == Status.RUNNING:
            return {"reason": "leased", "worker": job.get("worker")}
        return {"reason": f"status_{status}"}

    def list_recent_jobs(
        self, since: datetime, statuses: Iterable[str] = (), task: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """The collection's jobs changed since `since`, newest first: its status and job fields only, for
        GET /v1/admin/jobs. `statuses` and `task` narrow it."""
        where: dict[str, Any] = {"job": {"$exists": True}, "updated_at": {"$gte": since}}
        if statuses:
            where["status"] = {"$in": list(statuses)}
        if task:
            where["job.task"] = task
        fields = ("status", "entity_id", "created_at", "updated_at", "finished_at", "job")
        return list(self._records.find(where, dict.fromkeys(fields, 1)).sort("updated_at", -1).limit(limit))

    def count_jobs_by_task(self, failed_since: datetime) -> dict[tuple[str, str], int]:
        """{(task, status): count} of the jobs queued, retrying (queued after an outage), running, and failed
        since `failed_since`: the reaper's tsg_jobs_current gauge."""
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "job": {"$exists": True},
                    "$or": [
                        {"status": {"$in": [Status.QUEUED, Status.RUNNING]}},
                        {"status": Status.FAILED, "finished_at": {"$gte": failed_since}},
                    ],
                }
            },
            {
                "$group": {
                    "_id": {
                        "task": "$job.task",
                        "status": {
                            "$cond": [
                                {
                                    "$and": [
                                        {"$eq": ["$status", Status.QUEUED]},
                                        {"$ifNull": ["$job.retry", False]},
                                    ]
                                },
                                "retrying",
                                "$status",
                            ]
                        },
                    },
                    "count": {"$sum": 1},
                }
            },
        ]
        return {
            (row["_id"].get("task") or "unknown", row["_id"]["status"]): row["count"]
            for row in self._records.aggregate(pipeline)
        }

    def get_job_record(self, record_id: str) -> dict[str, Any] | None:
        """The record's status and job fields (GET /v1/admin/jobs/{job_id}); None for no such job."""
        fields = ("status", "entity_id", "created_at", "updated_at", "finished_at", "job")
        return self._records.find_one({"_id": record_id, "job": {"$exists": True}}, dict.fromkeys(fields, 1))

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
        lease the reaper read; False when its worker renewed or finished in between. A requeue drops any
        retry notice and the lost delivery's task id and worker: the job waits because its worker was lost,
        not for an outage."""
        changes = (
            {
                "status": Status.QUEUED,
                "job.due_at": now,
                "job.retry": None,
                "job.task_id": None,
                "job.worker": None,
            }
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
            {"$set": {"job.due_at": now, "updated_at": now}, "$inc": {"job.resends": int(counted)}}
            if error is None
            else {"$set": {**failed_job_fields(self._records.name, error, now), "updated_at": now}}
        )
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.QUEUED,
            "job.due_at": record["job"]["due_at"],
        }
        return bool(self._records.update_one(unchanged_since_read, update).modified_count)

    def note_unsent_job(self, record_id: str, task: str, epoch: int, retry_at: datetime) -> None:
        """Show a queued job's refused send on its status (job.retry, cleared by its claim): the queue was
        unreachable, and the next try comes with the reaper's re-send at `retry_at`."""
        notice = retry_notice(None, ErrorMessage.REDIS_UNREACHABLE, "$job.attempts", retry_at)
        unclaimed = {"_id": record_id, "status": Status.QUEUED, "job.task": task, "job.epoch": epoch}
        self._records.update_one(unclaimed, [{"$set": {"job.retry": notice, "updated_at": utc_now()}}])

    def count_resend(self, record: dict[str, Any], resent_at: datetime) -> None:
        """Count a re-send the broker took, while the job still waits with the due_at the re-send set."""
        still_waiting = {"_id": record["_id"], "status": Status.QUEUED, "job.due_at": resent_at}
        self._records.update_one(still_waiting, {"$inc": {"job.resends": 1}})


def _as_claimed(job: dict[str, Any], now: datetime) -> None:
    """The job's fields read before its claim, as the claim's lease sees them: its attempt counted (the
    claim's $inc), and a running job's due_at when it was last held, its queue wait counted from then: a
    takeover's when the old lease ran out, a take-back's its own last claim or renewal."""
    job["attempts"] = job.get("attempts", 0) + 1
    if old_lease_end := job.pop("lease_until", None):
        last_held = old_lease_end - timedelta(seconds=Lease.SECONDS)
        job["due_at"] = old_lease_end if old_lease_end < now else last_held


def _claimable(
    record_id: str, epoch: int, task: str, now: datetime, task_id: str, retries: int
) -> dict[str, Any]:
    """The job record a delivery may claim: this task and epoch, due (queued), or abandoned (lease expired)
    or its own lost claim with attempts left."""
    return {
        "_id": record_id,
        "job.epoch": epoch,
        "job.task": task,
        "$or": [
            # Due only, so a duplicate message never runs a job before its back-off ends; the skew allows for
            # another pod's clock.
            {"status": Status.QUEUED, "job.due_at": {"$lte": now + _CLOCK_SKEW}},
            # Attempts left too: a redelivery never takes a job past Lease.MAX_ATTEMPTS (the reaper fails it).
            {
                "status": Status.RUNNING,
                "job.lease_until": {"$lt": now},
                "job.attempts": {"$lt": Lease.MAX_ATTEMPTS},
            },
            # Its own claim whose answer was lost (MongoDB saved it, the reply failed): its retry, a higher
            # Celery retry count under the same task id, takes it back at once. A redelivered copy of a live
            # delivery has the same count, so it never steals the job; a new send has a new task id.
            # ponytail: a take-back still uses an attempt; one lost on the last attempt waits for the reaper
            {
                "status": Status.RUNNING,
                "job.task_id": task_id,
                "job.task_retries": {"$lt": retries},
                "job.attempts": {"$lt": Lease.MAX_ATTEMPTS},
            },
        ],
    }
