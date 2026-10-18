"""The `status` and `job.*` fields of every record carrying a leased job (tsg_sessions, tsg_remediations):
claim, fenced writes, and the reaper's reads and settling writes."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, ErrorCode, Lease, RunActionOutcome, Status, TaskName
from app.core.exceptions import LeaseLost  # the fenced writes raise it; workers import it from here too

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


def ended_fields(status: Status, now: datetime) -> dict[str, Any]:
    """A job's last fields on every path that ends one: `active` false frees the asset, `finished_at` says
    when."""
    return {"status": status, "active": False, "finished_at": now}


def _failed(records: MongoCollection, error: dict[str, str], now: datetime) -> dict[str, Any]:
    """A failed job's fields; a run's last action fails with it, so it never still reads "running"."""
    failed = {**ended_fields(Status.FAILED, now), "job.error": error}
    if records.name == Collection.SESSIONS:
        failed["last_action.outcome"] = RunActionOutcome.FAILED
    return failed


def find_job_status(records: MongoCollection, record_id: str) -> str | None:
    """A job record's status now; None once it is gone."""
    found = records.find_one({"_id": record_id}, {"status": 1})
    return None if found is None else found.get("status")


class JobLease:
    """One delivery's ownership of one job record: every write is fenced on (task_id, epoch, attempts)."""

    def __init__(self, records: MongoCollection, record_id: str, epoch: int, task_id: str, attempts: int):
        self._records = records
        self.record_id = record_id
        self.epoch = epoch
        self.task_id = task_id
        self.attempts = attempts

    @classmethod
    def claim(
        cls, records: MongoCollection, record_id: str, epoch: int, task: str, task_id: str
    ) -> "JobLease | None":
        """Take the job if it is due (queued) or abandoned (running, lease expired) for this task and epoch;
        None for a duplicate, stale or early delivery."""
        now = datetime.now(UTC)
        claimed = records.find_one_and_update(
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
            projection={"job.attempts": 1},
            return_document=ReturnDocument.AFTER,
        )
        return (
            None if claimed is None else cls(records, record_id, epoch, task_id, claimed["job"]["attempts"])
        )

    def write(self, changes: dict[str, Any], array_filters: list[dict[str, Any]] | None = None) -> None:
        """A fenced write for the work in progress; LeaseLost when this delivery no longer owns the job.
        `array_filters` pick the list items a change names, e.g. [{"p.path_id": path_id}]."""
        if not self._write_if_owned(changes, array_filters):
            raise LeaseLost(self.record_id)

    def renew(self) -> bool:
        """Extend the lease while the work goes on; False once it is lost."""
        return self._write_if_owned({"job.lease_until": datetime.now(UTC) + timedelta(seconds=Lease.SECONDS)})

    def finish(
        self, changes: dict[str, Any] | None = None, array_filters: list[dict[str, Any]] | None = None
    ) -> None:
        """The job done, with the work's last `changes` in the same fenced write."""
        ended = {**(changes or {}), **ended_fields(Status.DONE, datetime.now(UTC)), "job.lease_until": None}
        self.write(ended, array_filters)

    def queue_next(self, next_task: TaskName, changes: dict[str, Any] | None = None) -> None:
        """End this stage and queue the next one on the same record (same epoch); the caller sends it."""
        self.write(
            {
                **(changes or {}),
                "status": Status.QUEUED,
                "job.task": next_task,
                "job.due_at": datetime.now(UTC),
                "job.attempts": 0,
                "job.lease_until": None,
            }
        )

    def give_back(self, delay_seconds: int) -> bool:
        """Queue the job again, due after the retry delay (a temporary outage)."""
        due_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
        return self._write_if_owned({"status": Status.QUEUED, "job.due_at": due_at, "job.lease_until": None})

    def fail(self, code: ErrorCode, message: str) -> bool:
        """The job failed with this error, while still owned."""
        error = {"code": code, "message": message}
        return self._write_if_owned(
            {**_failed(self._records, error, datetime.now(UTC)), "job.lease_until": None}
        )

    def _write_if_owned(
        self, changes: dict[str, Any], array_filters: list[dict[str, Any]] | None = None
    ) -> bool:
        """The write, only while the job is running under this delivery's claim (task id, epoch, attempts)."""
        # Running too: once the reaper settles the record, a slow old owner can no longer finish it.
        # Attempts too: Celery reuses the task id on a retry or a redelivery, so a hung delivery and a copy
        # that claimed the job again after its lease ran out share task id and epoch; only the newer claim's
        # count matches.
        fence = {
            "_id": self.record_id,
            "status": Status.RUNNING,
            "job.task_id": self.task_id,
            "job.epoch": self.epoch,
            "job.attempts": self.attempts,
        }
        update = {"$set": {**changes, "updated_at": datetime.now(UTC)}}
        return self._records.update_one(fence, update, array_filters=array_filters).matched_count == 1


class JobRecords:
    """The reaper's view of one job collection: two index reads, and writes that apply only when nothing
    changed since the read."""

    def __init__(self, records: MongoCollection) -> None:
        self._records = records

    def ensure_indexes(self) -> None:
        """The reaper's two scans, each one index read."""
        self._records.create_index([("status", 1), ("job.lease_until", 1)])
        self._records.create_index([("status", 1), ("job.due_at", 1)])

    def find_expired_leases(self, now: datetime) -> Iterable[dict[str, Any]]:
        """Running jobs whose lease ran out."""
        return self._records.find({"status": Status.RUNNING, "job.lease_until": {"$lt": now}}, {"job": 1})

    def find_unsent(self, queued_before: datetime) -> Iterable[dict[str, Any]]:
        """Queued jobs due before `queued_before` that no worker claimed."""
        return self._records.find({"status": Status.QUEUED, "job.due_at": {"$lt": queued_before}}, {"job": 1})

    def requeue_expired(self, record: dict[str, Any], now: datetime) -> bool:
        """Queue an expired job again, due now; False when its worker renewed or finished in between."""
        return self._if_lease_unchanged(record, {"status": Status.QUEUED, "job.due_at": now}, now)

    def fail_expired(self, record: dict[str, Any], error: dict[str, str], now: datetime) -> bool:
        """Fail a job whose lease ran out too often; False when its worker renewed or finished in between."""
        return self._if_lease_unchanged(record, _failed(self._records, error, now), now)

    def _if_lease_unchanged(self, record: dict[str, Any], changes: dict[str, Any], now: datetime) -> bool:
        """`changes`, only while the job is running with the lease the reaper read."""
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.RUNNING,
            "job.lease_until": record["job"]["lease_until"],
        }
        settled = self._records.update_one(
            unchanged_since_read, {"$set": {**changes, "job.lease_until": None, "updated_at": now}}
        )
        return bool(settled.modified_count)

    def push_due_forward(self, record: dict[str, Any], now: datetime, *, counted: bool) -> bool:
        """Move a queued job's due_at to now (and, `counted`, count the re-send), only when nobody did since
        the read."""
        return self._if_still_queued(
            record, {"$set": {"job.due_at": now}, "$inc": {"job.resends": int(counted)}}
        )

    def fail_unsent(self, record: dict[str, Any], error: dict[str, str], now: datetime) -> bool:
        """Fail a job that was never claimed, only when nobody changed it since the read."""
        return self._if_still_queued(
            record, {"$set": {**_failed(self._records, error, now), "updated_at": now}}
        )

    def _if_still_queued(self, record: dict[str, Any], update: dict[str, Any]) -> bool:
        """`update`, only while the job is queued with the due_at the reaper read."""
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.QUEUED,
            "job.due_at": record["job"]["due_at"],
        }
        return bool(self._records.update_one(unchanged_since_read, update).modified_count)
