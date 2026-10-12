"""Job records: the `status` and `job.*` fields of every record that carries a leased job (tsg_sessions,
tsg_remediations).

A delivery claims a job with a time-limited lease, renews it while it works, and writes only while it still
owns it (fenced on task_id + epoch). The reaper's reads and its settling writes are here too; when to retry,
fail or re-send a job is decided in app/worker/jobs.py."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, ErrorCode, Lease, RunActionOutcome, Status, TaskName
from app.core.exceptions import LeaseLost  # the fenced writes raise it; workers import it from here too

_CLOCK_SKEW = timedelta(seconds=Lease.CLOCK_SKEW_SECONDS)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _ended(status: Status, now: datetime) -> dict[str, Any]:
    """A job's last fields, the same on every path that ends one: `active` false frees the asset (the unique
    "one active run per asset" index), and `finished_at` says when."""
    return {"status": status, "active": False, "finished_at": now}


def _failed(records: MongoCollection, error: dict[str, str], now: datetime) -> dict[str, Any]:
    """A failed job's fields, the same for its own failure and the reaper's. A run's last action ends with it,
    so a failed run never still reads "running" (G141); a remediation plan has no last action."""
    failed = {**_ended(Status.FAILED, now), "job.error": error}
    if records.name == Collection.SESSIONS:
        failed["last_action.outcome"] = RunActionOutcome.FAILED
    return failed


def find_job_status(records: MongoCollection, record_id: str) -> str | None:
    """A job record's status now; None once it is gone (its owner deleted the run, G214)."""
    found = records.find_one({"_id": record_id}, {"status": 1})
    return None if found is None else found.get("status")


class JobLease:
    """One delivery's ownership of one job record. Every write is fenced on (task_id, epoch), so once the
    lease is lost or a newer epoch replaced the job, this delivery can no longer change the record."""

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
        """Take the job if it is waiting (queued) or abandoned (running, lease expired) FOR THIS TASK. None =
        a duplicate or stale delivery: another delivery owns the job, it has moved on to another stage (a late
        copy of an earlier stage's message must not run that stage again on the next stage's record), it is
        not due yet (a copy arriving before the retry back-off ended), or a newer epoch replaced it."""
        now = _utc_now()
        claimed = records.find_one_and_update(
            {
                "_id": record_id,
                "job.epoch": epoch,
                "job.task": task,
                "$or": [
                    # Due only: a duplicate message must not run a job before its retry back-off ends.
                    # CLOCK_SKEW_SECONDS: another pod wrote due_at by its own, slightly different clock.
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
        `array_filters` pick the list items a change names, e.g. one plan path: "plan.paths.$[p].served" with
        [{"p.path_id": path_id}] (S24: a stale delivery can never change a path)."""
        if not self._write_if_owned(changes, array_filters):
            raise LeaseLost(self.record_id)

    def renew(self) -> bool:
        return self._write_if_owned({"job.lease_until": _utc_now() + timedelta(seconds=Lease.SECONDS)})

    def finish(
        self, changes: dict[str, Any] | None = None, array_filters: list[dict[str, Any]] | None = None
    ) -> None:
        """The job done, with the work's last `changes` in the same fenced write (`array_filters` as in
        write)."""
        ended = {**(changes or {}), **_ended(Status.DONE, _utc_now()), "job.lease_until": None}
        self.write(ended, array_filters)

    def queue_next(self, next_task: TaskName, changes: dict[str, Any] | None = None) -> None:
        """End this stage and queue the next one on the same record (same epoch); the caller sends it."""
        self.write(
            {
                **(changes or {}),
                "status": Status.QUEUED,
                "job.task": next_task,
                "job.due_at": _utc_now(),
                "job.attempts": 0,
                "job.lease_until": None,
            }
        )

    def give_back(self, delay_seconds: int) -> bool:
        """Queue the job again, due after the retry delay (a temporary outage)."""
        due_at = _utc_now() + timedelta(seconds=delay_seconds)
        return self._write_if_owned({"status": Status.QUEUED, "job.due_at": due_at, "job.lease_until": None})

    def fail(self, code: ErrorCode, message: str) -> bool:
        error = {"code": code, "message": message}
        return self._write_if_owned({**_failed(self._records, error, _utc_now()), "job.lease_until": None})

    def _write_if_owned(
        self, changes: dict[str, Any], array_filters: list[dict[str, Any]] | None = None
    ) -> bool:
        # Running too: once the reaper settles the record (re-queued or failed), the old owner is out at once;
        # without it a slow owner could still finish a job the reaper had already failed.
        fence = {
            "_id": self.record_id,
            "status": Status.RUNNING,
            "job.task_id": self.task_id,
            "job.epoch": self.epoch,
        }
        update = {"$set": {**changes, "updated_at": _utc_now()}}
        return self._records.update_one(fence, update, array_filters=array_filters).matched_count == 1


class JobRecords:
    """The reaper's view of one job collection: two index reads, and two writes that apply only when nothing
    changed since the read."""

    def __init__(self, records: MongoCollection) -> None:
        self._records = records

    def ensure_indexes(self) -> None:
        """The reaper's two scans, each one index read."""
        self._records.create_index([("status", 1), ("job.lease_until", 1)])
        self._records.create_index([("status", 1), ("job.due_at", 1)])

    def find_expired_leases(self, now: datetime) -> Iterable[dict[str, Any]]:
        return self._records.find({"status": Status.RUNNING, "job.lease_until": {"$lt": now}}, {"job": 1})

    def find_unsent(self, queued_before: datetime) -> Iterable[dict[str, Any]]:
        return self._records.find({"status": Status.QUEUED, "job.due_at": {"$lt": queued_before}}, {"job": 1})

    def requeue_expired(self, record: dict[str, Any], now: datetime) -> bool:
        """Queue a job whose lease ran out again, due now; False when its worker renewed or finished in
        between."""
        return self._if_lease_unchanged(record, {"status": Status.QUEUED, "job.due_at": now}, now)

    def fail_expired(self, record: dict[str, Any], error: dict[str, str], now: datetime) -> bool:
        """Fail a job whose lease ran out once too often; False when its worker renewed or finished in
        between."""
        return self._if_lease_unchanged(record, _failed(self._records, error, now), now)

    def _if_lease_unchanged(self, record: dict[str, Any], changes: dict[str, Any], now: datetime) -> bool:
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.RUNNING,
            "job.lease_until": record["job"]["lease_until"],
        }
        settled = self._records.update_one(
            unchanged_since_read, {"$set": {**changes, "job.lease_until": None, "updated_at": now}}
        )
        return bool(settled.modified_count)

    def push_due_forward(self, record: dict[str, Any], now: datetime) -> bool:
        """Move a queued job's due_at to now and count the re-send, only when nobody did since the read."""
        return self._if_still_queued(record, {"$set": {"job.due_at": now}, "$inc": {"job.resends": 1}})

    def fail_unsent(self, record: dict[str, Any], error: dict[str, str], now: datetime) -> bool:
        """Fail a job that was never claimed, only when nobody changed it since the read."""
        return self._if_still_queued(
            record, {"$set": {**_failed(self._records, error, now), "updated_at": now}}
        )

    def _if_still_queued(self, record: dict[str, Any], update: dict[str, Any]) -> bool:
        unchanged_since_read = {
            "_id": record["_id"],
            "status": Status.QUEUED,
            "job.due_at": record["job"]["due_at"],
        }
        return bool(self._records.update_one(unchanged_since_read, update).modified_count)
