"""An organisation's work in progress and its owner's two controls over it: cancel (stop now, keep what is
done) and delete (gone for good). Every write is scoped to the caller's entity."""

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database

from app.core.constants import Collection, JobControl, RunActionKind, RunActionOutcome, Status
from app.data_access.job_records import ended_fields
from app.data_access.scenario.scenarios import MAPPED_VERSIONS, STOPPABLE_CONTROLS, RunCounts

_WORKING = [Status.QUEUED, Status.RUNNING]
_LISTED_FIELDS = dict.fromkeys(
    ("asset_id", "status", "job.due_at", "job.attempts", "user_id", "client_id", "created_at", "updated_at"),
    1,
)
_RUN_FIELDS = _LISTED_FIELDS | dict.fromkeys(("context.asset.name", "step", "job.task", "counts"), 1)
_PLAN_FIELDS = _LISTED_FIELDS | dict.fromkeys(("session_id", "scenario_id"), 1)
#: Set on a run by the first step of its delete, in the update that checks no job of it is at work: from then
#: on nothing new starts on it, so the delete's check for work is final.
DELETING_MARK = "deleting_at"
#: The status's summary of each kind of action: a cancel ends it as cancelled.
_SUMMARY_OF: dict[str, str] = {
    RunActionKind.NEXT_SET: "last_next_set",
    RunActionKind.REGENERATE: "last_regen",
}
#: A resume's update of its run: done again unless at work, and its cancel stamp gone.
_RESUMED = [
    {
        "$set": {
            "status": {
                "$cond": [{"$in": ["$status", [Status.DONE, Status.CANCELLED]]}, Status.DONE, "$status"]
            }
        }
    },
    {"$unset": "cancelled"},
]
#: The records found, oldest first (at most JobControl.LIST_MAX per kind), and how many match in all.
Found = tuple[list[dict[str, Any]], int]


class JobControlRecords:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = db[Collection.SCENARIOS]
        self._plans = db[Collection.REMEDIATIONS]
        self._counts = RunCounts(db)

    def working_runs(self, entity_id: int) -> Found:
        """The entity's runs whose job is queued or running, and the finished ones whose controls are still
        being matched: two indexed reads."""
        working = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        matching = {"entity_id": entity_id, "status": {"$nin": _WORKING}}
        matching["counts.controls_waiting"] = {"$gt": 0}  # the partial index holds only these
        return _oldest_first(self._sessions, _RUN_FIELDS, (working, matching))

    def working_plans(self, entity_id: int) -> Found:
        """The entity's remediation plans being written (queued or running)."""
        query = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        return _oldest_first(self._plans, _PLAN_FIELDS, (query,))

    def cancel_run(self, session_id: str, entity_id: int, who: dict[str, Any]) -> tuple[bool, int]:
        """(whether the run's job was stopped, how many scenarios' controls were): the job while queued or
        running, the controls while waiting, being mapped or failed; its controls delivery lease ended."""
        now = datetime.now(UTC)
        run, cancelled = {"_id": session_id, "entity_id": entity_id}, {**who, "at": now}
        stop_run = {
            "$set": _cancelled_job(cancelled, now) | {"last_action.outcome": RunActionOutcome.CANCELLED},
            "$unset": {"controls_delivery": ""},
        }
        before = self._sessions.find_one_and_update(
            {**run, "status": {"$in": _WORKING}}, stop_run, {"last_action.kind": 1}
        )
        stopped = before is not None
        summary = _SUMMARY_OF.get(str(((before or {}).get("last_action") or {}).get("kind")))
        if stopped and summary:
            self._sessions.update_one(
                {"_id": session_id, f"{summary}.outcome": RunActionOutcome.RUNNING},
                {"$set": {f"{summary}.outcome": RunActionOutcome.CANCELLED}},
            )
        controls = self._scenarios.update_many(
            {"session_id": session_id, "entity_id": entity_id, "controls.status": {"$in": STOPPABLE_CONTROLS}}
            | MAPPED_VERSIONS,
            {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
        ).modified_count
        if controls:
            self._counts.refresh(session_id)
        if controls and not stopped:  # a finished run whose controls were still being matched
            self._sessions.update_one(
                run,
                {"$set": {"cancelled": cancelled, "updated_at": now}, "$unset": {"controls_delivery": ""}},
            )
        return stopped, controls

    def cancel_plan(self, remediation_id: str, entity_id: int, who: dict[str, Any]) -> bool:
        """The plan's job stopped while it is queued or running; who and when kept on the plan."""
        now = datetime.now(UTC)
        stopped = self._plans.update_one(
            {"_id": remediation_id, "entity_id": entity_id, "status": {"$in": _WORKING}},
            {"$set": _cancelled_job({**who, "at": now}, now)},
        )
        return bool(stopped.modified_count)

    def resume_controls(self, session_id: str) -> int | None:
        """A run resumed on purpose: the controls a cancel stopped wait again (how many), and a run not at
        work reads done again. None when the run is being deleted (nothing resumed). Checked after the
        re-queue, so either this sees the delete's mark or the delete's check for work sees these controls.
        A cancel landing meanwhile wins: the run is updated only while its cancel stamp is the one read
        first, else the re-queue is undone and nothing is resumed (0)."""
        read = self._sessions.find_one({"_id": session_id}, {"cancelled.at": 1}) or {}
        stamp_read = {"_id": session_id, "cancelled.at": (read.get("cancelled") or {}).get("at")}
        requeued = self._scenarios.update_many(
            {"session_id": session_id, "controls.status": Status.CANCELLED},
            {"$set": {"controls.status": Status.QUEUED, "controls.queued_at": datetime.now(UTC)}},
        ).modified_count
        if is_being_deleted(self._sessions, session_id):
            if requeued:  # undone: as before the click
                self._stop_requeued(session_id)
            return None
        if not requeued:
            return 0
        if not self._sessions.update_one(stamp_read, _RESUMED).matched_count:
            self._stop_requeued(session_id)  # cancelled meanwhile: the cancel stands
            return 0
        self._counts.refresh(session_id)
        return requeued

    def _stop_requeued(self, session_id: str) -> None:
        """The run's waiting controls stopped again, as a resume found them."""
        self._scenarios.update_many(
            {"session_id": session_id, "controls.status": Status.QUEUED},
            {"$set": {"controls.status": Status.CANCELLED}},
        )

    def _work_left(self, session_id: str, entity_id: int) -> bool:
        """Whether anything of the run is still queued or running: its job, its mapped scenarios' controls, or
        one of its plans."""
        working, run = {"$in": _WORKING}, {"session_id": session_id, "entity_id": entity_id}
        return any(
            records.find_one(query, {"_id": 1}) is not None
            for records, query in (
                (self._sessions, {"_id": session_id, "status": working}),
                (self._scenarios, {**run, "controls.status": working} | MAPPED_VERSIONS),
                (self._plans, {**run, "status": working}),
            )
        )

    def delete_run(self, session_id: str, entity_id: int) -> tuple[dict[str, int], list[str]] | None:
        """The run removed for good: marked, checked for work, then its scenarios, its plans and the run last,
        so a delete cut short is finished by calling it again. (how many of each were removed, the plans'
        ids); None when the run is not this entity's or something of it is still at work."""
        run = {"_id": session_id, "entity_id": entity_id}
        marked = self._sessions.update_one(
            {**run, "status": {"$nin": _WORKING}}, {"$set": {DELETING_MARK: datetime.now(UTC)}}
        ).matched_count
        if not marked:
            return None
        if self._work_left(session_id, entity_id):  # final: nothing new can start on a marked run
            self._sessions.update_one(run, {"$unset": {DELETING_MARK: ""}})
            return None
        children = {"session_id": session_id, "entity_id": entity_id}
        plan_ids: list[str] = self._plans.distinct("_id", children)
        removed = {
            "scenarios": self._scenarios.delete_many(children).deleted_count,
            "remediation_plans": self._plans.delete_many(children).deleted_count,
        }
        self._sessions.delete_one(run)
        return removed, plan_ids


def is_being_deleted(sessions: MongoCollection, session_id: str) -> bool:
    """Whether the run carries its delete's mark, or is gone already."""
    found = sessions.find_one({"_id": session_id}, {DELETING_MARK: 1})
    return found is None or DELETING_MARK in found


def _cancelled_job(cancelled: dict[str, Any], now: datetime) -> dict[str, Any]:
    """A cancel's fields on a job record: ended (the asset free again), its lease ended, who and when kept."""
    return ended_fields(Status.CANCELLED, now) | {
        "job.lease_until": None,
        "cancelled": cancelled,
        "updated_at": now,
    }


def _oldest_first(
    records: MongoCollection, fields: dict[str, int], queries: Iterable[dict[str, Any]]
) -> Found:
    """Each query's records oldest first, at most JobControl.LIST_MAX each; the total is counted only when a
    list is full."""
    found: list[dict[str, Any]] = []
    total = 0
    for query in queries:
        page = list(records.find(query, fields).sort("created_at", 1).limit(JobControl.LIST_MAX))
        found += page
        total += records.count_documents(query) if len(page) == JobControl.LIST_MAX else len(page)
    return found, total
