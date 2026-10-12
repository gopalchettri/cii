"""An organisation's own work in progress, and its owner's two controls over it (G214, owner 2026-10-12):
cancel (stop now, keep what is done) and delete (gone for good). Every write is scoped to the caller's entity,
so it can never touch another organisation's records, nor a run a worker holds when it must not.

Why a cancel needs nothing from the workers: a worker writes only while its job is `running` under its
own task id (job_records.JobLease), and checks that right before it saves a scenario (PlanProgress.hold), so
it stops once the run is `cancelled`; the claim and the reaper read only `queued` and `running`; the cancel
ends the run's controls delivery lease, so a delivery mapping it stops after its scenario in hand; the
controls claim reads only queued or running controls, and the sweep stops any a cancelled run still has
(scenario_controls.ControlSweep)."""

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database

from app.core.constants import Collection, JobControl, RunActionKind, RunActionOutcome, Status
from app.data_access.run_counts import RunCounts
from app.data_access.scenario_controls import STOPPABLE_CONTROLS
from app.data_access.scenarios import MAPPED_VERSIONS

_WORKING = [Status.QUEUED, Status.RUNNING]
_RUN_FIELDS = {
    "asset_id": 1,
    "context.asset.name": 1,
    "status": 1,
    "step": 1,
    "job.task": 1,
    "job.due_at": 1,
    "job.attempts": 1,
    "user_id": 1,
    "client_id": 1,
    "counts": 1,
    "created_at": 1,
    "updated_at": 1,
}
_PLAN_FIELDS = {
    "session_id": 1,
    "scenario_id": 1,
    "asset_id": 1,
    "status": 1,
    "job.due_at": 1,
    "job.attempts": 1,
    "user_id": 1,
    "client_id": 1,
    "created_at": 1,
    "updated_at": 1,
}
#: Set on a run by the first step of its delete, in the same conditional update that checks no job of it is
#: queued or running: from then on nothing new starts on it (next set, regenerate, controls resumed), so the
#: delete's check for work that follows is final, and a click racing the delete gets 409, never 202 (G214).
DELETING_MARK = "deleting_at"
#: The status's summary of each kind of action (data_access/run_actions.py): a cancel ends it as cancelled.
_SUMMARY_OF: dict[str, str] = {
    RunActionKind.NEXT_SET: "last_next_set",
    RunActionKind.REGENERATE: "last_regen",
}
#: The records found, oldest first (at most JobControl.LIST_MAX per kind), and how many match in all.
Found = tuple[list[dict[str, Any]], int]


class JobControlRecords:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = db[Collection.SCENARIOS]
        self._plans = db[Collection.REMEDIATIONS]
        self._counts = RunCounts(db)  # a run's counts follow its scenarios' controls (Rule S12)

    def working_runs(self, entity_id: int) -> Found:
        """The entity's runs whose job is queued or running, and those finished whose controls are still being
        matched: two indexed reads (SessionRepository.ensure_indexes), never a walk over every run it made."""
        working = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        matching = {"entity_id": entity_id, "status": {"$nin": _WORKING}}
        matching["counts.controls_waiting"] = {"$gt": 0}  # the partial index holds only these
        return _oldest_first(self._sessions, _RUN_FIELDS, (working, matching))

    def working_plans(self, entity_id: int) -> Found:
        """The entity's remediation plans being written (queued or running)."""
        query = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        return _oldest_first(self._plans, _PLAN_FIELDS, (query,))

    def cancel_run(self, session_id: str, entity_id: int, who: dict[str, Any]) -> tuple[bool, int]:
        """(whether the run's job was stopped, how many scenarios' controls were): its job only while it
        is queued or running, the controls the controls job maps while waiting, being mapped or failed. Who
        and when kept on the run; its controls delivery lease ended."""
        now = datetime.now(UTC)
        run, cancelled = {"_id": session_id, "entity_id": entity_id}, {**who, "at": now}
        before = self._sessions.find_one_and_update(
            {**run, "status": {"$in": _WORKING}}, _run_cancelled(cancelled, now), {"last_action.kind": 1}
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
            self._counts.refresh(session_id)  # controls_waiting → controls_cancelled: list and board follow
        if controls and not stopped:  # a finished run whose controls were still being matched
            self._sessions.update_one(
                run,
                {"$set": {"cancelled": cancelled, "updated_at": now}, "$unset": {"controls_delivery": ""}},
            )
        return stopped, controls

    def cancel_plan(self, remediation_id: str, entity_id: int, who: dict[str, Any]) -> bool:
        """The plan's job stopped while it is queued or running; who and when kept on the plan."""
        now = datetime.now(UTC)
        return bool(
            self._plans.update_one(
                {"_id": remediation_id, "entity_id": entity_id, "status": {"$in": _WORKING}},
                {
                    "$set": {
                        "status": Status.CANCELLED,
                        "active": False,
                        "finished_at": now,
                        "job.lease_until": None,
                        "cancelled": {**who, "at": now},
                        "updated_at": now,
                    }
                },
            ).modified_count
        )

    def resume_controls(self, session_id: str) -> int | None:
        """A run resumed on purpose (next set, regenerate): the controls its owner's cancel stopped wait again
        (how many), and a run that is not at work no longer reads as cancelled: done, its controls matched
        again (a resumed job's own update clears its mark). None when the run is being deleted: nothing
        resumed. Checked after the re-queue: either this sees the delete's mark, or the delete's check for
        work sees these controls; never neither."""
        requeued = self._scenarios.update_many(
            {"session_id": session_id, "controls.status": Status.CANCELLED},
            {"$set": {"controls.status": Status.QUEUED, "controls.queued_at": datetime.now(UTC)}},
        ).modified_count
        if is_being_deleted(self._sessions, session_id):
            if requeued:  # undone: as before the click
                self._scenarios.update_many(
                    {"session_id": session_id, "controls.status": Status.QUEUED},
                    {"$set": {"controls.status": Status.CANCELLED}},
                )
            return None
        if requeued:
            self._sessions.update_one(
                {"_id": session_id, "status": {"$in": [Status.DONE, Status.CANCELLED]}},
                {"$set": {"status": Status.DONE}, "$unset": {"cancelled": ""}},
            )
            self._counts.refresh(session_id)
        return requeued

    def _work_left(self, session_id: str, entity_id: int) -> bool:
        """Whether anything of the run is still queued or running: its job, the controls of a scenario the
        controls job maps (MAPPED_VERSIONS: a replaced version's are never mapped), or one of its plans."""
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
        """The run removed for good: marked first (DELETING_MARK), then checked for work, then its scenarios
        and remediation plans, the run last, so a delete cut short (an outage between the steps) is finished
        by calling it again: the run is still there to be found. (how many of each were removed, the plans'
        ids); None when the run is not this entity's or anything of it is still queued or running (its mark
        is then taken off again). Scenarios before plans: a plan request re-reads its scenario after its
        insert (services/remediation/requests.py), so no plan outlives its scenario."""
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


def _run_cancelled(cancelled: dict[str, Any], now: datetime) -> dict[str, Any]:
    """A cancel's update of the run: the asset is free again (one active run per asset), the job's lease and
    the controls delivery's ended."""
    return {
        "$set": {
            "status": Status.CANCELLED,
            "active": False,
            "finished_at": now,
            "job.lease_until": None,
            "last_action.outcome": RunActionOutcome.CANCELLED,
            "cancelled": cancelled,
            "updated_at": now,
        },
        "$unset": {"controls_delivery": ""},
    }


def _oldest_first(
    records: MongoCollection, fields: dict[str, int], queries: Iterable[dict[str, Any]]
) -> Found:
    """Each query's records oldest first, at most JobControl.LIST_MAX each; how many match in all is counted
    only when a list is full (the list never hides that it was cut)."""
    found: list[dict[str, Any]] = []
    total = 0
    for query in queries:
        page = list(records.find(query, fields).sort("created_at", 1).limit(JobControl.LIST_MAX))
        found += page
        total += records.count_documents(query) if len(page) == JobControl.LIST_MAX else len(page)
    return found, total
