"""Job control across tsg_sessions, tsg_scenarios and tsg_remediations: the owner's cancel, resume and delete
of scenario sessions and remediation plans, and the controls sweep. It writes through each owning
repository's collection: a session first, then its cards."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, JobControl, Lease, RunActionKind, RunActionOutcome, Status
from app.data_access.jobs.job_repository import ended_job_fields
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.data_access.scenario.threat_scenario_repository import (
    FAILED_WITH_ATTEMPTS_LEFT,
    MAPPED_VERSIONS,
    STOPPABLE_CONTROLS,
    SWEPT,
    ThreatScenarioRepository,
    waiting_controls,
)
from app.data_access.scenario.threat_scenario_session_repository import (
    DELETING_MARK,
    ThreatScenarioSessionRepository,
)

_WORKING = [Status.QUEUED, Status.RUNNING]
_LISTED_FIELDS = dict.fromkeys(
    ("asset_id", "status", "job.due_at", "job.attempts", "user_id", "client_id", "created_at", "updated_at"),
    1,
)
_SCENARIO_SESSION_FIELDS = _LISTED_FIELDS | dict.fromkeys(
    ("context.asset.name", "step", "job.task", "counts"), 1
)
_REMEDIATION_PLAN_FIELDS = _LISTED_FIELDS | dict.fromkeys(("session_id", "scenario_id"), 1)
#: The status's summary of each kind of action: a cancel ends it as cancelled.
_SUMMARY_OF: dict[str, str] = {
    RunActionKind.NEXT_SET: "last_next_set",
    RunActionKind.REGENERATE: "last_regen",
}
#: A resume's first update of its scenario session: done again unless at work (its cancel stamp kept).
_DONE_AGAIN = [
    {
        "$set": {
            "status": {
                "$cond": [{"$in": ["$status", [Status.DONE, Status.CANCELLED]]}, Status.DONE, "$status"]
            }
        }
    }
]
#: How far back the sweep looks for scenarios of any status whose session is gone: a write racing a delete
#: lands within one job's longest run. ponytail: scans the session_id index, a created_at index if it is slow.
_ORPHANS_WRITTEN_WITHIN = timedelta(seconds=Lease.MAX_JOB_SECONDS)
#: The records found, oldest first (at most JobControl.LIST_MAX per kind), and how many match in all.
Found = tuple[list[dict[str, Any]], int]


class WorkControlRepository:
    """An organisation's work in progress (tsg_sessions, tsg_scenarios, tsg_remediations) and its owner's
    controls over it: cancel (stop now, keep what is done), resume, and delete (gone for good). Every write
    is scoped to the caller's entity."""

    def __init__(
        self,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        remediations: RemediationRepository,
    ) -> None:
        self._sessions, self._scenarios, self._remediations = sessions, scenarios, remediations

    def list_working_scenario_sessions(self, entity_id: int) -> Found:
        """The entity's scenario sessions whose job is queued or running, and the finished ones whose controls
        are still being matched: two indexed reads."""
        working = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        matching = {"entity_id": entity_id, "status": {"$nin": _WORKING}}
        matching["counts.controls_waiting"] = {"$gt": 0}  # the partial index holds only these
        return _oldest_first(self._sessions.collection, _SCENARIO_SESSION_FIELDS, (working, matching))

    def list_working_remediation_plans(self, entity_id: int) -> Found:
        """The entity's remediation plans being written (queued or running)."""
        query = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        return _oldest_first(self._remediations.collection, _REMEDIATION_PLAN_FIELDS, (query,))

    def cancel_scenario_session(
        self, session_id: str, entity_id: int, who: dict[str, Any]
    ) -> tuple[bool, int]:
        """(whether the scenario session's job was stopped, how many scenarios' controls were): the job while
        queued or running, the controls while waiting, being mapped or failed with attempts left; its controls
        delivery lease ended. Order: the session (job cancelled, delivery lease unset), its summary's outcome,
        the cards, the counts, then the stamp on a finished session."""
        sessions, now = self._sessions.collection, datetime.now(UTC)
        session, cancelled = {"_id": session_id, "entity_id": entity_id}, {**who, "at": now}
        stop_session = {
            "$set": _cancelled_job(cancelled, now) | {"last_action.outcome": RunActionOutcome.CANCELLED},
            "$unset": {"controls_delivery": ""},
        }
        before = sessions.find_one_and_update(
            {**session, "status": {"$in": _WORKING}}, stop_session, {"last_action.kind": 1}
        )
        stopped = before is not None
        summary = _SUMMARY_OF.get(str(((before or {}).get("last_action") or {}).get("kind")))
        if stopped and summary:
            sessions.update_one(
                {"_id": session_id, f"{summary}.outcome": RunActionOutcome.RUNNING},
                {"$set": {f"{summary}.outcome": RunActionOutcome.CANCELLED}},
            )
        controls = self._scenarios.collection.update_many(
            {"session_id": session_id, "entity_id": entity_id, "$and": [STOPPABLE_CONTROLS, MAPPED_VERSIONS]},
            {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
        ).modified_count
        if controls:
            self._sessions.update_scenario_session_counts(session_id)
        if controls and not stopped:  # a finished scenario session whose controls were still being matched
            sessions.update_one(
                session,
                {"$set": {"cancelled": cancelled, "updated_at": now}, "$unset": {"controls_delivery": ""}},
            )
        return stopped, controls

    def cancel_remediation_plan(self, remediation_id: str, entity_id: int, who: dict[str, Any]) -> bool:
        """The plan's job stopped while it is queued or running; who and when kept on the plan."""
        now = datetime.now(UTC)
        stopped = self._remediations.collection.update_one(
            {"_id": remediation_id, "entity_id": entity_id, "status": {"$in": _WORKING}},
            {"$set": _cancelled_job({**who, "at": now}, now)},
        )
        return bool(stopped.modified_count)

    def resume_scenario_controls(self, session_id: str, cancelled_at: datetime | None) -> int | None:
        """A scenario session resumed on purpose: the controls a cancel stopped wait again (how many), and a
        session not at work reads done again. None when it is being deleted (nothing resumed). The session
        changes first, so the sweep never stops the re-queued controls as a cancelled session's; the delete's
        mark is checked again after the re-queue, so either this sees it or the delete's check for work sees
        these controls. A cancel landing since the caller read the session wins: the session changes only
        while its cancel stamp is still `cancelled_at` (the one the caller saw, None for none), else this
        re-queue is undone and nothing is resumed (0)."""
        sessions, scenarios = self._sessions.collection, self._scenarios.collection
        stopped = {"session_id": session_id, "controls.status": Status.CANCELLED}
        if scenarios.find_one(stopped, {"_id": 1}) is None:
            return 0
        stamp_seen = {"_id": session_id, "cancelled.at": cancelled_at}
        if not sessions.update_one(
            {**stamp_seen, DELETING_MARK: {"$exists": False}}, _DONE_AGAIN
        ).matched_count:
            return None if self._sessions.is_being_deleted(session_id) else 0
        requeued_at = datetime.now(UTC)
        requeued = scenarios.update_many(
            stopped, {"$set": {"controls.status": Status.QUEUED, "controls.queued_at": requeued_at}}
        ).modified_count
        if self._sessions.is_being_deleted(session_id):
            self._stop_requeued_controls(session_id, requeued_at)  # undone: as before the click
            return None
        if not sessions.update_one(stamp_seen, {"$unset": {"cancelled": ""}}).matched_count:
            self._stop_requeued_controls(session_id, requeued_at)  # cancelled meanwhile: the cancel stands
            return 0
        self._sessions.update_scenario_session_counts(session_id)
        return requeued

    def _stop_requeued_controls(self, session_id: str, requeued_at: datetime) -> None:
        """The controls a resume queued again at `requeued_at`, stopped again while they still wait."""
        self._scenarios.collection.update_many(
            {"session_id": session_id, "controls.status": Status.QUEUED, "controls.queued_at": requeued_at},
            {"$set": {"controls.status": Status.CANCELLED}},
        )

    def _work_left(self, session_id: str, entity_id: int) -> bool:
        """Whether anything of the scenario session is still queued or running: its job, its mapped
        scenarios' controls, or one of its plans."""
        working, children = {"$in": _WORKING}, {"session_id": session_id, "entity_id": entity_id}
        return any(
            records.find_one(query, {"_id": 1}) is not None
            for records, query in (
                (self._sessions.collection, {"_id": session_id, "status": working}),
                (self._scenarios.collection, {**children, "controls.status": working} | MAPPED_VERSIONS),
                (self._remediations.collection, {**children, "status": working}),
            )
        )

    def delete_scenario_session(
        self, session_id: str, entity_id: int
    ) -> tuple[dict[str, int], list[str]] | None:
        """The scenario session removed for good: marked, checked for work, then its scenarios' SQL operation
        records (a reused key must never replay a deleted scenario's answer), its scenarios, its plans and the
        session last, so a delete cut short is finished by calling it again. (how many of each were removed,
        the plans' ids); None when it is not this entity's or something of it is still at work."""
        sessions, scenarios = self._sessions.collection, self._scenarios.collection
        plans, session = self._remediations.collection, {"_id": session_id, "entity_id": entity_id}
        marked = sessions.update_one(
            {**session, "status": {"$nin": _WORKING}}, {"$set": {DELETING_MARK: datetime.now(UTC)}}
        ).matched_count
        if not marked:
            return None
        if self._work_left(session_id, entity_id):  # final: nothing new can start on a marked session
            sessions.update_one(session, {"$unset": {DELETING_MARK: ""}})
            return None
        children = {"session_id": session_id, "entity_id": entity_id}
        operation_ids = [  # tsg_sql_operations ids: promote:{scenario_id}, propose:{scenario_id}
            f"{write}:{scenario_id}"
            for scenario_id in scenarios.distinct("_id", children)
            for write in ("promote", "propose")
        ]
        if operation_ids:
            sessions.database[Collection.SQL_OPERATIONS].delete_many({"_id": {"$in": operation_ids}})
        plan_ids: list[str] = plans.distinct("_id", children)
        removed = {
            "scenarios": scenarios.delete_many(children).deleted_count,
            "remediation_plans": plans.delete_many(children).deleted_count,
        }
        sessions.delete_one(session)
        return removed, plan_ids

    def settle_stopped_scenario_sessions(self) -> None:
        """tsg_scenarios: controls waiting on a cancelled session stop, with its counts, never one a live
        lease holds (a plan job maps a cancelled session's scenario on purpose); every scenario of a deleted
        session goes, whatever its status (failure and blocked cards too). The waiting cards are read before
        the session states and only they are stopped: a card a resume queued again is never stopped again."""
        scenarios = self._scenarios.collection
        stoppable = {"$or": [*waiting_controls(datetime.now(UTC)), FAILED_WITH_ATTEMPTS_LEFT]}
        waiting = {**SWEPT, "$and": [MAPPED_VERSIONS, stoppable]}
        waiting_cards = list(scenarios.find(waiting, {"session_id": 1}))
        waiting_ids = {card.get("session_id") for card in waiting_cards}
        recent = {"created_at": {"$gte": datetime.now(UTC) - _ORPHANS_WRITTEN_WITHIN}}
        session_ids = [
            found for found in waiting_ids | set(scenarios.distinct("session_id", recent)) if found
        ]
        if not session_ids:
            return
        states = {
            record["_id"]: record.get("status")
            for record in self._sessions.list(fields=["status"], _id={"$in": session_ids})
        }
        if cancelled := {
            session_id for session_id in waiting_ids if states.get(session_id) == Status.CANCELLED
        }:
            stopped_cards = [card["_id"] for card in waiting_cards if card.get("session_id") in cancelled]
            scenarios.update_many(
                {**waiting, "_id": {"$in": stopped_cards}},
                {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
            )
            for session_id in cancelled:
                self._sessions.update_scenario_session_counts(session_id)
        if deleted := [session_id for session_id in session_ids if session_id not in states]:
            scenarios.delete_many({"session_id": {"$in": deleted}})

    def sweep_stalled_controls(self) -> list[str]:
        """The controls sweep: stopped sessions settled; then, at one moment, controls whose lease expired on
        their last attempt failed for good (with their sessions' counts) and stalled mappings queued again,
        never a live lease's. The sorted ids of the sessions that need a mapping message: those no delivery
        serves, read after the requeue, so a session released in between still gets its message."""
        self.settle_stopped_scenario_sessions()
        now = datetime.now(UTC)
        for session_id in self._scenarios.fail_abandoned_controls(now):
            self._sessions.update_scenario_session_counts(session_id)
        session_ids = self._scenarios.requeue_stalled_controls(now)
        live = self._sessions.list_scenario_sessions_with_live_delivery(session_ids)
        return sorted(set(session_ids) - live)


def _cancelled_job(cancelled: dict[str, Any], now: datetime) -> dict[str, Any]:
    """A cancel's fields on a job record: ended (the asset free again, the lease ended), who and when kept."""
    return ended_job_fields(Status.CANCELLED, now) | {"cancelled": cancelled, "updated_at": now}


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
