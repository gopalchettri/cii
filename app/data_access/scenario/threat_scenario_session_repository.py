"""tsg_sessions: unique starts, guarded new write jobs, fenced plan writes, the counts recompute, the delete
mark and the controls delivery lease. It reads tsg_scenarios through the scenario repository only."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection
from pymongo.errors import DuplicateKeyError

from app.core.constants import (
    Collection,
    Controls,
    PlanMessage,
    RunActionKind,
    RunActionOutcome,
    RunClash,
    SessionMessage,
    Status,
    Step,
    TaskName,
)
from app.core.exceptions import DuplicateRecord, LeaseLost, NotFound
from app.data_access.base import MongoRepository, Record
from app.data_access.jobs.job_repository import JobLease, new_job
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.models.scenario.views import SessionStatus

#: Set on a scenario session by the first step of its delete, in the update that checks no job of it is at
#: work: from then on nothing new starts on it, so the delete's check for work is final.
DELETING_MARK = "deleting_at"
#: The unique indexes a new scenario session can clash on (MongoDB's default names, kept as built in UAT).
ACTIVE_SESSION_INDEX = "entity_id_1_asset_id_1"
IDEMPOTENCY_KEY_INDEX = "entity_id_1_idempotency_key_1"
_ID_INDEX = "_id_"

_SESSION_INDEXES = (
    {
        "keys": [("entity_id", 1), ("asset_id", 1)],
        "unique": True,
        "partialFilterExpression": {"active": True},
    },
    {
        "keys": [("entity_id", 1), ("idempotency_key", 1)],
        "unique": True,
        "partialFilterExpression": {"idempotency_key": {"$exists": True}},
    },
    {"keys": [("entity_id", 1), ("status", 1), ("created_at", 1)]},
    {
        "keys": [("entity_id", 1), ("created_at", 1)],
        "name": "controls_waiting_by_entity",
        "partialFilterExpression": {"counts.controls_waiting": {"$gt": 0}},
    },
)
#: The session fields the status body reads: never the plan, nor the context's facts.
SESSION_STATUS_FIELDS: dict[str, int] = {
    "entity_id": 1,
    "asset_id": 1,
    "status": 1,
    "step": 1,
    "counts": 1,
    "last_action": 1,
    "job.error": 1,
    "job.attempts": 1,
    "updated_at": 1,
    "kind": 1,
    "user_id": 1,
    "context.asset.name": 1,
    "timings": 1,
    "last_next_set": 1,
    "last_regen": 1,
    "cancelled": 1,
    "job.epoch": 1,
}
_SESSION_FIELD_LISTS = {
    "status": SESSION_STATUS_FIELDS,
    "context": {"context": 1},
    "attack_paths": {"plan.paths": 1},
    "plan_threat": {"plan.threats.$": 1},
    "replay": {**SESSION_STATUS_FIELDS, "kind": 1, "request_hash": 1},
    "writing": {
        "entity_id": 1,
        "asset_id": 1,
        "context": 1,
        "job.batch": 1,
        "job.set": 1,
        "last_action.started_at": 1,
        "last_action.kind": 1,
        **{f"plan.{part}": 1 for part in ("threats", "paths", "frozen_at")},
    },
}
#: What a new next set or regenerate clears: the last set's times and a cancel's mark.
_CLEARED_BY_A_NEW_ACTION = {
    "finished_at": "",
    "timings.scenarios_s": "",
    "timings.controls_s": "",
    "cancelled": "",
}


def running_action(kind: RunActionKind, started_at: datetime) -> dict[str, Any]:
    """A run's `last_action` as an action starts: its kind, still running, and when it started."""
    return {"kind": kind, "outcome": RunActionOutcome.RUNNING, "reason": None, "started_at": started_at}


class ThreatScenarioSessionRepository(MongoRepository):
    """tsg_sessions with its unique starts, guarded new write jobs, fenced plan writes and counts, and the
    controls delivery lease: one delivery maps a scenario session's controls at a time, under a small lease
    taken in one conditional update."""

    def __init__(
        self,
        collection: str | MongoCollection = Collection.SESSIONS,
        *,
        scenarios: ThreatScenarioRepository,
    ) -> None:
        """`collection`: tsg_sessions by name (resolved on first use), or a pymongo collection in tests;
        `scenarios`: the repository the counts are read through."""
        super().__init__(
            collection,
            indexes=_SESSION_INDEXES,
            field_lists=_SESSION_FIELD_LISTS,
            required=("_id", "entity_id"),
            schema_version=1,
        )
        self._scenarios = scenarios

    def create_scenario_session(self, record: dict[str, Any]) -> RunClash | None:
        """Insert a new scenario session into tsg_sessions; None, or the unique rule that refused it."""
        try:
            self.create(record)
        except DuplicateRecord as clash:
            return (
                RunClash.ACTIVE_RUN if clash.index_name == ACTIVE_SESSION_INDEX else RunClash.IDEMPOTENCY_KEY
            )
        return None

    def get_scenario_session_context(self, session_id: str) -> dict[str, Any]:
        """The frozen asset context of a tsg_sessions record; NotFound for one that does not exist (or was
        deleted under the reader)."""
        found = self.get(fields="context", _id=session_id)
        if found is None:
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
        return found["context"]

    def create_manual_scenario_session(self, record: dict[str, Any]) -> RunClash | None:
        """Insert a hand-written scenario session into tsg_sessions once (a retry finds it stored); None when
        stored for this request, IDEMPOTENCY_KEY when another session took the key or another body this id."""
        try:
            self.create(record)
        except DuplicateRecord as clash:
            if clash.index_name != _ID_INDEX:
                return RunClash.IDEMPOTENCY_KEY
            stored = self.get(fields={"request_hash": 1}, _id=record["_id"])
            if stored is None or stored.get("request_hash") != record["request_hash"]:
                return RunClash.IDEMPOTENCY_KEY
        return None

    def update_scenario_session_job(
        self,
        session: SessionStatus,
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> RunClash | None:
        """Queue a new write job (epoch + 1) on a tsg_sessions record only while it is as read: finished in
        step scenarios at the same epoch, with the same cancel stamp, and not being deleted. None when queued;
        CHANGED or DELETING when it moved on; ACTIVE_RUN when another session of the asset is active."""
        still_as_read = {
            "_id": session.session_id,
            "entity_id": session.entity_id,
            "job.epoch": session.epoch,
            "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            "step": Step.SCENARIOS,
            "cancelled.at": (session.cancelled or {}).get("at"),  # None also matches no stamp
            DELETING_MARK: {"$exists": False},
        }
        epoch, now = session.epoch + 1, datetime.now(UTC)
        queued = {
            "status": Status.QUEUED,
            "active": True,
            "job": new_job(TaskName.WRITE_SCENARIOS, epoch, now, batch=batch, set=asked),
            "last_action": running_action(kind, now),
            **_running_summary(kind, batch, asked, epoch),
            "updated_at": now,
        }
        try:
            matched = self.collection.update_one(
                still_as_read, {"$set": queued, "$unset": _CLEARED_BY_A_NEW_ACTION}
            ).matched_count
        except DuplicateKeyError:
            return RunClash.ACTIVE_RUN
        if matched:
            return None
        return RunClash.DELETING if self.is_being_deleted(session.session_id) else RunClash.CHANGED

    def update_scenario_session_plan(
        self,
        lease: JobLease,
        attack_path_states: dict[str, dict[str, Any]],
        plan_figures: dict[str, int],
        also: dict[str, Any] | None = None,
    ) -> None:
        """Save attack path states, plan figures, scenario counts and plan note on tsg_sessions in ONE write
        fenced on the job lease; counts newer-wins: after a newer count the plan is written without counts.
        LeaseLost when the delivery no longer owns the job."""
        counted_at = datetime.now(UTC)  # taken before the aggregate: a later count always counts as newer
        scenario_counts = self._scenarios.count_scenarios_of_session(lease.record_id)
        note = PlanMessage.PLAN_NOTE.format(
            planned=plan_figures["planned"],
            written=scenario_counts["written"],
            remaining=plan_figures["remaining"],
        )
        plan = dict(also or {}) | {"plan_note": note, "updated_at": counted_at}
        plan |= {f"counts.{key}": value for key, value in plan_figures.items()}
        for number, state in enumerate(attack_path_states.values()):
            plan |= {f"plan.paths.$[p{number}].{key}": value for key, value in state.items()}
        picks = [{f"p{number}.path_id": path_id} for number, path_id in enumerate(attack_path_states)]
        counts = {f"counts.{key}": value for key, value in scenario_counts.items()} | {
            "counts_at": counted_at
        }
        fence = {  # the job lease's fence: running under this delivery's task id, epoch and attempts
            "_id": lease.record_id,
            "status": Status.RUNNING,
            "job.task_id": lease.task_id,
            "job.epoch": lease.epoch,
            "job.attempts": lease.attempts,
        }
        older_counts = {"$or": [{"counts_at": {"$lt": counted_at}}, {"counts_at": None}]}
        for only_if, changes in ((older_counts, counts | plan), ({}, plan)):
            written = self.collection.update_one({**fence, **only_if}, {"$set": changes}, array_filters=picks)
            if written.matched_count:
                return
        raise LeaseLost(lease.record_id)

    def update_scenario_session_counts(
        self, session_id: str, controls_seconds: float = 0.0
    ) -> dict[str, int]:
        """The scenario session's counts now, saved on tsg_sessions unless a later count was saved first
        (counts_at newer wins); `controls_seconds` is added to the controls time in the same write."""
        counted_at = datetime.now(UTC)  # taken before the aggregate: a later one always counts as newer
        counts = self._scenarios.count_scenarios_of_session(session_id)
        older = {"$or": [{"counts_at": {"$lt": counted_at}}, {"counts_at": None}]}
        changes: dict[str, Any] = {f"counts.{key}": value for key, value in counts.items()}
        changes |= {"counts_at": counted_at, "updated_at": counted_at}
        added = {"$inc": {"timings.controls_s": round(controls_seconds, 2)}} if controls_seconds > 0 else {}
        saved = self.collection.update_one({"_id": session_id, **older}, {"$set": changes, **added})
        if added and not saved.matched_count:  # a newer count was saved first: the time is still added
            self.collection.update_one({"_id": session_id}, added)
        return counts

    def is_being_deleted(self, session_id: str) -> bool:
        """Whether the tsg_sessions record carries its delete's mark, or is gone already."""
        found = self.collection.find_one({"_id": session_id}, {DELETING_MARK: 1})
        return found is None or DELETING_MARK in found

    def claim_controls_delivery(self, session_id: str, task_id: str) -> Record | None:
        """tsg_sessions: the session's delivery lease for `task_id` when free, expired, handed over or
        already its own, never for a cancelled session; its frozen context, or None while another delivery
        holds it."""
        now = datetime.now(UTC)
        free = [
            {"controls_delivery.until": {"$lt": now}},
            {"controls_delivery.task_id": {"$in": [None, task_id]}},  # also: no lease at all
        ]
        held = {"task_id": task_id, "until": now + timedelta(seconds=Controls.LEASE_SECONDS)}
        found = self.collection.find_one_and_update(
            {"_id": session_id, "status": {"$ne": Status.CANCELLED}, "$or": free},
            {"$set": {"controls_delivery": held}},
            projection={"context": 1},
        )
        return None if found is None else found.get("context", {})

    def update_controls_delivery(self, session_id: str, task_id: str, hand_over: bool = False) -> bool:
        """tsg_sessions: the delivery lease extended; `hand_over`, its next turn queued: no holder, and the
        session counts as served while that message waits. False once another delivery holds it."""
        if hand_over:
            until = datetime.now(UTC) + timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
            return self._update_if_held(
                session_id, task_id, {"$set": {"controls_delivery": {"task_id": None, "until": until}}}
            )
        until = datetime.now(UTC) + timedelta(seconds=Controls.LEASE_SECONDS)
        return self._update_if_held(session_id, task_id, {"$set": {"controls_delivery.until": until}})

    def release_controls_delivery(self, session_id: str, task_id: str) -> None:
        """tsg_sessions: the delivery lease ended."""
        self._update_if_held(session_id, task_id, {"$unset": {"controls_delivery": ""}})

    def list_scenario_sessions_with_live_delivery(self, session_ids: Iterable[str]) -> set[str]:
        """tsg_sessions: of `session_ids`, the ones a delivery maps now or whose next turn is on its way."""
        found = self.collection.find(
            {"_id": {"$in": list(session_ids)}, "controls_delivery.until": {"$gte": datetime.now(UTC)}},
            {"_id": 1},
        )
        return {record["_id"] for record in found}

    def _update_if_held(self, session_id: str, task_id: str, update: Record) -> bool:
        """tsg_sessions: `update`, only while `task_id` holds the session's delivery lease."""
        held = {"_id": session_id, "controls_delivery.task_id": task_id}
        return self.collection.update_one(held, update).matched_count == 1


def _running_summary(
    kind: RunActionKind, batch: list[dict[str, Any]], asked: list[str] | None, epoch: int
) -> dict[str, Any]:
    """The status summary of a new next set or regenerate from its first moment (requested, epoch)."""
    running = {"outcome": RunActionOutcome.RUNNING}
    if kind == RunActionKind.NEXT_SET:
        summary = {"requested": len(asked or []), "delivered": None, "reason": None, "remaining": None}
        return {"last_next_set": running | summary | {"epoch": epoch}}
    return {"last_regen": running | {"requested": len(batch), "replaced": None, "epoch": epoch}}
