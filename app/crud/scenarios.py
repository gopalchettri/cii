"""tsg_sessions and tsg_scenarios records, and the asset context from SQL Server."""

import json
import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from pymongo import ASCENDING, DESCENDING, ReturnDocument, UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core import constants as c
from app.core.clock import utc_now
from app.core.database import get_stored_procedure_client
from app.core.exceptions import DuplicateRecord, LeaseLost, NotFound
from app.core.singletons import singleton
from app.crud.base import Condition, MongoRepository, Record, drop_retired_index
from app.crud.jobs import JobLease, new_job
from app.schemas.scenario_internal import AssetContextRows
from app.schemas.scenarios import SessionStatus, StartRunRequest

MAPPED_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": c.Decision.ACCEPTED}]}
FAILED_WITH_ATTEMPTS_LEFT = {"controls.status": c.Status.FAILED, "controls.attempts": {"$lt": c.Controls.MAX_ATTEMPTS}}
# owner 2026-11-27: a MITRE card's controls are identified by its remediation plan, never mapped: one an older pod
# saved queued during a rolling deploy is never claimed nor requeued, whatever the rollout order.
NOT_MITRE = {"content.mitre": {"$exists": False}}
TITLE_INDEX = "one_title_per_run_all_versions"
_COUNTED_FIELDS = ("status", "superseded_by", "decision", "controls.status")
_DUPLICATE_CHECK_FIELDS = (
    "session_id",
    "path_id",
    "decision",
    "content.statement",
    "content.threat.key",
    "content.threat.name",
    "content.threat.library_id",
    "content.threat.library_status",
    "content.category",
    "content.systems.id",
)

RETIRED_ASSET_INDEX = "entity_id_1_asset_id_1_decision_1"
RETIRED_FAILED_CONTROLS_INDEX = "controls.status_1_controls.last_attempt_at_1"
_SCENARIO_INDEXES = (
    {"keys": [("session_id", ASCENDING), ("created_at", ASCENDING)]},
    {"keys": [("created_at", ASCENDING), ("session_id", ASCENDING)]},  # the sweep's recent sessions, covered
    {"keys": [("entity_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)]},
    {"keys": [("entity_id", ASCENDING), ("created_at", DESCENDING)]},
    {  # one accepted version per attack path, even under a race
        "keys": [("session_id", ASCENDING), ("path_id", ASCENDING)],
        "unique": True,
        "partialFilterExpression": {"decision": c.Decision.ACCEPTED},
    },
    {  # the results also list older decided versions, so titles stay unique across all of them
        "keys": [("session_id", ASCENDING), ("title_key", ASCENDING)],
        "unique": True,
        "partialFilterExpression": {"status": c.ScenarioStatus.DONE, "title_key": {"$exists": True}},
        "name": TITLE_INDEX,
    },
    {"keys": [("controls.status", ASCENDING), ("controls.queued_at", ASCENDING)]},
    {  # the sweep's failed and abandoned controls: attempts before time, so spent cards are never read
        "keys": [
            ("controls.status", ASCENDING),
            ("controls.attempts", ASCENDING),
            ("controls.last_attempt_at", ASCENDING),
        ]
    },
    {"keys": [("session_id", ASCENDING), ("controls.status", ASCENDING)]},
    {  # count_scenarios_of_session reads this index only, never a document
        "keys": [(field, ASCENDING) for field in ("session_id", *_COUNTED_FIELDS)],
        "name": "run_counts",
    },
    {  # count_current_scenarios of an entity reads this index only; decision second: its filter is one range
        "keys": [(field, ASCENDING) for field in ("entity_id", "decision", "status", "superseded_by")],
        "name": "entity_counts",
    },
)


def waiting_controls(now: datetime) -> list[Record]:
    """Controls that wait: queued, or running with a lease expired before `now` and attempts left."""
    return [
        {"controls.status": c.Status.QUEUED},
        {
            "controls.status": c.Status.RUNNING,
            "controls.lease_until": {"$lt": now},
            "controls.attempts": {"$lt": c.Controls.MAX_ATTEMPTS},
        },
    ]


def _controls_waiting(_: Any = True) -> Record:
    waiting = {"$or": waiting_controls(utc_now())}
    return {"status": c.ScenarioStatus.DONE, "$and": [MAPPED_VERSIONS, waiting], **NOT_MITRE}


_SCENARIO_CONDITIONS: dict[str, Condition] = {
    "served": {"status": {"$ne": c.ScenarioStatus.BLOCKED}},
    "current": {"$or": [{"superseded_by": None}, {"decision": {"$ne": c.Decision.PENDING}}]},
    "newest": {"superseded_by": None},
    "not_rejected": {"decision": {"$ne": c.Decision.REJECTED}},
    "not_promoted": {"library_promotion": {"$exists": False}},
    "accepted_or_replaced": {"$or": [{"decision": c.Decision.ACCEPTED}, {"superseded_by": {"$ne": None}}]},
    "scenario_id_in": lambda ids: {"_id": {"$in": list(ids)}},
    "session_id_in": lambda ids: {"session_id": {"$in": list(ids)}},
    "path_id_in": lambda ids: {"path_id": {"$in": list(ids)}},
    "controls_waiting": _controls_waiting,
    "controls_mapped": {"controls.status": c.Status.DONE, "controls.items.0": {"$exists": True}},
}

_SCENARIO_FIELD_LISTS = {
    "shown": dict.fromkeys(
        (
            "controls.query",
            "controls.shortlist",
            "controls.made_with",
            "controls.picks",  # an attack run's: what its controls and its card were made from, never shown
            "controls.dropped",
            "controls.technique_states",
            "content.attack",
            "plan_check",
        ),
        0,
    ),
    "version": ("path_id", "version", "superseded_by"),
    "lookup": ("session_id", "path_id", "version", "decision", "superseded_by"),
    "target": (
        "path_id",
        "source",
        "status",
        "decision",
        "superseded_by",
        "content.threat",
        "controls.status",
        "decision_id",
        "failure.reason",
    ),
    "path_id": ("path_id",),
}

_CLAIMED_FIELDS = dict.fromkeys(
    (
        "session_id",
        "source",
        "controls.attempts",
        "controls.origin",
        "controls.request_id",
        "controls.queued_at",  # its controls time counts only for the latest action's cards
        "content.category",
        "content.title",
        "content.statement",
        "content.risk_statement",
        "content.threat.type",
        "content.threat.name",
        "content.actors.name",
        "content.actors.role",
        "content.systems.id",
        "content.evidence.mitigations",
        "content.evidence.facts",  # the about-AI check leaves the cited attackers' names out
        "content.attack",  # POST /v1/create_session's card: its controls are picked from its mitigations' links
    ),
    1,
)
SWEPT = {"status": c.ScenarioStatus.DONE, "source": {"$ne": c.RunKind.MANUAL}}
_PLANS_CLAIM_TASK_ID = re.compile(f"{re.escape(c.Remediation.CONTROLS_CLAIM_SUFFIX)}$")


def run_controls_to_stop(now: datetime) -> Record:
    """The controls a run cancel stops, the run's own."""
    stoppable = {"$or": [{"controls.status": {"$in": [c.Status.QUEUED, c.Status.RUNNING]}}, FAILED_WITH_ATTEMPTS_LEFT]}
    plans_claim = {
        "controls.status": c.Status.RUNNING,
        "controls.task_id": _PLANS_CLAIM_TASK_ID,
        "controls.lease_until": {"$gte": now},
    }
    return {**SWEPT, "$and": [MAPPED_VERSIONS, stoppable], "$nor": [plans_claim]}


def _running(task_id: str, now: datetime) -> Record:
    return {
        "$set": {
            "controls.status": c.Status.RUNNING,
            "controls.task_id": task_id,
            "controls.lease_until": now + timedelta(seconds=c.Controls.LEASE_SECONDS),
            "controls.last_attempt_at": now,
            "controls.error": None,  # this attempt's own outcome says why, if it fails too
        },
        "$inc": {"controls.attempts": 1},
    }


class TitleTaken(Exception):
    """Another written scenario of the scenario session already has this title (TITLE_INDEX)."""


class ThreatScenarioRepository(MongoRepository):
    """tsg_scenarios with its rules."""

    def __init__(self, collection: str | MongoCollection = c.Collection.SCENARIOS) -> None:
        """`collection`: tsg_scenarios by name (resolved on first use), or a pymongo collection in tests."""
        super().__init__(
            collection,
            indexes=_SCENARIO_INDEXES,
            conditions=_SCENARIO_CONDITIONS,
            field_lists=_SCENARIO_FIELD_LISTS,
            required=("_id", "session_id", "status"),
            schema_version=1,
        )

    def create_indexes(self) -> None:
        """The validator and every index, after dropping the retired ones."""
        for retired in (RETIRED_ASSET_INDEX, RETIRED_FAILED_CONTROLS_INDEX):
            drop_retired_index(self.collection, retired)
        super().create_indexes()

    def save_scenario(self, record: Record) -> bool:
        """Insert a scenario, or replace its attack path's failure or blocked card."""
        try:
            return self.save(record, only_if={"status": {"$ne": c.ScenarioStatus.DONE}})
        except DuplicateRecord as clash:  # a server naming no index too: checked, never taken as written
            if self.count(_id=record["_id"], status=c.ScenarioStatus.DONE):
                return False
            raise TitleTaken(record["_id"]) from clash

    def count_scenarios_of_session(self, session_id: str) -> dict[str, int]:
        """The scenario session's tsg_scenarios counts in one aggregate over the run_counts index alone."""
        done = {"$eq": ["$status", c.ScenarioStatus.DONE]}
        newest = {"$eq": [{"$ifNull": ["$superseded_by", None]}, None]}
        accepted = {"$eq": ["$decision", c.Decision.ACCEPTED]}
        mapped = {"$or": [newest, accepted]}

        def with_controls(*statuses: c.Status) -> dict[str, Any]:
            """Mapped written versions whose controls are in one of `statuses`."""
            return _count({"$and": [done, {"$in": ["$controls.status", list(statuses)]}, mapped]})

        group = {
            "_id": None,
            "written": _count({"$and": [newest, done]}),
            "failed": _count({"$and": [newest, {"$eq": ["$status", c.ScenarioStatus.FAILED]}]}),
            "accepted": _count(accepted),
            "rejected": _count({"$and": [newest, {"$eq": ["$decision", c.Decision.REJECTED]}]}),
            "pending": _count({"$and": [newest, done, {"$eq": ["$decision", c.Decision.PENDING]}]}),
            "controls_waiting": with_controls(c.Status.QUEUED, c.Status.RUNNING),
            "controls_failed": with_controls(c.Status.FAILED),
            "controls_cancelled": with_controls(c.Status.CANCELLED),
        }
        match = self.filter({"session_id": session_id, "served": True})
        fields = {"_id": 0} | dict.fromkeys(_COUNTED_FIELDS, 1)
        pipeline = [{"$match": match}, {"$project": fields}, {"$group": group}]
        found = next(self.collection.aggregate(pipeline), None)
        return {key: int((found or {}).get(key, 0)) for key in group if key != "_id"}

    def count_current_scenarios(self, **where: Any) -> int:
        """Served current versions matching `where`, counted over entity_counts or run_counts alone."""
        newest = {"$eq": [{"$ifNull": ["$superseded_by", None]}, None]}
        current = {"$or": [newest, {"$ne": ["$decision", c.Decision.PENDING]}]}
        match = self.filter({**where, "served": True})
        fields = {"_id": 0, "status": 1, "superseded_by": 1, "decision": 1}
        group = {"_id": None, "total": _count(current)}
        pipeline = [{"$match": match}, {"$project": fields}, {"$group": group}]
        found = next(self.collection.aggregate(pipeline), None)
        return int((found or {}).get("total", 0))

    def list_scenarios_for_duplicate_check(self, session_id: str) -> list[Record]:
        """The scenario session's finished scenarios."""
        own_session: Record = {"session_id": session_id, "status": c.ScenarioStatus.DONE, **MAPPED_VERSIONS}
        return self.list(fields=_DUPLICATE_CHECK_FIELDS, **own_session)

    def update_scenario_decisions(
        self, scenario_ids: list[str], expected: c.Decision, decision: c.Decision, stamp: dict[str, Any]
    ) -> int:
        """`decision` (with `stamp`) on each tsg_scenarios record still at `expected`."""
        updates = [
            UpdateOne({"_id": scenario_id, "decision": expected}, {"$set": {"decision": decision, **stamp}})
            for scenario_id in scenario_ids
        ]
        return int(self.bulk_write_skipping_duplicates(updates, ordered=False).get("nModified", 0))

    def update_manual_scenario_findings(
        self, scenario_id: str, findings: dict[str, Any], fields: Iterable[str]
    ) -> Record | None:
        """Saves a hand-written record's plan-job findings and drops its `pending` mark in one write."""
        changes = {"$set": findings, "$unset": {"pending": ""}}
        return self.update_and_get(changes, fields=fields, _id=scenario_id)

    def claim_scenario_controls(self, session_id: str, task_id: str) -> Record | None:
        """tsg_scenarios: the session's oldest scenario whose controls wait, now running for `task_id`."""
        return self.collection.find_one_and_update(
            {"session_id": session_id, **_controls_waiting()},
            _running(task_id, utc_now()),
            projection=_CLAIMED_FIELDS,
            sort=[("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )

    def claim_scenario_controls_by_id(self, scenario_id: str, task_id: str, remap: bool = False) -> Record | None:
        """tsg_scenarios: one scenario's controls claimed by a plan job when not mapped."""
        now = utc_now()
        not_mapped = [
            *waiting_controls(now),
            {"controls.status": {"$in": [c.Status.FAILED, c.Status.CANCELLED]}},
            {"controls.status": c.Status.DONE, "controls.items": {"$size": 0}},
            {"controls": {"$exists": False}},
        ]
        if remap:
            not_mapped.append({"controls.status": c.Status.DONE})
        return self.collection.find_one_and_update(
            {"_id": scenario_id, "status": c.ScenarioStatus.DONE, "$or": not_mapped, **NOT_MITRE},
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            return_document=ReturnDocument.AFTER,
        )

    def get_plans_controls_claim(self, scenario_id: str) -> Record | None:
        """tsg_scenarios: a generated scenario while a plan job's claim holds its controls; else None."""
        held = {
            "_id": scenario_id,
            "source": {"$ne": c.RunKind.MANUAL},
            "controls.status": c.Status.RUNNING,
            "controls.task_id": _PLANS_CLAIM_TASK_ID,
        }
        return self.collection.find_one(held, {"session_id": 1, "controls.task_id": 1, "controls.attempts": 1})

    def update_scenario_controls(
        self,
        scenario_id: str,
        task_id: str,
        attempts: int,
        outcome: c.Status,
        mapping: Record | None = None,
        error: Record | None = None,
        attempt_returned: bool = False,
    ) -> bool:
        """tsg_scenarios: the claim's outcome, only while it still holds."""
        now = utc_now()
        counted = attempts - 1 if attempt_returned else attempts
        if outcome == c.Status.QUEUED and counted >= c.Controls.MAX_ATTEMPTS:
            outcome = c.Status.FAILED
        if outcome == c.Status.RUNNING:
            changes: Record = {"controls.lease_until": now + timedelta(seconds=c.Controls.LEASE_SECONDS)}
        elif outcome == c.Status.DONE:
            changes = {f"controls.{key}": value for key, value in (mapping or {}).items()}
            changes |= {"controls.status": c.Status.DONE, "controls.error": None}
        else:
            changes = {"controls.status": outcome, "controls.error": error}
            if outcome == c.Status.QUEUED:
                changes |= {"controls.queued_at": now, "controls.attempts": counted}
        if outcome != c.Status.RUNNING:
            changes["controls.lease_until"] = None
        fence = {
            "_id": scenario_id,
            "controls.task_id": task_id,
            "controls.attempts": attempts,
            "controls.status": c.Status.RUNNING,
        }
        return self.collection.update_one(fence, {"$set": changes}).matched_count == 1

    def fail_abandoned_controls(self, now: datetime) -> list[str]:
        """tsg_scenarios: written scenarios' controls whose running lease expired before `now`."""
        abandoned = {
            "status": c.ScenarioStatus.DONE,
            "controls.status": c.Status.RUNNING,
            "controls.lease_until": {"$lt": now},
            "controls.attempts": {"$gte": c.Controls.MAX_ATTEMPTS},
        }
        session_ids = [found for found in self.collection.distinct("session_id", abandoned) if found]
        if not session_ids:
            return []
        message = c.ErrorMessage.JOB_ABANDONED.format(attempts=c.Controls.MAX_ATTEMPTS)
        error = {"code": c.ErrorCode.JOB_ABANDONED, "message": message, "reason": c.AbandonReason.WORKER_STOPPED}
        failed = {"controls.status": c.Status.FAILED, "controls.error": error, "controls.lease_until": None}
        self.collection.update_many(abandoned, {"$set": failed})
        return session_ids

    def requeue_stalled_controls(self, now: datetime) -> list[str]:
        """tsg_scenarios: stalled mappings queued again (attempts kept); the session ids touched, sorted."""
        lost = now - timedelta(seconds=c.Controls.RESEND_QUEUED_AFTER_SECONDS)
        failed_long_ago = now - timedelta(seconds=c.Controls.RETRY_FAILED_AFTER_SECONDS)
        stalled = [
            {"controls.status": c.Status.QUEUED, "controls.queued_at": {"$lt": lost}},
            {"controls.status": c.Status.RUNNING, "controls.lease_until": {"$lt": now}},
            FAILED_WITH_ATTEMPTS_LEFT | {"controls.last_attempt_at": {"$lt": failed_long_ago}},
        ]
        query = {**SWEPT, "$and": [MAPPED_VERSIONS, {"$or": stalled}], **NOT_MITRE}
        session_ids: list[str] = self.collection.distinct("session_id", query)
        requeued = {"controls.status": c.Status.QUEUED, "controls.queued_at": now, "controls.lease_until": None}
        self.collection.update_many(query, {"$set": requeued})
        return sorted(session_ids)


def _count(condition: dict[str, Any]) -> dict[str, Any]:
    return {"$sum": {"$cond": [condition, 1, 0]}}


DELETING_MARK = "deleting_at"
RETIRED_ACTIVE_RUN_INDEX = "entity_id_1_asset_id_1"

_SESSION_INDEXES = (
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
SESSION_STATUS_FIELDS: dict[str, int] = {
    "entity_id": 1,
    "asset_id": 1,
    "status": 1,
    "step": 1,
    "counts": 1,
    "last_action": 1,
    "job.error": 1,
    "job.attempts": 1,
    "job.retry": 1,
    "updated_at": 1,
    "kind": 1,
    "user_id": 1,
    "context.asset.name": 1,
    "timings": 1,
    "last_next_set": 1,
    "last_regen": 1,
    "cancelled": 1,
    "job.epoch": 1,
    "controls_delivery.retry": 1,
    "pipeline": 1,
}
_SESSION_FIELD_LISTS = {
    "status": SESSION_STATUS_FIELDS,
    "context": {"context": 1},
    "attack_paths": {"plan.paths": 1},
    "plan_trace": {"plan_trace": 1, "plan.paths": 1},
    "plan_threat": {"plan.threats.$": 1},
    "replay": {**SESSION_STATUS_FIELDS, "kind": 1, "request_hash": 1, "created_at": 1},
    "writing": {
        "entity_id": 1,
        "asset_id": 1,
        "context": 1,
        "job.batch": 1,
        "job.set": 1,
        "last_action.started_at": 1,
        "last_action.kind": 1,
        "last_action.writing_started_at": 1,
        "timings.threats_s": 1,
        **{f"plan.{part}": 1 for part in ("threats", "paths", "frozen_at")},
        "pipeline": 1,  # an attack run's writer, its count rule's target and whether the other risks are listed
        "plan.target": 1,
        "plan.risks_listed_at": 1,
        "plan.risks_complete": 1,
    },
}
_CLEARED_BY_A_NEW_ACTION = {"finished_at": "", "timings": "", "cancelled": ""}
_LATEST_ACTION_BEGAN = {"$max": ["$plan.frozen_at", "$last_action.started_at"]}


def running_action(kind: c.RunActionKind, started_at: datetime) -> dict[str, Any]:
    """A run's `last_action` as an action starts: its kind, still running, and when it started."""
    return {"kind": kind, "outcome": c.RunActionOutcome.RUNNING, "reason": None, "started_at": started_at}


class ThreatScenarioSessionRepository(MongoRepository):
    """tsg_sessions: unique starts, guarded write jobs, fenced plan writes, counts and delivery leases."""

    def __init__(
        self, collection: str | MongoCollection = c.Collection.SESSIONS, *, scenarios: ThreatScenarioRepository
    ) -> None:
        """`collection`: tsg_sessions by name (resolved on first use), or a pymongo collection in tests."""
        super().__init__(
            collection,
            indexes=_SESSION_INDEXES,
            field_lists=_SESSION_FIELD_LISTS,
            required=("_id", "entity_id"),
            schema_version=1,
        )
        self._scenarios = scenarios

    def create_indexes(self) -> None:
        """The validator and every index, after dropping the retired one-active-run-per-asset index."""
        drop_retired_index(self.collection, RETIRED_ACTIVE_RUN_INDEX)
        super().create_indexes()

    def get_scenario_session_context(self, session_id: str) -> dict[str, Any]:
        """The frozen asset context of a tsg_sessions record; NotFound when it does not exist."""
        found = self.get(fields="context", _id=session_id)
        if found is None:
            raise NotFound(c.SessionMessage.NOT_FOUND.format(session_id=session_id))
        return found["context"]

    def create_scenario_session(self, record: dict[str, Any]) -> c.RunClash | None:
        """Insert a scenario session into tsg_sessions once (a retry finds it stored); else IDEMPOTENCY_KEY."""
        try:
            self.create(record)
        except DuplicateRecord as clash:
            if clash.index_name != "_id_":
                return c.RunClash.IDEMPOTENCY_KEY
            stored = self.get(fields={"request_hash": 1}, _id=record["_id"])
            if stored is None or stored.get("request_hash") != record.get("request_hash"):
                return c.RunClash.IDEMPOTENCY_KEY
        return None

    def update_scenario_session_job(
        self, session: SessionStatus, kind: c.RunActionKind, batch: list[dict[str, Any]], asked: list[str] | None = None
    ) -> c.RunClash | None:
        """Queue a new write job (epoch + 1) on a tsg_sessions record only while it is as read."""
        still_as_read = {
            "_id": session.session_id,
            "entity_id": session.entity_id,
            "job.epoch": session.epoch,
            "status": {"$in": [c.Status.DONE, c.Status.FAILED, c.Status.CANCELLED]},
            "step": c.Step.SCENARIOS,
            "cancelled.at": (session.cancelled or {}).get("at"),  # None also matches no stamp
            DELETING_MARK: {"$exists": False},
        }
        epoch, now = session.epoch + 1, utc_now()
        running = {"outcome": c.RunActionOutcome.RUNNING}
        if kind == c.RunActionKind.NEXT_SET:
            counts = {"requested": len(asked or []), "delivered": None, "reason": None, "remaining": None}
            summary = {"last_next_set": running | counts | {"epoch": epoch}}
        else:
            summary = {"last_regen": running | {"requested": len(batch), "replaced": None, "epoch": epoch}}
        queued = {
            "status": c.Status.QUEUED,
            "job": new_job(c.TaskName.WRITE_SCENARIOS, epoch, now, batch=batch, set=asked),
            "last_action": running_action(kind, now),
            **summary,
            "updated_at": now,
        }
        matched = self.collection.update_one(
            still_as_read, {"$set": queued, "$unset": _CLEARED_BY_A_NEW_ACTION}
        ).matched_count
        if matched:
            return None
        return c.RunClash.DELETING if self.is_being_deleted(session.session_id) else c.RunClash.CHANGED

    def update_scenario_session_plan(
        self,
        lease: JobLease,
        attack_path_states: dict[str, dict[str, Any]],
        plan_figures: dict[str, int],
        also: dict[str, Any] | None = None,
    ) -> None:
        """Save attack path states, plan figures and scenario counts on tsg_sessions in one fenced write."""
        counted_at = utc_now()  # taken before the aggregate: a later count always counts as newer
        scenario_counts = self._scenarios.count_scenarios_of_session(lease.record_id)
        plan = dict(also or {}) | {"updated_at": counted_at}
        plan |= {f"counts.{key}": value for key, value in plan_figures.items()}
        for number, state in enumerate(attack_path_states.values()):
            plan |= {f"plan.paths.$[p{number}].{key}": value for key, value in state.items()}
        picks = [{f"p{number}.path_id": path_id} for number, path_id in enumerate(attack_path_states)]
        counts = {f"counts.{key}": value for key, value in scenario_counts.items()} | {"counts_at": counted_at}
        older_counts = {"$or": [{"counts_at": {"$lt": counted_at}}, {"counts_at": None}]}
        for only_if, changes in ((older_counts, counts | plan), ({}, plan)):
            written = self.collection.update_one({**lease.fence, **only_if}, {"$set": changes}, array_filters=picks)
            if written.matched_count:
                return
        raise LeaseLost(lease.record_id)

    def update_scenario_session_counts(
        self, session_id: str, controls_seconds: float = 0.0, card_queued_at: datetime | None = None
    ) -> dict[str, int]:
        """The scenario session's counts now, saved unless a later count was saved first."""
        counted_at = utc_now()  # taken before the aggregate: a later one always counts as newer
        counts = self._scenarios.count_scenarios_of_session(session_id)
        older = {"$or": [{"counts_at": {"$lt": counted_at}}, {"counts_at": None}]}
        changes: dict[str, Any] = {f"counts.{key}": value for key, value in counts.items()}
        changes |= {"counts_at": counted_at, "updated_at": counted_at}
        self.collection.update_one({"_id": session_id, **older}, {"$set": changes})
        if controls_seconds > 0:
            latest = {"$expr": {"$gte": [card_queued_at, _LATEST_ACTION_BEGAN]}} if card_queued_at else {}
            added = {"$inc": {"timings.controls_s": round(controls_seconds, 2)}}
            self.collection.update_one({"_id": session_id, **latest}, added)
        return counts

    def is_being_deleted(self, session_id: str) -> bool:
        """Whether the tsg_sessions record carries its delete's mark, or is gone already."""
        found = self.collection.find_one({"_id": session_id}, {DELETING_MARK: 1})
        return found is None or DELETING_MARK in found

    def is_cancelled(self, session_id: str) -> bool:
        """Whether the owner's cancel stands on the scenario session."""
        # ponytail: read before a plan's claim is handed back; a run cancel landing between this read and
        # that write leaves the card queued (a second run cancel stops it). Keeping the cancel on the card
        # closes it.
        stands = {"_id": session_id, "$or": [{"status": c.Status.CANCELLED}, {"cancelled": {"$ne": None}}]}
        return self.collection.find_one(stands, {"_id": 1}) is not None

    def claim_controls_delivery(self, session_id: str, task_id: str) -> Record | None:
        """tsg_sessions: the session's delivery lease for `task_id` when free, expired or handed over."""
        now = utc_now()
        free = [
            {"controls_delivery.until": {"$lt": now}},
            {"controls_delivery.task_id": {"$in": [None, task_id]}},  # also: no lease at all
        ]
        held = {"task_id": task_id, "until": now + timedelta(seconds=c.Controls.LEASE_SECONDS)}
        return self.collection.find_one_and_update(
            {"_id": session_id, "status": {"$ne": c.Status.CANCELLED}, "$or": free},
            {"$set": {"controls_delivery": held}},
            projection={"job.request_id": 1},
        )

    def update_controls_delivery(self, session_id: str, task_id: str, hand_over: bool = False) -> bool:
        """tsg_sessions: the delivery lease extended; `hand_over` queues its next turn."""
        if hand_over:
            until = utc_now() + timedelta(seconds=c.Controls.RESEND_QUEUED_AFTER_SECONDS)
            return self._update_if_held(
                session_id, task_id, {"$set": {"controls_delivery": {"task_id": None, "until": until}}}
            )
        until = utc_now() + timedelta(seconds=c.Controls.LEASE_SECONDS)
        return self._update_if_held(session_id, task_id, {"$set": {"controls_delivery.until": until}})

    def release_controls_delivery(self, session_id: str, task_id: str) -> bool:
        """tsg_sessions: the delivery lease ended; False when `task_id` no longer held it."""
        return self._update_if_held(session_id, task_id, {"$unset": {"controls_delivery": ""}})

    def note_controls_retry(self, session_id: str, task_id: str, notice: Record) -> bool:
        """tsg_sessions: the delivery's outage notice, kept until the lease is next claimed."""
        return self._update_if_held(session_id, task_id, {"$set": {"controls_delivery.retry": notice}})

    def list_scenario_sessions_with_live_delivery(self, session_ids: Iterable[str]) -> set[str]:
        """tsg_sessions: of `session_ids`, the ones a delivery maps now or whose next turn is on its way."""
        found = self.collection.find(
            {"_id": {"$in": list(session_ids)}, "controls_delivery.until": {"$gte": utc_now()}}, {"_id": 1}
        )
        return {record["_id"] for record in found}

    def _update_if_held(self, session_id: str, task_id: str, update: Record) -> bool:
        held = {"_id": session_id, "controls_delivery.task_id": task_id}
        return self.collection.update_one(held, update).matched_count == 1


def get_asset_context(entity_id: int, request: StartRunRequest) -> AssetContextRows:
    """The asset facts a run is built from: one tsg_GetAssetContext call."""
    asset, services, sector, systems, options = get_stored_procedure_client().execute_procedure(
        c.StoredProcedure.GET_ASSET_CONTEXT,
        EntityID=entity_id,
        AssetID=request.asset_id,
        SystemIDs=json.dumps(request.supporting_system_ids),
        ServiceID=request.service_id,
        SectorID=request.sector_id,
        SubsectorID=request.subsector_id,
    )
    return AssetContextRows(
        asset=asset[0] if asset else None,
        services=services,
        sector=sector[0] if sector else None,
        systems=systems,
        options=options,
    )


@singleton
def get_threat_scenario_repository() -> ThreatScenarioRepository:
    return ThreatScenarioRepository()


@singleton
def get_threat_scenario_session_repository() -> ThreatScenarioSessionRepository:
    return ThreatScenarioSessionRepository(scenarios=get_threat_scenario_repository())
