"""The scenario repositories: tsg_sessions (scenario_sessions), tsg_scenarios (scenarios) and the controls
leases on both (scenario_controls, controls_deliveries), on the base repository with rule methods only."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ASCENDING, DESCENDING, ReturnDocument, UpdateOne
from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import (
    Collection,
    Controls,
    Decision,
    JobControl,
    Lease,
    PlanMessage,
    RunActionKind,
    RunActionOutcome,
    RunClash,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    TaskName,
)
from app.core.exceptions import DuplicateRecord, LeaseLost, NotFound
from app.data_access.base import MongoRepository, Record
from app.data_access.jobs.repository import (
    DELETING_MARK,
    JobLease,
    ended_job_fields,
    is_scenario_session_being_deleted,
    new_job,
)
from app.models.scenario.views import SessionStatus

#: The versions a reviewer works with: the newest of each attack path, and any older one already decided.
CURRENT_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": {"$ne": Decision.PENDING}}]}
#: The versions whose controls are mapped: the newest, or an older one a reviewer accepted.
MAPPED_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": Decision.ACCEPTED}]}
#: Controls not mapped yet that a cancel stops: waiting, being mapped, or failed (the sweep would retry it).
STOPPABLE_CONTROLS = [Status.QUEUED, Status.RUNNING, Status.FAILED]
#: Titles unique within a scenario session across every written version.
TITLE_INDEX = "one_title_per_run_all_versions"
#: What count_scenarios_of_session reads of a scenario, all in the run_counts index after session_id.
_COUNTED_FIELDS = ("status", "superseded_by", "decision", "controls.status")
#: What the duplicate check compares of a finished scenario: a few fields, never the evidence.
_DUPLICATE_CHECK_FIELDS = (
    "session_id",
    "path_id",
    "decision",
    "content.statement",
    "content.threat.key",
    "content.threat.library_id",
    "content.threat.library_status",
    "content.category",
    "content.systems.id",
)

_SCENARIO_INDEXES = (
    {"keys": [("session_id", ASCENDING), ("created_at", ASCENDING)]},
    {"keys": [("entity_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)]},
    {"keys": [("entity_id", ASCENDING), ("created_at", DESCENDING)]},
    # The duplicate check's other sessions: the asset's own records, never the entity's whole register.
    {"keys": [("entity_id", ASCENDING), ("asset_id", ASCENDING), ("decision", ASCENDING)]},
    {  # one accepted version per attack path, even under a race
        "keys": [("session_id", ASCENDING), ("path_id", ASCENDING)],
        "unique": True,
        "partialFilterExpression": {"decision": Decision.ACCEPTED},
    },
    {  # the results also list older decided versions, so titles stay unique across all of them
        "keys": [("session_id", ASCENDING), ("title_key", ASCENDING)],
        "unique": True,
        "partialFilterExpression": {"status": ScenarioStatus.DONE, "title_key": {"$exists": True}},
        "name": TITLE_INDEX,
    },
    {"keys": [("controls.status", ASCENDING), ("controls.queued_at", ASCENDING)]},
    {"keys": [("controls.status", ASCENDING), ("controls.last_attempt_at", ASCENDING)]},
    {"keys": [("session_id", ASCENDING), ("controls.status", ASCENDING)]},
    {  # count_scenarios_of_session reads this index only, never a document
        "keys": [(field, ASCENDING) for field in ("session_id", *_COUNTED_FIELDS)],
        "name": "run_counts",
    },
)

_SCENARIO_CONDITIONS = {
    "served": {"status": {"$ne": ScenarioStatus.BLOCKED}},
    "current": CURRENT_VERSIONS,
    "mapped": MAPPED_VERSIONS,
    "newest": {"superseded_by": None},
    "not_rejected": {"decision": {"$ne": Decision.REJECTED}},
    "not_promoted": {"library_promotion": {"$exists": False}},
    "accepted_or_replaced": {"$or": [{"decision": Decision.ACCEPTED}, {"superseded_by": {"$ne": None}}]},
    "scenario_id_in": lambda ids: {"_id": {"$in": list(ids)}},
    "session_id_in": lambda ids: {"session_id": {"$in": list(ids)}},
    "path_id_in": lambda ids: {"path_id": {"$in": list(ids)}},
}

_SCENARIO_FIELD_LISTS = {
    #: A served scenario as shown: never the control search text, what mapped it, the plan check.
    "shown": {"controls.query": 0, "controls.made_with": 0, "plan_check": 0},
    #: A regenerate's versions of an attack path.
    "version": ("path_id", "version", "superseded_by", "content.statement"),
    #: What finding an attack path's accepted version reads.
    "lookup": ("session_id", "path_id", "version", "decision", "superseded_by"),
    #: What a review call reads of a target: its state and threat, never its text.
    "target": (
        "path_id",
        "source",
        "status",
        "decision",
        "superseded_by",
        "content.threat",
        "controls.status",
        "decision_id",
    ),
    "path_id": ("path_id",),
}


class TitleTaken(Exception):
    """Another written scenario of the scenario session already has this title (TITLE_INDEX)."""


class ScenarioRepository(MongoRepository):
    """tsg_scenarios with its rules: the guarded save, the counts aggregate and their newer-wins write, the
    duplicate check's read and the guarded decision."""

    def save_scenario(self, record: Record) -> bool:
        """Insert a scenario into tsg_scenarios, or replace its attack path's failure or blocked card (same
        id). False when a written scenario already has its id; TitleTaken when another written version of
        the scenario session has its title."""
        try:
            return self.save(record, only_if={"status": {"$ne": ScenarioStatus.DONE}})
        except DuplicateRecord as clash:  # a server naming no index too: checked, never taken as written
            if self.count(_id=record["_id"], status=ScenarioStatus.DONE):
                return False
            raise TitleTaken(record["_id"]) from clash

    def count_scenarios_of_session(self, session_id: str) -> dict[str, int]:
        """The scenario session's tsg_scenarios counts in one aggregate over the run_counts index alone.
        Written, failed, rejected and pending count each attack path's newest version; accepted counts any
        version; the controls counts cover the mapped versions."""
        done = {"$eq": ["$status", ScenarioStatus.DONE]}
        newest = {"$eq": [{"$ifNull": ["$superseded_by", None]}, None]}
        accepted = {"$eq": ["$decision", Decision.ACCEPTED]}
        mapped = {"$or": [newest, accepted]}

        def with_controls(*statuses: Status) -> dict[str, Any]:
            """Mapped written versions whose controls are in one of `statuses`."""
            return _count({"$and": [done, {"$in": ["$controls.status", list(statuses)]}, mapped]})

        group = {
            "_id": None,
            "written": _count({"$and": [newest, done]}),
            "failed": _count({"$and": [newest, {"$eq": ["$status", ScenarioStatus.FAILED]}]}),
            "accepted": _count(accepted),
            "rejected": _count({"$and": [newest, {"$eq": ["$decision", Decision.REJECTED]}]}),
            "pending": _count({"$and": [newest, done, {"$eq": ["$decision", Decision.PENDING]}]}),
            "controls_waiting": with_controls(Status.QUEUED, Status.RUNNING),
            "controls_failed": with_controls(Status.FAILED),
            "controls_cancelled": with_controls(Status.CANCELLED),
        }
        # No current condition in the match: its superseded_by null test reads each document, and every count
        # above already takes the newest or an accepted version only, both current.
        match = self.filter({"session_id": session_id, "served": True})
        fields = {"_id": 0} | dict.fromkeys(_COUNTED_FIELDS, 1)
        pipeline = [{"$match": match}, {"$project": fields}, {"$group": group}]
        found = next(self.collection.aggregate(pipeline), None)
        return {key: int((found or {}).get(key, 0)) for key in group if key != "_id"}

    def update_scenario_session_counts(
        self, session_id: str, controls_seconds: float = 0.0
    ) -> dict[str, int]:
        """The scenario session's counts now, saved on tsg_sessions unless a later count was saved first
        (counts_at newer wins); `controls_seconds` is added to the controls time in the same write."""
        sessions = self.collection.database[Collection.SESSIONS]
        counted_at = datetime.now(UTC)  # taken before the aggregate: a later one always counts as newer
        counts = self.count_scenarios_of_session(session_id)
        older = {"$or": [{"counts_at": {"$lt": counted_at}}, {"counts_at": None}]}
        changes: dict[str, Any] = {f"counts.{key}": value for key, value in counts.items()}
        changes |= {"counts_at": counted_at, "updated_at": counted_at}
        added = {"$inc": {"timings.controls_s": round(controls_seconds, 2)}} if controls_seconds > 0 else {}
        saved = sessions.update_one({"_id": session_id, **older}, {"$set": changes, **added})
        if added and not saved.matched_count:  # a newer count was saved first: the time is still added
            sessions.update_one({"_id": session_id}, added)
        return counts

    def list_scenarios_for_duplicate_check(
        self, entity_id: int, asset_id: int, session_id: str
    ) -> tuple[list[Record], list[Record]]:
        """In one tsg_scenarios read: the scenario session's finished scenarios (each attack path's newest
        version and an older accepted one), and the asset's scenarios of its other sessions a reviewer
        accepted or has still to decide, read without their attack path (path ids repeat across sessions)."""
        own_session = {"session_id": session_id, "status": ScenarioStatus.DONE, **MAPPED_VERSIONS}
        elsewhere = {
            "entity_id": entity_id,
            "asset_id": asset_id,
            "decision": {"$in": [Decision.PENDING, Decision.ACCEPTED]},
            "session_id": {"$ne": session_id},
            "status": ScenarioStatus.DONE,
            **CURRENT_VERSIONS,
        }
        rows = self.list(fields=_DUPLICATE_CHECK_FIELDS, **{"$or": [own_session, elsewhere]})
        own, other = [], []
        for row in rows:
            if row.pop("session_id") == session_id:
                own.append(row)
            else:
                row.pop("path_id", None)
                other.append(row)
        return own, other

    def update_scenario_decisions(
        self, scenario_ids: list[str], expected: Decision, decision: Decision, stamp: dict[str, Any]
    ) -> int:
        """`decision` (with `stamp`) on each tsg_scenarios record still at `expected`, in one unordered bulk
        write, so every id is tried even when the one-accepted-version index refuses another; a write-concern
        error is raised. How many changed."""
        updates = [
            UpdateOne({"_id": scenario_id, "decision": expected}, {"$set": {"decision": decision, **stamp}})
            for scenario_id in scenario_ids
        ]
        return int(self.bulk_write_skipping_duplicates(updates, ordered=False).get("nModified", 0))

    def update_manual_scenario_findings(self, scenario_id: str, findings: dict[str, Any]) -> None:
        """A hand-written tsg_scenarios record's plan-job findings (attackers, library ids) saved and its
        `pending` mark removed, in one write."""
        self.collection.update_one({"_id": scenario_id}, {"$set": findings, "$unset": {"pending": ""}})


def _count(condition: dict[str, Any]) -> dict[str, Any]:
    """An aggregate sum of the documents matching `condition`."""
    return {"$sum": {"$cond": [condition, 1, 0]}}


scenarios = ScenarioRepository(
    Collection.SCENARIOS,
    indexes=_SCENARIO_INDEXES,
    conditions=_SCENARIO_CONDITIONS,
    field_lists=_SCENARIO_FIELD_LISTS,
    required=("_id", "session_id", "status"),
    schema_version=1,
)


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


def session_status_from_record(record: dict[str, Any]) -> SessionStatus:
    """The status of a tsg_sessions record read with SESSION_STATUS_FIELDS."""
    counts, job = record.get("counts") or {}, record.get("job") or {}
    step = record.get("step")
    # A done run still mapping its controls reads `controls` ("card first, controls later").
    if record["status"] == Status.DONE and counts.get("controls_waiting", 0) > 0:
        step = Step.CONTROLS
    return SessionStatus(
        session_id=record["_id"],
        entity_id=record["entity_id"],
        asset_id=record["asset_id"],
        status=record["status"],
        step=step,
        counts=counts,
        last_action=record.get("last_action"),
        error=job.get("error"),
        updated_at=record["updated_at"],
        kind=record.get("kind") or RunKind.GENERATED,
        user_id=record.get("user_id"),
        asset_name=((record.get("context") or {}).get("asset") or {}).get("name"),
        attempts=job.get("attempts") or 0,
        timings=record.get("timings") or {},
        last_next_set=record.get("last_next_set"),
        last_regen=record.get("last_regen"),
        cancelled=record.get("cancelled"),
        epoch=job.get("epoch") or 0,
    )


def running_action(kind: RunActionKind, started_at: datetime) -> dict[str, Any]:
    """A run's `last_action` as an action starts: its kind, still running, and when it started."""
    return {"kind": kind, "outcome": RunActionOutcome.RUNNING, "reason": None, "started_at": started_at}


class ScenarioSessionRepository(MongoRepository):
    """tsg_sessions with its unique starts, guarded new write jobs and fenced plan writes."""

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
        step scenarios at the same epoch and not being deleted. None when queued; CHANGED or DELETING when it
        moved on; ACTIVE_RUN when another session of the asset is active."""
        still_as_read = {
            "_id": session.session_id,
            "entity_id": session.entity_id,
            "job.epoch": session.epoch,
            "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            "step": Step.SCENARIOS,
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
        return (
            RunClash.DELETING
            if is_scenario_session_being_deleted(self.collection, session.session_id)
            else RunClash.CHANGED
        )

    def update_scenario_session_threat_evidence(
        self, lease: JobLease, found: dict[str, dict[str, Any]]
    ) -> None:
        """Save each planned threat's searched evidence (threat key -> {evidence, intel_search}) on the
        tsg_sessions plan in one write fenced on the job lease; LeaseLost when the delivery lost it."""
        changes: dict[str, Any] = {}
        for number, fields in enumerate(found.values()):
            changes |= {f"plan.threats.$[t{number}].{name}": value for name, value in fields.items()}
        lease.update_job(changes, [{f"t{number}.key": key} for number, key in enumerate(found)])

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
        scenario_counts = scenarios.count_scenarios_of_session(lease.record_id)
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


def _running_summary(
    kind: RunActionKind, batch: list[dict[str, Any]], asked: list[str] | None, epoch: int
) -> dict[str, Any]:
    """The status summary of a new next set or regenerate from its first moment (requested, epoch)."""
    running = {"outcome": RunActionOutcome.RUNNING}
    if kind == RunActionKind.NEXT_SET:
        summary = {"requested": len(asked or []), "delivered": None, "reason": None, "remaining": None}
        return {"last_next_set": running | summary | {"epoch": epoch}}
    return {"last_regen": running | {"requested": len(batch), "replaced": None, "epoch": epoch}}


scenario_sessions = ScenarioSessionRepository(
    Collection.SESSIONS,
    indexes=_SESSION_INDEXES,
    field_lists=_SESSION_FIELD_LISTS,
    required=("_id", "entity_id"),
    schema_version=1,
)


#: What a claim returns: the fields the control query reads (app/domain/scenario/controls.py) and the claim's.
_CLAIMED_FIELDS = dict.fromkeys(
    (
        "session_id",
        "source",
        "controls.attempts",
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
    ),
    1,
)
#: The scenarios the sweep looks after: written, never hand-written (those are mapped in their plan request).
_SWEPT = {"status": ScenarioStatus.DONE, "source": {"$ne": RunKind.MANUAL}}
#: How far back the sweep looks for scenarios of any status whose session is gone: a write racing a delete
#: lands within one job's longest run. ponytail: scans the session_id index, a created_at index if it is slow.
_ORPHANS_WRITTEN_WITHIN = timedelta(seconds=Lease.MAX_JOB_SECONDS)


def _controls_waiting(_: Any = True) -> Record:
    """Mapped written scenarios whose controls wait: queued, or running with an expired lease."""
    waiting = [
        {"controls.status": Status.QUEUED},
        {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": datetime.now(UTC)}},
    ]
    return {"status": ScenarioStatus.DONE, "$and": [MAPPED_VERSIONS, {"$or": waiting}]}


def _running(task_id: str, now: datetime) -> Record:
    """A claim's update: the controls running for `task_id` under a fresh lease, one more attempt counted."""
    return {
        "$set": {
            "controls.status": Status.RUNNING,
            "controls.task_id": task_id,
            "controls.lease_until": now + timedelta(seconds=Controls.LEASE_SECONDS),
            "controls.last_attempt_at": now,
        },
        "$inc": {"controls.attempts": 1},
    }


class ScenarioControlsRepository(MongoRepository):
    """tsg_scenarios: each written scenario's controls under its own lease; one conditional update claims it
    and every later write is fenced on the claim's task id, its attempts and running."""

    def claim_scenario_controls(self, session_id: str, task_id: str) -> Record | None:
        """tsg_scenarios: the session's oldest scenario whose controls wait, now running for `task_id`."""
        return self.collection.find_one_and_update(
            {"session_id": session_id, **_controls_waiting()},
            _running(task_id, datetime.now(UTC)),
            projection=_CLAIMED_FIELDS,
            sort=[("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )

    def claim_scenario_controls_by_id(
        self, scenario_id: str, task_id: str, remap: bool = False
    ) -> Record | None:
        """tsg_scenarios: one scenario's controls claimed by a plan job when not mapped (or, `remap`,
        mapped to retired controls only); None when mapped, or a live lease holds them."""
        now = datetime.now(UTC)
        not_mapped = [
            {"controls.status": {"$in": [Status.QUEUED, Status.FAILED, Status.CANCELLED]}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            {"controls.status": Status.DONE, "controls.items": {"$size": 0}},
            {"controls": {"$exists": False}},
        ]
        if remap:
            not_mapped.append({"controls.status": Status.DONE})
        return self.collection.find_one_and_update(
            {"_id": scenario_id, "status": ScenarioStatus.DONE, "$or": not_mapped},
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            return_document=ReturnDocument.AFTER,
        )

    def update_scenario_controls(
        self,
        scenario_id: str,
        task_id: str,
        attempts: int,
        outcome: Status,
        mapping: Record | None = None,
        error: Record | None = None,
    ) -> bool:
        """tsg_scenarios: the claim's outcome, only while it still holds (task id + attempts + running;
        Celery reuses a task id on a redelivery): RUNNING renews the lease, DONE saves `mapping`, QUEUED gives
        it back (FAILED once Controls.MAX_ATTEMPTS were used), FAILED saves `error`. False once taken over."""
        now = datetime.now(UTC)
        if outcome == Status.QUEUED and attempts >= Controls.MAX_ATTEMPTS:
            outcome = Status.FAILED
        if outcome == Status.RUNNING:
            changes: Record = {"controls.lease_until": now + timedelta(seconds=Controls.LEASE_SECONDS)}
        elif outcome == Status.DONE:
            changes = {f"controls.{key}": value for key, value in (mapping or {}).items()}
            changes |= {"controls.status": Status.DONE, "controls.mapped_at": now, "controls.error": None}
        else:
            changes = {"controls.status": outcome, "controls.error": error}
            if outcome == Status.QUEUED:
                changes["controls.queued_at"] = now
        if outcome != Status.RUNNING:
            changes["controls.lease_until"] = None
        fence = {
            "_id": scenario_id,
            "controls.task_id": task_id,
            "controls.attempts": attempts,
            "controls.status": Status.RUNNING,
        }
        return self.collection.update_one(fence, {"$set": changes}).matched_count == 1

    def requeue_stalled_controls(self) -> list[str]:
        """tsg_scenarios: mappings queued too long, running with an expired lease, or failed long ago with
        attempts left, queued again (attempts kept); the session ids touched. Cancelled and deleted sessions
        are settled first, so never one of theirs."""
        self._settle_stopped_scenario_sessions()
        now = datetime.now(UTC)
        lost = now - timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        failed_long_ago = now - timedelta(seconds=Controls.RETRY_FAILED_AFTER_SECONDS)
        stalled = [
            {"controls.status": Status.QUEUED, "controls.queued_at": {"$lt": lost}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            {
                "controls.status": Status.FAILED,
                "controls.last_attempt_at": {"$lt": failed_long_ago},
                "controls.attempts": {"$lt": Controls.MAX_ATTEMPTS},
            },
        ]
        query = {**_SWEPT, "$and": [MAPPED_VERSIONS, {"$or": stalled}]}
        session_ids: list[str] = self.collection.distinct("session_id", query)
        requeued = {"controls.status": Status.QUEUED, "controls.queued_at": now, "controls.lease_until": None}
        self.collection.update_many(query, {"$set": requeued})
        return sorted(session_ids)

    def _settle_stopped_scenario_sessions(self) -> None:
        """tsg_scenarios: controls waiting on a cancelled session stop, with its counts; every scenario of a
        deleted session goes, whatever its status (failure and blocked cards too)."""
        waiting = {**_SWEPT, "controls.status": {"$in": STOPPABLE_CONTROLS}} | MAPPED_VERSIONS
        waiting_ids = set(self.collection.distinct("session_id", waiting))
        recent = {"created_at": {"$gte": datetime.now(UTC) - _ORPHANS_WRITTEN_WITHIN}}
        session_ids = [
            found for found in waiting_ids | set(self.collection.distinct("session_id", recent)) if found
        ]
        if not session_ids:
            return
        states = {
            record["_id"]: record.get("status")
            for record in controls_deliveries.list(fields=["status"], _id={"$in": session_ids})
        }
        if cancelled := [
            session_id for session_id in waiting_ids if states.get(session_id) == Status.CANCELLED
        ]:
            self.collection.update_many(
                {**waiting, "session_id": {"$in": cancelled}},
                {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
            )
            for session_id in cancelled:
                scenarios.update_scenario_session_counts(session_id)
        if deleted := [session_id for session_id in session_ids if session_id not in states]:
            self.collection.delete_many({"session_id": {"$in": deleted}})


class ControlsDeliveryRepository(MongoRepository):
    """tsg_sessions: one delivery maps a scenario session's controls at a time, under a small lease taken in
    one conditional update."""

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


scenario_controls = ScenarioControlsRepository(
    Collection.SCENARIOS,
    conditions={
        "controls_waiting": _controls_waiting,
        "controls_mapped": {"controls.status": Status.DONE, "controls.items.0": {"$exists": True}},
    },
    schema_version=1,
)
controls_deliveries = ControlsDeliveryRepository(Collection.SESSIONS, schema_version=1)


#: Job control: the owner's cancel, resume and delete of scenario sessions and remediation plans.
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
#: A resume's update of its scenario session: done again unless at work, and its cancel stamp gone.
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


class JobControlRepository:
    """An organisation's work in progress (tsg_sessions, tsg_scenarios, tsg_remediations) and its owner's
    controls over it: cancel (stop now, keep what is done), resume, and delete (gone for good). Every write
    is scoped to the caller's entity."""

    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = db[Collection.SCENARIOS]
        self._plans = db[Collection.REMEDIATIONS]
        self._counts = scenarios

    def list_working_scenario_sessions(self, entity_id: int) -> Found:
        """The entity's scenario sessions whose job is queued or running, and the finished ones whose controls
        are still being matched: two indexed reads."""
        working = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        matching = {"entity_id": entity_id, "status": {"$nin": _WORKING}}
        matching["counts.controls_waiting"] = {"$gt": 0}  # the partial index holds only these
        return _oldest_first(self._sessions, _SCENARIO_SESSION_FIELDS, (working, matching))

    def list_working_remediation_plans(self, entity_id: int) -> Found:
        """The entity's remediation plans being written (queued or running)."""
        query = {"entity_id": entity_id, "status": {"$in": _WORKING}}
        return _oldest_first(self._plans, _REMEDIATION_PLAN_FIELDS, (query,))

    def cancel_scenario_session(
        self, session_id: str, entity_id: int, who: dict[str, Any]
    ) -> tuple[bool, int]:
        """(whether the scenario session's job was stopped, how many scenarios' controls were): the job while
        queued or running, the controls while waiting, being mapped or failed; its controls delivery lease
        ended."""
        now = datetime.now(UTC)
        session, cancelled = {"_id": session_id, "entity_id": entity_id}, {**who, "at": now}
        stop_session = {
            "$set": _cancelled_job(cancelled, now) | {"last_action.outcome": RunActionOutcome.CANCELLED},
            "$unset": {"controls_delivery": ""},
        }
        before = self._sessions.find_one_and_update(
            {**session, "status": {"$in": _WORKING}}, stop_session, {"last_action.kind": 1}
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
            self._counts.update_scenario_session_counts(session_id)
        if controls and not stopped:  # a finished scenario session whose controls were still being matched
            self._sessions.update_one(
                session,
                {"$set": {"cancelled": cancelled, "updated_at": now}, "$unset": {"controls_delivery": ""}},
            )
        return stopped, controls

    def cancel_remediation_plan(self, remediation_id: str, entity_id: int, who: dict[str, Any]) -> bool:
        """The plan's job stopped while it is queued or running; who and when kept on the plan."""
        now = datetime.now(UTC)
        stopped = self._plans.update_one(
            {"_id": remediation_id, "entity_id": entity_id, "status": {"$in": _WORKING}},
            {"$set": _cancelled_job({**who, "at": now}, now)},
        )
        return bool(stopped.modified_count)

    def resume_scenario_controls(self, session_id: str, cancelled_at: datetime | None) -> int | None:
        """A scenario session resumed on purpose: the controls a cancel stopped wait again (how many), and a
        session not at work reads done again. None when it is being deleted (nothing resumed). Checked after
        the re-queue, so either this sees the delete's mark or the delete's check for work sees these
        controls. A cancel landing since the caller read the session wins: the session is updated only while
        its cancel stamp is still `cancelled_at` (the one the caller saw, None for none), else the re-queue is
        undone and nothing is resumed (0)."""
        stamp_read = {"_id": session_id, "cancelled.at": cancelled_at}
        requeued = self._scenarios.update_many(
            {"session_id": session_id, "controls.status": Status.CANCELLED},
            {"$set": {"controls.status": Status.QUEUED, "controls.queued_at": datetime.now(UTC)}},
        ).modified_count
        if is_scenario_session_being_deleted(self._sessions, session_id):
            if requeued:  # undone: as before the click
                self._stop_requeued_controls(session_id)
            return None
        if not requeued:
            return 0
        if not self._sessions.update_one(stamp_read, _RESUMED).matched_count:
            self._stop_requeued_controls(session_id)  # cancelled meanwhile: the cancel stands
            return 0
        self._counts.update_scenario_session_counts(session_id)
        return requeued

    def _stop_requeued_controls(self, session_id: str) -> None:
        """The scenario session's waiting controls stopped again, as a resume found them."""
        self._scenarios.update_many(
            {"session_id": session_id, "controls.status": Status.QUEUED},
            {"$set": {"controls.status": Status.CANCELLED}},
        )

    def _work_left(self, session_id: str, entity_id: int) -> bool:
        """Whether anything of the scenario session is still queued or running: its job, its mapped
        scenarios' controls, or one of its plans."""
        working, children = {"$in": _WORKING}, {"session_id": session_id, "entity_id": entity_id}
        return any(
            records.find_one(query, {"_id": 1}) is not None
            for records, query in (
                (self._sessions, {"_id": session_id, "status": working}),
                (self._scenarios, {**children, "controls.status": working} | MAPPED_VERSIONS),
                (self._plans, {**children, "status": working}),
            )
        )

    def delete_scenario_session(
        self, session_id: str, entity_id: int
    ) -> tuple[dict[str, int], list[str]] | None:
        """The scenario session removed for good: marked, checked for work, then its scenarios, its plans and
        the session last, so a delete cut short is finished by calling it again. (how many of each were
        removed, the plans' ids); None when it is not this entity's or something of it is still at work."""
        session = {"_id": session_id, "entity_id": entity_id}
        marked = self._sessions.update_one(
            {**session, "status": {"$nin": _WORKING}}, {"$set": {DELETING_MARK: datetime.now(UTC)}}
        ).matched_count
        if not marked:
            return None
        if self._work_left(session_id, entity_id):  # final: nothing new can start on a marked session
            self._sessions.update_one(session, {"$unset": {DELETING_MARK: ""}})
            return None
        children = {"session_id": session_id, "entity_id": entity_id}
        plan_ids: list[str] = self._plans.distinct("_id", children)
        removed = {
            "scenarios": self._scenarios.delete_many(children).deleted_count,
            "remediation_plans": self._plans.delete_many(children).deleted_count,
        }
        self._sessions.delete_one(session)
        return removed, plan_ids


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
