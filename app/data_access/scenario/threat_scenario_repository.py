"""tsg_scenarios: the guarded save, the counts aggregate, the duplicate check's read, the guarded decision and
each written scenario's controls lease. It never touches tsg_sessions."""

import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from pymongo import ASCENDING, DESCENDING, ReturnDocument, UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import (
    AbandonReason,
    Collection,
    Controls,
    Decision,
    ErrorCode,
    ErrorMessage,
    Remediation,
    RunKind,
    ScenarioStatus,
    Status,
)
from app.core.exceptions import DuplicateRecord
from app.data_access.base import Condition, MongoRepository, Record, drop_retired_index

#: The versions a reviewer works with: the newest of each attack path, and any older one already decided.
CURRENT_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": {"$ne": Decision.PENDING}}]}
#: The versions whose controls are mapped: the newest, or an older one a reviewer accepted.
MAPPED_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": Decision.ACCEPTED}]}
#: Failed controls the sweep still retries: attempts left.
FAILED_WITH_ATTEMPTS_LEFT = {
    "controls.status": Status.FAILED,
    "controls.attempts": {"$lt": Controls.MAX_ATTEMPTS},
}
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
    "content.threat.name",
    "content.threat.library_id",
    "content.threat.library_status",
    "content.category",
    "content.systems.id",
)

#: Dropped at start-up: no query reads scenarios by asset; a duplicate check stays in its own session.
RETIRED_ASSET_INDEX = "entity_id_1_asset_id_1_decision_1"
#: Dropped at start-up: it read every failed card, those failed for good too (the attempts index replaces it).
RETIRED_FAILED_CONTROLS_INDEX = "controls.status_1_controls.last_attempt_at_1"
_SCENARIO_INDEXES = (
    {"keys": [("session_id", ASCENDING), ("created_at", ASCENDING)]},
    {"keys": [("created_at", ASCENDING), ("session_id", ASCENDING)]},  # the sweep's recent sessions, covered
    {"keys": [("entity_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)]},
    {"keys": [("entity_id", ASCENDING), ("created_at", DESCENDING)]},
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
)


def waiting_controls(now: datetime) -> list[Record]:
    """Controls that wait: queued, or running with a lease expired before `now` and attempts left."""
    return [
        {"controls.status": Status.QUEUED},
        {
            "controls.status": Status.RUNNING,
            "controls.lease_until": {"$lt": now},
            "controls.attempts": {"$lt": Controls.MAX_ATTEMPTS},
        },
    ]


def _controls_waiting(_: Any = True) -> Record:
    """Mapped written scenarios whose controls wait: queued, or running with an expired lease and attempts
    left."""
    return {
        "status": ScenarioStatus.DONE,
        "$and": [MAPPED_VERSIONS, {"$or": waiting_controls(utc_now())}],
    }


_SCENARIO_CONDITIONS: dict[str, Condition] = {
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
    "controls_waiting": _controls_waiting,
    "controls_mapped": {"controls.status": Status.DONE, "controls.items.0": {"$exists": True}},
}

_SCENARIO_FIELD_LISTS = {
    #: A served scenario as shown: never the control search text, what mapped it, the plan check.
    "shown": {"controls.query": 0, "controls.shortlist": 0, "controls.made_with": 0, "plan_check": 0},
    #: A regenerate's versions of an attack path.
    "version": ("path_id", "version", "superseded_by"),
    #: What finding an attack path's accepted version reads.
    "lookup": ("session_id", "path_id", "version", "decision", "superseded_by"),
    #: What a review call reads of a target: its state and threat (a failure card's outage), never its text.
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

#: What a claim returns: the fields the control query reads (app/domain/scenario/controls.py) and the claim's.
_CLAIMED_FIELDS = dict.fromkeys(
    (
        "session_id",
        "source",
        "controls.attempts",
        "controls.request_id",
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
        "content.evidence.facts",  # is_about_ai leaves the cited attackers' names out
    ),
    1,
)
#: The scenarios the sweep looks after: written, never hand-written (those are mapped in their plan request).
SWEPT = {"status": ScenarioStatus.DONE, "source": {"$ne": RunKind.MANUAL}}
#: A plan job's controls claim still live at `now`: that mapping is its plan's work.
_PLANS_LIVE_CLAIM = re.compile(f"{re.escape(Remediation.CONTROLS_CLAIM_SUFFIX)}$")


def run_controls_to_stop(now: datetime) -> Record:
    """The controls a run cancel stops, the run's own: a swept scenario's mapped version waiting, being mapped
    or failed with attempts left; never a plan job's live claim (a plan maps them on purpose)."""
    stoppable = {
        "$or": [{"controls.status": {"$in": [Status.QUEUED, Status.RUNNING]}}, FAILED_WITH_ATTEMPTS_LEFT]
    }
    plans_claim = {
        "controls.status": Status.RUNNING,
        "controls.task_id": _PLANS_LIVE_CLAIM,
        "controls.lease_until": {"$gte": now},
    }
    return {**SWEPT, "$and": [MAPPED_VERSIONS, stoppable], "$nor": [plans_claim]}


def _running(task_id: str, now: datetime) -> Record:
    """A claim's update: the controls running for `task_id` under a fresh lease, one more attempt counted."""
    return {
        "$set": {
            "controls.status": Status.RUNNING,
            "controls.task_id": task_id,
            "controls.lease_until": now + timedelta(seconds=Controls.LEASE_SECONDS),
            "controls.last_attempt_at": now,
            "controls.error": None,  # this attempt's own outcome says why, if it fails too
        },
        "$inc": {"controls.attempts": 1},
    }


class TitleTaken(Exception):
    """Another written scenario of the scenario session already has this title (TITLE_INDEX)."""


class ThreatScenarioRepository(MongoRepository):
    """tsg_scenarios with its rules: the guarded save, the counts aggregate, the duplicate check's read, the
    guarded decision, and each written scenario's controls under its own lease (one conditional update claims
    it; every later write is fenced on the claim's task id, its attempts and running)."""

    def __init__(self, collection: str | MongoCollection = Collection.SCENARIOS) -> None:
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

    def list_scenarios_for_duplicate_check(self, session_id: str) -> list[Record]:
        """The scenario session's finished scenarios (each attack path's newest version and an older accepted
        one): the only ones a new scenario of the session may repeat. The asset's other sessions never block
        one (owner, 2026-10-20: D15)."""
        own_session: Record = {"session_id": session_id, "status": ScenarioStatus.DONE, **MAPPED_VERSIONS}
        return self.list(fields=_DUPLICATE_CHECK_FIELDS, **own_session)

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

    def update_manual_scenario_findings(
        self, scenario_id: str, findings: dict[str, Any], fields: Iterable[str]
    ) -> Record | None:
        """Saves a hand-written tsg_scenarios record's plan-job findings (attackers, library ids) and removes
        its `pending` mark in one write; the record as changed (only `fields`), or None once it is gone."""
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

    def claim_scenario_controls_by_id(
        self, scenario_id: str, task_id: str, remap: bool = False
    ) -> Record | None:
        """tsg_scenarios: one scenario's controls claimed by a plan job when not mapped (or, `remap`,
        mapped to retired controls only); None when mapped, a live lease holds them, or an expired one used
        every attempt."""
        now = utc_now()
        not_mapped = [
            {"controls.status": {"$in": [Status.QUEUED, Status.FAILED, Status.CANCELLED]}},
            {
                "controls.status": Status.RUNNING,
                "controls.lease_until": {"$lt": now},
                "controls.attempts": {"$lt": Controls.MAX_ATTEMPTS},
            },
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
        now = utc_now()
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

    def fail_abandoned_controls(self, now: datetime) -> list[str]:
        """tsg_scenarios: written scenarios' controls running with a lease expired before `now` after every
        attempt, failed for good (job_abandoned); the session ids whose counts the caller recomputes."""
        abandoned = {
            "status": ScenarioStatus.DONE,
            "controls.status": Status.RUNNING,
            "controls.lease_until": {"$lt": now},
            "controls.attempts": {"$gte": Controls.MAX_ATTEMPTS},
        }
        session_ids = [found for found in self.collection.distinct("session_id", abandoned) if found]
        if not session_ids:
            return []
        message = ErrorMessage.JOB_ABANDONED.format(attempts=Controls.MAX_ATTEMPTS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": message, "reason": AbandonReason.WORKER_STOPPED}
        failed = {"controls.status": Status.FAILED, "controls.error": error, "controls.lease_until": None}
        self.collection.update_many(abandoned, {"$set": failed})
        return session_ids

    def requeue_stalled_controls(self, now: datetime) -> list[str]:
        """tsg_scenarios: mappings queued too long, running with a lease expired before `now`, or failed long
        ago with attempts left, queued again (attempts kept); the session ids touched, sorted. The caller
        first settles stopped sessions and fails abandoned controls at the same `now`, so a mapping whose
        lease expired on its last attempt is never queued again."""
        lost = now - timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        failed_long_ago = now - timedelta(seconds=Controls.RETRY_FAILED_AFTER_SECONDS)
        stalled = [
            {"controls.status": Status.QUEUED, "controls.queued_at": {"$lt": lost}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            FAILED_WITH_ATTEMPTS_LEFT | {"controls.last_attempt_at": {"$lt": failed_long_ago}},
        ]
        query = {**SWEPT, "$and": [MAPPED_VERSIONS, {"$or": stalled}]}
        session_ids: list[str] = self.collection.distinct("session_id", query)
        requeued = {"controls.status": Status.QUEUED, "controls.queued_at": now, "controls.lease_until": None}
        self.collection.update_many(query, {"$set": requeued})
        return sorted(session_ids)


def _count(condition: dict[str, Any]) -> dict[str, Any]:
    """An aggregate sum of the documents matching `condition`."""
    return {"$sum": {"$cond": [condition, 1, 0]}}
