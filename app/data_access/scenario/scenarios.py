"""tsg_scenarios: one document per scenario version, with its controls mapping and lease; a run's counts and
its controls delivery lease. A blocked scenario is kept for audit only: no read here serves or counts it."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ASCENDING, DESCENDING, ReturnDocument, UpdateOne
from pymongo.database import Database
from pymongo.errors import BulkWriteError, DuplicateKeyError

from app.core.constants import Collection, Controls, Decision, RunKind, ScenarioStatus, Status

#: The versions a reviewer works with: the newest of each path, and any older one already decided.
CURRENT_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": {"$ne": Decision.PENDING}}]}
#: The versions whose controls are mapped: the newest, or an older one a reviewer accepted.
MAPPED_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": Decision.ACCEPTED}]}
SERVED = {"status": {"$ne": ScenarioStatus.BLOCKED}}
#: What a scenario read leaves out: the control search text, what the mapping was made with, the plan check.
NOT_SHOWN = {"controls.query": 0, "controls.made_with": 0, "plan_check": 0}
#: Controls not mapped yet that a cancel stops: waiting, being mapped, or failed (the sweep would retry it).
STOPPABLE_CONTROLS = [Status.QUEUED, Status.RUNNING, Status.FAILED]
#: MongoDB's duplicate-key error code.
_DUPLICATE_KEY = 11000
#: What count_for_run reads of a scenario, all in the run_counts index after session_id.
_COUNTED_FIELDS = ("status", "superseded_by", "decision", "controls.status")

Page = tuple[list[dict[str, Any]], int]


class TitleTaken(Exception):
    """Another written scenario of the run already has this title (the one_title_per_run index)."""


class ScenarioRepository:
    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def ensure_indexes(self) -> None:
        """Every index of tsg_scenarios."""
        self._scenarios.create_index([("session_id", ASCENDING), ("created_at", ASCENDING)])
        self._scenarios.create_index(
            [("entity_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)]
        )
        self._scenarios.create_index([("entity_id", ASCENDING), ("created_at", DESCENDING)])
        # find_held_elsewhere: the asset's own records, never the entity's whole register.
        self._scenarios.create_index(
            [("entity_id", ASCENDING), ("asset_id", ASCENDING), ("decision", ASCENDING)]
        )
        self._scenarios.create_index(  # one accepted version per path, even under a race
            [("session_id", ASCENDING), ("path_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"decision": Decision.ACCEPTED},
        )
        # Titles unique within a run across every written version: the results also list older decided ones.
        self._scenarios.create_index(
            [("session_id", ASCENDING), ("title_key", ASCENDING)],
            unique=True,
            partialFilterExpression={"status": ScenarioStatus.DONE, "title_key": {"$exists": True}},
            name="one_title_per_run_all_versions",
        )
        self._scenarios.create_index([("controls.status", ASCENDING), ("controls.queued_at", ASCENDING)])
        self._scenarios.create_index(
            [("controls.status", ASCENDING), ("controls.last_attempt_at", ASCENDING)]
        )
        self._scenarios.create_index([("session_id", ASCENDING), ("controls.status", ASCENDING)])
        self._scenarios.create_index(  # count_for_run reads this index only, never a document
            [(field, ASCENDING) for field in ("session_id", *_COUNTED_FIELDS)], name="run_counts"
        )

    def list_for_run(self, session_id: str, offset: int, limit: int) -> Page:
        """The run's current versions, oldest first; replaced ones are nested by the read, never listed."""
        query: dict[str, Any] = {"session_id": session_id, **SERVED, **CURRENT_VERSIONS}
        return self._page(query, ASCENDING, offset, limit)

    def find_in_run(self, session_id: str, scenario_id: str) -> dict[str, Any] | None:
        """One served scenario of the run."""
        return self._scenarios.find_one({"_id": scenario_id, "session_id": session_id, **SERVED}, NOT_SHOWN)

    def list_for_entity(self, entity_id: int, decision: Decision | None, offset: int, limit: int) -> Page:
        """The entity's current versions, newest first, optionally of one decision."""
        query: dict[str, Any] = {"entity_id": entity_id, **SERVED, **CURRENT_VERSIONS}
        if decision is not None:
            query["decision"] = decision
        return self._page(query, DESCENDING, offset, limit)

    def find_written(self, session_id: str, path_ids: list[str]) -> dict[str, str]:
        """{path_id: scenario_id} of the paths already written: a retried or repeated batch skips them."""
        rows = self._scenarios.find(
            {
                "session_id": session_id,
                "path_id": {"$in": path_ids},
                "status": ScenarioStatus.DONE,
                "superseded_by": None,
            },
            {"path_id": 1},
        )
        return {row["path_id"]: row["_id"] for row in rows}

    def save(self, scenario: dict[str, Any]) -> bool:
        """Insert `scenario`, or replace its path's failure or blocked card (same id). False when a written
        scenario already has its id; TitleTaken when another written version of the run has its title."""
        try:
            self._scenarios.replace_one(
                {"_id": scenario["_id"], "status": {"$ne": ScenarioStatus.DONE}}, scenario, upsert=True
            )
        except DuplicateKeyError as exc:
            if self._scenarios.count_documents(
                {"_id": scenario["_id"], "status": ScenarioStatus.DONE}, limit=1
            ):
                return False
            raise TitleTaken(scenario["_id"]) from exc
        return True

    def count_for_run(self, session_id: str) -> dict[str, int]:
        """The run's scenario counts in one aggregation over the run_counts index alone. Written, failed,
        rejected and pending count each path's newest version; accepted counts any version; the controls
        counts cover MAPPED_VERSIONS."""
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
        # No CURRENT_VERSIONS in the match: its superseded_by null test reads each document, and every count
        # above already takes the newest or an accepted version only, both current.
        match = {"session_id": session_id, **SERVED}
        fields = {"_id": 0} | dict.fromkeys(_COUNTED_FIELDS, 1)
        pipeline = [{"$match": match}, {"$project": fields}, {"$group": group}]
        found = next(self._scenarios.aggregate(pipeline), None)
        return {key: int((found or {}).get(key, 0)) for key in group if key != "_id"}

    def _page(self, query: dict[str, Any], order: int, offset: int, limit: int) -> Page:
        """One indexed read and one count with the same filter."""
        items = list(
            self._scenarios.find(query, NOT_SHOWN).sort("created_at", order).skip(offset).limit(limit)
        )
        return items, self._scenarios.count_documents(query)


def _count(condition: dict[str, Any]) -> dict[str, Any]:
    """An aggregation sum of the documents matching `condition`."""
    return {"$sum": {"$cond": [condition, 1, 0]}}


class RunCounts:
    """A run's scenario counts, always derived from its scenarios, saved only when newer than the stored ones
    (two jobs and the review API refresh them at the same time)."""

    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = ScenarioRepository(db)

    def refresh(self, session_id: str, controls_seconds: float = 0.0) -> dict[str, int]:
        """The run's counts now, saved unless a later count was saved first; `controls_seconds` is added to
        the controls time in the same write, so no read sees the stage complete without it."""
        computed_at = datetime.now(UTC)  # taken before the aggregation: a later one always counts as newer
        counts = self._scenarios.count_for_run(session_id)
        older = {"$or": [{"counts_at": {"$lt": computed_at}}, {"counts_at": None}]}
        changes: dict[str, Any] = {f"counts.{key}": value for key, value in counts.items()}
        changes |= {"counts_at": computed_at, "updated_at": computed_at}
        added = {"$inc": {"timings.controls_s": round(controls_seconds, 2)}} if controls_seconds > 0 else {}
        saved = self._sessions.update_one({"_id": session_id, **older}, {"$set": changes, **added})
        if added and not saved.matched_count:  # a newer count was saved first: the time is still added
            self._sessions.update_one({"_id": session_id}, added)
        return counts


#: What the duplicate check compares of a finished scenario: a few fields, never the evidence.
_FINISHED_FIELDS = {
    "path_id": 1,
    "decision": 1,
    "content.statement": 1,
    "content.threat.key": 1,
    "content.threat.library_id": 1,
    "content.threat.library_status": 1,
    "content.category": 1,
    "content.systems.id": 1,
}
#: Another run's scenario is read without its path: path ids repeat across runs, so no own-path filter may
#: drop it.
_HELD_FIELDS = {field: 1 for field in _FINISHED_FIELDS if field != "path_id"}


def find_finished(db: Database, session_id: str) -> list[dict[str, Any]]:
    """The run's finished scenarios in the register, as the duplicate check reads them: each path's newest
    version and an older one a reviewer accepted."""
    query = {"session_id": session_id, "status": ScenarioStatus.DONE, **MAPPED_VERSIONS}
    return list(db[Collection.SCENARIOS].find(query, _FINISHED_FIELDS))


def find_held_elsewhere(db: Database, entity_id: int, asset_id: int, session_id: str) -> list[dict[str, Any]]:
    """The asset's scenarios of its other runs that a reviewer accepted or has still to decide, as the
    duplicate check reads them."""
    query = {
        "entity_id": entity_id,
        "decision": {"$in": [Decision.PENDING, Decision.ACCEPTED]},
        "asset_id": asset_id,
        "session_id": {"$ne": session_id},
        "status": ScenarioStatus.DONE,
        **CURRENT_VERSIONS,
    }
    return list(db[Collection.SCENARIOS].find(query, _HELD_FIELDS))


_VERSION_FIELDS = {"path_id": 1, "version": 1, "superseded_by": 1, "content.statement": 1}
#: What explains a given-up path: its newest card's threat and reason.
_GIVEN_UP_FIELDS = {"path_id": 1, "version": 1, "content.threat.name": 1, "failure": 1, "findings": 1}
#: What finding a path's accepted version reads.
_LOOKUP_FIELDS = {"session_id": 1, "path_id": 1, "version": 1, "decision": 1, "superseded_by": 1}


class ScenarioVersions:
    """A path's versions as regenerate changes them, and the other versions of a read page's paths."""

    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def find_versions(self, session_id: str, path_ids: list[str]) -> list[dict[str, Any]]:
        """Every written version of these paths, oldest first."""
        query = {"session_id": session_id, "path_id": {"$in": path_ids}, "status": ScenarioStatus.DONE}
        return list(self._scenarios.find(query, _VERSION_FIELDS).sort("version", 1))

    def supersede(self, old_id: str, new_id: str) -> None:
        """`old_id` replaced by `new_id` (saved first); a repeat changes nothing. An earlier failed
        regenerate's reason goes with it."""
        self._scenarios.update_one(
            {"_id": old_id, "superseded_by": None},
            {
                "$set": {"superseded_by": new_id, "updated_at": datetime.now(UTC)},
                "$unset": {"regenerate_error": ""},
            },
        )

    def note_failure(self, scenario_id: str, error: dict[str, Any]) -> None:
        """Why a regenerate wrote no new version ({code, message, at}); the version stays current."""
        self._scenarios.update_one(
            {"_id": scenario_id, "superseded_by": None},
            {"$set": {"regenerate_error": error, "updated_at": error["at"]}},
        )

    def newest_cards(self, session_id: str, path_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Each path's newest card of any status, by path id, in one read: why a path was given up."""
        query = {"session_id": session_id, "path_id": {"$in": path_ids}}
        return {
            doc["path_id"]: doc for doc in self._scenarios.find(query, _GIVEN_UP_FIELDS).sort("version", 1)
        }

    def find_other_versions(self, records: list[dict[str, Any]], with_replaced: bool) -> list[dict[str, Any]]:
        """In one read for a page: the accepted versions of its scenarios' paths and, `with_replaced`, every
        replaced version of them (whole documents only when they are nested)."""
        paths = {(record["session_id"], record["path_id"]) for record in records if record.get("path_id")}
        if not paths:
            return []
        wanted: list[dict[str, Any]] = [{"decision": Decision.ACCEPTED}]
        if with_replaced:
            wanted.append({"superseded_by": {"$ne": None}})
        query = {
            "session_id": {"$in": sorted({session for session, _ in paths})},
            "path_id": {"$in": sorted({path for _, path in paths})},
            **SERVED,
            "$or": wanted,
        }
        fields = NOT_SHOWN if with_replaced else _LOOKUP_FIELDS
        return [
            doc for doc in self._scenarios.find(query, fields) if (doc["session_id"], doc["path_id"]) in paths
        ]


#: What a review call reads of a target: its state and threat, never its text.
_TARGET_FIELDS = {
    "path_id": 1,
    "source": 1,
    "status": 1,
    "decision": 1,
    "superseded_by": 1,
    "content.threat": 1,
    "controls.status": 1,
    "decision_id": 1,
}


class ScenarioReview:
    """Reviewers' reads and writes. A decision is one update filtered on the decision it expects, so of two
    calls deciding one scenario exactly one changes it."""

    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def find_targets(self, session_id: str, scenario_ids: list[str]) -> dict[str, dict[str, Any]]:
        """The run's served scenarios among `scenario_ids`, by id: another run's is simply not found."""
        query = {"_id": {"$in": scenario_ids}, "session_id": session_id, **SERVED}
        return {row["_id"]: row for row in self._scenarios.find(query, _TARGET_FIELDS)}

    def find_acceptable(self, session_id: str) -> list[dict[str, Any]]:
        """Accept-all's scenarios: the run's current written versions not rejected, oldest first."""
        query = {
            "session_id": session_id,
            "status": ScenarioStatus.DONE,
            "superseded_by": None,
            "decision": {"$ne": Decision.REJECTED},
        }
        return list(self._scenarios.find(query, _TARGET_FIELDS).sort("created_at", ASCENDING))

    def find_accepted(self, session_id: str, path_ids: list[str]) -> dict[str, str]:
        """{path_id: scenario_id} of each path's accepted version (one at most, by the unique index)."""
        query = {"session_id": session_id, "path_id": {"$in": path_ids}, "decision": Decision.ACCEPTED}
        return {row["path_id"]: row["_id"] for row in self._scenarios.find(query, {"path_id": 1})}

    def set_decision(
        self, scenario_ids: list[str], expected: Decision, decision: Decision, stamp: dict[str, Any]
    ) -> int:
        """`decision` (with `stamp`) on each scenario still at `expected`, in one unordered bulk write, so
        every id is tried even when the one-accepted-version index refuses another. How many changed."""
        updates = [
            UpdateOne({"_id": scenario_id, "decision": expected}, {"$set": {"decision": decision, **stamp}})
            for scenario_id in scenario_ids
        ]
        try:
            return self._scenarios.bulk_write(updates, ordered=False).modified_count
        except BulkWriteError as exc:
            if any(error.get("code") != _DUPLICATE_KEY for error in exc.details.get("writeErrors", [])):
                raise
            return int(exc.details.get("nModified", 0))

    def record_promotion(self, scenario_id: str, promotion: dict[str, Any]) -> bool:
        """The scenario's library promotion, set once: True when this call recorded it."""
        result = self._scenarios.update_one(
            {"_id": scenario_id, "library_promotion": {"$exists": False}},
            {"$set": {"library_promotion": promotion, "updated_at": promotion["at"]}},
        )
        return bool(result.modified_count)


#: What the controls job reads of a claimed scenario.
_CLAIMED_FIELDS = {"session_id": 1, "path_id": 1, "source": 1, "content": 1, "controls.attempts": 1}
#: The scenarios the sweep looks after: written, never hand-written (those are mapped in their plan request).
_SWEPT = {"status": ScenarioStatus.DONE, "source": {"$ne": RunKind.MANUAL}}


class ControlLeases:
    """Each written scenario's controls mapping under its own small lease: one conditional update claims it,
    and every later write is fenced on the claim's task id."""

    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def claim(self, session_id: str, task_id: str) -> dict[str, Any] | None:
        """The run's oldest scenario whose controls wait, now running for `task_id`; None when none waits."""
        now = datetime.now(UTC)
        return self._scenarios.find_one_and_update(
            _waiting(session_id, now),
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            sort=[("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )

    def claim_scenario(self, scenario_id: str, task_id: str, remap: bool = False) -> dict[str, Any] | None:
        """One scenario's controls taken by a plan request when not mapped (or, `remap`, mapped to retired
        controls only). None when mapped, or a live lease holds them."""
        now = datetime.now(UTC)
        not_mapped = [
            {"controls.status": {"$in": [Status.QUEUED, Status.FAILED, Status.CANCELLED]}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            {"controls.status": Status.DONE, "controls.items": {"$size": 0}},
            {"controls": {"$exists": False}},
        ]
        if remap:
            not_mapped.append({"controls.status": Status.DONE})
        return self._scenarios.find_one_and_update(
            {"_id": scenario_id, "status": ScenarioStatus.DONE, "$or": not_mapped},
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            return_document=ReturnDocument.AFTER,
        )

    def find_mapped(self, scenario_id: str) -> list[dict[str, Any]] | None:
        """The scenario's mapped controls, or None while they are not mapped."""
        found = self._scenarios.find_one(
            {"_id": scenario_id, "controls.status": Status.DONE, "controls.items.0": {"$exists": True}},
            {"controls.items": 1},
        )
        return None if found is None else found["controls"]["items"]

    def renew(self, scenario_id: str, task_id: str, attempts: int) -> bool:
        """Extend the claim's lease; False once it was taken over."""
        lease_until = datetime.now(UTC) + timedelta(seconds=Controls.LEASE_SECONDS)
        return self._if_owned(scenario_id, task_id, attempts, {"controls.lease_until": lease_until})

    def finish(self, scenario_id: str, task_id: str, attempts: int, mapped: dict[str, Any]) -> bool:
        """The mapping saved and the controls done; False when this claim was taken over."""
        changes = {f"controls.{key}": value for key, value in mapped.items()}
        done = {
            "controls.status": Status.DONE,
            "controls.mapped_at": datetime.now(UTC),
            "controls.error": None,
        }
        return self._if_owned(scenario_id, task_id, attempts, changes | done | {"controls.lease_until": None})

    def give_back(self, scenario_id: str, task_id: str, attempts: int, error: dict[str, str]) -> bool:
        """After an outage: queued again, or failed once Controls.MAX_ATTEMPTS were used."""
        if attempts >= Controls.MAX_ATTEMPTS:
            return self.fail(scenario_id, task_id, attempts, error)
        queued = {
            "controls.status": Status.QUEUED,
            "controls.queued_at": datetime.now(UTC),
            "controls.error": error,
        }
        return self._if_owned(scenario_id, task_id, attempts, queued | {"controls.lease_until": None})

    def fail(self, scenario_id: str, task_id: str, attempts: int, error: dict[str, str]) -> bool:
        """The mapping failed; the sweep retries it later while Controls.MAX_ATTEMPTS are not used up."""
        failed = {"controls.status": Status.FAILED, "controls.error": error, "controls.lease_until": None}
        return self._if_owned(scenario_id, task_id, attempts, failed)

    def _if_owned(self, scenario_id: str, task_id: str, attempts: int, changes: dict[str, Any]) -> bool:
        """`changes`, only while the controls are running under this claim: its task id and the attempts it
        counted (Celery reuses a task id on a redelivery, so a hung copy and the copy that claimed again after
        its lease ran out share it)."""
        fence = {
            "_id": scenario_id,
            "controls.task_id": task_id,
            "controls.attempts": attempts,
            "controls.status": Status.RUNNING,
        }
        return self._scenarios.update_one(fence, {"$set": changes}).matched_count == 1


class ControlSweep:
    """The beat sweep: every stalled mapping queued again; and whether a run still has controls waiting."""

    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]
        self._sessions = db[Collection.SESSIONS]
        self._counts = RunCounts(db)

    def requeue_stalled(self) -> list[str]:
        """Mappings queued too long, running with an expired lease, or failed long ago with attempts left:
        queued now, attempts kept. The runs touched; never a cancelled or deleted run (settled first)."""
        self._settle_stopped_runs()
        now = datetime.now(UTC)
        lost = now - timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        failed_long_ago = now - timedelta(seconds=Controls.RETRY_FAILED_AFTER_SECONDS)
        retryable = {
            "controls.status": Status.FAILED,
            "controls.last_attempt_at": {"$lt": failed_long_ago},
            "controls.attempts": {"$lt": Controls.MAX_ATTEMPTS},
        }
        stalled = [
            {"controls.status": Status.QUEUED, "controls.queued_at": {"$lt": lost}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            retryable,
        ]
        query = {**_SWEPT, "$and": [MAPPED_VERSIONS, {"$or": stalled}]}
        runs: list[str] = self._scenarios.distinct("session_id", query)
        requeued = {"controls.status": Status.QUEUED, "controls.queued_at": now, "controls.lease_until": None}
        self._scenarios.update_many(query, {"$set": requeued})
        return sorted(runs)

    def _settle_stopped_runs(self) -> None:
        """Controls waiting on a cancelled run stop, with its counts; the scenarios of a deleted run go."""
        waiting = {**_SWEPT, "controls.status": {"$in": STOPPABLE_CONTROLS}} | MAPPED_VERSIONS
        runs = self._scenarios.distinct("session_id", waiting)
        if not runs:
            return
        found = self._sessions.find({"_id": {"$in": runs}}, {"status": 1})
        states = {record["_id"]: record.get("status") for record in found}
        if stopped := [run for run in runs if states.get(run) == Status.CANCELLED]:
            self._scenarios.update_many(
                {**waiting, "session_id": {"$in": stopped}},
                {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
            )
            for run in stopped:
                self._counts.refresh(run)
        if gone := [run for run in runs if run not in states]:
            self._scenarios.delete_many({"session_id": {"$in": gone}})

    def has_waiting(self, session_id: str) -> bool:
        """Whether one of the run's scenarios waits for its controls, as ControlLeases.claim takes them."""
        return self._scenarios.find_one(_waiting(session_id, datetime.now(UTC)), {"_id": 1}) is not None


class ControlDeliveries:
    """One delivery maps a run's controls at a time: a small lease on the run (controls_delivery {task_id,
    until}) taken in one conditional update."""

    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def take(self, session_id: str, task_id: str) -> bool:
        """The run's delivery lease for `task_id` when free, expired, handed over, or already its own; never
        for a cancelled run. False while another delivery holds it."""
        now = datetime.now(UTC)
        free = [
            {"controls_delivery.until": {"$lt": now}},
            {"controls_delivery.task_id": {"$in": [None, task_id]}},  # also: no lease at all
        ]
        held = {"task_id": task_id, "until": now + timedelta(seconds=Controls.LEASE_SECONDS)}
        found = self._sessions.update_one(
            {"_id": session_id, "status": {"$ne": Status.CANCELLED}, "$or": free},
            {"$set": {"controls_delivery": held}},
        )
        return found.matched_count == 1

    def renew(self, session_id: str, task_id: str) -> bool:
        """Extend the delivery lease; False once another delivery holds it."""
        until = datetime.now(UTC) + timedelta(seconds=Controls.LEASE_SECONDS)
        return self._if_held(session_id, task_id, {"$set": {"controls_delivery.until": until}})

    def hand_over(self, session_id: str, task_id: str) -> None:
        """The run's next turn is queued: no holder, and the run counts as served while that message waits."""
        until = datetime.now(UTC) + timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        self._if_held(session_id, task_id, {"$set": {"controls_delivery": {"task_id": None, "until": until}}})

    def release(self, session_id: str, task_id: str) -> None:
        """The delivery lease ended."""
        self._if_held(session_id, task_id, {"$unset": {"controls_delivery": ""}})

    def served(self, session_ids: Iterable[str]) -> set[str]:
        """Of `session_ids`, the runs a delivery maps now or whose next turn is on its way."""
        found = self._sessions.find(
            {"_id": {"$in": list(session_ids)}, "controls_delivery.until": {"$gte": datetime.now(UTC)}},
            {"_id": 1},
        )
        return {record["_id"] for record in found}

    def _if_held(self, session_id: str, task_id: str, update: dict[str, Any]) -> bool:
        """`update`, only while `task_id` holds the run's delivery lease."""
        held = {"_id": session_id, "controls_delivery.task_id": task_id}
        return self._sessions.update_one(held, update).matched_count == 1


def _waiting(session_id: str, now: datetime) -> dict[str, Any]:
    """The run's mapped written scenarios whose controls wait: queued, or running with an expired lease."""
    waiting = [
        {"controls.status": Status.QUEUED},
        {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
    ]
    return {
        "session_id": session_id,
        "status": ScenarioStatus.DONE,
        "$and": [MAPPED_VERSIONS, {"$or": waiting}],
    }


def _running(task_id: str, now: datetime) -> dict[str, Any]:
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
