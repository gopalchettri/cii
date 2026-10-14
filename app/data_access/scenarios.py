"""tsg_scenarios: one document per scenario version. The reads of runs' results, one scenario and an entity's
list; the write job's saves and counts (Step 12, BUILD_PLAN S23); every index of the collection.

A blocked scenario (spec v4.0 §7.4.7) is kept for audit only: no read here ever serves or counts it."""

from typing import Any

from pymongo import ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection, Decision, ScenarioStatus, Status

#: The versions a reviewer works with: the newest one of each path, and any older one already decided (an
#: accepted version stays listed after it was regenerated: owner 2026-10-09, guide §0 G-B).
CURRENT_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": {"$ne": Decision.PENDING}}]}
#: The versions whose controls are mapped and wait in `controls_waiting`: the newest, or an older one a
#: reviewer accepted (remediation needs its controls, G139). A replaced rejected or pending one is not (G148).
MAPPED_VERSIONS = {"$or": [{"superseded_by": None}, {"decision": Decision.ACCEPTED}]}
_SERVED = {"status": {"$ne": ScenarioStatus.BLOCKED}}
#: What a scenario read leaves out: the control search text (up to Controls.QUERY_MAX_CHARS each), what the
#: mapping was made with, and the plan check (its notes are in `findings`); no view shows them.
_NOT_SHOWN = {"controls.query": 0, "controls.made_with": 0, "plan_check": 0}
#: The title index before G142 (it covered only the newest versions): dropped once where it still exists.
_OLD_TITLE_INDEX = "one_title_per_run"

Page = tuple[list[dict[str, Any]], int]


class TitleTaken(Exception):
    """Another current written scenario of the run already has this title (the one_title_per_run index)."""


class ScenarioRepository:
    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def ensure_indexes(self) -> None:
        self._scenarios.create_index([("session_id", ASCENDING), ("created_at", ASCENDING)])
        self._scenarios.create_index(
            [("entity_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)]
        )
        self._scenarios.create_index([("entity_id", ASCENDING), ("created_at", DESCENDING)])
        self._scenarios.create_index(  # one accepted version per path, even under a race
            [("session_id", ASCENDING), ("path_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"decision": Decision.ACCEPTED},
        )
        # Titles unique within a run (owner, 2026-10-06), even under a race, across EVERY written version: the
        # results list also shows older versions a reviewer decided, so a regenerated version must not take
        # one's title once it is replaced (G142).
        if _OLD_TITLE_INDEX in self._scenarios.index_information():
            self._scenarios.drop_index(_OLD_TITLE_INDEX)
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

    def list_for_run(self, session_id: str, include_replaced: bool, offset: int, limit: int) -> Page:
        query: dict[str, Any] = {"session_id": session_id, **_SERVED}
        if not include_replaced:
            query |= CURRENT_VERSIONS
        return self._page(query, ASCENDING, offset, limit)

    def find_in_run(self, session_id: str, scenario_id: str) -> dict[str, Any] | None:
        return self._scenarios.find_one({"_id": scenario_id, "session_id": session_id, **_SERVED}, _NOT_SHOWN)

    def list_for_entity(self, entity_id: int, decision: Decision | None, offset: int, limit: int) -> Page:
        query: dict[str, Any] = {"entity_id": entity_id, **_SERVED, **CURRENT_VERSIONS}
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
        """Insert `scenario`, or replace its path's failure or blocked card (the same id). False when a
        written scenario already has its id (a repeated delivery saves once); TitleTaken when another written
        version of the run has its title."""
        try:
            self._scenarios.replace_one(
                {"_id": scenario["_id"], "status": {"$ne": ScenarioStatus.DONE}}, scenario, upsert=True
            )
        except DuplicateKeyError as exc:
            refused = (exc.details or {}).get("keyPattern") or {}
            if "title_key" in refused:
                raise TitleTaken(scenario["_id"]) from exc
            if refused or self._scenarios.count_documents(
                {"_id": scenario["_id"], "status": ScenarioStatus.DONE}, limit=1
            ):
                return False  # its id: this path's written scenario is already there
            # A server that does not name the index (an older one, or a MongoDB-compatible service): the id is
            # free, so it was the title.
            raise TitleTaken(scenario["_id"]) from exc
        return True

    def count_for_run(self, session_id: str) -> dict[str, int]:
        """The run's scenario counts, from the scenarios themselves in one aggregation (never +1 counters, so
        a retried save cannot count twice), BLUEPRINT R-7: written, failed, rejected and pending count each
        path's newest version; accepted counts any version (one per path at most); controls_waiting counts
        every version the controls job maps (MAPPED_VERSIONS), so the run reads step "controls" exactly while
        that job has work (G138: a regenerated path's accepted older version counted as written twice)."""
        done = {"$eq": ["$status", ScenarioStatus.DONE]}
        newest = {"$eq": [{"$ifNull": ["$superseded_by", None]}, None]}
        accepted = {"$eq": ["$decision", Decision.ACCEPTED]}
        waiting = {"$in": ["$controls.status", [Status.QUEUED, Status.RUNNING]]}
        failed_controls = {"$eq": ["$controls.status", Status.FAILED]}  # retried later by the sweep
        cancelled_controls = {"$eq": ["$controls.status", Status.CANCELLED]}  # stopped by the owner (G214)
        group = {
            "_id": None,
            "written": _count({"$and": [newest, done]}),
            "failed": _count({"$and": [newest, {"$eq": ["$status", ScenarioStatus.FAILED]}]}),
            "accepted": _count(accepted),
            "rejected": _count({"$and": [newest, {"$eq": ["$decision", Decision.REJECTED]}]}),
            "pending": _count({"$and": [newest, done, {"$eq": ["$decision", Decision.PENDING]}]}),
            "controls_waiting": _count({"$and": [done, waiting, {"$or": [newest, accepted]}]}),
            "controls_failed": _count({"$and": [done, failed_controls, {"$or": [newest, accepted]}]}),
            "controls_cancelled": _count({"$and": [done, cancelled_controls, {"$or": [newest, accepted]}]}),
        }
        match = {"session_id": session_id, **_SERVED, **CURRENT_VERSIONS}
        found = next(self._scenarios.aggregate([{"$match": match}, {"$group": group}]), None)
        return {key: int((found or {}).get(key, 0)) for key in group if key != "_id"}

    def _page(self, query: dict[str, Any], order: int, offset: int, limit: int) -> Page:
        """One indexed read and one count with the same filter."""
        items = list(
            self._scenarios.find(query, _NOT_SHOWN).sort("created_at", order).skip(offset).limit(limit)
        )
        return items, self._scenarios.count_documents(query)


def _count(condition: dict[str, Any]) -> dict[str, Any]:
    return {"$sum": {"$cond": [condition, 1, 0]}}


#: What the near-copy check compares of a finished scenario (G229): a few fields, never the evidence.
_FINISHED_FIELDS = {
    "path_id": 1,
    "content.statement": 1,
    "content.anatomy": 1,
    "content.threat.key": 1,
    "content.category": 1,
    "content.systems.id": 1,
}


def find_finished(db: Database, session_id: str) -> list[dict[str, Any]]:
    """The run's finished scenarios, current versions only, as the near-copy check reads them: one indexed
    read per write delivery (the write job keeps the list and adds what it saves)."""
    query = {"session_id": session_id, "status": ScenarioStatus.DONE, "superseded_by": None}
    return list(db[Collection.SCENARIOS].find(query, _FINISHED_FIELDS))
