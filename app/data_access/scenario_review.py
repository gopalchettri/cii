"""tsg_scenarios as reviewers change it (Step 14, BUILD_PLAN S39-S42): a call's targets, accept-all's
scenarios, each path's accepted version, decisions and a promotion's record.

A decision is ONE update filtered on the decision it expects, so of two calls deciding one scenario exactly
one changes it; the unique index "one accepted version per path" (ScenarioRepository.ensure_indexes) holds
even when two calls accept two versions of one path at the same moment."""

from typing import Any

from pymongo import ASCENDING, UpdateOne
from pymongo.database import Database
from pymongo.errors import BulkWriteError

from app.core.constants import Collection, Decision, ScenarioStatus

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
#: MongoDB's duplicate-key error: the one-accepted-version index refused one target.
_DUPLICATE_KEY = 11000


class ScenarioReview:
    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def find_targets(self, session_id: str, scenario_ids: list[str]) -> dict[str, dict[str, Any]]:
        """The run's served scenarios among `scenario_ids`, by id, in one read: another run's scenario (and so
        another entity's) or a hidden blocked draft is simply not found."""
        query = {
            "_id": {"$in": scenario_ids},
            "session_id": session_id,
            "status": {"$ne": ScenarioStatus.BLOCKED},
        }
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
        """`decision` (with who, when and the call's `decision_id`) on each of `scenario_ids` still at
        `expected`, in one unordered bulk write: every id is tried even when the one-accepted-version index
        refuses another (G144: an update_many stops at the first refusal, leaving later ids untried). How many
        this call changed: fewer than asked means another call changed some first, or the index refused some;
        the caller reads back what holds."""
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
        """The scenario's library promotion, set once: True when this call recorded it, False when an earlier
        call already had (a repeat changes nothing, BLUEPRINT §12.2)."""
        result = self._scenarios.update_one(
            {"_id": scenario_id, "library_promotion": {"$exists": False}},
            {"$set": {"library_promotion": promotion, "updated_at": promotion["at"]}},
        )
        return bool(result.modified_count)
