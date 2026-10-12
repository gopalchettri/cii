"""tsg_scenarios as regenerate (#6) changes it (BUILD_PLAN S41; BLUEPRINT R-8): the written versions of
the paths being regenerated, a version superseded by its successor, and a failed regenerate's reason on the
version that stays current."""

from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database

from app.core.constants import Collection, ScenarioStatus

_VERSION_FIELDS = {"path_id": 1, "version": 1, "superseded_by": 1, "content.statement": 1}


class ScenarioVersions:
    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def find_versions(self, session_id: str, path_ids: list[str]) -> list[dict[str, Any]]:
        """Every written version of these paths, oldest first (a hidden blocked draft or a failure card is not
        one): the regenerate's targets, the siblings its writer must differ from, and a successor already
        saved before a crash."""
        query = {"session_id": session_id, "path_id": {"$in": path_ids}, "status": ScenarioStatus.DONE}
        return list(self._scenarios.find(query, _VERSION_FIELDS).sort("version", 1))

    def supersede(self, old_id: str, new_id: str) -> None:
        """`old_id` replaced by `new_id` (saved first, so the path is never left without a current version);
        a repeat changes nothing. A reason left by an earlier failed regenerate goes with it."""
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
