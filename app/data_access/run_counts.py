"""A run's scenario counts (BLUEPRINT Rule S12): always derived from its scenarios in one aggregation, never
kept as +1 counters, and written only when newer than the stored ones, since two jobs (writing and
controls) and the review API refresh them at the same time."""

from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database

from app.core.constants import Collection
from app.data_access.scenarios import ScenarioRepository


class RunCounts:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = ScenarioRepository(db)

    def refresh(self, session_id: str, controls_seconds: float = 0.0) -> dict[str, int]:
        """The run's counts now; saved unless a count computed later was saved first (`counts_at`), with
        `updated_at`, so the status shows when its numbers last moved (during controls too).
        `controls_seconds`: one mapping's time, added to the set's controls time (the status's timings) in the
        same write as the counts that end its wait, so no read sees the stage complete without it."""
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
