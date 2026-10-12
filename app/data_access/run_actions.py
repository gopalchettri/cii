"""tsg_sessions as the review API gives a finished run more work (Step 14, BUILD_PLAN S40-S42): next set (#7)
and regenerate (#6) give the run a new write job in ONE conditional update, so of two clicks, or a click and a
worker, exactly one wins; promotion (#27) reads one threat of the frozen plan."""

from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import (
    Collection,
    RunActionKind,
    RunActionOutcome,
    RunClash,
    Status,
    Step,
    TaskName,
)
from app.data_access.job_control import DELETING_MARK, is_being_deleted
from app.models.scenarios import running_action

_RUN_FIELDS = {"entity_id": 1, "asset_id": 1, "status": 1, "step": 1, "job.epoch": 1}


class RunActionRecords:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def find_for_action(self, session_id: str, with_paths: bool) -> dict[str, Any]:
        """The run's state and job epoch, and with_paths its plan's paths (never the plan's threats or
        category records, its largest parts). KeyError for an unknown run."""
        fields = _RUN_FIELDS | ({"plan.paths": 1} if with_paths else {})
        found = self._sessions.find_one({"_id": session_id}, fields)
        if found is None:
            raise KeyError(session_id)
        return found

    def queue_again(
        self,
        run: dict[str, Any],
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> RunClash | None:
        """A new write job for `batch` (epoch + 1) and, for a next set, the set it asked for (`asked`), only
        while the run is still as read: done, failed or cancelled (G214: resumed on purpose) in step scenarios
        at the same epoch. None when queued; CHANGED when the run moved on (another click won, or a job runs);
        ACTIVE_RUN when another run of the asset is active (one active run per asset)."""
        now = datetime.now(UTC)
        job = _new_job(run["job"]["epoch"] + 1, batch, asked, now)
        still_as_read = {
            "_id": run["_id"],
            "entity_id": run["entity_id"],
            "job.epoch": run["job"]["epoch"],
            "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            "step": Step.SCENARIOS,
            DELETING_MARK: {"$exists": False},  # G214: a run its owner is deleting starts nothing more
        }
        update = {
            "$set": {
                "status": Status.QUEUED,
                "active": True,
                "job": job,
                "last_action": running_action(kind, now),
                **_running_summary(kind, batch, asked),
                "updated_at": now,
            },
            "$unset": _CLEARED_BY_A_NEW_ACTION,
        }
        try:
            matched = self._sessions.update_one(still_as_read, update).matched_count
        except DuplicateKeyError:
            return RunClash.ACTIVE_RUN
        if matched:
            return None
        return RunClash.DELETING if is_being_deleted(self._sessions, run["_id"]) else RunClash.CHANGED

    def find_plan_threat(self, session_id: str, threat_key: str) -> dict[str, Any] | None:
        """One threat of the run's frozen plan, by key, read alone (the positional projection: $elemMatch
        cannot reach a nested array): its exact library type name, name and primary category, as promotion
        (#27) proposes it."""
        found = self._sessions.find_one(
            {"_id": session_id, "plan.threats.key": threat_key}, {"plan.threats.$": 1}
        )
        threats = ((found or {}).get("plan") or {}).get("threats") or []
        return threats[0] if threats else None


#: What a new next set or regenerate clears: its own times (the status shows this set's writing and controls
#: times, not the last), and a cancel's mark (G214: a resumed run no longer reads as cancelled).
_CLEARED_BY_A_NEW_ACTION = {
    "finished_at": "",
    "timings.scenarios_s": "",
    "timings.controls_s": "",
    "cancelled": "",
}


def _running_summary(
    kind: RunActionKind, batch: list[dict[str, Any]], asked: list[str] | None
) -> dict[str, Any]:
    """The status's summary of this action, from its first moment, so it never shows the one before while this
    one runs or after it fails; its finish write fills in what it delivered (the status reads its outcome
    from last_action, which every job failure sets to failed)."""
    if kind == RunActionKind.NEXT_SET:
        requested = len(asked or [])
        return {
            "last_next_set": {"outcome": RunActionOutcome.RUNNING, "requested": requested, "delivered": None}
        }
    return {"last_regen": {"outcome": RunActionOutcome.RUNNING, "requested": len(batch), "replaced": None}}


def _new_job(
    epoch: int, batch: list[dict[str, Any]], asked: list[str] | None, now: datetime
) -> dict[str, Any]:
    """A write job as queue_again replaces the run's job with it, whole: a regenerate carries no set."""
    return {
        "task": TaskName.WRITE_SCENARIOS,
        "epoch": epoch,
        "task_id": None,
        "attempts": 0,
        "due_at": now,
        "lease_until": None,
        "resends": 0,
        "error": None,
        "batch": batch,
        "set": asked,
    }
