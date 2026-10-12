"""A remediation plan's versions as regenerate and the review change them (BLUEPRINT M11 R8-R9; BUILD_PLAN
S50). Each change is one conditional write on what was read: a new version only while the version read is
still the newest and is finished or failed; a decision only while no other decision was written since the
read (`decision_seq`, the owner's provisional rule 2, kept 2026-10-11), so two decisions made at the same
moment can never both apply to a stale read."""

from datetime import datetime
from typing import Any

from pymongo.database import Database

from app.core.constants import Collection, Decision, Status

#: What a regenerate or a decision reads first: never a snapshot or a plan.
_CHANGE_FIELDS = {
    "entity_id": 1,
    "scenario_id": 1,
    "session_id": 1,
    "status": 1,
    "job.epoch": 1,
    "accepted_version": 1,
    "decision": 1,
    "decision_seq": 1,
    "register": 1,
    **{f"versions.{field}": 1 for field in ("version", "status", "decision")},
}


class RemediationVersions:
    def __init__(self, db: Database) -> None:
        self._plans = db[Collection.REMEDIATIONS]

    def find_for_change(self, remediation_id: str) -> dict[str, Any] | None:
        return self._plans.find_one({"_id": remediation_id}, _CHANGE_FIELDS)

    def append_version(
        self, remediation_id: str, latest: int, item: dict[str, Any], job: dict[str, Any], now: datetime
    ) -> bool:
        """Version `latest + 1` queued as `item` with its `job`; False when `latest` is no longer the newest
        version or is still queued or running. The same write copies the latest version's status and error,
        which until now lived only at the top level (R3), onto its own item: an older version's are frozen
        there. An update pipeline, so the copy is of the values at the moment of the write; `$literal` keeps
        any text in the item that starts with "$" as text."""
        appended = self._plans.update_one(
            {
                "_id": remediation_id,
                "job.epoch": latest,
                # A cancelled plan may be written again on purpose (G214), as a failed one.
                "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            },
            [
                {
                    "$set": {
                        "versions": {"$concatArrays": [_with_outcome(latest), [{"$literal": item}]]},
                        "job": {"$literal": job},
                        "status": Status.QUEUED,
                        "active": True,
                        "finished_at": "$$REMOVE",
                        "cancelled": "$$REMOVE",  # written again: no longer reads as stopped (G214)
                        "updated_at": now,
                        "decision": _DECISION_WITH_A_NEW_VERSION,
                        "decision_seq": {
                            "$add": ["$decision_seq", 1]
                        },  # a decision on the older read reads again
                    }
                }
            ],
        )
        return bool(appended.modified_count)

    def decide(
        self,
        remediation_id: str,
        seen_seq: int,
        changes: dict[str, Any],
        array_filters: list[dict[str, Any]],
    ) -> bool:
        """One decision's `changes` (`array_filters` pick the versions they name), applied only if no other
        decision was written since `seen_seq` was read; False otherwise (the caller reads again once)."""
        decided = self._plans.update_one(
            {"_id": remediation_id, "decision_seq": seen_seq},
            {"$set": changes, "$inc": {"decision_seq": 1}},
            array_filters=array_filters or None,
        )
        return bool(decided.modified_count)


def _with_outcome(latest: int) -> dict[str, Any]:
    """The versions, the latest one with the record's status and error copied onto its item."""
    return {
        "$map": {
            "input": "$versions",
            "as": "v",
            "in": {
                "$cond": [
                    {"$eq": ["$$v.version", latest]},
                    {"$mergeObjects": ["$$v", {"status": "$status", "error": "$job.error"}]},
                    "$$v",
                ]
            },
        }
    }


#: A new version waits for a decision unless one is accepted (engine/remediation/decisions.record_decision).
_DECISION_WITH_A_NEW_VERSION = {
    "$cond": [
        {"$eq": [{"$ifNull": ["$accepted_version", None]}, None]},
        Decision.PENDING,
        Decision.ACCEPTED,
    ]
}
