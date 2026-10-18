"""A remediation plan's versions as regenerate and the review change them: each change is one conditional
write on what was read (the newest version; `decision_seq` for a decision)."""

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
        """What a regenerate or a decision reads first."""
        return self._plans.find_one({"_id": remediation_id}, _CHANGE_FIELDS)

    def append_version(
        self, remediation_id: str, latest: int, item: dict[str, Any], job: dict[str, Any], now: datetime
    ) -> bool:
        """Version `latest + 1` queued as `item` with its `job`; False when `latest` is no longer the newest
        or is still at work. The same pipeline write freezes the latest version's status and error onto its
        item; `$literal` keeps any text starting with "$" as text."""
        appended = self._plans.update_one(
            {
                "_id": remediation_id,
                "job.epoch": latest,
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
                        "cancelled": "$$REMOVE",
                        "updated_at": now,
                        "decision": _DECISION_WITH_A_NEW_VERSION,
                        "decision_seq": {
                            "$add": ["$decision_seq", 1]
                        },  # a decision on the older read retries
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


#: A new version waits for a decision unless one is accepted.
_DECISION_WITH_A_NEW_VERSION = {
    "$cond": [
        {"$eq": [{"$ifNull": ["$accepted_version", None]}, None]},
        Decision.PENDING,
        Decision.ACCEPTED,
    ]
}
