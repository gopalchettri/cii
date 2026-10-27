"""tsg_remediations: one remediation plan per scenario (a unique index, race-free) with its versions, and the
plan's guarded writes: a new version, an outage-failed one queued again, a decision, and the plan job's
version writes under its job lease."""

from datetime import datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Collection, Decision, ErrorCode, Status
from app.data_access.base import MongoRepository
from app.data_access.jobs.job_repository import JobLease, ended_job_fields
from app.models.remediation.plan import RemediationStatus, RemediationSummary

#: What a regenerate or a review reads first: never a snapshot or a plan.
_CHANGE_FIELDS = {
    "entity_id": 1,
    "scenario_id": 1,
    "session_id": 1,
    "status": 1,
    "job.epoch": 1,
    "job.error": 1,
    "accepted_version": 1,
    "decision_seq": 1,
    **{f"versions.{field}": 1 for field in ("version", "status", "decision")},
}
#: What a plan request and its plan job read of the scenario: owner, decision, content, controls, and what
#: its plan job still has to find.
PLANNED_SCENARIO_FIELDS = (
    "entity_id",
    "session_id",
    "asset_id",
    "source",
    "status",
    "decision",
    "content",
    "controls",
    "pending",
)
#: The list's filters: each with the newest-first sort is one index scan.
_LIST_FILTERS = ("status", "decision", "risk_level", "session_id")
#: A new version waits for a decision unless one is accepted.
_DECISION_WITH_A_NEW_VERSION = {
    "$cond": [
        {"$eq": [{"$ifNull": ["$accepted_version", None]}, None]},
        Decision.PENDING,
        Decision.ACCEPTED,
    ]
}
#: The decision stamp's fields, cleared on a version put back to pending.
_STAMP_FIELDS = ("decided_by", "decided_by_client", "decided_at", "review_comment")


class RemediationRepository(MongoRepository):
    """tsg_remediations with its rules on top of the plain reads and writes."""

    def __init__(self, collection: str | MongoCollection = Collection.REMEDIATIONS) -> None:
        """Defines tsg_remediations: its indexes, field lists and record shape."""
        super().__init__(
            collection,
            indexes=(
                {"keys": "scenario_id", "unique": True},  # one plan per scenario
                {"keys": [("entity_id", 1), ("created_at", -1)]},
                *({"keys": [("entity_id", 1), (field, 1), ("created_at", -1)]} for field in _LIST_FILTERS),
            ),
            field_lists={
                "status": RemediationStatus.RECORD_FIELDS,
                "change": _CHANGE_FIELDS,
                "summary": RemediationSummary.RECORD_FIELDS,
                "result": {"versions.snapshot": 0},
            },
            required=("_id", "scenario_id"),
            schema_version=1,
        )

    def create_remediation_plan_version(
        self,
        remediation_id: str,
        latest_version: int,
        new_version: dict[str, Any],
        job: dict[str, Any],
        now: datetime,
    ) -> bool:
        """Appends `new_version` (number `latest_version + 1`) with its job on tsg_remediations; False when
        `latest_version` is no longer the newest or is still at work. The latest version's status and error
        are frozen onto its item in the same write; `$literal` keeps any text starting with "$" as text."""
        appended = self.collection.update_one(
            {
                "_id": remediation_id,
                "job.epoch": latest_version,
                "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            },
            [
                {
                    "$set": {
                        "versions": {
                            "$concatArrays": [_with_outcome(latest_version), [{"$literal": new_version}]]
                        },
                        "job": {"$literal": job},
                        "status": Status.QUEUED,
                        "finished_at": "$$REMOVE",
                        "cancelled": "$$REMOVE",
                        "updated_at": now,
                        "decision": _DECISION_WITH_A_NEW_VERSION,
                        "decision_seq": {"$add": ["$decision_seq", 1]},  # an older read's decision retries
                    }
                }
            ],
        )
        return bool(appended.modified_count)

    def retry_remediation_plan_version(
        self, remediation_id: str, version: int, job: dict[str, Any], now: datetime
    ) -> bool:
        """Queues the latest `version` again in place with a fresh `job` on tsg_remediations, its snapshot
        cleared; False unless it is still the latest and failed for an outage."""
        retried = self.collection.update_one(
            {
                "_id": remediation_id,
                "job.epoch": version,
                "status": Status.FAILED,
                "job.error.code": ErrorCode.UNAVAILABLE,
            },
            {
                "$set": {
                    "job": job,
                    "status": Status.QUEUED,
                    "updated_at": now,
                    "versions.$[v].snapshot": None,
                },
                "$unset": {"finished_at": ""},
            },
            array_filters=[{"v.version": version}],
        )
        return retried.modified_count == 1

    def update_remediation_plan_decision(
        self, remediation_id: str, seen_decision_seq: int, change: dict[str, Any]
    ) -> bool:
        """Writes one decision on tsg_remediations only if no other decision was written since
        `seen_decision_seq` was read; False otherwise (the caller reads again once)."""
        stamp = change["stamp"]
        changes: dict[str, Any] = {
            "versions.$[v].decision": change["decision"],
            **{f"versions.$[v].{field}": stamp[field] for field in _STAMP_FIELDS},
            "accepted_version": change["accepted_version"],
            "decision": change["record_decision"],
            "updated_at": stamp["decided_at"],
        }
        array_filters: list[dict[str, Any]] = [{"v.version": change["version"]}]
        if change["back_to_pending"] is not None:
            changes["versions.$[w].decision"] = Decision.PENDING
            changes |= {f"versions.$[w].{field}": None for field in _STAMP_FIELDS}
            array_filters.append({"w.version": change["back_to_pending"]})
        decided = self.collection.update_one(
            {"_id": remediation_id, "decision_seq": seen_decision_seq},
            {"$set": changes, "$inc": {"decision_seq": 1}},
            array_filters=array_filters,
        )
        return bool(decided.modified_count)

    def update_remediation_plan_version(
        self, lease: JobLease, fields: dict[str, Any], done: bool = False
    ) -> None:
        """Sets `fields` on the leased version of tsg_remediations, fenced by the job lease; `done` also ends
        its job done in the same write."""
        changes = {f"versions.$[v].{field}": value for field, value in fields.items()}
        if done:
            changes |= ended_job_fields(Status.DONE)
        lease.update_job(changes, [{"v.version": lease.epoch}])

    def stop_remediation_plan_version(
        self, remediation_id: str, version: int, outage: dict[str, Any] | None = None
    ) -> None:
        """Ends `version`'s job cancelled on tsg_remediations while it still waits or runs (a regenerate that
        lost the race with its run's delete); an in-place retry ends failed with its `outage` error again."""
        now = utc_now()
        ended = ended_job_fields(Status.CANCELLED if outage is None else Status.FAILED, now)
        if outage is not None:
            ended["job.error"] = outage
        self.collection.update_one(
            {"_id": remediation_id, "job.epoch": version, "status": {"$in": [Status.QUEUED, Status.RUNNING]}},
            {"$set": ended | {"updated_at": now}},
        )


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
