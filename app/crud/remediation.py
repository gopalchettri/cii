"""tsg_remediations: one plan per scenario with its versions, and the plan's guarded writes."""

from datetime import datetime

from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Collection, Decision, ErrorCode, Status
from app.core.singletons import singleton
from app.crud.base import MongoRepository
from app.crud.jobs import JobLease, ended_job_fields
from app.schemas.remediation import Doc, RemediationStatus, RemediationSummary

_VERSION_STARTED_FIELDS = ("job", "status", "finished_at", "cancelled")
_CHANGE_READ = ("entity_id", "scenario_id", "session_id", "accepted_version", "decision_seq")
_CHANGE_VERSIONS = ("versions.version", "versions.status", "versions.decision")
_CHANGE_FIELDS = dict.fromkeys((*_CHANGE_READ, *_VERSION_STARTED_FIELDS, *_CHANGE_VERSIONS), 1)
_SCENARIO_OWNER = ("entity_id", "session_id", "asset_id", "source", "status", "decision")
PLANNED_SCENARIO_FIELDS = (*_SCENARIO_OWNER, "content", "controls", "pending")
_LIST_FILTERS = ("status", "decision", "risk_level", "session_id")
_DECISION_WITH_A_NEW_VERSION = {
    "$cond": [{"$eq": [{"$ifNull": ["$accepted_version", None]}, None]}, Decision.PENDING, Decision.ACCEPTED]
}
_A_VERSION_WAITS = {
    "$anyElementTrue": [
        {
            "$map": {
                "input": "$versions",
                "as": "v",
                "in": {
                    "$and": [
                        {"$eq": ["$$v.decision", Decision.PENDING]},
                        {"$or": [{"$eq": ["$$v.version", "$job.epoch"]}, {"$eq": ["$$v.status", Status.DONE]}]},
                    ]
                },
            }
        }
    ]
}
_RECORD_DECISION = {
    "$switch": {
        "branches": [
            {"case": {"$ne": [{"$ifNull": ["$accepted_version", None]}, None]}, "then": Decision.ACCEPTED},
            {"case": _A_VERSION_WAITS, "then": Decision.PENDING},
        ],
        "default": Decision.REJECTED,
    }
}
_STAMP_FIELDS = ("decided_by", "decided_by_client", "decided_at", "review_comment")


class RemediationRepository(MongoRepository):
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
        self, remediation_id: str, latest_version: int, new_version: Doc, job: Doc, now: datetime
    ) -> bool:
        """Appends `new_version` with its job; False when `latest_version` is stale or still at work."""
        appended = self.collection.update_one(
            {
                "_id": remediation_id,
                "job.epoch": latest_version,
                "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            },
            [
                {
                    "$set": {
                        "versions": {"$concatArrays": [_with_outcome(latest_version), [{"$literal": new_version}]]},
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

    def retry_remediation_plan_version(self, remediation_id: str, version: int, job: Doc, now: datetime) -> bool:
        """Queues the latest outage-failed `version` again in place with a fresh `job`, snapshot cleared."""
        retried = self.collection.update_one(
            {
                "_id": remediation_id,
                "job.epoch": version,
                "status": Status.FAILED,
                "job.error.code": ErrorCode.UNAVAILABLE,
            },
            {
                "$set": {"job": job, "status": Status.QUEUED, "updated_at": now, "versions.$[v].snapshot": None},
                "$unset": {"finished_at": ""},
            },
            array_filters=[{"v.version": version}],
        )
        return retried.modified_count == 1

    def update_remediation_plan_decision(self, remediation_id: str, seen_decision_seq: int, change: Doc) -> bool:
        """Writes one decision only if no other was written since `seen_decision_seq`; False otherwise."""
        stamp = change["stamp"]
        changes: Doc = {
            "versions.$[v].decision": change["decision"],
            **{f"versions.$[v].{field}": stamp[field] for field in _STAMP_FIELDS},
            "accepted_version": change["accepted_version"],
            "decision": change["record_decision"],
            "updated_at": stamp["decided_at"],
        }
        array_filters: list[Doc] = [{"v.version": change["version"]}]
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
        self, lease: JobLease, fields: Doc, done: bool = False, timings: dict[str, float] | None = None
    ) -> None:
        """Sets `fields` and `timings` on the leased version, fenced by the job lease; `done` ends its job."""
        changes = {f"versions.$[v].{field}": value for field, value in fields.items()}
        changes |= {f"job.timings.{key}": round(seconds, 1) for key, seconds in (timings or {}).items()}
        if done:
            changes |= ended_job_fields(Status.DONE)
        lease.update_job(changes, [{"v.version": lease.epoch}])

    def stop_remediation_plan_version(self, remediation_id: str, version: int, outage: Doc) -> None:
        """Fails `version`, queued again in place, with its `outage` error again while it waits or runs."""
        now = utc_now()
        ended = ended_job_fields(Status.FAILED, now) | {"job.error": outage, "updated_at": now}
        self.collection.update_one(
            {"_id": remediation_id, "job.epoch": version, "status": {"$in": [Status.QUEUED, Status.RUNNING]}},
            {"$set": ended},
        )

    def undo_remediation_plan_version(self, read: Doc, version: int) -> None:
        """Removes `version`, appended after `read` and never sent, keeping a decision written meanwhile."""
        restored = {
            field: {"$literal": read[field]} if field in read else "$$REMOVE" for field in _VERSION_STARTED_FIELDS
        }
        self.collection.update_one(
            {"_id": read["_id"], "job.epoch": version, "status": Status.QUEUED},
            [
                {
                    "$set": restored
                    | {
                        "versions": {"$slice": ["$versions", len(read["versions"])]},
                        "decision_seq": {"$add": ["$decision_seq", 1]},
                        "updated_at": utc_now(),
                    }
                },
                {"$set": {"decision": _RECORD_DECISION}},
            ],
        )


@singleton
def get_remediation_repository() -> RemediationRepository:
    return RemediationRepository()


def _with_outcome(latest: int) -> Doc:
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
