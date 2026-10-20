"""MongoDB Service Mapper records, guarded generations and authoritative review stamps."""

from datetime import UTC, datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, Status
from app.data_access.base import MongoRepository
from app.data_access.jobs.job_repository import JobLease, ended_job_fields


class MappingRepository(MongoRepository):
    def __init__(self, collection: str | MongoCollection = Collection.SERVICE_MAPPINGS) -> None:
        super().__init__(
            collection,
            indexes=(
                {"keys": [("tenant_id", 1), ("entity_id", 1), ("created_at", -1)]},
                {
                    "keys": [("tenant_id", 1), ("entity_id", 1), ("create_key", 1)],
                    "unique": True,
                    "partialFilterExpression": {"create_key": {"$type": "string"}},
                },
            ),
            required=("_id", "tenant_id", "entity_id", "status", "generation", "job"),
        )

    def start_generation(
        self,
        mapping_id: str,
        seen_generation: int,
        seen_seq: int,
        next_job: dict[str, Any],
        key_hash: str | None,
        frozen: dict[str, Any],
        limits: dict[str, int],
        now: datetime,
    ) -> bool:
        """CAS: a review or another regeneration since the read makes this attempt retry."""
        changes: dict[str, Any] = {
            "generation": seen_generation + 1,
            "status": Status.QUEUED,
            "active": True,
            "job": next_job,
            "result": None,
            "review": "pending",
            "reviewed_at": None,
            "reviewed_by": None,
            "updated_at": now,
            "finished_at": None,
            "pending_archive": frozen,
            "limits": limits,
        }
        if key_hash is not None:
            changes[f"regen_keys.{key_hash}"] = seen_generation + 1
        changed = self.collection.update_one(
            {
                "_id": mapping_id,
                "generation": seen_generation,
                "decision_seq": seen_seq,
                "status": {"$in": [Status.DONE, Status.FAILED]},
            },
            {"$set": changes, "$inc": {"decision_seq": 1}},
        )
        return bool(changed.modified_count)

    def clear_pending_archive(self, mapping_id: str, archived_generation: int) -> None:
        self.collection.update_one(
            {"_id": mapping_id, "pending_archive.generation": archived_generation},
            {"$unset": {"pending_archive": ""}},
        )

    def finish_generation(self, lease: JobLease, result: dict[str, Any]) -> None:
        lease.update_job({"result": result, **ended_job_fields(Status.DONE)})

    def decide_mapping(
        self,
        mapping_id: str,
        generation: int,
        seen_seq: int,
        accepted: bool,
        by: str,
        at: datetime,
    ) -> bool:
        decided = self.collection.update_one(
            {
                "_id": mapping_id,
                "generation": generation,
                "decision_seq": seen_seq,
                "status": Status.DONE,
                **(_NOTHING_PENDING if accepted else {}),
            },
            {
                "$set": {
                    "review": "accepted" if accepted else "rejected",
                    "reviewed_at": at,
                    "reviewed_by": by,
                    "updated_at": at,
                },
                "$inc": {"decision_seq": 1},
            },
        )
        return bool(decided.modified_count)

    def decide_dependency(
        self,
        mapping_id: str,
        generation: int,
        seen_seq: int,
        dependency_id: str,
        direction: str,
        accepted: bool,
        by: str,
        at: datetime,
    ) -> bool:
        prefix = f"result.dependencies.$[d].relations.{direction}"
        decided = self.collection.update_one(
            {
                "_id": mapping_id,
                "generation": generation,
                "decision_seq": seen_seq,
                "status": Status.DONE,
                "review": "pending",  # a decided mapping freezes its relationships
                "result.dependencies.dependency_id": dependency_id,
            },
            {
                "$set": {
                    f"{prefix}.isAccepted": accepted,
                    f"{prefix}.accepted_datetime": at if accepted else None,
                    f"{prefix}.accepted_by": by if accepted else None,
                    f"{prefix}.reviewed_datetime": at,
                    f"{prefix}.reviewed_by": by,
                    "updated_at": at,
                },
                "$inc": {"decision_seq": 1},
            },
            array_filters=[{"d.dependency_id": dependency_id}],
        )
        return bool(decided.modified_count)


#: Accepting a mapping also requires, in the same update, that no relationship is still undecided.
_NOTHING_PENDING = {
    "result.dependencies": {
        "$not": {
            "$elemMatch": {
                "$or": [
                    {"relations.upstream.isAccepted": {"$type": "null"}},
                    {"relations.downstream.isAccepted": {"$type": "null"}},
                ]
            }
        }
    }
}


class MappingHistoryRepository(MongoRepository):
    def __init__(self, collection: str | MongoCollection = Collection.SERVICE_MAPPING_HISTORY) -> None:
        super().__init__(
            collection,
            indexes=({"keys": [("mapping_id", 1), ("generation", -1)]},),
            required=("_id", "mapping_id", "generation", "tenant_id", "entity_id"),
        )

    def archive(self, mapping: dict[str, Any]) -> None:
        """Save the frozen generation kept in the header until this write succeeds."""
        self.save(
            {
                "_id": f"{mapping['_id']}:{mapping['generation']}",
                "mapping_id": mapping["_id"],
                "generation": mapping["generation"],
                "tenant_id": mapping["tenant_id"],
                "entity_id": mapping["entity_id"],
                "status": mapping["status"],
                "review": mapping["review"],
                "result": mapping.get("result"),
                "error": mapping.get("error"),
                "archived_at": datetime.now(UTC),
            }
        )
