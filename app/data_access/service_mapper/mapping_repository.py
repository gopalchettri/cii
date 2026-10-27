"""MongoDB Service Mapper records, guarded generations and authoritative relationship decisions."""

from datetime import datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Collection, MapperLimits, Status
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
        """CAS: a decision or another regeneration since the read makes this attempt retry."""
        changes: dict[str, Any] = {
            "generation": seen_generation + 1,
            "status": Status.QUEUED,
            "job": next_job,
            "result": None,
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

    def decide_dependencies(
        self,
        mapping_id: str,
        generation: int,
        seen_seq: int,
        changes: list[tuple[str, str, bool]],
        by: str,
        at: datetime,
    ) -> bool:
        """Saves every (dependency_id, direction, accepted) in one update; CAS on generation, decision_seq."""
        ids = dict.fromkeys(dependency_id for dependency_id, _direction, _accepted in changes)
        slots = {dependency_id: f"d{i}" for i, dependency_id in enumerate(ids)}
        fields: dict[str, Any] = {"updated_at": at}
        for dependency_id, direction, accepted in changes:
            prefix = f"result.dependencies.$[{slots[dependency_id]}].relations.{direction}"
            fields |= {
                f"{prefix}.isAccepted": accepted,
                f"{prefix}.accepted_datetime": at if accepted else None,
                f"{prefix}.accepted_by": by if accepted else None,
                f"{prefix}.reviewed_datetime": at,
                f"{prefix}.reviewed_by": by,
            }
        decided = self.collection.update_one(
            {
                "_id": mapping_id,
                "generation": generation,
                "decision_seq": seen_seq,
                "status": Status.DONE,
            },
            {"$set": fields, "$inc": {"decision_seq": 1}},
            array_filters=[{f"{slot}.dependency_id": dependency_id} for dependency_id, slot in slots.items()],
        )
        return bool(decided.modified_count)


class MappingHistoryRepository(MongoRepository):
    def __init__(self, collection: str | MongoCollection = Collection.SERVICE_MAPPING_HISTORY) -> None:
        super().__init__(
            collection,
            indexes=({"keys": [("mapping_id", 1), ("generation", -1)]},),
            ttl=[("archived_at", MapperLimits.HISTORY_KEEP_DAYS * 86_400)],
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
                "result": mapping.get("result"),
                "error": mapping.get("error"),
                "archived_at": utc_now(),
            }
        )
