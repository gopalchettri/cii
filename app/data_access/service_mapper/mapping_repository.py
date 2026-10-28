"""MongoDB Service Mapper records: one per service, runs that only add services, relationship decisions."""

from datetime import datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, Status, TaskName
from app.data_access.base import MongoRepository, drop_retired_index
from app.data_access.jobs.job_repository import JobLease, ended_job_fields, new_job

#: The unique index that keeps one mapping per service of an entity (DuplicateRecord.index_name).
ONE_MAPPING_PER_SERVICE = "one_mapping_per_service"
#: Dropped at start-up: the Idempotency-Key index of a mapping's first request; keys are in request_keys.
RETIRED_CREATE_KEY_INDEX = "tenant_id_1_entity_id_1_create_key_1"
_GENERATING = [Status.QUEUED, Status.RUNNING]


class MappingRepository(MongoRepository):
    def __init__(self, collection: str | MongoCollection = Collection.SERVICE_MAPPINGS) -> None:
        super().__init__(
            collection,
            indexes=(
                {"keys": [("tenant_id", 1), ("entity_id", 1), ("created_at", -1)]},
                # the entity's mappings being generated, oldest first: GET /v1/jobs
                {"keys": [("tenant_id", 1), ("entity_id", 1), ("status", 1), ("created_at", 1)]},
                {
                    "keys": [("tenant_id", 1), ("entity_id", 1), ("service_key", 1)],
                    "name": ONE_MAPPING_PER_SERVICE,
                    "unique": True,
                    "partialFilterExpression": {"service_key": {"$type": "string"}},
                },
                {"keys": [("tenant_id", 1), ("entity_id", 1), ("request_keys.key", 1)]},
            ),
            required=("_id", "tenant_id", "entity_id", "status", "job"),
        )

    def create_indexes(self) -> None:
        """The validator and every index, after dropping the retired create-key index."""
        drop_retired_index(self.collection, RETIRED_CREATE_KEY_INDEX)
        super().create_indexes()

    def start_next_run(
        self,
        mapping_id: str,
        seen_run: int,
        request: dict[str, Any],
        input_hash: str,
        limits: dict[str, int],
        key_hash: str,
        now: datetime,
    ) -> bool:
        """Queue run `seen_run + 1` with `request`; False when another call started a run since the read."""
        run = seen_run + 1
        started = self.collection.update_one(
            {"_id": mapping_id, "job.epoch": seen_run, "status": {"$nin": _GENERATING}},
            {
                "$set": {
                    "status": Status.QUEUED,
                    "job": new_job(TaskName.MAP_SERVICES, run, now, requested_at=now),
                    "request": request,
                    "input_hash": input_hash,
                    "limits": limits,
                    "updated_at": now,
                    "finished_at": None,
                },
                "$push": {"request_keys": request_key(key_hash, run, input_hash, now)},
            },
        )
        return bool(started.modified_count)

    def finish_generation(self, lease: JobLease, found: dict[str, Any]) -> None:
        """Add the run's new dependencies after those the mapping holds, never rewriting those (a reviewer may
        have decided some while it ran), and how many it found."""
        done = {**ended_job_fields(Status.DONE), "last_run_found": len(found["dependencies"])}
        counted = {"$inc": {"generations_done": 1}}
        if lease.record.get("result") is None:  # an older record whose only generation failed: no list yet
            lease.update_job({**done, "result": found}, operators=counted)
            return
        lease.update_job(
            {
                **done,
                "result.selected_service": found["selected_service"],
                "result.catalog_version": found["catalog_version"],
            },
            operators={**counted, "$push": {"result.dependencies": {"$each": found["dependencies"]}}},
        )

    def decide_dependencies(
        self,
        mapping_id: str,
        changes: list[tuple[str, str, bool]],
        by: str,
        at: datetime,
    ) -> None:
        """Saves every (dependency_id, direction, accepted) in one update."""
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
        self.collection.update_one(
            {"_id": mapping_id},
            {"$set": fields},
            array_filters=[{f"{slot}.dependency_id": dependency_id} for dependency_id, slot in slots.items()],
        )


def request_key(key_hash: str, run: int, input_hash: str, at: datetime) -> dict[str, Any]:
    """One Idempotency-Key's claim: the run it started, with which details, and when."""
    return {"key": key_hash, "generation": run, "input_hash": input_hash, "at": at}
