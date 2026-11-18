"""tsg_service_mappings (one per service; runs only add services) and the onboarding catalog procedures."""

from datetime import datetime
from typing import Any

from pymongo.database import Database

from app.core.clock import utc_now
from app.core.constants import Collection, Status, StoredProcedure, TaskName
from app.core.database import StoredProcedureClient
from app.core.exceptions import SetupError
from app.crud.base import MongoRepository
from app.crud.jobs import JobLease, ended_job_fields, new_job

_GENERATING = [Status.QUEUED, Status.RUNNING]
_INDEXES = (
    {"keys": [("tenant_id", 1), ("entity_id", 1), ("created_at", -1)]},
    {"keys": [("tenant_id", 1), ("entity_id", 1), ("status", 1), ("created_at", 1)]},  # GET /v1/jobs
    {
        "keys": [("tenant_id", 1), ("entity_id", 1), ("service_key", 1)],
        "name": "one_mapping_per_service",
        "unique": True,
        "partialFilterExpression": {"service_key": {"$type": "string"}},
    },
    {"keys": [("tenant_id", 1), ("entity_id", 1), ("request_keys.key", 1)]},
)
# what a list item shows: never a run's dependencies
_LIST_FIELDS = dict.fromkeys(("status", "job.epoch", "generations_done", "result.selected_service"), 1)
_LIST_FIELDS |= dict.fromkeys(("request", "created_at", "updated_at"), 1)


def create_indexes(db: Database) -> None:
    """The validator and every index of tsg_service_mappings."""
    # generation (the latest run) stays required: UAT's stored rule needs it and its user may not run collMod
    required = ("_id", "tenant_id", "entity_id", "status", "generation", "job")
    MongoRepository(db[Collection.SERVICE_MAPPINGS], indexes=_INDEXES, required=required).create_indexes()


def get_mapping(db: Database, **where: Any) -> dict | None:
    return db[Collection.SERVICE_MAPPINGS].find_one(where)


def list_mappings(db: Database, tenant_id: str, entity_id: int, skip: int, limit: int) -> tuple[list[dict], int]:
    where = {"tenant_id": tenant_id, "entity_id": entity_id}
    mappings = db[Collection.SERVICE_MAPPINGS]
    page = mappings.find(where, _LIST_FIELDS, skip=skip, limit=limit).sort("created_at", -1)
    return list(page), mappings.count_documents(where)


def insert_mapping(db: Database, record: dict) -> None:
    MongoRepository(db[Collection.SERVICE_MAPPINGS]).create(record)


def run_fields(run: int, request: dict, input_hash: str, limits: dict, now: datetime) -> dict[str, Any]:
    return {
        "status": Status.QUEUED,
        "generation": run,
        "job": new_job(TaskName.MAP_SERVICES, run, now, requested_at=now),
        "request": request,
        "input_hash": input_hash,
        "limits": limits,
        "updated_at": now,
    }


def start_next_run(db: Database, record: dict, request: dict, input_hash: str, limits: dict, key: str) -> bool:
    """Queue the record's next run; False when another call started one since it was read."""
    seen, now = record["job"]["epoch"], utc_now()
    started = db[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": record["_id"], "job.epoch": seen, "status": {"$nin": _GENERATING}},
        {
            "$set": run_fields(seen + 1, request, input_hash, limits, now) | {"finished_at": None},
            "$push": {"request_keys": request_key(key, seen + 1, input_hash, now)},
        },
    )
    return bool(started.modified_count)


def add_request_key(db: Database, mapping_id: str, claim: dict[str, Any]) -> None:
    db[Collection.SERVICE_MAPPINGS].update_one(
        {
            "_id": mapping_id,
            "status": {"$in": _GENERATING},
            "job.epoch": claim["generation"],
            "request_keys.key": {"$ne": claim["key"]},
        },
        {"$push": {"request_keys": claim}},
    )


def request_key(key: str, run: int, input_hash: str, at: datetime) -> dict[str, Any]:
    return {"key": key, "generation": run, "input_hash": input_hash, "at": at}


def finish_run(lease: JobLease, found: dict[str, Any], timings: dict[str, float]) -> None:
    """Adds the run's new dependencies after those held, never rewriting them; its count and timings."""
    done = {**ended_job_fields(Status.DONE), "last_run_found": len(found["dependencies"])}
    done |= {f"job.timings.{key}": round(seconds, 1) for key, seconds in timings.items()}
    counted = {"$inc": {"generations_done": 1}}
    if lease.record.get("result") is None:  # a record from before 28 Oct whose only run failed: no list yet
        lease.update_job({**done, "result": found}, operators=counted)
        return
    done |= {"result.selected_service": found["selected_service"], "result.catalog_version": found["catalog_version"]}
    lease.update_job(done, operators={**counted, "$push": {"result.dependencies": {"$each": found["dependencies"]}}})


def save_decisions(
    db: Database, mapping_id: str, changes: list[tuple[str, str, bool]], by: str, at: datetime
) -> dict | None:
    """Saves every (dependency_id, direction, accepted) in one update; the mapping as saved."""
    slots = {dependency_id: f"d{i}" for i, dependency_id in enumerate(dict.fromkeys(c[0] for c in changes))}
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
    return db[Collection.SERVICE_MAPPINGS].find_one_and_update(
        {"_id": mapping_id},
        {"$set": fields},
        array_filters=[{f"{slot}.dependency_id": dependency_id} for dependency_id, slot in slots.items()],
        return_document=True,
    )


def load_catalog_rows(sql: StoredProcedureClient) -> tuple[list[dict], ...]:
    """The onboarding catalog: services, sectors, service-sector links and entity links."""
    services = sql.execute_procedure(StoredProcedure.GET_SERVICES_WITH_SECTOR_DETAILS)
    associations = sql.execute_procedure(StoredProcedure.GET_SERVICE_MAPPER_ASSOCIATIONS)
    if len(services) != 1 or len(associations) != 3:
        raise SetupError("The Service Mapper SQL procedures returned an unexpected number of result sets.")
    return (*services, *associations)
