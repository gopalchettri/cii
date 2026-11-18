"""tsg_ai_call_texts: the prompt and answer of every answered chat call, kept for good (owner 2026-10-29),
under its usage row's _id; read back to reuse an answer. Every read and write within RECORD_WRITE_SECONDS."""

from datetime import datetime, timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import AiOutcome, AiUsageLimits, Timeouts
from app.crud.base import NeverDeletedRepository

INDEXES = [
    {"keys": [("record_id", 1), ("epoch", 1), ("job_task", 1), ("prompt_hash", 1)]},  # one job's calls
    {"keys": [("prompt_hash", 1), ("created_at", -1)]},  # any run's newest answer (threat finding's reuse)
]
_NEWEST = {"projection": {"response": 1, "model": 1}, "sort": [("created_at", -1), ("_id", -1)]}
_DAY = timedelta(days=1)


def store(calls: MongoCollection) -> NeverDeletedRepository:
    """tsg_ai_call_texts (`calls`): zstd, never expired, delete refused, rows stamped schema_version 1."""
    return NeverDeletedRepository(calls, indexes=INDEXES, schema_version=1)


def insert_call(calls: MongoCollection, record: dict[str, Any]) -> None:
    with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
        store(calls).create(record)


def find_ok_response(calls: MongoCollection, job: dict[str, Any], prompt_hash: str) -> tuple[str, str] | None:
    """(response, model) of the job's newest ok call with this conversation (`job`: record, epoch, stage)."""
    with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
        found = calls.find_one({**job, "prompt_hash": prompt_hash, "outcome": AiOutcome.OK}, **_NEWEST)
    return (found["response"], found.get("model", "")) if found else None


def find_recent_ok_response(
    calls: MongoCollection, task: str, prompt_hash: str, models: list[tuple[str, bool]], since: datetime
) -> tuple[str, str] | None:
    """(response, model) of any run's newest ok `task` call of this conversation since `since` by `models`."""
    answered_by = [{"model": name, "thinking": on} for name, on in models]
    match = {"prompt_hash": prompt_hash, "task": task, "outcome": AiOutcome.OK, "$or": answered_by}
    with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
        found = calls.find_one(match | {"created_at": {"$gte": since}}, **_NEWEST)
    return (found["response"], found["model"]) if found else None


def copy_records_from(calls: MongoCollection, source: str) -> int:
    """Copies `source`'s records in a day at a time (one already here is kept); how many are held now."""
    old, into = calls.database[source], calls
    merge = {"into": into.name, "on": "_id", "whenMatched": "keepExisting", "whenNotMatched": "insert"}
    oldest = old.find_one({"created_at": {"$type": "date"}}, {"created_at": 1}, sort=[("created_at", 1)])
    day, end = (oldest["created_at"] if oldest else utc_now()), utc_now() + _DAY
    batches: list[dict[str, Any]] = [{"created_at": {"$not": {"$type": "date"}}}]  # untimed records: one batch
    while day < end:
        batches.append({"created_at": {"$gte": day, "$lt": day + _DAY}})
        day += _DAY
    for batch in batches:
        with pymongo.timeout(AiUsageLimits.COPY_DAY_SECONDS):
            old.aggregate([{"$match": batch}, {"$merge": merge}])
    return into.estimated_document_count()
