"""tsg_ai_usage (one row per AI attempt or reused answer), tsg_ai_usage_hourly (their totals per UTC hour)
and tsg_ai_usage_requests (one summary per API request): kept for good. Each report read is bounded by
REPORT_SECONDS (a slow one answers 503) and never spills to disk."""

from datetime import datetime
from typing import Any

import pymongo
from pymongo import InsertOne, ReplaceOne
from pymongo.database import Database

from app.core.constants import AiUsageCollection, AiUsageLimits, AiUsageOutcome
from app.crud.base import NeverDeletedRepository

#: The fields a row is added up by in the hourly totals ("" when a row has none).
HOURLY_KEYS = ("module", "api", "bucket", "task", "model", "entity_id", "client_id")
#: Who a request was for, as its summary and its list entry show it.
REQUEST_FIELDS = ("module", "api", "session_id", "entity_id", "client_id")
INDEXES: dict[str, list[dict[str, Any]]] = {
    AiUsageCollection.USAGE: [
        {"keys": [("created_at", 1)]},
        *(
            {"keys": [(field, 1), ("created_at", 1)], "partialFilterExpression": {field: {"$exists": True}}}
            for field in ("request_id", "session_id")
        ),
    ],
    AiUsageCollection.HOURLY: [{"keys": [("hour", 1)]}],
    AiUsageCollection.REQUESTS: [{"keys": [("first_at", -1), ("_id", -1)]}],
}
_COUNTERS = ("total_ai_calls", *AiUsageOutcome, "asks", "tokens_in", "tokens_out", "seconds")


def store(db: Database, name: str) -> NeverDeletedRepository:
    """One of the three collections: zstd, never expired, delete refused, rows stamped schema_version 1."""
    return NeverDeletedRepository(db[name], indexes=INDEXES[name], schema_version=1)


def insert_rows(db: Database, rows: list[dict[str, Any]]) -> None:
    """The rows in one write; one already stored (a replay) is skipped."""
    rows_of = store(db, AiUsageCollection.USAGE)
    rows_of.bulk_write_skipping_duplicates([InsertOne(row | rows_of._stamp) for row in rows], ordered=False)


def replace_if_newer(db: Database, name: str, documents: list[dict[str, Any]]) -> None:
    """Each document whole, unless one read later is stored already (its duplicate insert is skipped)."""
    target = store(db, name)
    replaces = [
        ReplaceOne({"_id": doc["_id"], "read_at": {"$not": {"$gte": doc["read_at"]}}}, doc | target._stamp, upsert=True)
        for doc in documents
    ]
    target.bulk_write_skipping_duplicates(replaces, ordered=False)


def _aggregate(db: Database, name: str, pipeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    with pymongo.timeout(AiUsageLimits.REPORT_SECONDS):
        return list(db[name].aggregate(pipeline))


def _page(
    db: Database, name: str, match: dict, at: str, limit: int, after: tuple[datetime, Any] | None
) -> list[dict[str, Any]]:
    if after is not None:
        match = {"$and": [match, _older_than(after, at)]}
    with pymongo.timeout(AiUsageLimits.REPORT_SECONDS):
        return list(db[name].find(match).sort([(at, -1), ("_id", -1)]).limit(limit))


def _older_than(cursor: tuple[datetime, Any] | None, at: str) -> dict[str, Any]:
    if cursor is None:
        return {}
    return {"$or": [{at: {"$lt": cursor[0]}}, {at: cursor[0], "_id": {"$lt": cursor[1]}}]}


def usage_counters() -> dict[str, Any]:
    """$group accumulators of rows: attempts (a reused answer is none), each outcome, asks (try 1), tokens."""
    count_if = lambda condition: {"$sum": {"$cond": [condition, 1, 0]}}  # noqa: E731
    return {
        "total_ai_calls": count_if({"$ne": ["$outcome", AiUsageOutcome.REUSED]}),
        **{outcome.value: count_if({"$eq": ["$outcome", outcome.value]}) for outcome in AiUsageOutcome},
        "asks": count_if({"$eq": ["$try_no", 1]}),
        **{name: {"$sum": {"$ifNull": [f"${name}", 0]}} for name in ("tokens_in", "tokens_out", "seconds")},
    }


def group_rows(db: Database, match: dict[str, Any], key: dict[str, Any]) -> list[dict[str, Any]]:
    """Counters per `key` of the rows matching `match`."""
    return _aggregate(db, AiUsageCollection.USAGE, [{"$match": match}, {"$group": {"_id": key, **usage_counters()}}])


def part_key(by_request: bool = False) -> dict[str, Any]:
    key = {"bucket": "$bucket", "task": "$task", "model": {"$ifNull": ["$model", ""]}}
    return key | {"request_id": "$request_id"} if by_request else key


def hour_key() -> dict[str, Any]:
    """A row's UTC hour and HOURLY_KEYS."""
    parts = {part: {f"${part}": "$created_at"} for part in ("year", "month", "hour")}
    hour = {"$dateFromParts": {**parts, "day": {"$dayOfMonth": "$created_at"}}}
    return {"hour": hour, **{name: {"$ifNull": [f"${name}", ""]} for name in HOURLY_KEYS}}


def summarize_requests(
    db: Database, match: dict[str, Any], limit: int = 0, after: tuple[datetime, str] | None = None
) -> list[dict[str, Any]]:
    """One entry per request of the rows matching `match`; with `limit`, a page newest first."""
    who = {name: {"$max": f"${name}"} for name in REQUEST_FIELDS}  # every row of a request says the same
    group = {"_id": "$request_id", "first_at": {"$min": "$created_at"}, "last_at": {"$max": "$created_at"}}
    pipeline: list[dict[str, Any]] = [{"$match": match}, {"$group": group | who}]
    if limit:
        pipeline += [
            {"$match": _older_than(after, "first_at")},
            {"$sort": {"first_at": -1, "_id": -1}},
            {"$limit": limit},
        ]
    return _aggregate(db, AiUsageCollection.USAGE, pipeline)


def first_rows_of_requests(db: Database, since: datetime, until: datetime) -> tuple[list[dict[str, Any]], set[str]]:
    """Each request's first row in [since, until), and the requests with a row before `since`."""
    window = {"created_at": {"$gte": since, "$lt": until}, "request_id": {"$exists": True}}
    firsts = {name: {"$first": {"$ifNull": [f"${name}", ""]}} for name in HOURLY_KEYS}
    group = {"$group": {"_id": "$request_id", "created_at": {"$first": "$created_at"}, **firsts}}
    found = _aggregate(db, AiUsageCollection.USAGE, [{"$match": window}, {"$sort": {"created_at": 1}}, group])
    if not found:
        return found, set()
    earlier = {"request_id": {"$in": [first["_id"] for first in found]}, "created_at": {"$lt": since}}
    with pymongo.timeout(AiUsageLimits.REPORT_SECONDS):
        return found, set(db[AiUsageCollection.USAGE].distinct("request_id", earlier))


def newest_hour(db: Database) -> datetime | None:
    """The newest hour added up, else the oldest row's; None while there is no row."""
    for name, field, order in ((AiUsageCollection.HOURLY, "hour", -1), (AiUsageCollection.USAGE, "created_at", 1)):
        if found := db[name].find_one({field: {"$exists": True}}, {field: 1}, sort=[(field, order)]):
            return found[field]
    return None


def sum_hours(db: Database, match: dict[str, Any], keys: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """One item per `keys` over the hours matching `match`, at most `limit`, with its counters per part."""
    sums = {name: {"$sum": f"${name}"} for name in (*_COUNTERS, "requests")}
    part = {"bucket": "$_id._part", **{name: f"${name}" for name in sums}}
    per_item = {"$group": {"_id": {name: f"$_id.{name}" for name in keys}, "parts": {"$push": part}}}
    pipeline = [{"$match": match}, {"$group": {"_id": {**keys, "_part": "$bucket"}, **sums}}, per_item]
    return _aggregate(db, AiUsageCollection.HOURLY, [*pipeline, {"$sort": {"_id": 1}}, {"$limit": limit}])


def sum_total(db: Database, match: dict[str, Any]) -> list[dict[str, Any]]:
    """The counters of every hour matching `match`, in one document (a report whose items were cut)."""
    sums = {name: {"$sum": f"${name}"} for name in (*_COUNTERS, "requests")}
    return _aggregate(db, AiUsageCollection.HOURLY, [{"$match": match}, {"$group": {"_id": None, **sums}}])


def list_request_summaries(db: Database, match: dict, limit: int, after: tuple[datetime, str] | None) -> list[dict]:
    return _page(db, AiUsageCollection.REQUESTS, match, "first_at", limit, after)


def list_rows(db: Database, match: dict, limit: int, after: tuple[datetime, Any] | None) -> list[dict]:
    return _page(db, AiUsageCollection.USAGE, match, "created_at", limit, after)
