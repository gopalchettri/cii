"""tsg_ai_usage: one lean row per AI attempt or reused answer (app/ai/attempts.py); tsg_ai_usage_hourly: those
rows added up per UTC hour, for dashboards; tsg_ai_usage_requests: one summary per API request (who, first and
last AI call), so request lists page by an index. All kept for good. Each report read is bounded by
AiUsageLimits.REPORT_SECONDS (a slow one answers 503) and never spills to disk."""

import functools
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

import pymongo
from pymongo import InsertOne, ReplaceOne
from pymongo.collection import Collection as MongoCollection

from app.core.constants import AiUsageCollection, AiUsageLimits, AiUsageOutcome
from app.data_access.base import NeverDeletedRepository, Record

#: The fields a row is added up by in the hourly totals ("" when a row has none).
HOURLY_KEYS = ("module", "api", "bucket", "task", "model", "entity_id", "client_id")
#: Who a request was for, as its summary and its list entry show it.
REQUEST_FIELDS = ("module", "api", "session_id", "entity_id", "client_id")
#: The hourly collection's one document that is no hour: the hour the scheduled add-up has reached.
_FRONTIER_ID = "rolled_up_until"


def _within_report_time[**Params, Result](read: Callable[Params, Result]) -> Callable[Params, Result]:
    """`read` bounded by AiUsageLimits.REPORT_SECONDS: a slow report never holds a thread for long."""

    @functools.wraps(read)
    def bounded(*args: Params.args, **kwargs: Params.kwargs) -> Result:
        with pymongo.timeout(AiUsageLimits.REPORT_SECONDS):
            return read(*args, **kwargs)

    return bounded


def usage_counters() -> dict[str, Any]:
    """$group accumulators of usage rows: calls (attempts: a reused answer is none), each outcome, asks (an
    attempt numbered 1), tokens and seconds."""

    def count_if(condition: dict[str, Any]) -> dict[str, Any]:
        return {"$sum": {"$cond": [condition, 1, 0]}}

    outcomes = {outcome.value: count_if({"$eq": ["$outcome", outcome.value]}) for outcome in AiUsageOutcome}
    return {
        "total_ai_calls": count_if({"$ne": ["$outcome", AiUsageOutcome.REUSED]}),
        **outcomes,
        "asks": count_if({"$eq": ["$try_no", 1]}),
        "tokens_in": {"$sum": {"$ifNull": ["$tokens_in", 0]}},
        "tokens_out": {"$sum": {"$ifNull": ["$tokens_out", 0]}},
        "seconds": {"$sum": {"$ifNull": ["$seconds", 0]}},
    }


def _older_than(cursor: tuple[datetime, Any] | None, time_field: str) -> Record:
    """The entries after a page's last one ((its time, its _id)), newest first; {} for the first page."""
    if cursor is None:
        return {}
    at, last_id = cursor
    return {"$or": [{time_field: {"$lt": at}}, {time_field: at, "_id": {"$lt": last_id}}]}


class AiUsageRepository(NeverDeletedRepository):
    """tsg_ai_usage: insert-only rows; three indexes (time, request, session) keep each write cheap."""

    def __init__(self, collection: str | MongoCollection = AiUsageCollection.USAGE) -> None:
        super().__init__(
            collection,
            indexes=[
                {"keys": [("created_at", 1)]},  # the hourly add-up
                {
                    "keys": [("request_id", 1), ("created_at", 1)],
                    "partialFilterExpression": {"request_id": {"$exists": True}},
                },
                {
                    "keys": [("session_id", 1), ("created_at", 1)],
                    "partialFilterExpression": {"session_id": {"$exists": True}},
                },
            ],
            schema_version=1,
        )

    def create_rows(self, rows: list[Record]) -> None:
        """Inserts the rows in one write; a row already stored (a replay) is skipped."""
        self.bulk_write_skipping_duplicates([InsertOne(row | self._stamp) for row in rows], ordered=False)

    @_within_report_time
    def list_session_requests(
        self, session_id: str, who: Record, limit: int, after: tuple[datetime, str] | None
    ) -> list[Record]:
        """One entry per request of the session matching `who`: who and when, newest first call first (a time
        that never moves as later rows arrive, so no entry is skipped between pages), after `after`."""
        pipeline: list[Record] = [
            {"$match": {"session_id": session_id, "request_id": {"$exists": True}, **who}},
            {"$group": {"_id": "$request_id", **_who_and_when()}},
            {"$match": _older_than(after, "first_at")},
            {"$sort": {"first_at": -1, "_id": -1}},
            {"$limit": limit},
        ]
        return list(self.collection.aggregate(pipeline))

    @_within_report_time
    def summarize_requests(self, request_ids: Iterable[str]) -> list[Record]:
        """Each request's summary over all its rows: who it was for, its first and last AI call."""
        match = {"request_id": {"$in": list(request_ids)}}
        return list(
            self.collection.aggregate(
                [{"$match": match}, {"$group": {"_id": "$request_id", **_who_and_when()}}]
            )
        )

    @_within_report_time
    def count_parts(self, match: Record, by_request: bool) -> list[Record]:
        """Counters per (request, when `by_request`) part, task and model of the rows matching `match`."""
        key = {"bucket": "$bucket", "task": "$task", "model": {"$ifNull": ["$model", ""]}}
        if by_request:
            key["request_id"] = "$request_id"
        return list(
            self.collection.aggregate([{"$match": match}, {"$group": {"_id": key, **usage_counters()}}])
        )

    @_within_report_time
    def list_rows(self, match: Record, limit: int, after: tuple[datetime, Any] | None) -> list[Record]:
        """The rows matching `match`, newest first, after `after` ((created_at, _id) of the last one
        shown)."""
        if after is not None:
            match = {"$and": [match, _older_than(after, "created_at")]}
        return list(self.collection.find(match).sort([("created_at", -1), ("_id", -1)]).limit(limit))

    @_within_report_time
    def sum_hours(self, since: datetime, until: datetime) -> list[Record]:
        """Counters per UTC hour and HOURLY_KEYS of the rows in [since, until)."""
        hour = {
            "$dateFromParts": {
                "year": {"$year": "$created_at"},
                "month": {"$month": "$created_at"},
                "day": {"$dayOfMonth": "$created_at"},
                "hour": {"$hour": "$created_at"},
            }
        }
        key = {"hour": hour, **{name: {"$ifNull": [f"${name}", ""]} for name in HOURLY_KEYS}}
        window = {"created_at": {"$gte": since, "$lt": until}}
        return list(
            self.collection.aggregate([{"$match": window}, {"$group": {"_id": key, **usage_counters()}}])
        )

    @_within_report_time
    def first_rows_of_requests(self, since: datetime, until: datetime) -> list[Record]:
        """Each request's first row in [since, until): its time and HOURLY_KEYS."""
        window = {"created_at": {"$gte": since, "$lt": until}, "request_id": {"$exists": True}}
        firsts = {name: {"$first": {"$ifNull": [f"${name}", ""]}} for name in HOURLY_KEYS}
        return list(
            self.collection.aggregate(
                [
                    {"$match": window},
                    {"$sort": {"created_at": 1}},
                    {"$group": {"_id": "$request_id", "created_at": {"$first": "$created_at"}, **firsts}},
                ]
            )
        )

    @_within_report_time
    def requests_seen_before(self, request_ids: Iterable[str], before: datetime) -> set[str]:
        """Which of the requests already had a row before `before` (their first row is older)."""
        found = {"request_id": {"$in": list(request_ids)}, "created_at": {"$lt": before}}
        return set(self.collection.distinct("request_id", found))

    def oldest_row_time(self) -> datetime | None:
        """When the oldest row was written; None while there is none."""
        oldest = self.list(("created_at",), "created_at", limit=1)
        return oldest[0]["created_at"] if oldest else None


def _who_and_when() -> dict[str, Any]:
    """$group accumulators of a request's entry: its first and last AI call, and who it was for."""
    who = {name: {"$max": f"${name}"} for name in REQUEST_FIELDS}  # every row of a request says the same
    return {"first_at": {"$min": "$created_at"}, "last_at": {"$max": "$created_at"}, **who}


class AiUsageHourlyRepository(NeverDeletedRepository):
    """tsg_ai_usage_hourly: one document per UTC hour and HOURLY_KEYS, _id the key as text, replaced whole by
    each add-up of its hour (idempotent: the rows are never deleted); and one frontier document."""

    def __init__(self, collection: str | MongoCollection = AiUsageCollection.HOURLY) -> None:
        super().__init__(collection, indexes=[{"keys": [("hour", 1)]}], schema_version=1)

    def frontier(self) -> datetime | None:
        """The hour the scheduled add-up has reached; None before its first run."""
        found = self.get(("until",), _id=_FRONTIER_ID)
        return found["until"] if found else None

    def move_frontier(self, until: datetime) -> None:
        """Records the hour the scheduled add-up reached (only it moves it: a manual add-up never skips the
        hours it has not reached)."""
        self.collection.replace_one({"_id": _FRONTIER_ID}, {"until": until} | self._stamp, upsert=True)

    def replace_hours(self, documents: list[Record]) -> None:
        """Writes each hour's documents whole, in one write."""
        replaces = [ReplaceOne({"_id": doc["_id"]}, doc | self._stamp, upsert=True) for doc in documents]
        self.bulk_write_skipping_duplicates(replaces, ordered=False)

    @_within_report_time
    def sum_items(self, match: Record, keys: Record, limit: int) -> list[Record]:
        """Over the hours matching `match`: one item per `keys` (a $group _id), at most `limit`, sorted by
        key, with its counters (and requests) per part in `parts`."""
        sums = _hourly_sums()
        per_part = {"$group": {"_id": {**keys, "_part": "$bucket"}, **sums}}
        part = {"bucket": "$_id._part", **{name: f"${name}" for name in sums}}
        per_item = {"$group": {"_id": {name: f"$_id.{name}" for name in keys}, "parts": {"$push": part}}}
        items: list[Record] = [
            {"$match": match},
            per_part,
            per_item,
            {"$sort": {"_id": 1}},
            {"$limit": limit},
        ]
        return list(self.collection.aggregate(items))

    @_within_report_time
    def sum_total(self, match: Record) -> list[Record]:
        """The counters of every hour matching `match`, in one document (a report whose items were cut)."""
        return list(
            self.collection.aggregate([{"$match": match}, {"$group": {"_id": None, **_hourly_sums()}}])
        )


def _hourly_sums() -> dict[str, Any]:
    """$group accumulators summing hourly documents' counters."""
    counters = ("total_ai_calls", *(outcome.value for outcome in AiUsageOutcome), "asks", "requests")
    return {name: {"$sum": f"${name}"} for name in (*counters, "tokens_in", "tokens_out", "seconds")}


class AiUsageRequestRepository(NeverDeletedRepository):
    """tsg_ai_usage_requests: one summary per API request (_id its request id), replaced by each add-up that
    sees it; paged newest first call first by its index."""

    def __init__(self, collection: str | MongoCollection = AiUsageCollection.REQUESTS) -> None:
        super().__init__(collection, indexes=[{"keys": [("first_at", -1), ("_id", -1)]}], schema_version=1)

    def replace_requests(self, summaries: list[Record]) -> None:
        """Writes each summary whole, in one write."""
        replaces = [ReplaceOne({"_id": doc["_id"]}, doc | self._stamp, upsert=True) for doc in summaries]
        self.bulk_write_skipping_duplicates(replaces, ordered=False)

    @_within_report_time
    def list_page(self, match: Record, limit: int, after: tuple[datetime, str] | None) -> list[Record]:
        """The summaries matching `match`, newest first call first, after `after`."""
        if after is not None:
            match = {"$and": [match, _older_than(after, "first_at")]}
        return list(self.collection.find(match).sort([("first_at", -1), ("_id", -1)]).limit(limit))
