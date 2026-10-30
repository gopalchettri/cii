"""AI usage reports (GET /v1/ai-usage..., no key, owner 2026-10-29) and the hourly add-up the totals read
(tsg_roll_up_ai_usage, every 5 minutes on the maintenance worker). Counts only, each with its model,
activity and a one-line description: never a prompt or an answer."""

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any, cast

import pymongo
import structlog
from bson import ObjectId
from pydantic import BaseModel
from pymongo.errors import OperationFailure
from redis import Redis

from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    BUCKET_INFO,
    GROUP_TIME_FORMATS,
    MODULE_BUCKETS,
    AiBucket,
    AiUsageGroup,
    AiUsageLimits,
    AiUsageLogEvent,
    AiUsageMessage,
    AiUsageOutcome,
    activity_info,
    api_info,
)
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, Invalid, NotFound, Unavailable
from app.data_access.admin.ai_usage_repository import (
    HOURLY_KEYS,
    REQUEST_FIELDS,
    AiUsageHourlyRepository,
    AiUsageRepository,
    AiUsageRequestRepository,
)
from app.models.ai_usage.usage_report import (
    RequestUsageQuery,
    UsageCallQuery,
    UsageFilters,
    UsageTotalsQuery,
)
from app.services.ai_usage.report_times import (
    HOUR,
    as_utc,
    ceil_hour,
    check_span,
    check_whole_hours,
    floor_hour,
    page_cursor,
    read_cursor,
    time_zone,
)
from app.services.ai_usage.rollup_lock import held_rollup_lock, renew_rollup_lock

log = structlog.get_logger(__name__)
#: MongoDB's code for a time zone its own zone database lacks (it may be older than Python's).
_UNKNOWN_TIME_ZONE = 40485
#: The counters of an added-up document, summed into a report's counts.
_COUNTERS = (
    "total_ai_calls",
    *(outcome.value for outcome in AiUsageOutcome),
    "asks",
    "tokens_in",
    "tokens_out",
)


class AiUsageService:
    """Reads tsg_ai_usage (one row per AI attempt), tsg_ai_usage_hourly (its hourly totals) and
    tsg_ai_usage_requests (one summary per request), and writes the last two. Totals and request lists over a
    range are served from Redis for REPORT_CACHE_SECONDS."""

    def __init__(
        self,
        usage: AiUsageRepository,
        hourly: AiUsageHourlyRepository,
        requests: AiUsageRequestRepository,
        redis: Redis | None,
    ) -> None:
        self._usage, self._hourly, self._requests, self._redis = usage, hourly, requests, redis

    def summarize_ai_usage(self, query: UsageTotalsQuery) -> dict[str, Any]:
        """Totals by `group_by` over [since, until) in `tz`, from the hourly add-up: each group's counts, its
        API calls and its parts."""
        return self._cached(_cache_key("totals", query), lambda: self._totals(query))

    def kept_ai_usage_totals(self, query: UsageTotalsQuery) -> dict[str, Any] | None:
        """The totals report Redis holds for `query` while fresh; None when it must be computed."""
        return self._kept(_cache_key("totals", query))

    def kept_request_ai_usage(self, query: RequestUsageQuery) -> dict[str, Any] | None:
        """The request list Redis holds for a range's `query` while fresh; None when it must be computed (a
        session's always: it is read live)."""
        return None if query.session_id else self._kept(_cache_key("requests", query))

    def list_request_ai_usage(self, query: RequestUsageQuery) -> dict[str, Any]:
        """One entry per API call (request), newest first call first: its counts per part and model. A
        session's are read live, with the session's totals; a range's (at most MAX_SPAN_DAYS) come from the
        request summaries the 5-minute add-up keeps."""
        if query.session_id:
            who, after = _filters(query), read_cursor(query.after, str)
            entries = self._usage.list_session_requests(query.session_id, who, query.limit + 1, after)
            session = {"session_id": query.session_id, **who}
            return self._request_page(query, entries, _session_usage(self._usage.count_parts(session, True)))
        until = as_utc(query.until) if query.until else utc_now()
        since = as_utc(query.since) if query.since else until - timedelta(days=1)
        check_span(since, until, AiUsageLimits.MAX_SPAN_DAYS, AiUsageMessage.SPAN_TOO_LONG)
        match = {"first_at": {"$gte": since, "$lt": until}, **_filters(query)}

        def page() -> dict[str, Any]:
            entries = self._requests.list_page(match, query.limit + 1, read_cursor(query.after, str))
            return self._request_page(query, entries, None)

        return self._cached(_cache_key("requests", query), page)

    def get_request_ai_usage(self, request_id: str) -> dict[str, Any]:
        """One API call's counts, parts and models, and each activity (a task in a part, on one model)."""
        entries = self._usage.summarize_requests([request_id])
        if not entries:
            raise NotFound(AiUsageMessage.REQUEST_NOT_FOUND.format(request_id=request_id))
        parts = self._usage.count_parts({"request_id": request_id}, by_request=False)
        activities = sorted(parts, key=lambda doc: (_bucket_rank(doc["_id"]["bucket"]), doc["_id"]["task"]))
        return {**_request_usage(entries[0], parts), "activities": [_activity(doc) for doc in activities]}

    def list_ai_usage_calls(self, query: UsageCallQuery) -> dict[str, Any]:
        """Every AI attempt (and reused answer) of one request or one session, newest first, a page at a
        time."""
        match = {name: value for name in ("request_id", "session_id") if (value := getattr(query, name))}
        if not match:
            raise Invalid(AiUsageMessage.CALLS_NEED_SCOPE)
        after = read_cursor(query.after, ObjectId)
        rows = self._usage.list_rows(match, query.limit + 1, after)
        page = rows[: query.limit]
        more = len(rows) > query.limit
        return {
            "items": [_call(row) for row in page],
            "next": page_cursor(page[-1]["created_at"], str(page[-1]["_id"])) if more else None,
        }

    def roll_up_ai_usage(self) -> int:
        """The scheduled add-up: every hour from its frontier (less ROLLUP_LOOKBACK_HOURS: an ask writes its
        rows as it ends, possibly into an hour already added up) to this one, then the frontier moves to this
        hour. After any downtime it catches up from where it stopped. Skipped while another add-up runs;
        stopped, its frontier kept, if its lock ran out mid-run. How many hours were written."""
        with held_rollup_lock(self._redis) as token:
            if token is None:
                log.info(AiUsageLogEvent.ROLLUP_BUSY)
                return 0
            frontier, now = self._hourly.frontier(), utc_now()
            lookback = AiUsageLimits.ROLLUP_LOOKBACK_HOURS * HOUR
            start = frontier - lookback if frontier else self._usage.oldest_row_time()
            try:
                hours = 0 if start is None else self._roll_up(start, now, token)
            except Unavailable as exc:
                if exc.detail != AiUsageMessage.ROLLUP_LOCK_LOST:
                    raise
                log.warning(
                    AiUsageLogEvent.ROLLUP_LOCK_LOST
                )  # another add-up may write now; the next redoes it
                return 0
            self._hourly.move_frontier(floor_hour(now))
        metrics.record_reaper_time(metrics.AI_USAGE_ROLLUP_LAST_SUCCESS)
        log.info(AiUsageLogEvent.ROLLUP_DONE, hours=hours)
        return hours

    def roll_up_hours(self, since: datetime, until: datetime) -> int:
        """An add-up by hand (a rebuild): every UTC hour from since's to until's, both included. How many
        hours were written (see replay_rows)."""
        return self.replay_rows([], since, until)

    def replay_rows(self, rows: list[dict[str, Any]], since: datetime, until: datetime) -> int:
        """Stores `rows` (one already stored is skipped), then adds up every UTC hour from since's to
        until's, both under the scheduled add-up's lock, waited for up to ROLLUP_LOCK_WAIT_SECONDS (503 after
        it). Before storing, the scheduled add-up's frontier is set back to since's hour, and put back once
        the hours are added up: should this stop part way (MongoDB too slow), the next scheduled add-up adds
        them up, so no stored row stays uncounted. No hour it has not reached is skipped. How many hours were
        written."""
        with held_rollup_lock(self._redis, AiUsageLimits.ROLLUP_LOCK_WAIT_SECONDS) as token:
            if token is None:
                raise Unavailable(AiUsageMessage.ROLLUP_BUSY)
            frontier = self._hourly.frontier() if rows else None
            if frontier is not None:
                self._hourly.move_frontier(min(frontier, floor_hour(as_utc(since))))
            if rows:
                with pymongo.timeout(AiUsageLimits.ROLLUP_CHUNK_SECONDS):
                    self._usage.create_rows(rows)
            written = self._roll_up(since, until, token)
            if frontier is not None:
                self._hourly.move_frontier(frontier)
            return written

    def _roll_up(self, since: datetime, until: datetime, token: str) -> int:
        """Every UTC hour from since's to until's, ROLLUP_CHUNK_HOURS per read, each chunk within
        ROLLUP_CHUNK_SECONDS of a fresh lock (renewed before it, so whatever ran before never eats its time,
        and once after the last); Unavailable, and no more writes, once the lock ran out."""
        start, end = floor_hour(as_utc(since)), floor_hour(as_utc(until)) + HOUR
        written = 0
        while start < end:
            renew_rollup_lock(self._redis, token)
            stop = min(start + AiUsageLimits.ROLLUP_CHUNK_HOURS * HOUR, end)
            with pymongo.timeout(AiUsageLimits.ROLLUP_CHUNK_SECONDS):
                written += self._roll_up_chunk(start, stop)
            start = stop
        renew_rollup_lock(self._redis, token)  # still held: the caller may write what follows (the frontier)
        return written

    def _roll_up_chunk(self, since: datetime, until: datetime) -> int:
        """The hours in [since, until): their documents, each with the requests whose first AI call it holds;
        and the summary of every request with a row in them."""
        documents: dict[str, dict[str, Any]] = {}
        for group in self._usage.sum_hours(since, until):
            key = group.pop("_id")
            documents[_hour_id(key)] = {"_id": _hour_id(key), **key, **group, "requests": 0}
        firsts = self._usage.first_rows_of_requests(since, until)
        seen = (
            self._usage.requests_seen_before([first["_id"] for first in firsts], since) if firsts else set()
        )
        for first in firsts:
            if first["_id"] not in seen:
                key = {
                    "hour": floor_hour(first["created_at"]),
                    **{name: first[name] for name in HOURLY_KEYS},
                }
                if (document := documents.get(_hour_id(key))) is not None:  # always: its first row is there
                    document["requests"] += 1
        self._hourly.replace_hours(list(documents.values()))
        if firsts:
            self._requests.replace_requests(self._usage.summarize_requests(first["_id"] for first in firsts))
        return len({document["hour"] for document in documents.values()})

    def _totals(self, query: UsageTotalsQuery) -> dict[str, Any]:
        zone = time_zone(query.tz)
        until = ceil_hour(as_utc(query.until) if query.until else utc_now())
        default_since = until - timedelta(days=AiUsageLimits.DEFAULT_SPAN_DAYS)
        since = floor_hour(as_utc(query.since) if query.since else default_since)
        check_span(since, until, AiUsageLimits.MAX_SPAN_DAYS, AiUsageMessage.SPAN_TOO_LONG)
        check_whole_hours(query.tz, zone, since, until)
        match = {"hour": {"$gte": since, "$lt": until}, **_filters(query)}
        match |= {name: getattr(query, name) for name in ("bucket", "model") if getattr(query, name)}
        if query.task:
            match["task"] = {"$in": query.task}
        keys = {group.value: _group_key(group, query.tz) for group in query.group_by}
        try:
            found = self._hourly.sum_items(match, keys, AiUsageLimits.MAX_GROUPS + 1)
        except OperationFailure as exc:
            if exc.code != _UNKNOWN_TIME_ZONE:
                raise
            raise Invalid(AiUsageMessage.TZ_UNKNOWN.format(tz=query.tz)) from exc
        items, truncated = found[: AiUsageLimits.MAX_GROUPS], len(found) > AiUsageLimits.MAX_GROUPS
        # The whole range's counts: its rows' while none is cut (no second read, so they always agree), else
        # every matching hour's
        parts = [part for item in found for part in item["parts"]]
        total = self._hourly.sum_total(match) if truncated else parts
        return {
            "since": since.astimezone(zone),
            "until": until.astimezone(zone),
            "tz": query.tz,
            "group_by": query.group_by,
            "truncated": truncated,
            "total": _counts(total),
            "items": [_totals_row(dict(item["_id"]), item["parts"]) for item in items],
        }

    def _request_page(
        self, query: RequestUsageQuery, entries: list[dict[str, Any]], summary: dict[str, Any] | None
    ) -> dict[str, Any]:
        """A page of request entries (one more than the page, to tell there is a next) with their counts."""
        page, more = entries[: query.limit], len(entries) > query.limit
        ids = [entry["_id"] for entry in page]
        parts = self._usage.count_parts({"request_id": {"$in": ids}}, by_request=True) if ids else []
        by_request: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for part in parts:
            by_request[part["_id"]["request_id"]].append(part)
        return {
            "session_id": query.session_id,
            "summary": summary,
            "items": [_request_usage(entry, by_request[entry["_id"]]) for entry in page],
            "next": page_cursor(page[-1]["first_at"], page[-1]["_id"]) if more else None,
        }

    def _kept(self, key: str) -> dict[str, Any] | None:
        """The report Redis holds under `key` while fresh; None otherwise, or while Redis is down."""
        try:
            if self._redis is not None and (kept := cast(str | None, self._redis.get(key))):  # decoded: a str
                return json.loads(kept)
        except REDIS_UNAVAILABLE_ERRORS:
            log.warning(AiUsageLogEvent.REPORT_CACHE_FAILED, exc_info=True)
        return None

    def _cached(self, key: str, compute: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        """The report from Redis while fresh, else computed and kept REPORT_CACHE_SECONDS; Redis down only
        means it is computed."""
        if (kept := self._kept(key)) is not None:
            return kept
        text = json.dumps(compute(), default=_json_value)
        try:  # a large report is not kept: the Redis server also holds the job queues
            if self._redis is not None and len(text) <= AiUsageLimits.REPORT_CACHE_MAX_BYTES:
                self._redis.set(key, text, ex=AiUsageLimits.REPORT_CACHE_SECONDS)
        except REDIS_UNAVAILABLE_ERRORS:
            log.warning(AiUsageLogEvent.REPORT_CACHE_FAILED, exc_info=True)
        return json.loads(text)  # as a cached one reads: the same values from Redis or not


def _counts(documents: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """UsageCounts of added-up documents (count_parts' or the hourly ones)."""
    sums: dict[str, float] = defaultdict(float)
    for document in documents:
        for name in (*_COUNTERS, "seconds"):
            sums[name] += document.get(name, 0) or 0
    total, ok, reused, asks = (int(sums[name]) for name in ("total_ai_calls", "ok", "reused", "asks"))
    # asks: attempts numbered 1 (a reused answer is no attempt), so extra_attempts are retries and re-asks
    outcomes = {outcome.value: int(sums[outcome.value]) for outcome in AiUsageOutcome if sums[outcome.value]}
    return {
        "total_ai_calls": total,
        "successful_calls": ok,
        "failed_calls": total - ok,
        "asks": asks,
        "extra_attempts": max(0, total - asks),
        "reused_answers": reused,
        "outcomes": outcomes,
        "tokens_in": int(sums["tokens_in"]),
        "tokens_out": int(sums["tokens_out"]),
        "seconds": round(sums["seconds"], 1),
    }


def _parts(module: str | None, documents: list[dict[str, Any]], bucket_of: Callable[[dict], str]) -> dict:
    """PartCounts per part: the module's own parts always (0 when none), any other part found too."""
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for document in documents:
        found[bucket_of(document)].append(document)
    own = MODULE_BUCKETS.get(module or "", ())
    names = [*own, *(name for name in found if name not in own)]
    parts = {}
    for name in names:
        counts, (label, description) = _counts(found[name]), BUCKET_INFO.get(name, (name, ""))
        by_task: dict[str, int] = defaultdict(int)
        for document in found[name]:
            if task := (document.get("_id") or {}).get("task"):
                by_task[task] += document.get("total_ai_calls", 0)
        parts[name] = {
            "label": label,
            "description": description,
            "total_ai_calls": counts["total_ai_calls"],
            "successful_calls": counts["successful_calls"],
            "failed_calls": counts["failed_calls"],
            "by_task": dict(by_task),
        }
    return parts


def _models(parts: list[dict[str, Any]]) -> dict[str, int]:
    """AI calls per model (a model that only gave reused answers made none)."""
    calls: dict[str, int] = defaultdict(int)
    for part in parts:
        calls[part["_id"].get("model") or "none"] += part.get("total_ai_calls", 0)
    return {model: count for model, count in calls.items() if count}


def _request_usage(entry: dict[str, Any], parts: list[dict[str, Any]]) -> dict[str, Any]:
    """One request's entry (list_request_pages') with its counts, models and parts (count_parts')."""
    label, description = api_info(entry.get("module"), entry.get("api"))
    return {
        "request_id": entry["_id"],
        **{name: entry.get(name) for name in REQUEST_FIELDS},
        "api_label": label,
        "api_description": description,
        "first_at": entry["first_at"],
        "last_at": entry["last_at"],
        **_counts(parts),
        "models": _models(parts),
        "buckets": _parts(entry.get("module"), parts, lambda part: part["_id"]["bucket"]),
    }


def _session_usage(parts: list[dict[str, Any]]) -> dict[str, Any]:
    requests = {part["_id"].get("request_id") for part in parts} - {None}
    return {
        **_counts(parts),
        "requests": len(requests),
        "models": _models(parts),
        "buckets": _parts(None, parts, lambda part: part["_id"]["bucket"]),
    }


def _activity(document: dict[str, Any]) -> dict[str, Any]:
    key, counts = document["_id"], _counts([document])
    activity, description = activity_info(key["bucket"], key["task"])
    return {
        "bucket": key["bucket"],
        "bucket_label": BUCKET_INFO.get(key["bucket"], (key["bucket"], ""))[0],
        "task": key["task"],
        "activity": activity,
        "description": description,
        "model": key.get("model") or "none",
        **{
            name: counts[name]
            for name in ("total_ai_calls", "successful_calls", "failed_calls", "reused_answers")
        },
        **{name: counts[name] for name in ("tokens_in", "tokens_out", "seconds")},
    }


def _totals_row(key: dict[str, Any], parts: list[dict[str, Any]]) -> dict[str, Any]:
    """One totals group: its counts, API calls and parts, and its labels when the key holds what they need."""
    row = {"key": key, **_counts(parts), "requests": sum(part.get("requests", 0) for part in parts)}
    if "module" in key and "api" in key and key["api"]:
        row["api_label"], row["api_description"] = api_info(key["module"], key["api"])
    if "bucket" in key and "task" in key:
        row["activity"], row["activity_description"] = activity_info(key["bucket"], key["task"])
    row["buckets"] = _parts(key.get("module"), parts, lambda part: part["bucket"])
    return row


def _call(row: dict[str, Any]) -> dict[str, Any]:
    """One usage row as the calls list shows it: its ids as text, with its activity and description."""
    activity, description = activity_info(row["bucket"], row["task"])
    shown = {name: value for name, value in row.items() if name not in ("_id", "ask_id", "schema_version")}
    return {
        **shown,
        "id": str(row["_id"]),
        "ask_id": str(row["ask_id"]) if row.get("ask_id") else None,
        "activity": activity,
        "description": description,
    }


def _filters(query: UsageFilters) -> dict[str, Any]:
    """The filters a query names; an entity id (digits, checked by the query model) matches as a number or as
    text."""
    match: dict[str, Any] = {
        name: value for name in ("module", "api", "client_id") if (value := getattr(query, name))
    }
    if query.entity_id is not None:
        match["entity_id"] = {"$in": [int(query.entity_id), query.entity_id]}
    return match


def _group_key(group: AiUsageGroup, tz: str) -> Any:
    """A $group key part: a time step's text in `tz`, else the field."""
    if group in GROUP_TIME_FORMATS:
        return {"$dateToString": {"format": GROUP_TIME_FORMATS[group], "date": "$hour", "timezone": tz}}
    return f"${group.value}"


def _bucket_rank(bucket: str) -> int:
    order = list(AiBucket)
    return order.index(AiBucket(bucket)) if bucket in AiBucket else len(order)


def _hour_id(key: dict[str, Any]) -> str:
    """An hourly document's _id: its hour and HOURLY_KEYS as text."""
    return "|".join([key["hour"].isoformat(), *(str(key[name]) for name in HOURLY_KEYS)])


def _cache_key(name: str, query: BaseModel) -> str:
    """The Redis key a report of `name` for `query` is kept under."""
    text = json.dumps([name, query.model_dump(mode="json")], sort_keys=True)
    return AiUsageLimits.REPORT_CACHE_KEY.format(digest=hashlib.sha256(text.encode()).hexdigest()[:32])


def _json_value(value: Any) -> str:
    """A cached report's value JSON cannot hold: a time as ISO text, anything else as text."""
    return value.isoformat() if isinstance(value, datetime) else str(value)
