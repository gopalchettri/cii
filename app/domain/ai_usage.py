"""AI usage reports (GET /v1/ai-usage..., no key, owner 2026-10-29) and the hourly add-up the totals read
(tsg_roll_up_ai_usage, every 5 minutes). Counts only, never a prompt or an answer; a bad time zone, range or
cursor answers 422, never 500."""

import base64
import json
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pymongo
import structlog
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.database import Database
from pymongo.errors import OperationFailure

from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    BUCKET_INFO,
    GROUP_TIME_FORMATS,
    MODULE_BUCKETS,
    AiBucket,
    AiUsageCollection,
    AiUsageLimits,
    AiUsageLogEvent,
    AiUsageMessage,
    AiUsageOutcome,
    activity_info,
    api_info,
)
from app.core.exceptions import Invalid, NotFound
from app.crud import ai_usage as crud
from app.schemas.ai_usage import RequestUsageQuery, UsageCallQuery, UsageFilters, UsageTotalsQuery, reportable_time

log = structlog.get_logger(__name__)
HOUR, DAY = timedelta(hours=1), timedelta(days=1)
_UNKNOWN_TIME_ZONE = 40485  # MongoDB's code for a zone its own zone database lacks
_LOOKBACK = 2 * HOUR  # an ask writes its rows as it ends, maybe into an hour already added up


def summarize_ai_usage(db: Database, query: UsageTotalsQuery) -> dict[str, Any]:
    """Report 1: totals by `group_by` over [since, until) in `tz`, from the hourly add-up."""
    zone = _time_zone(query.tz)
    until = _ceil_hour(_as_utc(query.until) if query.until else utc_now())
    since = _floor_hour(
        _as_utc(query.since) if query.since else until - timedelta(days=AiUsageLimits.DEFAULT_SPAN_DAYS)
    )
    _check_span(since, until)
    moment = since
    while moment <= until:  # ponytail: every hour (at most 8,784, ~10 ms); a part-hour offset splits totals
        if (moment.astimezone(zone).utcoffset() or timedelta()).total_seconds() % 3600:
            raise Invalid(AiUsageMessage.TZ_NOT_WHOLE_HOURS.format(tz=query.tz))
        moment += HOUR
    match = {"hour": {"$gte": since, "$lt": until}, **_filters(query)}
    match |= {name: getattr(query, name) for name in ("bucket", "model") if getattr(query, name)}
    if query.task:
        match["task"] = {"$in": query.task}
    keys = {group.value: _group_key(group.value, query.tz) for group in query.group_by}
    try:
        found = crud.sum_hours(db, match, keys, AiUsageLimits.MAX_GROUPS + 1)
    except OperationFailure as exc:
        if exc.code != _UNKNOWN_TIME_ZONE:
            raise
        raise Invalid(AiUsageMessage.TZ_UNKNOWN.format(tz=query.tz)) from exc
    truncated = len(found) > AiUsageLimits.MAX_GROUPS
    # the whole range: its rows' while none is cut (no second read, so they always agree), else every hour's
    total = crud.sum_total(db, match) if truncated else [part for item in found for part in item["parts"]]
    return {
        "since": since.astimezone(zone),
        "until": until.astimezone(zone),
        "tz": query.tz,
        "group_by": query.group_by,
        "truncated": truncated,
        "total": _counts(total),
        "items": [_totals_row(dict(item["_id"]), item["parts"]) for item in found[: AiUsageLimits.MAX_GROUPS]],
    }


def list_request_ai_usage(db: Database, query: RequestUsageQuery) -> dict[str, Any]:
    """Report 2: one entry per API call, newest first: a session's live with totals, a range's from summaries."""
    if query.session_id:
        who = _filters(query)
        match = {"session_id": query.session_id, "request_id": {"$exists": True}, **who}
        entries = crud.summarize_requests(db, match, query.limit + 1, _read_cursor(query.after, str))
        parts = crud.group_rows(db, {"session_id": query.session_id, **who}, crud.part_key(by_request=True))
        requests = {part["_id"].get("request_id") for part in parts} - {None}
        summary = {
            **_counts(parts),
            "requests": len(requests),
            "models": _models(parts),
            "buckets": _parts(None, parts),
        }
        return _request_page(db, query, entries, summary)
    until = _as_utc(query.until) if query.until else utc_now()
    since = _as_utc(query.since) if query.since else until - DAY
    _check_span(since, until)
    match = {"first_at": {"$gte": since, "$lt": until}, **_filters(query)}
    entries = crud.list_request_summaries(db, match, query.limit + 1, _read_cursor(query.after, str))
    return _request_page(db, query, entries, None)


def _request_page(
    db: Database, query: RequestUsageQuery, entries: list[dict[str, Any]], summary: dict[str, Any] | None
) -> dict[str, Any]:
    page, more = entries[: query.limit], len(entries) > query.limit
    ids = [entry["_id"] for entry in page]
    by_request: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for part in crud.group_rows(db, {"request_id": {"$in": ids}}, crud.part_key(by_request=True)) if ids else []:
        by_request[part["_id"]["request_id"]].append(part)
    return {
        "session_id": query.session_id,
        "summary": summary,
        "items": [_request_usage(entry, by_request[entry["_id"]]) for entry in page],
        "next": _page_cursor(page[-1]["first_at"], page[-1]["_id"]) if more else None,
    }


def get_request_ai_usage(db: Database, request_id: str) -> dict[str, Any]:
    """Report 3: one API call's counts, parts and models, and each activity (a task in a part, on a model)."""
    if not (entries := crud.summarize_requests(db, {"request_id": {"$in": [request_id]}})):
        raise NotFound(AiUsageMessage.REQUEST_NOT_FOUND.format(request_id=request_id))
    parts = crud.group_rows(db, {"request_id": request_id}, crud.part_key())
    ranks = {bucket.value: rank for rank, bucket in enumerate(AiBucket)}
    parts.sort(key=lambda doc: (ranks.get(doc["_id"]["bucket"], len(ranks)), doc["_id"]["task"]))
    return {**_request_usage(entries[0], parts), "activities": [_activity(doc) for doc in parts]}


def list_ai_usage_calls(db: Database, query: UsageCallQuery) -> dict[str, Any]:
    """Report 4: every AI attempt (and reused answer) of one request or session, newest first."""
    if not (match := {name: value for name in ("request_id", "session_id") if (value := getattr(query, name))}):
        raise Invalid(AiUsageMessage.CALLS_NEED_SCOPE)
    rows = crud.list_rows(db, match, query.limit + 1, _read_cursor(query.after, ObjectId))
    page = rows[: query.limit]
    calls = []
    for row in page:
        activity, description = activity_info(row["bucket"], row["task"])
        shown = {name: value for name, value in row.items() if name not in ("_id", "ask_id", "schema_version")}
        ask_id = str(row["ask_id"]) if row.get("ask_id") else None
        calls.append(
            {**shown, "id": str(row["_id"]), "ask_id": ask_id, "activity": activity, "description": description}
        )
    more = len(rows) > query.limit
    return {"items": calls, "next": _page_cursor(page[-1]["created_at"], str(page[-1]["_id"])) if more else None}


def roll_up_ai_usage(db: Database, since: datetime | None = None, until: datetime | None = None) -> int:
    """Adds up each UTC hour from `since` (default: the newest added, less _LOOKBACK) to `until`; hours written."""
    start = since or ((newest := crud.newest_hour(db)) and newest - _LOOKBACK)
    if start is None:  # no row yet: nothing to add up, and the beat still counts as done
        start = until = utc_now()
    start, end, written = _floor_hour(_as_utc(start)), _floor_hour(_as_utc(until or utc_now())) + HOUR, 0
    while start < end:
        stop = min(start + DAY, end)
        with pymongo.timeout(AiUsageLimits.ROLLUP_CHUNK_SECONDS):
            written += _write_hours(db, start, stop)
        start = stop
    if since is None:
        metrics.record_reaper_time(metrics.AI_USAGE_ROLLUP_LAST_SUCCESS)
    log.info(AiUsageLogEvent.ROLLUP_DONE, hours=written)
    return written


def _write_hours(db: Database, since: datetime, until: datetime) -> int:
    read_at, documents = utc_now(), {}
    for group in crud.group_rows(db, {"created_at": {"$gte": since, "$lt": until}}, crud.hour_key()):
        key = group.pop("_id")
        hour_id = "|".join([key["hour"].isoformat(), *(str(key[name]) for name in crud.HOURLY_KEYS)])
        documents[hour_id] = {"_id": hour_id, **key, **group, "requests": 0, "read_at": read_at}
    firsts, seen_before = crud.first_rows_of_requests(db, since, until)
    for first in (first for first in firsts if first["_id"] not in seen_before):
        names = [_floor_hour(first["created_at"]).isoformat(), *(str(first[name]) for name in crud.HOURLY_KEYS)]
        if (document := documents.get("|".join(names))) is not None:  # always: its first row is there
            document["requests"] += 1
    crud.replace_if_newer(db, AiUsageCollection.HOURLY, list(documents.values()))
    if firsts:
        summaries = crud.summarize_requests(db, {"request_id": {"$in": [first["_id"] for first in firsts]}})
        crud.replace_if_newer(db, AiUsageCollection.REQUESTS, [doc | {"read_at": read_at} for doc in summaries])
    return len({document["hour"] for document in documents.values()})


def _counts(documents: Iterable[dict[str, Any]]) -> dict[str, Any]:
    sums: dict[str, float] = defaultdict(float)
    for document in documents:
        for name in ("total_ai_calls", *AiUsageOutcome, "asks", "tokens_in", "tokens_out", "seconds"):
            sums[name] += document.get(name, 0) or 0
    total, ok, asks = (int(sums[name]) for name in ("total_ai_calls", "ok", "asks"))
    return {
        "total_ai_calls": total,
        "successful_calls": ok,
        "failed_calls": total - ok,
        "asks": asks,
        "extra_attempts": max(0, total - asks),  # asks: attempts numbered 1, so the rest are retries, re-asks
        "reused_answers": int(sums["reused"]),
        "outcomes": {outcome.value: int(sums[outcome]) for outcome in AiUsageOutcome if sums[outcome]},
        "tokens_in": int(sums["tokens_in"]),
        "tokens_out": int(sums["tokens_out"]),
        "seconds": round(sums["seconds"], 1),
    }


def _parts(module: str | None, documents: list[dict[str, Any]], bucket_of: Callable[[dict], str] | None = None) -> dict:
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for document in documents:
        found[bucket_of(document) if bucket_of else document["_id"]["bucket"]].append(document)
    own = MODULE_BUCKETS.get(module or "", ())
    parts = {}
    for name in [*own, *(name for name in found if name not in own)]:
        counts, (label, description) = _counts(found[name]), BUCKET_INFO.get(name, (name, ""))
        by_task: dict[str, int] = defaultdict(int)
        for document in found[name]:
            if task := (document.get("_id") or {}).get("task"):
                by_task[task] += document.get("total_ai_calls", 0)
        calls = {key: counts[key] for key in ("total_ai_calls", "successful_calls", "failed_calls")}
        parts[name] = {"label": label, "description": description, **calls, "by_task": dict(by_task)}
    return parts


def _models(parts: list[dict[str, Any]]) -> dict[str, int]:
    calls: dict[str, int] = defaultdict(int)
    for part in parts:
        calls[part["_id"].get("model") or "none"] += part.get("total_ai_calls", 0)
    return {model: count for model, count in calls.items() if count}


def _request_usage(entry: dict[str, Any], parts: list[dict[str, Any]]) -> dict[str, Any]:
    label, description = api_info(entry.get("module"), entry.get("api"))
    return {
        "request_id": entry["_id"],
        **{name: entry.get(name) for name in crud.REQUEST_FIELDS},
        "api_label": label,
        "api_description": description,
        "first_at": entry["first_at"],
        "last_at": entry["last_at"],
        **_counts(parts),
        "models": _models(parts),
        "buckets": _parts(entry.get("module"), parts),
    }


def _activity(document: dict[str, Any]) -> dict[str, Any]:
    key, counts = document["_id"], _counts([document])
    activity, description = activity_info(key["bucket"], key["task"])
    shown = ("total_ai_calls", "successful_calls", "failed_calls", "reused_answers", "tokens_in", "tokens_out")
    return {
        "bucket": key["bucket"],
        "bucket_label": BUCKET_INFO.get(key["bucket"], (key["bucket"], ""))[0],
        "task": key["task"],
        "activity": activity,
        "description": description,
        "model": key.get("model") or "none",
        **{name: counts[name] for name in (*shown, "seconds")},
    }


def _totals_row(key: dict[str, Any], parts: list[dict[str, Any]]) -> dict[str, Any]:
    row = {"key": key, **_counts(parts), "requests": sum(part.get("requests", 0) for part in parts)}
    if "module" in key and "api" in key and key["api"]:
        row["api_label"], row["api_description"] = api_info(key["module"], key["api"])
    if "bucket" in key and "task" in key:
        row["activity"], row["activity_description"] = activity_info(key["bucket"], key["task"])
    return row | {"buckets": _parts(key.get("module"), parts, lambda part: part["bucket"])}


def _filters(query: UsageFilters) -> dict[str, Any]:
    match: dict[str, Any] = {name: value for name in ("module", "api", "client_id") if (value := getattr(query, name))}
    if query.entity_id is not None:
        match["entity_id"] = {"$in": [int(query.entity_id), query.entity_id]}
    return match


def _group_key(group: str, tz: str) -> Any:
    if group in GROUP_TIME_FORMATS:
        return {"$dateToString": {"format": GROUP_TIME_FORMATS[group], "date": "$hour", "timezone": tz}}
    return f"${group}"


def _time_zone(tz: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:  # OSError: a folder's name ("America")
        raise Invalid(AiUsageMessage.TZ_UNKNOWN.format(tz=tz)) from exc


def _check_span(since: datetime, until: datetime) -> None:
    if since >= until:
        raise Invalid(AiUsageMessage.SPAN_EMPTY)
    if until - since > timedelta(days=(most := AiUsageLimits.MAX_SPAN_DAYS)):
        raise Invalid(AiUsageMessage.SPAN_TOO_LONG.format(days=(until - since).days, max_days=most))


def _as_utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _floor_hour(moment: datetime) -> datetime:
    return moment.replace(minute=0, second=0, microsecond=0)


def _ceil_hour(moment: datetime) -> datetime:
    return floor if (floor := _floor_hour(moment)) == moment else floor + HOUR


def _page_cursor(at: datetime, last_id: str) -> str:
    return base64.urlsafe_b64encode(json.dumps([at.isoformat(), last_id]).encode()).decode()


def _read_cursor[Id](cursor: str | None, id_type: Callable[[str], Id]) -> tuple[datetime, Id] | None:
    if cursor is None:
        return None
    try:
        at, last_id = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return reportable_time(datetime.fromisoformat(at)), id_type(last_id)
    except (ValueError, TypeError, InvalidId) as exc:
        raise Invalid(AiUsageMessage.BAD_CURSOR) from exc
