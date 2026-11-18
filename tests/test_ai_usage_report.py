"""The AI usage reports (GET /v1/ai-usage..., no key) and the hourly add-up they read, over usage rows written
here for one session of three requests: totals by module and API (and by day in Dubai's time), a session's
requests with its totals, one request's activities, and its every call. Each test names the mutation it
catches."""

import asyncio
import base64
import json
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo import _csot

from app.api.routes import ai_usage as ai_usage_routes
from app.core.clock import utc_now
from app.core.constants import AiApi, AiUsageCollection, AiUsageLimits, Module
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.crud import ai_usage as crud
from app.domain import ai_usage
from app.domain.ai_usage import roll_up_ai_usage
from app.schemas.ai_usage import UsageCallList, UsageTotalsQuery

DAY = datetime(2025, 3, 10, tzinfo=UTC)
WINDOW = {"since": "2025-03-10T00:00:00Z", "until": "2025-03-12T00:00:00Z"}


def _row(request: dict[str, Any], minute: int, bucket: str, task: str, outcome: str = "ok", **extra: Any) -> dict:
    """One usage row of `request`, `minute` minutes after its start (a reused answer has no try number)."""
    if outcome == "reused":
        extra.setdefault("try_no", None)
    row = {
        "_id": ObjectId(),
        "created_at": request["at"] + timedelta(minutes=minute),
        "module": request["module"],
        "api": request["api"],
        "session_id": request["session_id"],
        "request_id": request["request_id"],
        "entity_id": request["entity_id"],
        "client_id": "ui-client",
        "bucket": bucket,
        "task": task,
        "job_task": "tsg_test",
        "model": extra.pop("model", "kimi"),
        "outcome": outcome,
        "ask_id": extra.pop("ask_id", ObjectId()),
        "try_no": extra.pop("try_no", 1),
        "tokens_in": 100 if outcome == "ok" else 0,
        "tokens_out": 10 if outcome == "ok" else 0,
        "seconds": 1.5,
        **extra,
    }
    return {name: value for name, value in row.items() if value is not None}


@pytest.fixture(scope="module")
def session() -> dict[str, Any]:
    """One session of three requests on 10 March 2025 (UTC evening: the next day in Dubai): create_scenario
    (one AI-busy retry, one reused answer), next_set (one answer cut off and asked again), and a plan."""
    entity, session_id = uuid.uuid4().int % 10**9, uuid.uuid4().hex  # unique: the totals are cached

    def request(api: str, module: str, hour: int, minute: int) -> dict[str, Any]:
        at = DAY.replace(hour=hour, minute=minute)
        return {
            "request_id": uuid.uuid4().hex,
            "api": api,
            "module": module,
            "at": at,
            "session_id": session_id,
            "entity_id": entity,
        }

    create = request(AiApi.CREATE_SCENARIO, Module.THREAT_SCENARIOS, 20, 30)
    next_set = request(AiApi.NEXT_SET, Module.THREAT_SCENARIOS, 21, 10)
    plan = request(AiApi.CREATE_PLAN, Module.REMEDIATION, 21, 40)
    gate, write = ObjectId(), ObjectId()
    rows = [
        _row(create, 0, "threats", "relevance_gate", "unavailable", ask_id=gate, reason="ai_busy"),
        _row(create, 1, "threats", "relevance_gate", ask_id=gate, try_no=2),
        _row(create, 2, "threats", "gap_fill"),
        _row(create, 3, "scenario", "write_scenario"),
        _row(create, 4, "scenario", "plan_check"),
        _row(create, 5, "controls", "embed", model="embedder"),
        _row(create, 6, "controls", "rerank", model="reranker"),
        _row(create, 7, "threats", "relevance_gate", "reused"),
        _row(next_set, 0, "scenario", "write_scenario", "truncated", ask_id=write),
        _row(next_set, 1, "scenario", "write_scenario", ask_id=write, try_no=2),
        _row(next_set, 2, "controls", "rerank", model="reranker"),
        _row(plan, 0, "remediation", "remediation_plan", model="glm"),
        _row(plan, 1, "controls", "embed", model="embedder"),
        _row(plan, 2, "controls", "rerank", model="reranker"),
    ]
    crud.insert_rows(get_mongodb(), rows)
    roll_up_ai_usage(get_mongodb(), DAY, DAY + timedelta(hours=23))
    return {
        "entity": entity,
        "session_id": session_id,
        "create": create,
        "next_set": next_set,
        "plan": plan,
        "rows": rows,
    }


def _totals(client: TestClient, session: dict[str, Any], **params: Any) -> Any:
    return client.get("/v1/ai-usage", params={**WINDOW, "entity_id": session["entity"], **params})  # no key


def test_totals_by_module_and_api_count_each_part_and_label_each_api(client: TestClient, session: dict) -> None:
    """Mutation: count a reused answer as an AI call, or drop `requests` from the add-up."""
    response = _totals(client, session)
    assert response.status_code == 200, response.text
    items = {(item["key"]["module"], item["key"]["api"]): item for item in response.json()["items"]}
    create = items[("threat_scenarios", "create_scenario")]
    assert (create["total_ai_calls"], create["successful_calls"], create["failed_calls"]) == (7, 6, 1)
    # 6 asks (a reused answer is none), 1 extra attempt (the busy relevance check's retry)
    counts = (create["requests"], create["reused_answers"], create["asks"], create["extra_attempts"])
    assert counts == (1, 1, 6, 1)
    assert (create["api_label"], create["api_description"]) == (
        "Create scenario",
        "Starts a run: finds threats, writes the first set, picks controls",
    )
    parts = {
        name: (part["label"], part["total_ai_calls"], part["failed_calls"]) for name, part in create["buckets"].items()
    }
    assert parts == {
        "threats": ("Finding threats", 3, 1),
        "scenario": ("Writing scenarios", 2, 0),
        "controls": ("Picking controls", 2, 0),
    }
    next_set = items[("threat_scenarios", "next_set")]
    assert (next_set["total_ai_calls"], next_set["failed_calls"], next_set["buckets"]["threats"]["total_ai_calls"]) == (
        3,
        1,
        0,
    )
    plan = items[("remediation", "create_plan")]
    assert set(plan["buckets"]) == {"remediation", "controls"} and plan["total_ai_calls"] == 3
    assert response.json()["total"]["total_ai_calls"] == 13


def test_totals_by_day_are_days_in_the_callers_time_zone(client: TestClient, session: dict) -> None:
    """20:30 UTC on 10 March is 00:30 on 11 March in Dubai. Mutation: drop the timezone from $dateToString."""
    utc = _totals(client, session, group_by=["day"]).json()["items"]
    dubai = _totals(client, session, group_by=["day"], tz="Asia/Dubai").json()["items"]
    assert [item["key"]["day"] for item in utc] == ["2025-03-10"]
    assert [item["key"]["day"] for item in dubai] == ["2025-03-11"]


@pytest.mark.parametrize(
    "params",
    [
        {"tz": "Asia/Kolkata"},  # +05:30: totals are kept per UTC hour
        {"tz": "Mars/Olympus"},
        {"tz": "America"},  # fix-check 2026-10-29: a folder of zones, not one (it answered 500)
        {"tz": "A" * 300},  # fix-check 2026-10-29: an unbounded name reached the zone lookup
        {"since": "1500-01-01T00:00:00Z", "until": "1500-01-02T00:00:00Z"},  # fix-check: BSON-safe years only
        {"since": "9999-12-30T00:00:00Z", "until": "9999-12-31T00:00:00Z"},
        # Review 2026-10-29: whole hours at both ends (+11 in summer), +10:30 in between: checked every hour
        {"tz": "Australia/Lord_Howe", "since": "2025-03-01T00:00:00Z", "until": "2025-12-01T00:00:00Z"},
        {"since": "2024-01-01T00:00:00Z", "until": "2025-03-12T00:00:00Z"},  # over 366 days
        {"since": "2025-03-12T00:00:00Z", "until": "2025-03-10T00:00:00Z"},
        {"group_by": ["planet"]},
    ],
)
def test_a_totals_report_it_cannot_answer_right_is_refused(client: TestClient, session: dict, params: dict) -> None:
    assert _totals(client, session, **params).status_code == 422


def test_a_sessions_requests_newest_first_with_its_totals_and_pages(client: TestClient, session: dict) -> None:
    """Mutation: leave the plan (its session is the run) out of the session, or lose the cursor's place."""
    first = client.get("/v1/ai-usage/requests", params={"session_id": session["session_id"], "limit": 2}).json()
    assert [item["api"] for item in first["items"]] == ["create_plan", "next_set"]
    assert (first["summary"]["requests"], first["summary"]["total_ai_calls"], first["summary"]["failed_calls"]) == (
        3,
        13,
        2,
    )
    rest = client.get(
        "/v1/ai-usage/requests", params={"session_id": session["session_id"], "limit": 2, "after": first["next"]}
    ).json()
    assert [item["api"] for item in rest["items"]] == ["create_scenario"] and rest["next"] is None
    create = rest["items"][0]
    assert create["buckets"]["threats"]["by_task"] == {"relevance_gate": 2, "gap_fill": 1}
    assert create["models"] == {"kimi": 5, "embedder": 1, "reranker": 1}
    assert (create["api_label"], create["entity_id"]) == ("Create scenario", session["entity"])


def test_a_request_list_over_too_long_a_range_is_refused(client: TestClient) -> None:
    params = {"since": "2024-01-01T00:00:00Z", "until": "2025-03-12T00:00:00Z"}  # over 366 days
    assert client.get("/v1/ai-usage/requests", params=params).status_code == 422


def test_a_ranges_requests_page_by_index_from_the_summaries_the_add_up_keeps(client: TestClient, session: dict) -> None:
    """Review 2026-10-29: a request list over a range grouped every raw row of the range again on every page.
    It now pages the per-request summaries by their (first_at, _id) index. Mutation: stop writing the
    summaries in the add-up."""
    window = {**WINDOW, "entity_id": session["entity"], "limit": 2}
    first = client.get("/v1/ai-usage/requests", params=window).json()
    assert [item["api"] for item in first["items"]] == ["create_plan", "next_set"] and first["summary"] is None
    rest = client.get("/v1/ai-usage/requests", params={**window, "after": first["next"]}).json()
    assert [(item["api"], item["total_ai_calls"]) for item in rest["items"]] == [("create_scenario", 7)]


def test_a_request_still_running_is_never_skipped_between_pages(client: TestClient) -> None:
    """Review 2026-10-29: pages went by each request's last call, which moves while it runs: a request just
    past page 1 that wrote another row jumped above the cursor and was on no page. Pages go by its first call
    now. Mutation: page by last_at again."""
    session_id, at = uuid.uuid4().hex, datetime(2025, 6, 1, 8, tzinfo=UTC)
    requests = [
        {"request_id": uuid.uuid4().hex, "api": api, "module": Module.THREAT_SCENARIOS, "entity_id": 7}
        | {"session_id": session_id, "at": at + timedelta(minutes=10 * n)}
        for n, api in enumerate((AiApi.CREATE_SCENARIO, AiApi.NEXT_SET, AiApi.REGENERATE))
    ]
    crud.insert_rows(get_mongodb(), [_row(request, 0, "scenario", "write_scenario") for request in requests])
    params = {"session_id": session_id, "limit": 2}
    first = client.get("/v1/ai-usage/requests", params=params).json()
    assert [item["api"] for item in first["items"]] == ["regenerate", "next_set"]
    crud.insert_rows(get_mongodb(), [_row(requests[0], 90, "controls", "rerank")])  # the oldest one goes on
    rest = client.get("/v1/ai-usage/requests", params={**params, "after": first["next"]}).json()
    assert [item["api"] for item in rest["items"]] == ["create_scenario"]


def test_a_malformed_entity_id_is_refused_not_a_server_error(client: TestClient) -> None:
    """Review 2026-10-29: "--5" or 20 digits reached int() or BSON and answered 500; and a pattern's \\d also
    takes other scripts' digits, some of which int() refuses (a Garay digit). Mutations: drop the pattern;
    allow \\d."""
    for entity in ("--5", "9" * 20, "12a", "\U00010d40", "٣"):
        assert client.get("/v1/ai-usage", params={"entity_id": entity}).status_code == 422, entity


def test_a_cursor_with_a_year_mongodb_cannot_hold_is_refused(client: TestClient, session: dict) -> None:
    """Review 2026-10-29: `after` was not checked like `since` and `until`, so year 1 overflowed MongoDB's
    date and answered 500. Mutation: read the cursor's time unchecked."""
    for at in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
        after = base64.urlsafe_b64encode(json.dumps([at, "0" * 24]).encode()).decode()
        calls = client.get("/v1/ai-usage/calls", params={"request_id": "any", "after": after})
        listed = client.get("/v1/ai-usage/requests", params={"session_id": session["session_id"], "after": after})
        assert (calls.status_code, listed.status_code) == (422, 422), at


def test_a_time_zone_mongodb_does_not_know_is_refused_not_a_server_error(
    client: TestClient, session: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 2026-10-29: Python's zone list can be newer than MongoDB's (America/Coyhaique came in tzdata
    2025b), so a zone Python took failed the aggregate and answered 500. Mutation: let MongoDB's refusal
    through."""
    monkeypatch.setattr(ai_usage, "_time_zone", lambda tz: ZoneInfo("UTC"))  # Python takes it
    response = _totals(client, session, tz="Mars/Olympus", group_by=["day"], client_id=uuid.uuid4().hex)
    assert response.status_code == 422 and "Mars/Olympus" in response.text


class _NoPlace:
    """Every report place taken, as a route sees it once its wait is over."""

    async def acquire(self) -> None:
        raise TimeoutError


def test_reports_answer_503_when_too_many_run(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review 2026-10-29: the no-key report routes shared the threads every UI route runs on, so a burst of
    slow reports stalled the UI. They now run apart, at most REPORTS_AT_ONCE per process; one more answers 503
    with Retry-After once REPORT_SLOT_WAIT_SECONDS pass. Mutation: wait for a free place without end (the
    wait is checked under asyncio.wait_for, so that fails here instead of hanging the suite)."""
    monkeypatch.setattr(AiUsageLimits, "REPORT_SLOT_WAIT_SECONDS", 0.1)

    async def report_with_every_place_taken() -> Any:
        monkeypatch.setattr(ai_usage_routes, "_REPORTS", asyncio.Semaphore(0))
        return await asyncio.wait_for(ai_usage_routes._report(UsageCallList, lambda: {"items": []}), 5)

    with pytest.raises(Unavailable):
        asyncio.run(report_with_every_place_taken())
    monkeypatch.setattr(ai_usage_routes, "_REPORTS", _NoPlace())
    busy = client.get("/v1/ai-usage")
    assert busy.status_code == 503 and busy.headers.get("Retry-After")


def test_a_report_waits_briefly_for_a_free_place(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fix-check 2026-10-29: a dashboard's panels load together, so a third report answered 503 though the
    first two took milliseconds. It waits for a place now. Mutation: refuse at once when none is free."""

    async def third_report() -> Any:
        places = asyncio.Semaphore(1)
        await places.acquire()  # both places taken...
        asyncio.get_running_loop().call_later(0.2, places.release)  # ...and one freed soon
        monkeypatch.setattr(ai_usage_routes, "_REPORTS", places)
        return await ai_usage_routes._report(UsageCallList, lambda: {"items": []})

    assert json.loads(asyncio.run(third_report()).body) == {"items": [], "next": None}


def test_a_reports_work_and_its_json_run_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review 2026-10-29: only the MongoDB reads left the event loop; checking and writing a large answer
    (11 MB: a third of a second) still held every route of the process. Mutations: run the work, or write its
    JSON, on the loop."""
    threads: list[threading.Thread] = []
    rendered = ai_usage_routes._rendered

    def render(shape: Any, report: dict[str, Any]) -> str:
        threads.append(threading.current_thread())
        return rendered(shape, report)

    def work() -> dict[str, Any]:
        threads.append(threading.current_thread())
        return {"items": []}

    async def report() -> tuple[threading.Thread, Any]:
        return threading.current_thread(), await ai_usage_routes._report(UsageCallList, work)

    monkeypatch.setattr(ai_usage_routes, "_rendered", render)
    loop_thread, response = asyncio.run(report())
    assert len(threads) == 2 and loop_thread not in threads
    # Review 2026-10-29: the reports' own threads, never asyncio's default ones the status streams use
    assert all(thread.name.startswith("ai-usage-report") for thread in threads)
    assert json.loads(response.body) == {"items": [], "next": None}


def test_one_requests_activities_each_have_a_name_a_description_and_a_model(client: TestClient, session: dict) -> None:
    """Mutation: key the activity catalogue by task alone (embed and rerank differ per part)."""
    response = client.get(f"/v1/ai-usage/requests/{session['create']['request_id']}")
    assert response.status_code == 200, response.text
    found = {
        (item["activity"], item["model"]): (item["total_ai_calls"], item["failed_calls"])
        for item in response.json()["activities"]
    }
    assert found[("Relevance check", "kimi")] == (2, 1)
    assert found[("Control ranking", "reranker")] == (1, 0)
    gate = next(item for item in response.json()["activities"] if item["task"] == "relevance_gate")
    assert gate["description"].startswith("AI picks which library threats apply") and gate["reused_answers"] == 1
    assert client.get(f"/v1/ai-usage/requests/{uuid.uuid4().hex}").status_code == 404


def test_every_call_of_a_request_newest_first_with_its_activity_and_never_its_text(
    client: TestClient, session: dict
) -> None:
    response = client.get("/v1/ai-usage/calls", params={"request_id": session["create"]["request_id"], "limit": 50})
    calls = response.json()["items"]
    assert len(calls) == 8 and calls[0]["outcome"] == "reused" and calls[-1]["outcome"] == "unavailable"
    assert calls[0]["try_no"] is None  # fix-check 2026-10-29: a reused answer is no attempt (it answered 500)
    assert (calls[-1]["activity"], calls[-1]["reason"], calls[-1]["try_no"]) == ("Relevance check", "ai_busy", 1)
    assert not [call for call in calls if "prompt" in call or "response" in call]
    assert client.get("/v1/ai-usage/calls").status_code == 422


def test_the_hourly_add_up_equals_a_raw_recount_and_running_it_again_changes_nothing(session: dict) -> None:
    """Mutation: drop $ifNull from the add-up key, or count a request in every hour it touches."""
    hourly = get_mongodb()[AiUsageCollection.HOURLY]
    mine = {"entity_id": session["entity"]}
    before = sorted(hourly.find(mine, {"read_at": 0}), key=lambda doc: doc["_id"])
    roll_up_ai_usage(get_mongodb(), DAY, DAY + timedelta(hours=23))
    assert sorted(hourly.find(mine, {"read_at": 0}), key=lambda doc: doc["_id"]) == before
    raw = [row for row in session["rows"] if row["outcome"] != "reused"]
    assert sum(doc["total_ai_calls"] for doc in before) == len(raw)
    assert sum(doc["requests"] for doc in before) == 3
    assert {doc["hour"].hour for doc in before} == {20, 21}


def test_a_row_with_no_entity_or_api_is_added_up_under_empty_keys() -> None:
    """Shared work has no request, API or entity. Mutation: drop $ifNull (null keys)."""
    at = datetime(2025, 4, 1, 9, 15, tzinfo=UTC)
    marker = f"library-indexes-{uuid.uuid4().hex}"
    row = {
        "_id": ObjectId(),
        "created_at": at,
        "bucket": "shared",
        "task": "embed",
        "job_task": marker,
        "model": marker,
        "outcome": "ok",
    }
    crud.insert_rows(get_mongodb(), [row])
    roll_up_ai_usage(get_mongodb(), at, at)
    [doc] = get_mongodb()[AiUsageCollection.HOURLY].find({"model": marker})
    assert (doc["module"], doc["api"], doc["entity_id"], doc["total_ai_calls"], doc["requests"]) == ("", "", "", 1, 0)


def test_an_hour_read_earlier_never_replaces_one_read_later() -> None:
    """Two add-ups may run at once (no lock): the later read wins. Mutation: replace without the read_at
    guard, or guard with $lt (a document stored before read_at existed would never be replaced)."""
    hourly, hour_id = get_mongodb()[AiUsageCollection.HOURLY], f"test-{uuid.uuid4().hex}"
    later, earlier = utc_now(), utc_now() - timedelta(minutes=1)
    hourly.insert_one({"_id": hour_id, "total_ai_calls": 1})  # stored before read_at existed
    crud.replace_if_newer(get_mongodb(), AiUsageCollection.HOURLY, [{"_id": hour_id, "read_at": later, "n": 2}])
    crud.replace_if_newer(get_mongodb(), AiUsageCollection.HOURLY, [{"_id": hour_id, "read_at": earlier, "n": 3}])
    assert hourly.find_one({"_id": hour_id})["n"] == 2


def test_an_add_up_with_no_row_yet_still_records_its_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: return before the success metric when nothing is stored (AiUsageRollupBehind would fire)."""
    seen: list[str] = []
    monkeypatch.setattr(crud, "newest_hour", lambda db: None)
    monkeypatch.setattr(ai_usage.metrics, "record_reaper_time", lambda gauge: seen.append(gauge))
    roll_up_ai_usage(get_mongodb())
    assert seen == [ai_usage.metrics.AI_USAGE_ROLLUP_LAST_SUCCESS]


def test_a_replayed_row_of_an_older_request_rebuilds_its_summary() -> None:
    """A request with rows before the window still gets its summary rebuilt (its last_at moves); only its
    hourly count stays in its first hour. Mutation: rebuild only requests first seen in the window."""
    request_id, at = uuid.uuid4().hex, datetime(2025, 7, 1, 8, tzinfo=UTC)
    row = {"bucket": "scenario", "task": "write_scenario", "outcome": "ok", "request_id": request_id}
    row["model"] = request_id  # a marker
    for hours in (0, 5):
        crud.insert_rows(get_mongodb(), [row | {"_id": ObjectId(), "created_at": at + timedelta(hours=hours)}])
        roll_up_ai_usage(get_mongodb(), at + timedelta(hours=hours), at + timedelta(hours=hours))
    summary = get_mongodb()[AiUsageCollection.REQUESTS].find_one({"_id": request_id})
    assert summary["last_at"].replace(tzinfo=UTC) == at + timedelta(hours=5)
    hourly = get_mongodb()[AiUsageCollection.HOURLY].find({"model": request_id})
    assert sorted((doc["hour"].hour, doc["requests"]) for doc in hourly) == [(8, 1), (13, 0)]


def test_each_add_up_day_has_a_mongodb_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: drop the day's timeout."""
    deadlines: list[float | None] = []
    real = ai_usage._write_hours
    monkeypatch.setattr(ai_usage, "_write_hours", lambda *args: deadlines.append(_csot.remaining()) or real(*args))
    roll_up_ai_usage(get_mongodb(), DAY, DAY)
    assert deadlines and all(left is not None and left <= AiUsageLimits.ROLLUP_CHUNK_SECONDS for left in deadlines)


def test_totals_grouped_by_part_and_task_keep_both_and_name_the_activity(client: TestClient, session: dict) -> None:
    """Review 2026-10-29: a requested `bucket` was dropped from the key, so embed in threats and embed in
    controls merged and no activity was named. Mutation: pop bucket from the key again."""
    items = _totals(client, session, group_by=["bucket", "task"]).json()["items"]
    found = {(item["key"]["bucket"], item["key"]["task"]): item for item in items}
    assert found[("controls", "rerank")]["total_ai_calls"] == 3
    assert found[("controls", "rerank")]["activity"] == "Control ranking"
    assert found[("threats", "relevance_gate")]["activity_description"].startswith("AI picks which library")
    # Swagger says so (PartCounts.by_task): in totals the task is in the key, never in by_task
    assert all(part["by_task"] == {} for item in items for part in item["buckets"].values())


def test_a_totals_report_holds_at_most_max_groups_rows(
    client: TestClient, session: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 2026-10-29: the cap counted one row per part, so a report could hold six times MAX_GROUPS rows.
    Fix-check 2026-10-29: its `total` then added up only the rows kept. 1 of 3 groups kept (the read fetches
    2), so a total of the fetched rows fails too. Mutations: cap the parts instead of the rows; add the total
    up from the items, or from every item read."""
    counted = ("total_ai_calls", "successful_calls", "failed_calls")
    rows = _totals(client, session, client_id="ui-client", group_by=["bucket"]).json()["items"]
    whole = {name: sum(row[name] for row in rows) for name in counted}  # from the rows, not from `total`
    monkeypatch.setattr(AiUsageLimits, "MAX_GROUPS", 1)
    body = _totals(client, session, client_id="ui-client", group_by=["module", "api"]).json()
    assert len(body["items"]) == 1 and body["truncated"] is True
    assert whole["total_ai_calls"] > 0
    assert {name: body["total"][name] for name in counted} == whole  # every matching hour, whatever the cut


def test_a_report_with_nothing_cut_adds_its_total_from_its_rows_in_one_read(
    session: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 2026-10-29: the total was always a second read, so an add-up landing between the two gave a
    total its rows did not add up to. Mutation: read the total although nothing was cut."""
    monkeypatch.setattr(crud, "sum_total", lambda *_: pytest.fail("a second read with nothing cut"))
    query = UsageTotalsQuery(
        entity_id=str(session["entity"]), tz="UTC", group_by=["bucket"], since=DAY, until=DAY + timedelta(days=1)
    )
    body = ai_usage.summarize_ai_usage(get_mongodb(), query)
    assert body["truncated"] is False
    assert body["total"]["total_ai_calls"] == sum(item["total_ai_calls"] for item in body["items"]) > 0
