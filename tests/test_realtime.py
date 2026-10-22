"""Live updates end to end: a real server streams Server-Sent Events; a worker's publish reaches the client
through Redis."""

import asyncio
import contextlib
import json
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from functools import partial
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import structlog
import uvicorn
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError

from app import container
from app.api.routers import scenario as events
from app.core.constants import Collection, Event, Header, Realtime, SessionState, StageState, Status, Step
from app.core.database import get_mongodb, get_redis_client
from app.main import create_app
from app.realtime import event_hub
from app.realtime.event_hub import RESYNC, EventHub, _offer
from app.realtime.publisher import (
    publish_mapping_status,
    publish_remediation_status,
    publish_session_status,
    session_channel,
)
from tests.plan_addresses import plan_url


@pytest.fixture(scope="module")
def server_url() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "server did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


@pytest.fixture(scope="module")
def identity() -> dict[str, str]:
    _, api_key = container.get_admin_service().create_api_client(f"sse-{uuid.uuid4().hex[:8]}", None, None)
    return {Header.API_KEY: api_key, Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}


def _insert_session(entity_id: int) -> str:
    session_id = uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {
            "_id": session_id,
            "entity_id": entity_id,
            "asset_id": 103,
            "status": Status.RUNNING,
            "step": Step.THREATS,
            "updated_at": datetime.now(UTC),
        }
    )
    return session_id


def _events(response: httpx.Response, within_seconds: float = 20) -> Iterator[tuple[str, dict[str, Any]]]:
    """(event name, data) for each server-sent event; keep-alive comments are skipped. Fails once the stream
    has run within_seconds: its keep-alive lines would otherwise keep a test waiting for ever on an event
    that never comes (the read timeout restarts at every line)."""
    deadline = time.monotonic() + within_seconds
    name = ""
    for line in response.iter_lines():
        assert time.monotonic() < deadline, f"the awaited event did not come within {within_seconds} s"
        if line.startswith("event:"):
            name = line.removeprefix("event:").strip()
        elif line.startswith("data:"):
            yield name, json.loads(line.removeprefix("data:"))


def _next_after_publishing(
    events: Iterator[tuple[str, dict[str, Any]]], publish: Callable[[], None]
) -> tuple[str, dict[str, Any]]:
    """The next event, while `publish` repeats like a worker's (the pod's subscription may still be starting).
    The hub's first subscription tells every stream to re-read once, so a test proves a publish reaches its
    channel only from its second change on."""
    stop = threading.Event()

    def repeat() -> None:
        while not stop.wait(0.3):
            publish()

    threading.Thread(target=repeat, daemon=True).start()
    try:
        return next(events)
    finally:
        stop.set()


def test_a_stream_gets_the_status_at_once_and_every_change_a_worker_publishes(
    server_url: str, identity: dict[str, str]
) -> None:
    session_id = _insert_session(86)
    url = f"{server_url}/v1/sessions/{session_id}/events"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        events = _events(response)
        name, status = next(events)
        assert name == Event.SESSION_UPDATED and status["session_status"] == SessionState.ACTIVE

        # The same body as GET /v1/sessions/{id}: each change shows as the stage it completes.
        for changes, stage in (({"step": Step.SCENARIOS}, "threats"), ({"status": Status.DONE}, "scenarios")):
            get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": changes})
            name, status = _next_after_publishing(events, partial(publish_session_status, session_id))
            assert name == Event.SESSION_UPDATED and status["session_id"] == session_id
            assert status["progress"][stage] == StageState.COMPLETE
        assert status["session_status"] == SessionState.COMPLETED


def test_a_status_published_late_never_replaces_the_newer_saved_one(
    server_url: str, identity: dict[str, str]
) -> None:
    """Before: the message carried the status a worker had read. Two workers changing one run moments apart
    could publish in the opposite order, and the client kept the older status until the next change. Now a
    message only says "changed" and the stream reads MongoDB."""
    session_id = _insert_session(86)
    url = f"{server_url}/v1/sessions/{session_id}/events"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        events = _events(response)
        assert next(events)[1]["session_status"] == SessionState.ACTIVE
        get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": {"status": Status.DONE}})
        stale = json.dumps({"session_id": session_id, "status": Status.QUEUED})  # an older status, late
        stop = threading.Event()

        def publish_stale() -> None:  # repeated: the pod's subscription may still be starting
            while not stop.wait(0.3):
                get_redis_client().publish(session_channel(session_id), stale)

        threading.Thread(target=publish_stale, daemon=True).start()
        try:
            name, status = next(events)
        finally:
            stop.set()
        assert name == Event.SESSION_UPDATED and status["session_status"] == SessionState.COMPLETED


def _insert_plan(entity_id: int) -> str:
    """A remediation plan whose version 1 is being written."""
    plan_id = uuid.uuid4().hex
    get_mongodb()[Collection.REMEDIATIONS].insert_one(
        {"_id": plan_id, "entity_id": entity_id, "scenario_id": uuid.uuid4().hex, "session_id": "run",
         "status": Status.QUEUED, "decision": "pending", "job": {"epoch": 1, "error": None},
         "updated_at": datetime.now(UTC)}
    )  # fmt: skip
    return plan_id


def test_a_plan_stream_gets_its_status_at_once_and_each_published_change(
    server_url: str, identity: dict[str, str]
) -> None:
    """#28: the same hub and rules as #8, on the plan's own channel; two changes (_next_after_publishing)."""
    plan_id = _insert_plan(86)
    url = f"{server_url}{plan_url(plan_id, 'events')}"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        assert response.status_code == 200
        events = _events(response)
        name, status = next(events)
        assert (name, status["latest_status"], status["progress"]["overall"]) == (
            Event.REMEDIATION_UPDATED,
            Status.QUEUED,
            "generating",
        )
        for changed in (Status.RUNNING, Status.DONE):
            get_mongodb()[Collection.REMEDIATIONS].update_one({"_id": plan_id}, {"$set": {"status": changed}})
            name, status = _next_after_publishing(events, partial(publish_remediation_status, plan_id))
            assert (name, status["latest_status"]) == (Event.REMEDIATION_UPDATED, changed)
    unknown = f"/v1/sessions/run/scenarios/{uuid.uuid4().hex}/treatment-plan/events"
    for refused, expected in ((plan_url(_insert_plan(99), "events"), 403), (unknown, 404)):
        answer = httpx.get(f"{server_url}{refused}", headers=identity, timeout=10)
        assert answer.status_code == expected


def _insert_mapping(entity_id: int) -> str:
    mapping_id, now = uuid.uuid4().hex, datetime.now(UTC)
    get_mongodb()[Collection.SERVICE_MAPPINGS].insert_one(
        {"_id": mapping_id, "tenant_id": "DESC", "entity_id": entity_id, "created_by": "u1",
         "status": Status.QUEUED, "generation": 1, "job": {"epoch": 1, "error": None}, "result": None,
         "created_at": now, "updated_at": now}
    )  # fmt: skip
    return mapping_id


def test_a_mapping_stream_gets_its_status_at_once_and_each_published_change(
    server_url: str, identity: dict[str, str]
) -> None:
    """The body of GET /v1/service-mapper/{id}/status, on the mapping's own channel, as for runs and plans."""
    mapping_id = _insert_mapping(86)
    url = f"{server_url}/v1/service-mapper/{mapping_id}/events"
    one_pending = {"dependencies": [{"relations": {"upstream": {"isAccepted": None}}}]}
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        assert response.status_code == 200
        events = _events(response)
        name, status = next(events)
        assert (name, status["mapping_id"], status["progress"]["overall"]) == (
            Event.MAPPING_UPDATED,
            mapping_id,
            "generating",
        )
        for changes, overall, total in (
            ({"status": Status.RUNNING}, "generating", 0),
            ({"status": Status.DONE, "result": one_pending}, "done", 1),
        ):
            get_mongodb()[Collection.SERVICE_MAPPINGS].update_one({"_id": mapping_id}, {"$set": changes})
            name, status = _next_after_publishing(events, partial(publish_mapping_status, mapping_id))
            assert (name, status["status"], status["progress"]["overall"]) == (
                Event.MAPPING_UPDATED,
                changes["status"],
                overall,
            )
            counts = status["progress"]["relationships"]
            assert counts["total"] == counts["pending"] == total
        assert "review" not in status
    unknown = f"/v1/service-mapper/{uuid.uuid4().hex}/events"
    for refused, expected in ((f"/v1/service-mapper/{_insert_mapping(99)}/events", 403), (unknown, 404)):
        answer = httpx.get(f"{server_url}{refused}", headers=identity, timeout=10)
        assert answer.status_code == expected


@pytest.mark.parametrize(("entity_id", "expected"), [(99, 403), (None, 404)])
def test_another_entitys_run_or_an_unknown_run_is_refused_before_streaming(
    server_url: str, identity: dict[str, str], entity_id: int | None, expected: int
) -> None:
    session_id = _insert_session(entity_id) if entity_id else uuid.uuid4().hex
    response = httpx.get(f"{server_url}/v1/sessions/{session_id}/events", headers=identity, timeout=10)
    assert response.status_code == expected
    assert response.headers["content-type"] == "application/problem+json"


def test_a_stream_without_a_valid_key_is_refused(server_url: str, identity: dict[str, str]) -> None:
    wrong = identity | {Header.API_KEY: "tsg_wrong"}
    response = httpx.get(f"{server_url}/v1/sessions/{_insert_session(86)}/events", headers=wrong, timeout=10)
    assert response.status_code == 401


def test_an_open_stream_ends_once_its_api_key_is_revoked(
    server_url: str, identity: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A revoked key ends its open stream at the next recheck, with no message published."""
    monkeypatch.setattr(Realtime, "RECHECK_SECONDS", 0.2)
    clients = container.get_admin_service()
    client, api_key = clients.create_api_client(f"sse-revoked-{uuid.uuid4().hex[:8]}", None, "test")
    url = f"{server_url}/v1/sessions/{_insert_session(86)}/events"
    headers = identity | {Header.API_KEY: api_key}
    with httpx.Client(timeout=15) as http, http.stream("GET", url, headers=headers) as response:
        events = _events(response, within_seconds=10)
        assert next(events)[0] == Event.SESSION_UPDATED
        clients.revoke_api_client(client["client_id"], "test")
        assert next(events, None) is None  # the stream ended with no message published


def test_a_slow_client_keeps_the_newest_updates() -> None:
    async def scenario() -> list[object]:
        updates: asyncio.Queue[object] = asyncio.Queue(maxsize=2)
        for update in (1, 2, 3):
            _offer(updates, update)
        return [updates.get_nowait(), updates.get_nowait()]

    assert asyncio.run(scenario()) == [2, 3]


def test_a_silent_redis_connection_is_noticed_and_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: a black-holed Redis kept the hub's socket open for minutes (redis-py's health check never waits
    for the PONG), and every stream silently stopped updating."""
    monkeypatch.setattr(Realtime, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(Realtime, "SILENT_LIMIT_SECONDS", 0.05)
    pings: list[int] = []

    class SilentRedis:
        async def get_message(self, timeout: float) -> None:
            await asyncio.sleep(timeout)

        async def ping(self) -> None:
            pings.append(1)

    with pytest.raises(RedisConnectionError):  # a TimeoutError instead = the silence check is broken
        asyncio.run(asyncio.wait_for(EventHub()._relay(SilentRedis()), 2))  # type: ignore[arg-type]
    assert pings


def test_a_quiet_connection_that_answers_ping_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    # A PONG comes back within ~2 polls (20 ms, or ~32 ms with Windows' 15.6 ms timer): the silence limit is
    # well above that, so a busy laptop cannot fail this test (before: 50 ms, a 19 ms margin).
    monkeypatch.setattr(Realtime, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(Realtime, "SILENT_LIMIT_SECONDS", 0.2)

    class QuietRedis:
        pong_due = False

        async def get_message(self, timeout: float) -> dict | None:
            await asyncio.sleep(timeout)
            if self.pong_due:
                self.pong_due = False
                return {"type": "pong", "channel": None, "data": ""}
            return None

        async def ping(self) -> None:
            self.pong_due = True

    with pytest.raises(TimeoutError):  # still relaying after 5 silent limits
        asyncio.run(asyncio.wait_for(EventHub()._relay(QuietRedis()), 1.0))  # type: ignore[arg-type]


def _fake_redis(monkeypatch: pytest.MonkeyPatch, replies: list[object]) -> None:
    """The hub's Redis, answering get_message with the replies in turn (an exception is raised)."""

    class FakeSubscription:
        async def __aenter__(self) -> "FakeSubscription":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def psubscribe(self, _pattern: str) -> None:
            return None

        async def get_message(self, timeout: float) -> object:
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

    class FakeRedis(FakeSubscription):
        def pubsub(self) -> FakeSubscription:
            return FakeSubscription()

    monkeypatch.setattr(event_hub.AsyncRedis, "from_url", lambda *_args, **_kwargs: FakeRedis())


def _read_once(channel: str) -> list[object]:
    """One subscription of the hub, with one stream open on channel: what that stream was handed."""
    hub, updates = EventHub(), asyncio.Queue()  # type: ignore[var-annotated]
    hub._streams[channel] = {updates}
    with pytest.raises((RedisConnectionError, ResponseError)):
        asyncio.run(hub._read_until_disconnected())
    return [updates.get_nowait() for _ in range(updates.qsize())]


@pytest.mark.parametrize("reply", [ResponseError("NOPERM no access to the channels"), None])
def test_a_refused_or_unconfirmed_subscription_sends_no_resync(
    monkeypatch: pytest.MonkeyPatch, reply: object
) -> None:
    """Before: every stream was told to re-read its status as soon as PSUBSCRIBE was sent, so a refused
    subscription made each open stream query MongoDB on every reconnect (2 s) for ever."""
    _fake_redis(monkeypatch, [reply])
    assert _read_once("tsg:session:a") == []


def test_only_published_messages_reach_a_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """After the confirmed subscription: RESYNC first, then each published message; a PONG or a subscription
    notice is never handed to a stream as if it were a status."""
    channel = "tsg:session:a"
    _fake_redis(
        monkeypatch,
        [
            {"type": "psubscribe", "channel": Realtime.CHANNEL_PATTERN, "data": 1},
            {"type": "pong", "channel": channel, "data": channel},
            {"type": "pmessage", "channel": channel, "data": "status"},
            {"type": "punsubscribe", "channel": channel, "data": 0},
            RedisConnectionError("gone"),
        ],
    )
    assert _read_once(channel) == [RESYNC, "status"]


def test_the_hub_keeps_reading_after_an_unexpected_redis_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: any error outside the connection errors (a NOPERM on PSUBSCRIBE) ended the reader for good, and
    open streams waited for ever with nothing logged."""
    monkeypatch.setattr(Realtime, "RECONNECT_SECONDS", 0)
    hub = EventHub()
    attempts: list[int] = []

    async def read_until_disconnected() -> None:
        attempts.append(1)
        if len(attempts) == 1:
            raise ResponseError("NOPERM this user has no permissions to access one of the channels")
        await asyncio.sleep(10)

    monkeypatch.setattr(hub, "_read_until_disconnected", read_until_disconnected)

    async def scenario() -> None:
        reader = asyncio.create_task(hub._read_forever())
        await asyncio.sleep(0.1)
        reader.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reader

    asyncio.run(scenario())
    assert len(attempts) == 2


def test_the_shared_reader_carries_no_caller_s_log_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: the reader task started inside the first stream's request kept that request's request_id and
    entity_id, so every later hub log line (reconnecting, failed) named that one caller."""
    hub = EventHub()
    seen: list[dict[str, Any]] = []

    async def read_until_disconnected() -> None:
        seen.append(structlog.contextvars.get_contextvars())
        await asyncio.sleep(10)

    monkeypatch.setattr(hub, "_read_until_disconnected", read_until_disconnected)

    async def first_stream() -> None:
        structlog.contextvars.bind_contextvars(request_id="first-caller", entity_id="86")
        async with hub.listen("tsg:session:a"):
            await asyncio.sleep(0.05)
        await hub.close()

    asyncio.run(first_stream())
    assert seen == [{}]


def test_a_lost_last_update_still_reaches_the_client(
    server_url: str, identity: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a stream read only when a message came. When a run's last change was never announced (a
    failed publish or a failed read), the client showed "running" for a finished run for ever."""
    monkeypatch.setattr(Realtime, "RECHECK_SECONDS", 0.2)
    session_id = _insert_session(86)
    url = f"{server_url}/v1/sessions/{session_id}/events"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        events = _events(response, within_seconds=10)
        assert next(events)[1]["session_status"] == SessionState.ACTIVE
        _publish_a_change_and_receive_it(session_id, events)  # the hub is live: no start-up re-read is due
        get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": {"status": Status.DONE}})
        assert next(events)[1]["session_status"] == SessionState.COMPLETED  # nothing was published


def test_a_run_still_matching_controls_is_read_again_without_a_message(
    server_url: str, identity: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer 2026-10-12: a run whose writing is done but whose controls are still matched is read again
    every RECHECK_SECONDS, so the last mapping reaches the client even when its publish was lost."""
    monkeypatch.setattr(Realtime, "RECHECK_SECONDS", 0.2)
    session_id = _insert_session(86)
    sessions = get_mongodb()[Collection.SESSIONS]
    url = f"{server_url}/v1/sessions/{session_id}/events"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        events = _events(response, within_seconds=10)
        assert next(events)[1]["session_status"] == SessionState.ACTIVE
        _publish_a_change_and_receive_it(session_id, events)  # the hub is live: no start-up re-read is due
        mapping = {"status": Status.DONE, "counts": {"written": 1, "controls_waiting": 1}}
        sessions.update_one({"_id": session_id}, {"$set": mapping})
        _, status = _next_after_publishing(events, partial(publish_session_status, session_id))
        assert (status["session_status"], status["progress"]["controls"]) == ("completed", StageState.RUNNING)
        sessions.update_one({"_id": session_id}, {"$set": {"counts.controls_waiting": 0}})
        assert next(events)[1]["progress"]["controls"] == StageState.COMPLETE  # nothing was published


def _publish_a_change_and_receive_it(session_id: str, events: Iterator[tuple[str, dict[str, Any]]]) -> None:
    get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": {"step": Step.SCENARIOS}})
    stop = threading.Event()

    def publish() -> None:  # repeated: the pod's subscription may still be starting
        while not stop.wait(0.3):
            publish_session_status(session_id)

    publisher = threading.Thread(target=publish, daemon=True)
    publisher.start()
    try:
        assert next(events)[1]["progress"]["threats"] == StageState.COMPLETE
    finally:
        stop.set()
        publisher.join()
    time.sleep(0.5)  # a message still on its way finds nothing new and sends nothing


def test_a_watcher_of_a_deleted_run_is_told_once_and_the_stream_ends(
    server_url: str, identity: dict[str, str]
) -> None:
    """G214 review: a deleted run read as "not there yet": no event came, and the stream stayed open."""
    session_id = _insert_session(86)
    url = f"{server_url}/v1/sessions/{session_id}/events"
    with httpx.Client(timeout=15) as client, client.stream("GET", url, headers=identity) as response:
        events = _events(response)
        assert next(events)[0] == Event.SESSION_UPDATED
        get_mongodb()[Collection.SESSIONS].delete_one({"_id": session_id})
        gone = _next_after_publishing(events, partial(publish_session_status, session_id))
        assert gone == (Event.SESSION_DELETED, {"session_id": session_id})
        assert next(events, None) is None  # the stream ended


def test_a_burst_of_changes_costs_one_status_read_made_after_the_burst() -> None:
    """Five changes announced within Realtime.COALESCE_SECONDS: one read after the first status, and it shows
    the last change saved, never an earlier one."""
    saved = {"change": 0}
    reads: list[int] = []

    def read_status() -> dict[str, Any]:
        reads.append(saved["change"])
        return {"session_status": SessionState.ACTIVE, "change": saved["change"]}

    class CountingHub:
        def __init__(self) -> None:
            self.updates: asyncio.Queue[object] = asyncio.Queue()

        @contextlib.asynccontextmanager
        async def listen(self, _channel: str) -> Any:
            yield self.updates

    async def scenario() -> tuple[object, object]:
        hub = CountingHub()
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(event_hub=hub)))
        stream = events._status_stream(
            request, "channel", read_status, (Event.SESSION_UPDATED, None), lambda: True
        )
        first = await anext(stream)

        async def save_a_burst() -> None:
            for change in range(1, 6):
                saved["change"] = change
                hub.updates.put_nowait("record-id")
                await asyncio.sleep(0.02)

        burst = asyncio.create_task(save_a_burst())
        second = await anext(stream)
        await burst
        await stream.aclose()
        return first, second

    first, second = asyncio.run(scenario())
    assert first.data["change"] == 0 and second.data["change"] == 5  # type: ignore[attr-defined]
    assert reads == [0, 5]
