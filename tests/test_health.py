import asyncio
import gc
import inspect
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from redis.exceptions import ResponseError

from app import worker
from app.core.constants import Dependency, ErrorCode, Header, LogEvent, Timeouts
from app.core.exceptions import Conflict, Invalid, NotFound
from app.services import readiness
from app.worker import heartbeat, lifecycle


@pytest.fixture(autouse=True)
def fresh_checks() -> Iterator[None]:
    """Each test starts with no remembered check run (a run is reused READY_CHECK_REUSE_SECONDS)."""
    readiness._runs.clear()
    yield
    readiness._runs.clear()


@pytest.fixture
def every_queue_has_a_worker() -> Iterator[None]:
    """A heartbeat on every routed queue, as a running worker pod would write it; removed afterwards."""
    beating = heartbeat.WorkerHeartbeat(worker.ROUTED_QUEUES, f"celery@test-{uuid.uuid4().hex}")
    beating.beat()
    yield
    beating.stop()


def test_health_is_ok(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_ready_checks_every_store_and_every_queue_has_a_worker(
    client: TestClient, every_queue_has_a_worker: None
) -> None:
    response = client.get("/ready")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dependencies"] == {d.value: True for d in Dependency}
    assert set(body["workers"]) == set(worker.ROUTED_QUEUES)
    assert all(count >= 1 for count in body["workers"].values())


def test_ready_is_503_when_a_queue_has_no_worker(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    online = dict.fromkeys(worker.ROUTED_QUEUES, 1) | {worker.ROUTED_QUEUES[0]: 0}
    monkeypatch.setattr(readiness, "count_online_workers", lambda _queues: online)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["workers"] == online


def _is_down() -> None:
    raise ConnectionError("refused")


def test_ready_is_503_naming_the_store_that_is_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, _is_down)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["dependencies"] == {"mongo": False, "sql": True, "redis": True}


def test_ready_reports_sql_server_down_without_failing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    """Before: an SQL Server outage made /ready 503, so OpenShift took every route out, MongoDB-only too."""
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.SQL, _is_down)
    response = client.get("/ready")
    assert response.status_code == 200 and response.json()["status"] == "ready"
    assert response.json()["dependencies"] == {"mongo": True, "sql": False, "redis": True}


def test_unknown_route_answers_in_problem_format(client: TestClient) -> None:
    response = client.get("/no-such-route")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == ErrorCode.NOT_FOUND
    assert response.headers[Header.REQUEST_ID]
    # RFC 9457: the title is the fixed phrase of the kind of problem, the detail says what happened.
    assert response.json()["title"] == "Not Found"


def test_a_missing_key_says_how_to_authenticate(client: TestClient) -> None:
    """RFC 9110 §15.5.2: every 401 carries a WWW-Authenticate challenge."""
    response = client.get("/v1/sessions/any-run/events")
    assert response.status_code == 401 and response.headers["WWW-Authenticate"].startswith("ApiKey ")


def test_the_public_probes_hold_no_request_thread_while_they_wait() -> None:
    """Before: /ready and /metrics were sync handlers, each holding one of the threads every route shares for
    up to 5 s during a slow outage; anyone could call them until authentication itself stalled."""
    from app.api.routers import health

    assert inspect.iscoroutinefunction(health.report_readiness)
    assert inspect.iscoroutinefunction(health.export_prometheus_metrics)


def _health_requests(metrics_text: str) -> float:
    for family in text_string_to_metric_families(metrics_text):
        for sample in family.samples:
            if sample.name == "tsg_http_requests_total" and sample.labels.get("route") == "/health":
                return sample.value
    return 0.0


def test_metrics_are_exposed(client: TestClient) -> None:
    """The request just made is counted, under its route, on the page Prometheus scrapes (a metric name
    alone would pass with a counter that never moves)."""
    before = _health_requests(client.get("/metrics").text)
    client.get("/health")
    assert _health_requests(client.get("/metrics").text) == before + 1


def test_a_hanging_check_answers_in_time_and_is_never_started_twice(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    """A store that never answers (a network black hole) makes /ready answer 503 within its bound, and the
    stuck check is reused by the next probe instead of piling up a new one."""
    release = threading.Event()
    started: list[int] = []

    def mongo_hangs() -> None:
        started.append(1)
        release.wait(10)

    monkeypatch.setattr(Timeouts, "READY_CHECK_SECONDS", 0.2)
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, mongo_hangs)
    try:
        for _ in range(2):
            began = time.monotonic()
            response = client.get("/ready")
            assert response.status_code == 503 and response.json()["dependencies"]["mongo"] is False
            assert time.monotonic() - began < 2
        assert started == [1]
    finally:
        release.set()


def test_a_scrape_reports_the_stores_as_they_are_now(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: tsg_dependency_up changed only when /ready ran, so on a laptop (no probe) it stayed stale."""
    monkeypatch.setattr(Timeouts, "READY_CHECK_REUSE_SECONDS", 0)
    client.get("/metrics")
    assert 'tsg_dependency_up{name="sql"} 1.0' in client.get("/metrics").text

    def sql_is_down() -> None:
        raise ConnectionError("refused")

    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.SQL, sql_is_down)
    assert 'tsg_dependency_up{name="sql"} 0.0' in client.get("/metrics").text


def test_a_burst_of_public_calls_runs_each_check_once_and_logs_an_outage_once(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/ready and /metrics are public: before, every call pinged every store and logged every failure, so a
    caller could multiply database load and log volume at will."""
    monkeypatch.setattr(
        Timeouts, "READY_CHECK_REUSE_SECONDS", 3600
    )  # one run for the whole burst, however slow
    calls: list[int] = []
    warnings: list[str] = []

    def sql_is_down() -> None:
        calls.append(1)
        raise ConnectionError("refused")

    class CountingLog:
        def warning(self, event: str, **_: object) -> None:
            warnings.append(event)

    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.SQL, sql_is_down)
    monkeypatch.setattr(readiness, "log", CountingLog())
    for path in ["/ready", "/metrics"] * 10:
        client.get(path)
    assert calls == [1]
    assert warnings.count(LogEvent.DEPENDENCY_UNAVAILABLE) == 1


def test_an_unknown_worker_count_is_not_shown_as_the_last_known_one(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    """Before: when Redis could not count workers, tsg_workers_online kept its old value and showed workers
    that nobody could see any more."""
    assert "tsg_workers_online{" in client.get("/metrics").text
    readiness._runs.clear()

    def redis_is_down(_queues: object) -> None:
        raise ConnectionError("refused")

    monkeypatch.setattr(readiness, "count_online_workers", redis_is_down)
    assert "tsg_workers_online{" not in client.get("/metrics").text


def test_while_a_store_hangs_only_the_first_call_waits(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    """Before: every call during a hang waited the full bound again, so ~40 public calls held every request
    thread and the liveness probe (/health) queued behind them until OpenShift restarted the pod."""
    release = threading.Event()
    monkeypatch.setattr(Timeouts, "READY_CHECK_SECONDS", 1)
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, lambda: release.wait(10))
    try:
        client.get("/ready")  # the first caller waits the bound
        began = time.monotonic()
        assert client.get("/ready").status_code == 503
        assert client.get("/metrics").status_code == 200
        assert time.monotonic() - began < 0.5
    finally:
        release.set()


def test_a_refreshed_check_does_not_wait_again_for_a_store_still_hanging(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, every_queue_has_a_worker: None
) -> None:
    """Before: once the other checks were refreshed (after READY_CHECK_REUSE_SECONDS), wait() was handed the
    hung check too and waited for all of them, so every later probe or scrape held a thread for the bound."""
    release = threading.Event()
    monkeypatch.setattr(Timeouts, "READY_CHECK_SECONDS", 1)
    monkeypatch.setattr(Timeouts, "READY_CHECK_REUSE_SECONDS", 0)  # every call refreshes the other checks
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, lambda: release.wait(10))
    try:
        client.get("/ready")  # the first caller waits the bound
        began = time.monotonic()
        assert client.get("/ready").status_code == 503
        assert time.monotonic() - began < 0.5
    finally:
        release.set()


def test_an_unreadable_worker_count_is_logged_once(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: Redis answered PING but counting failed (a key of the wrong type): /ready said 503 and nothing
    said why."""
    monkeypatch.setattr(Timeouts, "READY_CHECK_REUSE_SECONDS", 3600)
    warnings: list[str] = []

    class CountingLog:
        def warning(self, event: str, **_: object) -> None:
            warnings.append(event)

    def wrong_type(_queues: object) -> None:
        raise ResponseError("WRONGTYPE Operation against a key holding the wrong kind of value")

    monkeypatch.setattr(readiness, "count_online_workers", wrong_type)
    monkeypatch.setattr(readiness, "log", CountingLog())
    for _ in range(5):
        assert client.get("/ready").status_code == 503
    assert warnings.count(LogEvent.WORKERS_UNKNOWN) == 1


def test_a_check_that_fails_while_waited_for_logs_no_unread_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: during a real outage (a check failing after seconds, not at once) asyncio logged "Future
    exception was never retrieved" in plain text, not JSON, on every probe and scrape until it ended."""
    monkeypatch.setattr(Timeouts, "READY_CHECK_SECONDS", 0.2)

    def sql_fails_late() -> None:
        time.sleep(0.4)
        raise ConnectionError("refused")

    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.SQL, sql_fails_late)
    unread: list[dict] = []

    async def probe() -> None:
        asyncio.get_running_loop().set_exception_handler(lambda _loop, context: unread.append(context))
        await readiness.check_readiness_without_a_thread()
        await asyncio.sleep(0.5)  # the check fails after the wait gave up on it
        readiness._runs.clear()
        gc.collect()

    asyncio.run(probe())
    assert unread == []


def test_a_status_has_one_title_whoever_raises_it(client: TestClient) -> None:
    """RFC 9457 §4.2.1: with type "about:blank" the title is the status phrase. Before: a framework 404 said
    "Not Found" and the app's own NotFound "Not found"; each title was spelled twice."""

    def not_found() -> None:
        raise NotFound("No such run.")

    client.app.add_api_route("/test-only/not-found", not_found)  # type: ignore[attr-defined]
    ours, framework = client.get("/test-only/not-found").json(), client.get("/no-such-route").json()
    assert ours["title"] == framework["title"] == "Not Found"
    assert ours["code"] == framework["code"] == ErrorCode.NOT_FOUND


def test_a_refusal_carries_its_reason_fields_and_details(client: TestClient) -> None:
    """RFC 9457 problem body: `reason` says which rule refused, `errors` which fields, `details` what the
    caller can act on (e.g. the id of the run already active on the asset)."""

    def busy() -> None:
        raise Conflict(
            "Asset 103 already has an active run.",
            reason="active_session_exists",
            details={"active_session_id": "abc"},
        )

    def invalid() -> None:
        raise Invalid(
            "One or more fields are invalid.",
            errors=[{"field": "body.sector_id", "message": "Not the sub-sector's parent."}],
        )

    client.app.add_api_route("/test-only/busy", busy)  # type: ignore[attr-defined]
    client.app.add_api_route("/test-only/invalid", invalid)  # type: ignore[attr-defined]
    conflict, refused = client.get("/test-only/busy").json(), client.get("/test-only/invalid").json()
    assert conflict["reason"] == "active_session_exists" and conflict["details"] == {
        "active_session_id": "abc"
    }
    assert refused["errors"] == [{"field": "body.sector_id", "message": "Not the sub-sector's parent."}]
    assert "details" not in refused and "errors" not in conflict  # only what applies


def test_ready_shows_the_mongodb_topology_and_never_waits_for_it(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The replica set (or standalone), version and default write concern; a topology read that hangs leaves
    the body's "mongodb" null and /ready answers within its bound."""
    topology = None
    for _ in range(50):  # the read runs beside the checks: a first call may answer before it
        topology = client.get("/ready").json()["mongodb"]
        if topology:
            break
        time.sleep(0.1)
    assert topology and topology["replica_set"] and topology["version"]
    assert set(topology) == {"replica_set", "version", "default_write_concern"}

    readiness._runs.clear()
    release = threading.Event()
    monkeypatch.setattr(readiness, "describe_mongodb_topology", lambda: release.wait(10))
    try:
        began = time.monotonic()
        assert client.get("/ready").json()["mongodb"] is None
        assert time.monotonic() - began < Timeouts.READY_CHECK_SECONDS + 1
    finally:
        release.set()


def test_the_start_up_topology_line_never_fails_start_up(monkeypatch: pytest.MonkeyPatch) -> None:
    def mongodb_is_down() -> None:
        raise ConnectionError("refused")

    logged: list[dict[str, object]] = []

    class RecordingLog:
        def info(self, event: str, **fields: object) -> None:
            logged.append({"event": event, **fields})

        warning = info

    monkeypatch.setattr(lifecycle, "log", RecordingLog())
    lifecycle.log_mongodb_topology()
    monkeypatch.setattr(lifecycle, "describe_mongodb_topology", mongodb_is_down)
    lifecycle.log_mongodb_topology()
    assert [line["event"] for line in logged] == [LogEvent.MONGODB_TOPOLOGY] * 2
    assert logged[0]["replica_set"] and logged[0]["version"] and logged[1]["replica_set"] is None
