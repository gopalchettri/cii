"""Redis failover and OOM are outages, /ready gates on MongoDB only, a MongoDB blip keeps live streams
open, and the Redis client has no hidden retries."""

import asyncio
import contextlib
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pymongo.errors import AutoReconnect
from redis.exceptions import OutOfMemoryError, ReadOnlyError

from app import worker
from app.api.status_stream import status_stream
from app.core import readiness
from app.core.constants import Dependency, ErrorMessage, Event
from app.core.database import get_redis_client
from app.core.exceptions import TEMPORARY_ERRORS
from app.worker.jobs import describe_outage

REDIS_REFUSALS = [ReadOnlyError("READONLY replica"), OutOfMemoryError("OOM command not allowed")]


@pytest.fixture(autouse=True)
def fresh_checks() -> Iterator[None]:
    """Each test starts with no remembered readiness run."""
    readiness._runs.clear()
    yield
    readiness._runs.clear()


@pytest.mark.parametrize("refusal", REDIS_REFUSALS)
def test_a_redis_failover_or_oom_answers_503(client: TestClient, refusal: Exception) -> None:
    """Before: READONLY and OOM fell through to the 500 handler."""
    path = f"/test-only/redis-refusal/{type(refusal).__name__}"

    def raise_refusal() -> None:
        raise refusal

    client.app.add_api_route(path, raise_refusal)  # type: ignore[attr-defined]
    response = client.get(path)
    assert response.status_code == 503
    assert response.json()["detail"] == ErrorMessage.REDIS_UNREACHABLE


@pytest.mark.parametrize("refusal", REDIS_REFUSALS)
def test_a_worker_retries_a_redis_failover_or_oom(refusal: Exception) -> None:
    """Before: a job failed for good on READONLY or OOM instead of being given back."""
    assert isinstance(refusal, TEMPORARY_ERRORS)
    assert describe_outage(refusal) == ErrorMessage.REDIS_UNREACHABLE


def _is_down() -> None:
    raise ConnectionError("refused")


def test_ready_stays_200_without_redis_or_a_worker_and_reports_both(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: one queue without a live worker, or Redis down, took every API route out of service."""
    online = dict.fromkeys(worker.ROUTED_QUEUES, 1) | {worker.ROUTED_QUEUES[0]: 0}
    monkeypatch.setattr(readiness, "count_online_workers", lambda _queues: online)
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.REDIS, _is_down)
    response = client.get("/ready")
    assert response.status_code == 200 and response.json()["status"] == "ready"
    assert response.json()["dependencies"]["redis"] is False
    assert response.json()["workers"] == online


def test_ready_is_503_when_mongodb_is_down(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, _is_down)
    response = client.get("/ready")
    assert response.status_code == 503 and response.json()["dependencies"]["mongo"] is False


def test_a_mongodb_blip_during_the_key_recheck_keeps_the_stream_open() -> None:
    """Before: the re-check's ConnectionFailure escaped the generator and ended every open stream."""

    def key_check_hits_an_outage() -> bool:
        raise AutoReconnect("primary stepped down")

    class QuietHub:
        @contextlib.asynccontextmanager
        async def listen(self, _channel: str) -> Any:
            yield asyncio.Queue()

    async def first_event() -> Any:
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(event_hub=QuietHub())))
        stream = status_stream(
            request,  # type: ignore[arg-type]
            "channel",
            lambda: {"status": "running"},
            Event.SESSION_UPDATED,
            key_check_hits_an_outage,
        )
        try:
            return await anext(stream)
        finally:
            await stream.aclose()

    assert asyncio.run(first_event()).data == {"status": "running"}


def test_the_redis_client_has_no_hidden_retries() -> None:
    """Before: no retry was set, so redis-py's default policy applied (3 retries with back-off in 6+)."""
    assert get_redis_client().get_retry().get_retries() == 0  # type: ignore[union-attr]
