"""Every request is counted, logged and tagged with a request id — a crash too; bodies are size-capped."""

import uuid
from collections.abc import Callable

import pytest
import structlog
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from app.api import middleware
from app.api.middleware import _bind_request_context
from app.core.config import get_settings
from app.core.constants import Header, LogEvent
from app.core.logging import mask_secret_values
from app.main import create_app
from app.services.api_clients import get_api_client_service


@pytest.fixture(scope="module")
def app_client() -> TestClient:
    app: FastAPI = create_app()

    def crash() -> None:
        raise RuntimeError("boom")

    def echo(payload: dict = Body(...)) -> dict:  # noqa: B008 — FastAPI's own way to declare a body
        return {"keys": len(payload)}

    app.add_api_route("/test-only/crash", crash)
    app.add_api_route("/test-only/echo", echo, methods=["POST"])
    return TestClient(app, raise_server_exceptions=False)


def test_a_crash_is_counted_and_carries_the_request_id(app_client: TestClient) -> None:
    response = app_client.get("/test-only/crash")
    assert response.status_code == 500
    assert response.headers[Header.REQUEST_ID] == response.json()["request_id"]
    assert 'route="/test-only/crash",status="500"' in app_client.get("/metrics").text


def test_a_plain_request_id_is_kept_and_an_unsafe_one_replaced(app_client: TestClient) -> None:
    kept = app_client.get("/health", headers={Header.REQUEST_ID: "abc-123"})
    replaced = app_client.get("/health", headers={Header.REQUEST_ID: "x" * 65})
    assert kept.headers[Header.REQUEST_ID] == "abc-123"
    assert len(replaced.headers[Header.REQUEST_ID]) == 32


def test_a_body_over_the_limit_is_refused_with_413(
    app_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(middleware, "_BYTES_PER_MB", 1)  # the .env values then read as bytes
    monkeypatch.setattr(get_settings(), "max_request_mb", 10)
    assert app_client.post("/test-only/echo", json={"a": 1}).status_code == 200
    response = app_client.post("/test-only/echo", json={"a": "x" * 50})
    assert response.status_code == 413 and response.json()["status"] == 413


def test_secrets_are_masked_but_token_counts_are_not() -> None:
    event = {"api_key": "s3cret", "db_dsn": "mssql://u:p@h", "tokens_in": 23, "key_prefix": "tsg_abcd"}
    assert mask_secret_values(None, "info", event) == {
        "api_key": "***",
        "db_dsn": "***",
        "tokens_in": 23,
        "key_prefix": "tsg_abcd",
    }


def test_only_a_numeric_entity_id_reaches_the_log_lines() -> None:
    """Before: the raw public X-Entity-Id header was copied into every log line of every request."""
    for header, expected in [(b"86", "86"), (b"x" * 5000, None), (b"-1", None)]:
        _bind_request_context({"type": "http", "headers": [(b"x-entity-id", header)]})
        assert structlog.contextvars.get_contextvars()["entity_id"] == expected


def test_a_body_labelled_as_an_upload_gets_the_same_limit(
    app_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: a body labelled multipart/form-data was allowed 32 MB. The label is the caller's to choose, so
    anyone could send a JSON body as 'multipart' and make a pod read 32 MB before the key check. One limit
    for every request (owner, 2026-10-09)."""
    monkeypatch.setattr(middleware, "_BYTES_PER_MB", 1)  # the .env value then reads as bytes
    monkeypatch.setattr(get_settings(), "max_request_mb", 10)
    as_json = app_client.post(
        "/test-only/echo", content=b"x" * 500, headers={"Content-Type": "application/json"}
    )
    no_type = app_client.post("/test-only/echo", content=b"x" * 500)
    upload = app_client.post("/test-only/echo", files={"file": ("a.csv", b"x" * 500)})
    assert [as_json.status_code, no_type.status_code, upload.status_code] == [413, 413, 413]


class _RecordedLines:
    """Stands in for the middleware's logger (structlog caches it, so captured output would miss it)."""

    def __init__(self) -> None:
        self.lines: list[dict] = []

    def __getattr__(self, _level: str) -> Callable[..., None]:
        return lambda event, **fields: self.lines.append({"event": event, **fields})


def test_the_access_line_names_the_calling_system(
    app_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner, 2026-10-09: the platform and the chatbot each call with their own key, and each request's line
    says which system it was (None without a valid key). Nothing is refused because of it."""
    client, api_key = get_api_client_service().mint_api_client(f"line-{uuid.uuid4().hex[:8]}", None, "test")
    recorded = _RecordedLines()
    monkeypatch.setattr(middleware, "log", recorded)
    identity = {Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}
    unknown_run = f"/v1/sessions/{uuid.uuid4().hex}/events"
    app_client.get(unknown_run, headers=identity | {Header.API_KEY: api_key})  # 404, after the key check
    app_client.get(unknown_run, headers=identity | {Header.API_KEY: "tsg_wrong"})  # 401
    access = [line for line in recorded.lines if line["event"] == LogEvent.HTTP_REQUEST]
    assert [(line["status"], line["client_id"]) for line in access] == [
        (404, client["client_id"]),
        (401, None),
    ]


def test_an_unexpected_error_reaches_a_browser_with_cors_and_the_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: Starlette answered the 500 outside the CORS middleware, so a browser could not read the problem
    body or the request id it asks the user to quote."""
    monkeypatch.setattr(get_settings(), "cors_origins", "http://ui.test")
    app = create_app()

    def crash() -> None:
        raise RuntimeError("boom")

    app.add_api_route("/test-only/crash", crash)
    response = TestClient(app, raise_server_exceptions=False).get(
        "/test-only/crash", headers={"Origin": "http://ui.test"}
    )
    assert response.status_code == 500
    assert response.headers["access-control-allow-origin"] == "http://ui.test"
    assert response.headers[Header.REQUEST_ID] == response.json()["request_id"]


def test_cors_allows_exactly_the_methods_the_routes_use(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: only GET and POST, so a browser's preflight refused PUT, PATCH and DELETE routes."""
    monkeypatch.setattr(get_settings(), "cors_origins", "http://ui.test")
    app = create_app()
    routed = {method.upper() for operations in app.openapi()["paths"].values() for method in operations}
    preflight = TestClient(app).options(
        "/v1/jobs/any",
        headers={"Origin": "http://ui.test", "Access-Control-Request-Method": "DELETE"},
    )
    assert preflight.status_code == 200
    assert set(preflight.headers["access-control-allow-methods"].split(", ")) == routed
