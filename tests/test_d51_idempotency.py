"""Idempotency of the four POSTs that start work: with no Idempotency-Key the server derives one (caller,
method, path, exact body, one-minute window) and refuses its repeat with 409 duplicate_request naming the
first record; a caller's own key still replays; the key used is in the answer's Idempotency-Key header and in
the access line, so a repeat's request id links to the first."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from starlette.middleware.cors import CORSMiddleware
from structlog.testing import capture_logs

from app import container
from app.api import dependencies
from app.core.constants import Collection, Header, LogEvent, Status, TaskName
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.logging import mask_secret_values
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.scenario.asset_repository import AssetRepository
from app.data_access.service_mapper.mapping_repository import MappingRepository
from app.services.service_mapper.service_mapper_service import ServiceMapperService
from tests.plan_job_fakes import (  # noqa: F401 — api_key_fixture and world_fixture are fixtures
    CONTROLS,
    api_key_fixture,
    fake_library,
    remediation_plan_service,
    world_fixture,
)
from tests.service_builders import threat_scenario_service

START = {"asset_id": 103, "supporting_system_id": [321, 322], "subsector_id": 11}
MAPPING = {
    "service_name": "Power Generation System",
    "service_description": "Generates and dispatches electricity to the transmission grid.",
    "sector": "Energy",
    "subsector": "Power",
    "entity_names": ["Example Utility"],
}
MANUAL = {
    "is_manual": True,
    "manual_scenario": {
        "asset_id": 103,
        "entity_id": 86,
        "supporting_system_id": [321, 322],
        "threat_type_name": "Malware",
        "threat_name": "Firmware tampering",
        "threat_scenario": "A cybercriminal could push unsigned firmware to the RTU.",
        "risk_statement": "Loss of trusted control could interrupt electricity transmission.",
        "mapped_controls": ["CII-CID-1"],
    },
}
DUPLICATE = "duplicate_request"


@pytest.fixture
def window(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """The derived key's clock, held still so a minute boundary never splits a test's two requests."""
    now = {"seconds": 1_800_000_000.0}
    monkeypatch.setattr(dependencies, "epoch_seconds", lambda: now["seconds"], raising=False)
    return now


@pytest.fixture
def caller(api_key: str) -> dict[str, str]:
    """A fresh user per test, so no other test's derived key is ever this test's."""
    user = f"u-{uuid.uuid4().hex[:8]}"
    return {Header.API_KEY: api_key, Header.USER_ID: user, Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}


@pytest.fixture
def runs(client: TestClient, sql_test_engine: Engine) -> Iterator[None]:
    """The scenario and remediation services on the SQL test database's asset 103 (entity 86)."""
    assets = AssetRepository(StoredProcedureClient(sql_test_engine))
    plans = remediation_plan_service(
        library=fake_library(tuple(CONTROLS.values())), assets=assets, send_job=lambda *args: None
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_threat_scenario_service] = lambda: threat_scenario_service(assets=assets)
    overrides[container.get_remediation_plan_service] = lambda: plans
    get_mongodb()[Collection.SESSIONS].delete_many({"entity_id": 86, "asset_id": 103})
    yield
    overrides.pop(container.get_threat_scenario_service, None)
    overrides.pop(container.get_remediation_plan_service, None)


@pytest.fixture
def mapper(client: TestClient) -> Iterator[None]:
    """The service mapper on the test database, sending and publishing nothing; no mapping left by an earlier
    test (a service has one)."""
    get_mongodb()[Collection.SERVICE_MAPPINGS].delete_many({})
    service = ServiceMapperService(
        MappingRepository(),
        container.get_settings(),
        lambda *args: True,
        None,
        AuditRepository(),
        lambda _mapping_id: None,
    )
    client.app.dependency_overrides[container.get_service_mapper_service] = lambda: service  # type: ignore[attr-defined]
    yield
    client.app.dependency_overrides.pop(container.get_service_mapper_service, None)  # type: ignore[attr-defined]


def _refused_as_duplicate(answer: Any, **first: Any) -> None:
    """A 409 duplicate_request naming what the first request started, how long ago, and what to do."""
    problem = answer.json()
    assert (answer.status_code, problem.get("reason")) == (409, DUPLICATE), answer.text
    assert {name: problem["details"][name] for name in first} == first
    assert 0 <= problem["details"]["started_seconds_ago"] <= 60
    assert str(next(iter(first.values()))) in problem["detail"] and "Idempotency-Key" in problem["detail"]


def test_a_keyless_repeat_start_is_refused_naming_the_first_run(
    client: TestClient, caller: dict[str, str], window: dict[str, float], runs: None
) -> None:
    """The same caller and body in the same minute: 202, then 409 naming the run; the key is derived, echoed
    on both answers and held by one run. The next minute, or another user, starts a new run."""
    first = client.post("/v1/sessions", json=START, headers=caller)
    again = client.post("/v1/sessions", json=START, headers=caller)
    assert first.status_code == 202, first.text
    _refused_as_duplicate(again, session_id=first.json()["session_id"])
    key = first.headers.get(Header.IDEMPOTENCY_KEY, "")
    assert key.startswith("derived-") and again.headers[Header.IDEMPOTENCY_KEY] == key
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 1
    window["seconds"] += 60
    assert client.post("/v1/sessions", json=START, headers=caller).status_code == 202
    other_user = caller | {Header.USER_ID: f"{caller[Header.USER_ID]}-b"}
    assert client.post("/v1/sessions", json=START, headers=other_user).status_code == 202


def test_a_callers_own_key_still_replays_and_is_echoed(
    client: TestClient, caller: dict[str, str], runs: None
) -> None:
    """A key the caller sent: the repeat answers 200 with the same run, and both answers carry that key."""
    keyed = caller | {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    first = client.post("/v1/sessions", json=START, headers=keyed)
    again = client.post("/v1/sessions", json=START, headers=keyed)
    assert (first.status_code, again.status_code) == (202, 200)
    assert again.json()["session_id"] == first.json()["session_id"]
    assert first.headers.get(Header.IDEMPOTENCY_KEY) == again.headers.get(Header.IDEMPOTENCY_KEY)
    assert again.headers.get(Header.IDEMPOTENCY_KEY) == keyed[Header.IDEMPOTENCY_KEY]


def test_a_callers_key_that_starts_like_a_derived_one_still_replays(
    client: TestClient, caller: dict[str, str], runs: None
) -> None:
    """A key is derived only when the caller sent none, whatever its spelling: 202, then 200, one run."""
    keyed = caller | {Header.IDEMPOTENCY_KEY: f"derived-{uuid.uuid4().hex}"}
    first = client.post("/v1/sessions", json=START, headers=keyed)
    again = client.post("/v1/sessions", json=START, headers=keyed)
    assert (first.status_code, again.status_code) == (202, 200), again.text
    assert again.json()["session_id"] == first.json()["session_id"]


def _sent_again_with_its_echoed_key(
    client: TestClient, path: str, caller: dict[str, str], body: dict[str, Any] | None = None
) -> tuple[dict[str, Any], Any]:
    """A key-less request (its 202 body), then the same request carrying the key its answer echoed."""
    first = client.post(path, json=body, headers=caller)
    assert first.status_code == 202, first.text
    echoed = caller | {Header.IDEMPOTENCY_KEY: first.headers[Header.IDEMPOTENCY_KEY]}
    return first.json(), client.post(path, json=body, headers=echoed)


def test_a_retry_with_the_echoed_key_replays_on_every_route(
    client: TestClient,
    caller: dict[str, str],
    runs: None,
    mapper: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 202 lost on the way back, retried with the Idempotency-Key it echoed: the caller sent that key, so
    each route answers 200 with what the first request started (a manual plan also when it looked before the
    first saved)."""
    run, again = _sent_again_with_its_echoed_key(client, "/v1/sessions", caller, START)
    assert (again.status_code, again.json()["session_id"]) == (200, run["session_id"]), again.text
    plan, again = _sent_again_with_its_echoed_key(client, "/v1/remediation", caller, MANUAL)
    assert (again.status_code, again.json()["remediation_id"]) == (200, plan["remediation_id"]), again.text
    sessions = container.get_threat_scenario_session_repository()
    real_get = sessions.get
    monkeypatch.setattr(
        sessions,
        "get",
        lambda fields=None, **where: None if fields == "replay" else real_get(fields, **where),
    )
    echoed = caller | {Header.IDEMPOTENCY_KEY: again.headers[Header.IDEMPOTENCY_KEY]}
    raced = client.post("/v1/remediation", json=MANUAL, headers=echoed)
    assert (raced.status_code, raced.json()["remediation_id"]) == (200, plan["remediation_id"]), raced.text
    mapping, again = _sent_again_with_its_echoed_key(client, "/v1/service-mapper", caller, MAPPING)
    assert (again.status_code, again.json()["mapping_id"]) == (200, mapping["mapping_id"]), again.text
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": mapping["mapping_id"]}, {"$set": {"status": Status.DONE, "updated_at": datetime.now(UTC)}}
    )
    path = f"/v1/service-mapper/{mapping['mapping_id']}/regenerate"
    regenerated, again = _sent_again_with_its_echoed_key(client, path, caller)
    assert (again.status_code, again.json()["generation"]) == (200, regenerated["generation"]), again.text


def test_a_keyless_manual_plan_starts_and_its_repeat_is_refused(
    client: TestClient,
    caller: dict[str, str],
    window: dict[str, float],
    runs: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hand-written plan needs no key any more: 202; the same body again is 409 naming its run and
    scenario, also when it was sent at the same moment (it looked before the first saved)."""
    first = client.post("/v1/remediation", json=MANUAL, headers=caller)
    assert first.status_code == 202, first.text
    ids = {name: first.json()[name] for name in ("session_id", "scenario_id")}
    _refused_as_duplicate(client.post("/v1/remediation", json=MANUAL, headers=caller), **ids)
    sessions = container.get_threat_scenario_session_repository()
    real_get = sessions.get
    monkeypatch.setattr(
        sessions,
        "get",
        lambda fields=None, **where: None if fields == "replay" else real_get(fields, **where),
    )
    _refused_as_duplicate(client.post("/v1/remediation", json=MANUAL, headers=caller), **ids)


def test_a_keyless_repeat_mapping_or_regenerate_is_refused(
    client: TestClient, caller: dict[str, str], window: dict[str, float], mapper: None
) -> None:
    """A double click on create, then on regenerate: 202, then 409 naming the mapping (and generation)."""
    created = client.post("/v1/service-mapper", json=MAPPING, headers=caller)
    assert created.status_code == 202, created.text
    mapping_id = created.json()["mapping_id"]
    _refused_as_duplicate(
        client.post("/v1/service-mapper", json=MAPPING, headers=caller), mapping_id=mapping_id
    )
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": mapping_id}, {"$set": {"status": Status.DONE, "updated_at": datetime.now(UTC)}}
    )
    path = f"/v1/service-mapper/{mapping_id}/regenerate"
    regenerated = client.post(path, headers=caller)
    assert (regenerated.status_code, regenerated.json()["generation"]) == (202, 2), regenerated.text
    _refused_as_duplicate(client.post(path, headers=caller), mapping_id=mapping_id, generation=2)
    stored = get_mongodb()[Collection.SERVICE_MAPPINGS].find_one({"_id": mapping_id})
    assert (stored["job"]["epoch"], stored["job"]["task"]) == (2, TaskName.MAP_SERVICES)


def test_a_repeat_logs_the_key_of_the_request_it_repeats(
    client: TestClient, caller: dict[str, str], window: dict[str, float], runs: None
) -> None:
    """Each answer keeps its own X-Request-Id; both access lines carry the one idempotency key, so the
    repeat's request id leads to the first request and its run."""
    with capture_logs() as logs:
        first = client.post("/v1/sessions", json=START, headers=caller | {Header.REQUEST_ID: "first-1"})
        again = client.post("/v1/sessions", json=START, headers=caller | {Header.REQUEST_ID: "again-2"})
    assert (first.headers[Header.REQUEST_ID], again.headers[Header.REQUEST_ID]) == ("first-1", "again-2")
    lines = [
        mask_secret_values(None, "", line)  # as the log writes it: a secret-named field is masked
        for line in logs
        if line["event"] == LogEvent.HTTP_REQUEST and line["route"] == "/v1/sessions"
    ]
    assert [line["status"] for line in lines] == [202, 409]
    key = first.headers.get(Header.IDEMPOTENCY_KEY)
    assert key and [line.get("idempotency") for line in lines] == [key, key]


def test_a_browser_can_read_the_idempotency_key(client: TestClient) -> None:
    cors = next(layer for layer in client.app.user_middleware if layer.cls is CORSMiddleware)
    assert Header.IDEMPOTENCY_KEY in cors.kwargs["expose_headers"]
