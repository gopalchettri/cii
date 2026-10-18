"""The runs API (#1, #2, #3, #9, #10): T-SCN-01..12 and the cross-entity checks T-SEC-01..04. Asset facts come
from the SQL test database (entity 86 owns asset 103 with systems 321 and 322; 323 is not linked)."""

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.config import get_settings
from app.core.constants import (
    Collection,
    ConflictReason,
    Decision,
    Header,
    RunClash,
    SessionMessage,
    Status,
    Step,
    StoredProcedure,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.exceptions import Conflict
from app.data_access.job_records import JobLease
from app.data_access.scenario.runs import AssetContextRepository, SessionRepository
from app.models.api_clients import Principal
from app.models.asset_context import FrozenContext
from app.models.scenario.views import SessionStatus, StartRunRequest
from app.services.api_clients import get_api_client_service
from app.services.scenario import runs as runs_module
from app.services.scenario.runs import RunService, get_run_service

START = {"asset_id": 103, "supporting_system_id": [321, 322], "subsector_id": 11}


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"runs-{uuid.uuid4().hex[:8]}", None, "test")
    return key


def _identity(api_key: str, entity_id: int = 86) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


@pytest.fixture(autouse=True)
def runs_on_the_sql_test_database(client: TestClient, sql_test_engine: Engine) -> Iterator[None]:
    """The run service reads asset facts from the SQL test database; asset 103 starts every test free."""
    service = RunService(
        AssetContextRepository(StoredProcedureClient(sql_test_engine)), SessionRepository(get_mongodb())
    )
    client.app.dependency_overrides[get_run_service] = lambda: service  # type: ignore[attr-defined]
    get_mongodb()[Collection.SESSIONS].delete_many({"entity_id": 86, "asset_id": 103})
    yield
    client.app.dependency_overrides.pop(get_run_service, None)  # type: ignore[attr-defined]


def _start(client: TestClient, api_key: str, body: dict[str, Any] = START, **headers: str) -> Any:
    return client.post("/v1/sessions", json=body, headers=_identity(api_key) | headers)


def _run(session_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})


def test_a_start_queues_the_whole_job_with_the_frozen_context(client: TestClient, api_key: str) -> None:
    """T-SCN-01 / T-SCN-08: 202, systems SYS1 and SYS2 in request order, option codes as names, the calling
    system stored (never shown), and a job a worker can claim at once (it has job.due_at)."""
    response = _start(client, api_key)
    assert response.status_code == 202, response.text
    body = response.json()
    progress = body["progress"]
    assert (body["session_status"], progress["threats"], progress["overall"]) == (
        "active",
        "PENDING",
        "pending",
    )
    assert progress["scenario_count"]["total"] is None and "client_id" not in body
    run = _run(body["session_id"])
    assert (run["status"], run["step"]) == (Status.QUEUED, Step.THREATS)
    assert (body["asset_name"], body["user_id"]) == (run["context"]["asset"]["name"], run["user_id"])
    context = run["context"]
    assert [(s["alias"], s["id"]) for s in context["systems"]] == [("SYS1", 321), ("SYS2", 322)]
    assert context["systems"][0]["description"] == "Runs the transmission grid."  # the procedure's facts
    assert context["systems"][0]["category_code"] == "OT" and context["asset"]["category_code"] == "OT"
    facts = context["asset_context"]
    assert (facts["sector"], facts["sub_sector"]) == ("Energy", "Electricity")
    assert "sector" not in context and "critical_service" not in context  # each fact once: no top-level copy
    # G203: the asset itself keeps only what names and the control pool need; its facts live in asset_context.
    assert set(context["asset"]) == {"id", "name", "category_code"}
    assert context["asset_context"]["critical_service"] == "Electricity transmission"
    assert "id" not in context["asset_context"]  # the prompts' view of the asset never carries an id
    assert run["client_id"] == get_api_client_service().find_client_id_for_api_key(api_key)
    assert run["active"] is True and run["job"]["task"] == TaskName.FIND_THREATS
    lease = JobLease.claim(get_mongodb()[Collection.SESSIONS], run["_id"], 1, TaskName.FIND_THREATS, "w1")
    assert lease is not None


@pytest.mark.parametrize(
    ("body", "status", "reason"),
    [
        ({**START, "asset_id": 104}, 403, "asset_not_owned"),  # T-SCN-02
        ({**START, "supporting_system_id": [321, 323]}, 403, "system_not_linked"),  # T-SCN-03
        ({**START, "sector_id": 99}, 422, None),  # T-SCN-04: not the sub-sector's parent
        ({**START, "service_id": 77}, 404, None),  # T-SCN-05
    ],
)
def test_a_start_the_asset_facts_refuse_writes_nothing(
    client: TestClient, api_key: str, body: dict[str, Any], status: int, reason: str | None
) -> None:
    response = _start(client, api_key, body)
    assert response.status_code == status, response.text
    assert response.json().get("reason") == reason
    assert get_mongodb()[Collection.SESSIONS].count_documents({"entity_id": 86, "asset_id": 103}) == 0


def test_a_required_property_not_recorded_refuses_the_start_and_names_each_gap(
    client: TestClient, api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G197 (owner 2026-10-11): SYSTEM_PROPERTIES_REQUIRED=description and system 322 has none recorded ->
    422 required_facts_missing naming system 322 at its place in the request; no run is written."""
    monkeypatch.setattr(get_settings(), "system_properties_required", "description")
    response = _start(client, api_key)
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "required_facts_missing"
    assert response.json()["errors"] == [
        {"field": "body.supporting_system_id.1", "message": "system 322: description not recorded."}
    ]
    assert get_mongodb()[Collection.SESSIONS].count_documents({"entity_id": 86, "asset_id": 103}) == 0


def test_a_run_stores_exactly_the_procedures_columns(
    client: TestClient, api_key: str, sql_test_engine: Engine
) -> None:
    """G203 (owner 2026-10-11): the stored facts are the asset procedure's columns, in its order, and nothing
    else: the head columns aside, the asset's are its asset_context, each system's follow its alias."""
    asset, _, _, systems, _ = StoredProcedureClient(sql_test_engine).execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT, EntityID=86, AssetID=103, SystemIDs="[321, 322]", SubsectorID=11
    )
    context = _run(_start(client, api_key).json()["session_id"])["context"]
    head = ("id", "name", "category_code")
    assert list(context["asset_context"]) == [column for column in asset[0] if column not in head]
    for stored in context["systems"]:
        assert list(stored) == ["id", "alias", *head[1:], *(c for c in systems[0] if c not in head)]


def test_an_unlinked_system_is_named(client: TestClient, api_key: str) -> None:
    response = _start(client, api_key, {**START, "supporting_system_id": [321, 323]})
    assert response.json()["details"] == {"system_ids": [323]}


def test_a_wrong_sector_names_the_field(client: TestClient, api_key: str) -> None:
    errors = _start(client, api_key, {**START, "sector_id": 99}).json()["errors"]
    assert [error["field"] for error in errors] == ["body.sector_id"]


def test_one_active_run_per_asset_even_when_two_start_at_once(client: TestClient, api_key: str) -> None:
    """T-SCN-06: two parallel starts → 202 and 409 active_session_exists, with the active run's id."""
    answers: list[Any] = []
    starts = [threading.Thread(target=lambda: answers.append(_start(client, api_key))) for _ in range(2)]
    for start in starts:
        start.start()
    for start in starts:
        start.join()
    created, refused = sorted(answers, key=lambda answer: answer.status_code)
    assert (created.status_code, refused.status_code) == (202, 409)
    assert refused.json()["reason"] == "active_session_exists"
    assert refused.json()["details"] == {"active_session_id": created.json()["session_id"]}


def test_the_same_idempotency_key_replays_and_another_asset_is_refused(
    client: TestClient, api_key: str
) -> None:
    """T-SCN-07: a repeat with the same key → 200 with that run; the same key for another asset → 409."""
    key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    first = _start(client, api_key, START, **key)
    again = _start(client, api_key, START, **key)
    assert (first.status_code, again.status_code) == (202, 200)
    assert again.json()["session_id"] == first.json()["session_id"]
    other_asset = _start(client, api_key, {**START, "asset_id": 104}, **key)
    assert (other_asset.status_code, other_asset.json()["reason"]) == (409, "idempotency_key_conflict")


def test_the_same_retry_key_with_other_systems_is_a_conflict(client: TestClient, api_key: str) -> None:
    """G111 (spec v4.0 §6.1 #1): a key reused for another request is refused, never answered with the old run;
    the same systems in another order are the same request."""
    key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    first = _start(client, api_key, START, **key)
    reordered = _start(
        client, api_key, {**START, "supporting_system_id": START["supporting_system_id"][::-1]}, **key
    )
    assert (first.status_code, reordered.status_code) == (202, 200)
    other = _start(client, api_key, {**START, "supporting_system_id": [321]}, **key)
    assert (other.status_code, other.json()["reason"]) == (409, "idempotency_key_conflict")


def test_an_unknown_body_field_is_refused(client: TestClient, api_key: str) -> None:
    """G111: a misspelt field (sector_idd) is a 422 naming it, never silently ignored; no run is created."""
    response = _start(client, api_key, {**START, "sector_idd": 5})
    assert response.status_code == 422
    assert [error["field"] for error in response.json()["errors"]] == ["body.sector_idd"]
    assert get_mongodb()[Collection.SESSIONS].count_documents({"entity_id": 86, "asset_id": 103}) == 0


def test_parallel_starts_with_one_key_make_one_run(client: TestClient, api_key: str) -> None:
    key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    answers: list[Any] = []
    starts = [
        threading.Thread(target=lambda: answers.append(_start(client, api_key, START, **key)))
        for _ in range(2)
    ]
    for start in starts:
        start.start()
    for start in starts:
        start.join()
    assert sorted(answer.status_code for answer in answers) in ([200, 202], [202, 409])
    assert get_mongodb()[Collection.SESSIONS].count_documents({"entity_id": 86, "asset_id": 103}) == 1


def test_a_run_s_status_and_the_controls_step(client: TestClient, api_key: str) -> None:
    """T-SCN-09: the status body; step reads `controls` while a done run still maps controls."""
    session_id = _start(client, api_key).json()["session_id"]
    status = client.get(f"/v1/sessions/{session_id}", headers=_identity(api_key))
    assert status.status_code == 200 and status.json()["session_id"] == session_id
    record = {
        **_run(session_id),
        "status": Status.DONE,
        "step": Step.SCENARIOS,
        "counts": {"controls_waiting": 2},
    }
    assert SessionStatus.from_record(record).step == Step.CONTROLS


def _scenario(session_id: str, path_id: str, version: int, **fields: Any) -> str:
    scenario_id = uuid.uuid4().hex
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {
            "_id": scenario_id,
            "session_id": session_id,
            "entity_id": 86,
            "asset_id": 103,
            "path_id": path_id,
            "version": version,
            "source": "generated",
            "status": Status.DONE,
            "decision": Decision.PENDING,
            "superseded_by": None,
            "content": {
                "title": f"Loss of {path_id}",
                "statement": "It stops.",
                "why_applies": "It is exposed.",
            },
            "findings": [{"code": "x", "severity": "warning", "message": "m"}],
            "created_at": datetime.now(UTC) + timedelta(milliseconds=version),
            **fields,
        }
    )
    return scenario_id


def test_results_show_current_versions_and_keep_a_decided_older_one(client: TestClient, api_key: str) -> None:
    """T-SCN-10: an older version is hidden once replaced, unless it was decided (G-B); include_replaced shows
    all; paging returns the total."""
    session_id = _start(client, api_key).json()["session_id"]
    newer = _scenario(session_id, "p1", 2)
    _scenario(session_id, "p1", 1, superseded_by=newer)  # replaced, pending: hidden
    accepted_old = _scenario(session_id, "p2", 1, superseded_by="v2", decision=Decision.ACCEPTED)
    url, headers = f"/v1/sessions/{session_id}/results", _identity(api_key)
    shown = client.get(url, headers=headers).json()
    assert {item["scenario_id"] for item in shown["scenarios"]} == {newer, accepted_old} and shown[
        "total"
    ] == 2
    # v1's layout (owner 2026-10-12): the run and its progress first, as its status shows them.
    status = client.get(f"/v1/sessions/{session_id}", headers=headers).json()
    assert {key: shown[key] for key in status if key not in ("session_status", "updated_at")} == {
        key: status[key] for key in status if key not in ("session_status", "updated_at")
    }
    # G267 (v1's shape): include_replaced nests a path's older versions, newest first and flat, in each listed
    # version; they are never extra items.
    nested = client.get(url, params={"include_replaced": True}, headers=headers).json()
    assert nested["total"] == 2
    listed = {item["scenario_id"]: item for item in nested["scenarios"]}
    assert [old["scenario_number"] for old in listed[newer]["replaced_scenarios"]] == [1]
    assert listed[newer]["replaced_scenarios"][0]["replaced_scenarios"] == []
    assert all(item["replaced_scenarios"] == [] for item in shown["scenarios"])  # without it: none
    page = client.get(url, params={"limit": 1, "offset": 1}, headers=headers).json()
    assert len(page["scenarios"]) == 1 and page["total"] == 2


def test_a_version_says_which_accepted_version_of_its_path_it_would_replace(
    client: TestClient, api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G267, v1's replaces_accepted_version: accepting it replaces the path's accepted version
    (replace_accepted); the accepted one, and a path with none, show None. One read per page, on every
    route."""
    from app.data_access.scenario.scenarios import ScenarioVersions

    session_id = _start(client, api_key).json()["session_id"]
    newer = _scenario(session_id, "p1", 2)
    accepted = _scenario(session_id, "p1", 1, superseded_by=newer, decision=Decision.ACCEPTED)
    alone = _scenario(session_id, "p2", 1)
    reads: list[int] = []
    original = ScenarioVersions.find_other_versions
    monkeypatch.setattr(
        ScenarioVersions,
        "find_other_versions",
        lambda self, *args: reads.append(1) or original(self, *args),
    )
    headers = _identity(api_key)
    shown = client.get(f"/v1/sessions/{session_id}/results", headers=headers).json()["scenarios"]
    by_id = {item["scenario_id"]: item["replaces_accepted_version"] for item in shown}
    assert by_id == {newer: accepted, accepted: None, alone: None} and reads == [1]
    one = client.get(f"/v1/sessions/{session_id}/scenarios/{newer}", headers=headers).json()
    assert one["replaces_accepted_version"] == accepted
    listed = client.get("/v1/entities/86/scenarios", headers=headers).json()["scenarios"]
    assert (
        next(item for item in listed if item["scenario_id"] == newer)["replaces_accepted_version"] == accepted
    )


def test_results_work_the_coverage_out_from_the_plan(client: TestClient, api_key: str) -> None:
    """G228: the results read the plan's paths themselves (the status never does): none before a plan; then
    each kind with its finished paths, an abandoned one not counted."""
    session_id = _start(client, api_key).json()["session_id"]
    url, headers = f"/v1/sessions/{session_id}/results", _identity(api_key)
    assert client.get(url, headers=headers).json()["coverage"] is None  # no plan yet
    paths = [
        {"path_id": "p1", "systems": [321], "categories": ["Spoofing"], "selected": True, "abandoned": False},
        {"path_id": "p2", "systems": [322], "categories": ["Tampering"], "selected": True, "abandoned": True},
    ]
    paths[0]["served"] = "s1"  # G229: only a finished scenario covers
    plan = {"plan.paths": paths, "plan.target": 15}
    get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": plan})
    coverage = client.get(url, headers=headers).json()["coverage"]
    assert (coverage["limit"], coverage["selected"], coverage["finished"]) == (15, 1, 1)
    kinds = coverage["kinds"]
    assert kinds["Spoofing"]["path_ids"] == ["p1"] and kinds["Tampering"]["finished"] == 0
    assert {"kind": "Tampering", "reason": "scenarios_failed"} in coverage["not_covered"]
    assert "coverage" not in client.get(f"/v1/sessions/{session_id}", headers=headers).json()


def test_one_scenario_with_its_computed_fields(client: TestClient, api_key: str) -> None:
    """T-SCN-11: the statement shown with why it applies, and validation_status computed; an unknown id in
    the run → 404."""
    session_id = _start(client, api_key).json()["session_id"]
    scenario_id = _scenario(session_id, "p1", 1)
    url = f"/v1/sessions/{session_id}/scenarios"
    shown = client.get(f"{url}/{scenario_id}", headers=_identity(api_key)).json()
    assert shown["scenario"]["scenario_statement"] == "It stops.\n\nWhy this threat applies: It is exposed."
    assert (shown["validation_status"], shown["validation_errors"]) == ("warning", ["m"])
    assert client.get(f"{url}/{uuid.uuid4().hex}", headers=_identity(api_key)).status_code == 404


def test_an_entity_s_scenarios_newest_first_by_decision(client: TestClient, api_key: str) -> None:
    """T-SCN-12."""
    session_id = _start(client, api_key).json()["session_id"]
    accepted = _scenario(session_id, "p1", 1, decision=Decision.ACCEPTED)
    url = "/v1/entities/86/scenarios"
    listed = client.get(url, params={"decision": "accepted"}, headers=_identity(api_key)).json()["scenarios"]
    assert accepted in [item["scenario_id"] for item in listed]
    assert all(item["accepted"] and item["rejected_by"] is None for item in listed)


def test_another_entity_sees_nothing_of_this_entity(client: TestClient, api_key: str) -> None:
    """T-SEC-01..04: entity 99 asks for entity 86's run, its results, a scenario and its entity list."""
    session_id = _start(client, api_key).json()["session_id"]
    scenario_id = _scenario(session_id, "p1", 1)
    other = _identity(api_key, entity_id=99)
    for url in (
        f"/v1/sessions/{session_id}",
        f"/v1/sessions/{session_id}/results",
        f"/v1/sessions/{session_id}/scenarios/{scenario_id}",
        "/v1/entities/86/scenarios",
    ):
        assert client.get(url, headers=other).status_code == 403, url
    assert client.get(f"/v1/sessions/{uuid.uuid4().hex}", headers=other).status_code == 404


def test_an_idempotency_key_too_long_is_refused(client: TestClient, api_key: str) -> None:
    assert _start(client, api_key, START, **{Header.IDEMPOTENCY_KEY: "k" * 201}).status_code == 422


def test_a_replay_whose_run_was_deleted_since_is_a_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parallel start with the same Idempotency-Key won, then its run was deleted before this start read it:
    409 naming the race. Before, an assert failed there (a 500)."""
    monkeypatch.setattr(runs_module, "refuse_without_intel_data", lambda: None)
    asset = {"id": 103, "name": "Grid", "category_code": None}
    context = FrozenContext.from_record(
        {"asset": asset, "asset_context": {}, "systems": [], "missing_facts": []}
    )
    monkeypatch.setattr(runs_module, "freeze_context", lambda request, rows: context)
    sessions = SimpleNamespace(
        find_by_idempotency_key=lambda *args: None, insert_run=lambda record: RunClash.IDEMPOTENCY_KEY
    )
    service = RunService(SimpleNamespace(read=lambda *args: None), sessions)  # type: ignore[arg-type]
    with pytest.raises(Conflict) as refused:
        service.start(Principal("client", "u1", 86, "DESC"), StartRunRequest.model_validate(START), "key-1")
    assert refused.value.reason == ConflictReason.IDEMPOTENCY_KEY_CONFLICT
    assert refused.value.detail == SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
