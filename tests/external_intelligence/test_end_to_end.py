"""One run end to end, with external intelligence off and on: started through the API on the SQL test
database, planned, written and its controls mapped by the real jobs on the test MongoDB with fake AI models,
then read, one scenario accepted, and read again."""

import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.constants import (
    Collection,
    Decision,
    EvidenceMode,
    Header,
    RunActionOutcome,
    Status,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.library.repository import SqlServerRepository
from app.data_access.scenario.repository import scenario_sessions, scenarios
from app.models.library import ThreatLibrary
from app.services.api_clients import get_api_client_service
from app.services.scenario import review as review_module
from app.services.scenario import runs as runs_module
from app.services.scenario.review import ReviewService, get_review_service
from app.services.scenario.runs import RunService, get_run_service
from app.worker import jobs
from app.worker.tasks import controls as controls_job
from app.worker.tasks import scenarios as scenario_tasks
from app.worker.tasks import writing
from tests.planner_samples import ACTORS, ADMIN_ABUSE, LOG_WIPE, THREATS, finder, planner_chat
from tests.test_control_mapping import _CONTROLS, _ScoresByText, _snapshot
from tests.test_runs import START
from tests.test_v1_scenario_format import V1_KEYS, V2_EXTRAS
from tests.test_writing_job import _deliver_until_done, chat  # noqa: F401 - fixture used by name

LIBRARY = ThreatLibrary(THREATS, ACTORS)  # the planner's threats and attackers, all live
RESULTS_KEYS = [
    "session_id", "entity_id", "asset_id", "asset_name", "user_id", "progress", "scenarios", "total",
]  # fmt: skip


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"e2e-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def jobs_faked(
    client: TestClient,
    sql_test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    chat: Any,  # noqa: F811
) -> Iterator[list[tuple[Any, ...]]]:
    """Asset 103 free with no scenarios; the run service on the SQL test database; every job message and live
    update recorded; the planner, writer, reranker and libraries faked. The messages sent, in order."""
    get_mongodb()[Collection.SESSIONS].delete_many({"entity_id": 86, "asset_id": 103})
    get_mongodb()[Collection.SCENARIOS].delete_many({"entity_id": 86, "asset_id": 103})
    sent: list[tuple[Any, ...]] = []
    for module in (runs_module, jobs, writing, controls_job):
        monkeypatch.setattr(module, "send_job", lambda *args: sent.append(args))
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _session_id: None)
    monkeypatch.setattr(controls_job, "publish_session_status", lambda _session_id: None)
    monkeypatch.setattr(review_module, "publish_session_status", lambda _session_id: None)
    planner = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(planner))
    monkeypatch.setattr(
        writing, "get_library_service", lambda: SimpleNamespace(get_threat_library=lambda: LIBRARY)
    )
    rerank = _ScoresByText({"Backup of controller logic": 87.0, "Backup policy": 70.0})
    monkeypatch.setattr(
        controls_job, "get_library_search", lambda: SimpleNamespace(snapshot=lambda: _snapshot(*_CONTROLS))
    )
    monkeypatch.setattr(controls_job, "get_rerank_model", lambda: rerank)
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    run_service = RunService(SqlServerRepository(StoredProcedureClient(sql_test_engine)), scenario_sessions)
    review_service = ReviewService(lambda: LIBRARY)
    overrides[get_run_service], overrides[get_review_service] = lambda: run_service, lambda: review_service
    yield sent
    overrides.pop(get_run_service, None)
    overrides.pop(get_review_service, None)


@pytest.fixture(params=["off", "on"])
def intelligence(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Off as the suite runs; on: both switches, an indexed snapshot, the fake finder, evidence stories."""
    if request.param == "on":
        request.getfixturevalue("intel")
        request.getfixturevalue("story_chat")
        monkeypatch.setattr(
            runs_module, "get_external_intelligence_switch", lambda: SimpleNamespace(is_enabled=lambda: True)
        )
        active = {"snapshot_id": "s1", "counts": {"indexed": 12}}
        monkeypatch.setattr(runs_module, "intel_snapshots", SimpleNamespace(get=lambda *_, **__: active))
    return request.param


def _identity(api_key: str) -> dict[str, str]:
    return {Header.API_KEY: api_key, Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}


def test_a_run_is_started_planned_written_mapped_read_and_reviewed(
    client: TestClient, api_key: str, jobs_faked: list[tuple[Any, ...]], intelligence: str
) -> None:
    headers = _identity(api_key)
    started = client.post("/v1/sessions", json=START, headers=headers)
    assert started.status_code == 202, started.text
    session_id = started.json()["session_id"]
    assert jobs_faked == [(TaskName.FIND_THREATS, session_id, 1)]

    assert scenario_tasks.find_threats.apply(args=(session_id, 1)).successful()  # the real task
    assert jobs_faked[-1] == (TaskName.WRITE_SCENARIOS, session_id, 1)
    assert _deliver_until_done(session_id) == 1
    task, *message = jobs_faked[-1]
    assert task == TaskName.MAP_CONTROLS and message[0] == session_id
    assert controls_job.map_controls.apply(args=message, task_id="controls-1").successful()

    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})
    assert (run["status"], run["active"], run["last_action"]["outcome"]) == (
        Status.DONE,
        False,
        RunActionOutcome.COMPLETE,
    )
    assert {key: run["counts"][key] for key in ("planned", "written", "remaining")} == {
        "planned": 2,
        "written": 2,
        "remaining": 0,
    }
    results = client.get(f"/v1/sessions/{session_id}/results", headers=headers).json()
    assert list(results) == RESULTS_KEYS and results["total"] == 2
    shown = results["scenarios"]
    assert all(list(item) == V1_KEYS + V2_EXTRAS for item in shown)
    assert {item["scenario"]["threat_name"] for item in shown} == {LOG_WIPE.name, ADMIN_ABUSE.name}
    assert all(item["controls_status"] == Status.DONE and item["controls"] for item in shown)
    expected_mode = EvidenceMode.SOURCE_DOCUMENTED if intelligence == "on" else None
    assert {item["evidence_mode"] for item in shown} == {expected_mode}
    assert results["progress"]["scenario_count"]["served"] == 2

    first = shown[0]["scenario_id"]
    accepted = client.post(
        f"/v1/sessions/{session_id}/accept", json={"scenario_ids": [first]}, headers=headers
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["accepted"] == [first]
    count = client.get(f"/v1/sessions/{session_id}", headers=headers).json()["progress"]["scenario_count"]
    assert (count["total"], count["served"], count["accepted"], count["pending_review"]) == (2, 2, 1, 1)
    again = client.get(f"/v1/sessions/{session_id}/results", headers=headers).json()
    decisions = {item["scenario_id"]: item["accepted"] for item in again["scenarios"]}
    assert decisions == {first: True, shown[1]["scenario_id"]: False}
    assert scenarios.get(_id=first)["decision"] == Decision.ACCEPTED
