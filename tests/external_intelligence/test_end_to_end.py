"""One run end to end, with external intelligence off and on: started through the API on the SQL test
database, planned, written and its controls mapped by the real jobs on the test MongoDB with fake AI models,
then read, one scenario accepted, and read again."""

import json
import uuid
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    Collection,
    Decision,
    EvidenceMode,
    Header,
    RunActionOutcome,
    Status,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.scenario.asset_repository import AssetRepository
from app.models.library.library import ThreatLibrary
from app.worker import jobs
from app.worker.scenario import controls_job, write_job
from app.worker.scenario import tasks as scenario_tasks
from app.worker.scenario.controls_job import ControlsJob
from app.worker.scenario.plan_job import PlanJob
from tests.fakes import FakeChatModel, brief_of, slot_blocks
from tests.planner_samples import ACTORS, ADMIN_ABUSE, LOG_WIPE, THREATS, finder, judged, planner_chat
from tests.service_builders import threat_scenario_service
from tests.test_control_mapping import _CONTROLS, _ScoresByText, _snapshot
from tests.test_runs import START
from tests.test_v1_scenario_format import V1_KEYS, V2_EXTRAS
from tests.test_writing_job import (  # noqa: F401 - fixture used by name
    _deliver_until_done,
    chat,
    write_job_with,
)

LIBRARY = ThreatLibrary(THREATS, ACTORS)  # the planner's threats and attackers, all live
RESULTS_KEYS = [
    "session_id", "entity_id", "asset_id", "asset_name", "user_id", "progress", "error", "scenarios", "total",
]  # fmt: skip


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = container.get_admin_service().create_api_client(f"e2e-{uuid.uuid4().hex[:8]}", None, "test")
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
    record = lambda *args, **_priority: sent.append(args)  # noqa: E731 - every job message, in order
    for module in (jobs, write_job, controls_job):
        monkeypatch.setattr(module, "send_job", record)
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _session_id: None)
    monkeypatch.setattr(controls_job, "publish_session_status", lambda _session_id: None)
    # One fake answers every AI call of a click, the threat check's and the writer's, as the one model does.
    chat.responders |= planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]}).responders
    plan = PlanJob(finder(chat), container.get_intelligence_switch())
    monkeypatch.setattr(container, "get_plan_job", lambda: plan)
    writer = write_job_with(chat, LIBRARY)
    monkeypatch.setattr(container, "get_scenario_write_job", lambda: writer)
    rerank = _ScoresByText({"Backup of controller logic": 87.0, "Backup policy": 70.0})
    search = SimpleNamespace(snapshot=lambda: _snapshot(*_CONTROLS))
    controls = ControlsJob(
        container.get_threat_scenario_session_repository(),
        container.get_threat_scenario_repository(),
        container.get_work_control_repository(),
        search,  # type: ignore[arg-type]
        rerank,  # type: ignore[arg-type]
    )
    monkeypatch.setattr(container, "get_controls_job", lambda: controls)
    service = threat_scenario_service(
        assets=AssetRepository(StoredProcedureClient(sql_test_engine)),
        threat_library=lambda: LIBRARY,
        send_job=record,
        publish_session_status=lambda _session_id: None,
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[container.get_threat_scenario_service] = lambda: service
    yield sent
    overrides.pop(container.get_threat_scenario_service, None)


@pytest.fixture(params=["off", "on"])
def intelligence(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Off as the suite runs; on: both switches, an indexed snapshot, the fake finder, evidence stories."""
    if request.param == "on":
        request.getfixturevalue("intel")
        request.getfixturevalue("story_chat")
        active = {"snapshot_id": "s1", "counts": {"indexed": 12}}
        monkeypatch.setattr(container.get_intel_snapshot_repository(), "get", lambda *_, **__: active)
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
    assert scenario_tasks.map_controls.apply(args=message, task_id="controls-1").successful()

    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})
    assert (run["status"], "active" in run, run["last_action"]["outcome"]) == (
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
    assert container.get_threat_scenario_repository().get(_id=first)["decision"] == Decision.ACCEPTED


_ACTION = "altering SYS1 setpoints"  # the threat check's action, naming a system by its alias


def _gate_giving_actions(user_prompt: str) -> dict[str, Any]:
    """The threat check finding every candidate relevant on SYS1, each with one action."""
    answer = judged(dict.fromkeys((threat.name for threat in THREATS), ["SYS1"]))(user_prompt)
    return answer | {"verdicts": [verdict | {"actions": [_ACTION]} for verdict in answer["verdicts"]]}


def _review_carrying_out_every_action(block: str) -> dict[str, Any]:
    """A clean review of one slot, judging each action its PLAN lists carried out."""
    plan, _ = json.JSONDecoder().raw_decode(block.split("PLAN:\n", 1)[1])
    actions = plan["threat"].get("threat_actions") or []
    consistent = {"rules": {"1": "holds"}, "same_threat": True, "same_impact": True}
    return consistent | {"threat_actions": dict.fromkeys(actions, "carried out")}


def _unreadable_first(threats: set[str], written: Callable[[str], dict[str, Any]]) -> Callable[..., Any]:
    """A writer whose first answer for each of `threats` is missing its texts; its rewrite is good."""
    return lambda block: (
        {"scenario_title": "x"}
        if brief_of(block)["threat"]["threat"] in threats and "REJECTED:" not in block
        else written(block)
    )


@pytest.mark.parametrize(
    ("unreadable", "calls"),
    [
        (set(), [AiTask.RELEVANCE_GATE, AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]),
        (
            {LOG_WIPE.name, ADMIN_ABUSE.name},
            [AiTask.RELEVANCE_GATE, AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
            + [AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK],
        ),
    ],
)
def test_a_click_plans_and_writes_its_first_set_of_six_in_three_ai_calls(
    client: TestClient,
    api_key: str,
    jobs_faked: list[tuple[Any, ...]],
    chat: FakeChatModel,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    unreadable: set[str],
    calls: list[AiTask],
) -> None:
    """Lean design, plan test 1: a click (the plan and its first set of 6) with good answers makes exactly 3
    AI model calls: one threat check for every threat, one write and one review for the set. Two unreadable
    first drafts add one rewrite and one review holding only those two: 4 writing calls. The threat check's
    actions reach every brief and review, systems by name."""
    monkeypatch.setattr(get_settings(), "initial_set_size", 6)
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_giving_actions
    chat.responders[AiTask.PLAN_CHECK] = _review_carrying_out_every_action
    chat.responders[AiTask.WRITE_SCENARIO] = _unreadable_first(
        unreadable, chat.responders[AiTask.WRITE_SCENARIO]
    )
    started = client.post("/v1/sessions", json=START, headers=_identity(api_key))
    session_id = started.json()["session_id"]
    assert scenario_tasks.find_threats.apply(args=(session_id, 1)).successful()
    assert _deliver_until_done(session_id) == 1

    assert [task for task, _ in chat.calls] == calls
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})
    assert (run["counts"]["written"], run["counts"]["abandoned"]) == (6, 0)
    rewrites = chat.asked(AiTask.REPAIR_SCENARIO)
    assert [len(slot_blocks(prompt)) for prompt in rewrites] == ([2] if unreadable else [])
    sys1 = next(system["name"] for system in run["context"]["systems"] if system["alias"] == "SYS1")
    named = _ACTION.replace("SYS1", sys1)
    briefs = [
        brief_of(block) for prompt in chat.asked(AiTask.WRITE_SCENARIO) for _, block in slot_blocks(prompt)
    ]
    assert [brief["threat"]["threat_actions"] for brief in briefs] == [[named]] * 6
    assert all(f'"threat_actions": ["{named}"]' in prompt for prompt in chat.asked(AiTask.PLAN_CHECK))
