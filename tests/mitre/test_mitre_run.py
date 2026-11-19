"""A MITRE run end to end (ADR-010): started on the SQL test database (entity 86: OT asset 103 with the OT system
321 "SCADA master station" and the IT system 322 "Process historian"), its sets written by the real Celery tasks
on the test MongoDB with the synthetic MITRE index and fake AI models, its controls picked from the CII library;
then its routes, the shared routes that read it and the shared ones that refuse it."""

import json
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from celery import states
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    Collection,
    ConflictReason,
    ControlLinks,
    Header,
    IntelSource,
    MitreStage,
    RunPipeline,
    ScenarioStatus,
    Status,
    TaskName,
    TechniqueControlState,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.exceptions import Unavailable
from app.crud import admin as admin_crud
from app.crud import scenarios as scenario_crud
from app.crud.mitre.mitre_stix import get_mitre_enterprise_stix_repository, get_mitre_ics_stix_repository
from app.domain.scenario import attack_controls
from app.domain.scenario.mitre_scenario import mitre_session
from app.worker import jobs
from app.worker.scenario import controls_job
from app.worker.scenario import tasks as scenario_tasks
from app.worker.scenario.mitre import mitre_tasks
from tests.fakes import FakeChatModel, FakeEmbeddings
from tests.mitre.mitre_samples import actor_row, documents, sample_index, writer_answer
from tests.test_attack_controls import CONTROLS, MFA_IT, MFA_OT, WORDS, Picking, scenarios_in
from tests.test_attack_controls import _link as link_controls
from tests.test_control_mapping import _OT_CONTEXT, _ScoresByText, _snapshot

GRID = {"asset_id": 103, "supporting_system_id": [321, 322]}
BILLING = {"asset_id": 105, "supporting_system_id": [323]}  # the IT asset with its IT system
SCADA = "SCADA master station"
#: Four crossing paths (Phishing then Modify Control Logic), one per category: none repeats another.
CATEGORIES = ("Tampering", "Denial of Service", "Spoofing", "Elevation of Privilege")
TASKS = {
    TaskName.WRITE_MITRE_SCENARIOS: mitre_tasks.write_mitre_scenarios,
    TaskName.MAP_CONTROLS: scenario_tasks.map_controls,
}


class MitreAi(FakeChatModel):
    """The MITRE run's fake AI: Zeta selected, four planned paths, each writer naming its first candidate group
    (a path titled in `failing` names a group MITRE does not document: dropped), and the picker giving each
    scenario's first sentence its first offered control. `outage_once`: that path's first write is an outage."""

    def __init__(self, failing: tuple[str, ...] = (), outage_once: str = "") -> None:
        super().__init__()
        self.failing, self.outage_once = failing, outage_once
        self.responders[AiTask.MITRE_ACTOR_SELECTION] = lambda _: {"relevant_actors": [actor_row("G0101", 5)]}
        self.responders[AiTask.MITRE_PLAN] = self._plan
        self.responders[AiTask.MITRE_WRITE] = self._write
        self.responders[AiTask.PICK_CONTROLS] = self._pick

    @staticmethod
    def _plan(_: str) -> dict[str, Any]:
        plans = [
            {
                "title": f"P{number}",
                "objective": "Disrupt the grid",
                "category": category,
                "technique_ids": ["T1566", "T0831"],
                "supporting_systems": [SCADA],
            }
            for number, category in enumerate(CATEGORIES)
        ]
        return {"plans": plans}

    def _write(self, user_prompt: str) -> dict[str, Any]:
        data = json.loads(user_prompt)
        title = data["plan"]["title"]
        if title == self.outage_once:
            self.outage_once = ""
            raise Unavailable("the AI is down")
        first = data["candidate_actors"][0]
        groups = (("Beta", "G0103"),) if title in self.failing else ((first["name"], first["mitre_id"]),)
        narrative = f"An attacker could phish an operator of the {SCADA}, then alter its control logic."
        answer = writer_answer(title=f"Grid scenario {title}", narrative=narrative, groups=groups)
        return {"scenarios": [answer | {"supporting_systems": [SCADA]}]}

    @staticmethod
    def _pick(user_prompt: str) -> dict[str, Any]:
        picked = []
        for item in scenarios_in(user_prompt):
            picks = [{"sentence": "S1", "label": item["CONTROLS"][0]["label"], "effect": "prevent"}]
            picked.append({"slot": item["slot"], "picks": picks if item["CONTROLS"] else []})
        return {"scenarios": picked}

    def titles_written(self) -> list[str]:
        """The path title of every writer call, re-asks included, in order."""
        return [json.loads(prompt)["plan"]["title"] for prompt in self.asked(AiTask.MITRE_WRITE)]


class MitreFlow:
    """The API as one caller uses it and the workers behind it: each message sent is delivered to its task."""

    def __init__(self, client: TestClient, api_key: str) -> None:
        self.client, self.chat = client, MitreAi()
        self.headers = {Header.API_KEY: api_key, Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}
        self.sent: list[tuple[Any, ...]] = []
        self.delivered = 0

    def call(self, method: str, path: str, status: int = 200, key: str | None = None, **body: Any) -> dict[str, Any]:
        headers = self.headers | {Header.IDEMPOTENCY_KEY: key or uuid.uuid4().hex}
        response = self.client.request(method, path, json=body or None, headers=headers)
        assert response.status_code == status, response.text
        return dict(response.json())

    def start(self, body: dict[str, Any] = GRID) -> str:
        started = self.call("POST", "/v1/mitre_create_session", 202, **body)
        assert started["status"] == "queued" and started["status_url"] == f"/v1/mitre_sessions/{started['session_id']}"
        return str(started["session_id"])

    def work(self) -> list[tuple[str, str]]:
        """Deliver every message sent and not yet delivered, in order: each task and how it ended."""
        ran = []
        while self.delivered < len(self.sent):
            task, record_id, epoch = self.sent[self.delivered]
            self.delivered += 1
            result = TASKS[task].apply(args=(record_id, epoch), task_id=f"task-{uuid.uuid4().hex}")
            ran.append((task, result.state))
        return ran

    def status(self, session_id: str) -> dict[str, Any]:
        return self.call("GET", f"/v1/mitre_sessions/{session_id}")


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = admin_crud.create_api_client(get_mongodb(), f"mitre-run-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def flow(client: TestClient, api_key: str, sql_test_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> MitreFlow:
    """Both test assets free of runs; the asset facts from the SQL test database; the MITRE samples imported,
    M1017 (User Training, Phishing's mitigation) linked to the authentication control; the AI models, the MITRE
    index, the control library and the job queue the test's own."""
    for collection in (Collection.SESSIONS, Collection.SCENARIOS):
        get_mongodb()[collection].delete_many({"entity_id": 86, "asset_id": {"$in": [103, 105]}})
    for repository, domain in (
        (get_mitre_enterprise_stix_repository(), "enterprise"),
        (get_mitre_ics_stix_repository(), "ics"),
    ):
        repository.replace_stix_objects(documents()[domain], "mitre-run-test")
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    get_mongodb()[Collection.CONTROL_LINKS].insert_one(
        {
            "_id": "M1017",
            "name": "User Training",
            "fingerprint": "f",
            "links": [{"control_id": MFA_IT.control_id, "effect": "prevent", "reason": "r", "rerank": 90.0}],
            "prepared_at": utc_now(),
        }
    )
    made = MitreFlow(client, api_key)
    send = lambda *args, **_priority: made.sent.append(args)  # noqa: E731 - every job message, in order
    quiet = lambda _record_id: None  # noqa: E731 - no live update
    monkeypatch.setattr(scenario_crud, "get_stored_procedure_client", lambda: StoredProcedureClient(sql_test_engine))
    for module in (mitre_session, mitre_tasks, controls_job, jobs):
        monkeypatch.setattr(module, "send_job", send)
    for module in (mitre_session, mitre_tasks, controls_job):
        monkeypatch.setattr(module, "publish_session_status", quiet)
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, quiet)
    index = sample_index()
    monkeypatch.setattr(mitre_tasks, "get_current_mitre_index", lambda: index)
    monkeypatch.setattr(mitre_tasks, "get_scenario_chat_model", lambda: made.chat)
    monkeypatch.setattr(attack_controls, "get_scenario_chat_model", lambda: made.chat)
    snapshot = _snapshot(*CONTROLS, embeddings=FakeEmbeddings(WORDS))
    monkeypatch.setattr(controls_job, "get_library_search", lambda: SimpleNamespace(snapshot=lambda: snapshot))
    monkeypatch.setattr(controls_job, "get_rerank_model", lambda: _ScoresByText({}))
    for name, value in {
        "rerank_base_url": "",  # a local reranker: one scenario at a time
        "initial_set_size": 2,
        "next_set_size": 2,
        "total_scenario_count": 0,
        "attack_path_techniques": "2-8",
        "mitre_parallel_writers": 1,  # one writer at a time: the order of the writes is the test's
        "max_scenario_share_per_group": 0.5,
    }.items():
        monkeypatch.setattr(get_settings(), name, value)
    return made


def _cards(session_id: str) -> list[dict[str, Any]]:
    return sorted(
        get_mongodb()[Collection.SCENARIOS].find({"session_id": session_id}), key=lambda card: card["path_rank"]
    )


def _run(session_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})


def test_a_run_is_planned_once_and_written_set_by_set_with_the_group_share_held_across_sets(flow: MitreFlow) -> None:
    """The first set selects actors and plans once, then writes INITIAL_SET_SIZE cards whose controls the
    controls job picks; the next set writes the rest with no new plan. Zeta, the selected group, names at most
    half of the run's four scenarios. Mutation: count group usage from this set only and Zeta names all four."""
    session_id = flow.start()
    assert flow.sent == [(TaskName.WRITE_MITRE_SCENARIOS, session_id, 1)]
    run = _run(session_id)
    assert (run["pipeline"], run["step"], run["job"]["set_goal"]) == (RunPipeline.MITRE, "scenarios", 2)
    assert run["mitre"]["asset_context"]["asset_type"] == "OT" and "contact" not in json.dumps(run["mitre"])

    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    shown = flow.status(session_id)
    assert (shown["status"], shown["stage"], shown["written"], shown["run_target"]) == ("complete", "complete", 2, 4)
    assert shown["scenarios_left"] == 2 and shown["partial_scenarios"] is None
    scenarios, metadata = shown["result"]["scenarios"], shown["result"]["metadata"]
    assert [scenario["scenario_title"] for scenario in scenarios] == ["Grid scenario P0", "Grid scenario P1"]
    board_times = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["timings"]
    assert board_times["threats"] is not None and board_times["scenarios"] is not None, board_times
    first_set_leads = [scenario["relevant_groups"][0]["mitre_id"] for scenario in scenarios]
    assert first_set_leads.count("G0101") == 1, first_set_leads  # half of the 2 written, not of the 4 planned
    for scenario in scenarios:
        assert scenario["controls_status"] == Status.DONE and scenario["controls"]
        assert scenario["controls"][0]["control_id"] == MFA_OT.control_id  # the OT copy: S1 names the OT system
    assert (metadata["relevant_actors_selected"], metadata["valid_paths_found"]) == (1, 4)
    assert metadata["it_ot_crossing_required"] is True and metadata["it_ot_crossing_met"] is True
    assert [(actor["mitre_id"], actor["relevance"]) for actor in metadata["relevant_actors"]] == [("G0101", 5)]
    assert metadata["relevant_actors"][0]["evidence_quote"] and "matched_fields" in metadata["relevant_actors"][0]
    stored_removed = _run(session_id)["mitre"]["groups_removed_over_share"]  # the set's $inc, 0 included
    assert metadata["groups_removed_over_share"] == stored_removed

    get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": {"timings.controls_s": 999.0}})
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/next-set", 202)
    assert _run(session_id)["timings"] == {}  # the next set's times only, as the shared next set
    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    assert len(flow.chat.asked(AiTask.MITRE_PLAN)) == 1 and len(flow.chat.asked(AiTask.MITRE_ACTOR_SELECTION)) == 1
    board_times = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["timings"]
    assert board_times["threats"] is None and board_times["scenarios"] is not None, board_times  # no new plan
    cards = _cards(session_id)
    assert [card["path_id"] for card in cards] == ["mitre-1", "mitre-2", "mitre-3", "mitre-4"]
    leads = [card["content"]["mitre"]["relevant_groups"][0]["mitre_id"] for card in cards]
    assert leads.count("G0101") == 2, leads
    assert flow.status(session_id)["scenarios_left"] == 0
    refused = flow.call("POST", f"/v1/mitre_sessions/{session_id}/next-set", 409)
    assert refused["reason"] == ConflictReason.NOTHING_LEFT


def test_a_path_that_failed_its_checks_is_never_written_again(flow: MitreFlow) -> None:
    """P1 names a group MITRE does not document: asked twice (the one re-ask), dropped, and P2 written in its
    place; the next set writes P3 and never asks for P1 again."""
    flow.chat.failing = ("P1",)
    session_id = flow.start()
    flow.work()
    assert flow.chat.titles_written() == ["P0", "P1", "P1", "P2"]
    assert _run(session_id)["mitre"]["failed_path_ids"] == ["mitre-2"]
    assert flow.status(session_id)["result"]["metadata"]["failed_scenarios"] == 1
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/next-set", 202)
    flow.work()
    assert flow.chat.titles_written() == ["P0", "P1", "P1", "P2", "P3"]
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-3", "mitre-4"]
    assert _run(session_id)["counts"]["remaining"] == 0


def test_a_retried_set_writes_only_what_its_first_try_did_not_save(flow: MitreFlow) -> None:
    """The AI is down for P1 after P0 is saved: the job is retried, P0 is not written again and P1 is."""
    flow.chat.outage_once = "P1"
    session_id = flow.start()
    first_try = flow.work()
    assert first_try[0][0] == TaskName.WRITE_MITRE_SCENARIOS and _run(session_id)["status"] == Status.QUEUED
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1"]
    get_mongodb()[Collection.SESSIONS].update_one(
        {"_id": session_id}, {"$set": {"job.due_at": utc_now() - timedelta(seconds=1)}}
    )
    TASKS[TaskName.WRITE_MITRE_SCENARIOS].apply(args=(session_id, 1), task_id="retry")
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-2"]
    assert flow.chat.titles_written().count("P0") == 1 and _run(session_id)["status"] == Status.DONE
    assert _run(session_id)["mitre"]["stage"] == MitreStage.COMPLETE


def test_a_replay_answers_the_same_run_and_another_body_under_its_key_is_refused(flow: MitreFlow) -> None:
    key = uuid.uuid4().hex
    started = flow.call("POST", "/v1/mitre_create_session", 202, key=key, **GRID)
    replayed = flow.call("POST", "/v1/mitre_create_session", 200, key=key, **GRID)
    assert replayed["session_id"] == started["session_id"] and len(flow.sent) == 1
    refused = flow.call("POST", "/v1/mitre_create_session", 409, key=key, **BILLING)
    assert refused["reason"] == ConflictReason.IDEMPOTENCY_KEY_CONFLICT


def test_no_mitre_data_refuses_the_start_and_an_it_asset_needs_enterprise_only(flow: MitreFlow) -> None:
    get_mongodb()[Collection.MITRE_ICS_STIX].delete_many({})
    refused = flow.call("POST", "/v1/mitre_create_session", 409, **GRID)
    assert refused["reason"] == ConflictReason.INTEL_NO_DATA and "ICS" in refused["detail"]
    flow.start(BILLING)
    get_mongodb()[Collection.MITRE_ENTERPRISE_STIX].delete_many({})
    assert flow.call("POST", "/v1/mitre_create_session", 409, **BILLING)["reason"] == ConflictReason.INTEL_NO_DATA


def test_the_mitre_routes_do_not_know_another_pipelines_run(flow: MitreFlow) -> None:
    other = uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {
            "_id": other,
            "entity_id": 86,
            "asset_id": 103,
            "status": Status.DONE,
            "step": "scenarios",
            "counts": {},
            "updated_at": utc_now(),
        }
    )
    flow.call("GET", f"/v1/mitre_sessions/{other}", 404)
    flow.call("POST", f"/v1/mitre_sessions/{other}/next-set", 404)


def test_the_shared_routes_read_a_mitre_run_and_refuse_to_rewrite_it(flow: MitreFlow) -> None:
    session_id = flow.start()
    flow.work()
    run_url = f"/v1/sessions/{session_id}"
    board = flow.call("GET", run_url)
    assert board["progress"]["scenario_count"]["served"] == 2
    results = flow.call("GET", f"{run_url}/results")
    assert results["total"] == 2
    first = results["scenarios"][0]
    assert first["scenario"]["scenario_title"] == "Grid scenario P0" and first["controls"]
    assert [system["supporting_system"] for system in first["scenario"]["supporting_systems_involved"]] == [SCADA]
    assert flow.call("GET", f"{run_url}/scenarios/{first['scenario_id']}")["scenario_id"] == first["scenario_id"]
    refused = flow.call("POST", f"{run_url}/regenerate/scenarios", 409, scenario_ids=[first["scenario_id"]])
    assert refused["reason"] == ConflictReason.SCENARIOS_NOT_REGENERABLE
    refused = flow.call("POST", f"{run_url}/scenarios/next-set", 409)  # its own next-set writes its sets
    assert refused["reason"] == ConflictReason.SCENARIOS_NOT_REGENERABLE
    assert flow.work() == []


def test_a_mitre_card_is_the_shape_the_controls_picker_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """content.attack lists the lead group, each technique with its recorded mitigations and the mitigations
    once each (a non-defence left out of that list); the picker reads it and states each technique."""
    picker = Picking()
    monkeypatch.setattr(attack_controls, "get_scenario_chat_model", lambda: picker.chat)
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    not_a_defence = sorted(ControlLinks.NOT_MITIGATIONS)[0]
    scenario = {
        "scenario_title": "Operator accounts abused",
        "threat_scenario": "Zeta could log in to the SCADA server with stolen operator accounts.",
        "risk_statement": "Loss of control of the SCADA server could stop transmission.",
        "assumptions": [],
        "category": "Spoofing",
        "supporting_systems": ["SCADA server"],
        "relevant_groups": [{"name": "Zeta", "mitre_id": "G0101"}, {"name": "Gamma", "mitre_id": "G0104"}],
        "attack_techniques": [{"mitre_id": "T0859", "name": "Valid Accounts", "domain": "ics", "stix_id": "x"}],
        "mitigations": [
            {
                "technique": "T0859",
                "technique_name": "Valid Accounts",
                "mitigations": [{"mitre_id": "M0932", "name": "MFA"}, {"mitre_id": not_a_defence, "name": "Audit"}],
            }
        ],
    }
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": _OT_CONTEXT.to_record()}
    card = mitre_session.build_mitre_card(run, {"path_id": "mitre-1", "path_rank": 1}, scenario, 1)
    assert card["controls"]["status"] == Status.QUEUED and card["status"] == ScenarioStatus.DONE
    assert card["content"]["attack"] == {
        "group": {"id": "G0101", "name": "Zeta"},
        "techniques": [
            {
                "id": "T0859",
                "name": "Valid Accounts",
                "source": IntelSource.ATTACK_ICS,
                "mitigations": ["M0932", not_a_defence],
            }
        ],
        "mitigations": [{"id": "M0932", "name": "MFA"}],
    }
    assert card["content"]["systems"] == [{"id": 321, "name": "SCADA server", "entry_point": False}]
    assert attack_controls.is_attack_scenario(card)
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    record = picker.pick(card)[card["_id"]]
    assert [item["control_id"] for item in record["items"]] == [MFA_OT.control_id]
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]


def test_the_engine_gets_the_assets_facts_and_its_own_it_or_ot_types() -> None:
    asset = mitre_session.build_engine_asset_context(_OT_CONTEXT)
    assert (asset["asset_name"], asset["asset_type"], asset["sector"], asset["subsector"]) == (
        "Grid Control Centre",
        "OT",
        "Energy",
        "Electricity",
    )
    systems = asset["supporting_systems"]
    assert [(system["name"], system["type"]) for system in systems] == [("SCADA server", "OT"), ("Historian", "IT")]
    assert not {"id", "alias", "category_code"} & set(systems[0]) and systems[0]["technology_used"]
