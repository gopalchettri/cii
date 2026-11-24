"""A MITRE run end to end (ADR-010): started on the SQL test database (entity 86: OT asset 103 with the OT system
321 "SCADA master station" and the IT system 322 "Process historian"), its sets written by the real Celery tasks
on the test MongoDB with the synthetic MITRE index and fake AI models, its controls picked from the CII library;
then its routes, the shared routes that read it and the shared ones that refuse it."""

import json
import re
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from celery import states
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine

from app.ai import TruncatedAiAnswer
from app.core import metrics
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    ActionStatus,
    AiTask,
    Collection,
    ConflictReason,
    ControlLinks,
    ControlMatch,
    ControlPickDrop,
    ErrorCode,
    Header,
    IntelSource,
    MitreMessage,
    MitreStage,
    PromotionOutcome,
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
from app.crud.scenarios import get_threat_scenario_repository
from app.domain.scenario import attack_controls
from app.domain.scenario.mitre_scenario import mitre_session
from app.schemas import scenarios as views
from app.schemas.mitre.mitre_scenarios import MitreNextSetStarted
from app.worker import jobs
from app.worker.scenario import controls_job
from app.worker.scenario import tasks as scenario_tasks
from app.worker.scenario.mitre import mitre_tasks
from tests.fakes import FakeEmbeddings
from tests.mitre.mitre_samples import THREAT_TYPES, MitreChat, actor_row, documents, sample_index, writer_answer
from tests.test_attack_controls import BACKUP_OT, CONTROLS, FILTER, MFA_IT, MFA_OT, WORDS, Picking, scenarios_in
from tests.test_attack_controls import _link as link_controls
from tests.test_control_mapping import _OT_CONTEXT, _ScoresByText, _snapshot

GRID = {"asset_id": 103, "supporting_system_id": [321, 322]}
BILLING = {"asset_id": 105, "supporting_system_id": [323]}  # the IT asset with its IT system
SCADA = "SCADA master station"
#: Four crossing paths (Phishing then Modify Control Logic), one per category: none repeats another.
CATEGORIES = ("Tampering", "Denial of Service", "Spoofing", "Elevation of Privilege")
# Four distinct paths (any two share at most a third of their techniques: never duplicates), each with an ICS step.
PATH_TECHNIQUES = (("T1566", "T0831"), ("T1566", "T0813"), ("T1078", "T0831"), ("T1078", "T0813"))
TASKS = {
    TaskName.WRITE_MITRE_SCENARIOS: mitre_tasks.write_mitre_scenarios,
    TaskName.MAP_CONTROLS: scenario_tasks.map_controls,
}


class MitreAi(MitreChat):
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
                "technique_ids": list(technique_ids),
                "supporting_systems": [SCADA],
            }
            for number, (category, technique_ids) in enumerate(zip(CATEGORIES, PATH_TECHNIQUES, strict=True))
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
        techniques = []  # the path's own techniques, as the real writer copies them
        for technique in data["techniques"]:
            techniques.append({name: technique[name] for name in ("mitre_id", "name", "domain", "stix_id")})
        return {"scenarios": [answer | {"supporting_systems": [SCADA], "attack_techniques": techniques}]}

    @staticmethod
    def _pick(user_prompt: str) -> dict[str, Any]:
        """Per technique (a MITRE card's controls, owner 2026-11-24): each technique's best-linked control."""
        picked = []
        for item in scenarios_in(user_prompt):
            picks = []
            for technique in item["TECHNIQUES"]:
                picks.append(
                    {"technique": technique["id"], "label": technique["CONTROLS"][0]["label"], "effect": "prevent"}
                )
            picked.append({"slot": item["slot"], "picks": picks})
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
        session_id = started["session_id"]
        assert started["session_status"] == "active" and started["mitre"]["stage"] == MitreStage.QUEUED
        assert started["mitre"]["status_url"] == f"/v1/mitre_sessions/{session_id}"
        for field, value in self.call("GET", f"/v1/sessions/{session_id}").items():  # POST /v1/sessions' answer
            if field == "updated_at":  # as POST /v1/sessions: the saved record's time, stored to the millisecond
                assert started[field][:23] == value[:23]
            else:
                assert started[field] == value, field
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

    def mitre_details(self, session_id: str) -> dict[str, Any]:
        """The `mitre` block of GET /v1/mitre_sessions/{session_id}."""
        return self.call("GET", f"/v1/mitre_sessions/{session_id}")["mitre"]


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
    library = SimpleNamespace(get_threat_library=lambda: None)  # the threat types below replace its own
    monkeypatch.setattr(mitre_tasks, "get_library_cache", lambda: library)
    monkeypatch.setattr(mitre_tasks, "list_threat_choices", lambda _library: ([], THREAT_TYPES))
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
        "mitre_planner_max_further_rounds": 5,
    }.items():
        monkeypatch.setattr(get_settings(), name, value)
    return made


def _cards(session_id: str) -> list[dict[str, Any]]:
    return sorted(
        get_mongodb()[Collection.SCENARIOS].find({"session_id": session_id}), key=lambda card: card["path_rank"]
    )


def _run(session_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})


def _check_mitre_results_show_groups_and_techniques(flow: MitreFlow, session_id: str, written: list[dict]) -> None:
    """Both results routes give the same cards: each card's actors are its MITRE groups, the lead first and
    acting, and attack_techniques its techniques, each with its attack.mitre.org page. Mutation: build actors from
    the card's lead actor only and the names differ."""
    shared = flow.call("GET", f"/v1/sessions/{session_id}/results")
    assert flow.call("GET", f"/v1/mitre_sessions/{session_id}/results") == shared
    for card, scenario in zip(shared["scenarios"], written, strict=True):
        group_names = [group["name"] for group in scenario["relevant_groups"]]
        assert [actor["actor_name"] for actor in card["actors"]] == group_names
        lead, technique = card["actors"][0], card["attack_techniques"][0]
        assert lead["role"] == "acting" and lead["url"].startswith("https://attack.mitre.org/groups/")
        assert lead["relevance"] and lead["documented_techniques"]
        assert technique["url"].startswith("https://attack.mitre.org/techniques/") and "stix_id" not in technique
        # MITRE's procedure examples and mitigations as the MITRE status shows them (owner 2026-11-24), no stix id.
        # A technique MITRE lists no mitigation for names the parent it borrows them from (inherited_from).
        shown_mitigations = [
            entry | {"inherited_from": entry.get("inherited_from")} for entry in scenario["mitigations"]
        ]
        assert card["procedures"] and card["mitigations"] == shown_mitigations
        assert all(link["text"] for entry in card["mitigations"] for link in entry["mitigations"])
        shown_fields = ("technique", "actor", "actor_mitre_id", "actor_type", "via_software", "text")
        assert card["procedures"] == [{key: p.get(key) for key in shown_fields} for p in scenario["procedures"]]
        # The writer's threat line in the scenario block too (owner 2026-11-23), as the MITRE status shows it.
        description = card["scenario"]["threat_scenario_description"]
        assert description and description == scenario["threat_scenario_description"]
        # An AI-written threat has no threat_id (owner 2026-11-23): it names no library threat.
        threat = card["threat"]
        assert (threat["threat_id"], threat["is_threat_ai_generated"], threat["threat_catalogue_id"]) == (
            None,
            True,
            None,
        )


def _ask_next_set_with_nothing_left(flow: MitreFlow, session_id: str) -> dict:
    """A next set with nothing left: 200 (never a conflict, owner 2026-11-23), remaining 0, nothing queued."""
    epoch = _run(session_id)["job"]["epoch"]
    done = flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 200)
    assert done["remaining"] == 0 and done["epoch"] == epoch and done["message"]
    assert flow.work() == [] and _run(session_id)["job"]["epoch"] == epoch  # no job, no new epoch
    return done


def test_a_mitre_next_set_past_total_scenario_count_says_target_reached(
    flow: MitreFlow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOTAL_SCENARIO_COUNT=2 over 4 valid paths: the first set writes 2, and the next set says target_reached
    with the 2 paths it left out. Mutation: leave out the left-out count and it says nothing_left."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", 2)
    session_id = flow.start()
    flow.work()
    done = _ask_next_set_with_nothing_left(flow, session_id)
    assert (done["status"], done["written"], done["dropped"]) == ("target_reached", 2, 0)
    assert done["message"] == MitreMessage.TARGET_REACHED.format(target=2, written=2, dropped=0, left_out=2)


def test_a_run_is_planned_once_and_written_set_by_set_with_the_group_share_held_across_sets(flow: MitreFlow) -> None:
    """The first set selects actors and plans once, then writes INITIAL_SET_SIZE cards whose controls the
    controls job picks; the next set writes the rest with no new plan. Zeta, the selected group, names at most
    half of the run's four scenarios. Mutation: count group usage from this set only and Zeta names all four."""
    session_id = flow.start()
    assert flow.sent == [(TaskName.WRITE_MITRE_SCENARIOS, session_id, 1)]
    run = _run(session_id)
    assert (run["pipeline"], run["step"], run["job"]["set_goal"]) == (RunPipeline.MITRE, "threats", 2)
    assert flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["threats"] == "PENDING"  # not yet planned
    assert run["mitre"]["asset_context"]["asset_type"] == "OT" and "contact" not in json.dumps(run["mitre"])

    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    body = flow.call("GET", f"/v1/mitre_sessions/{session_id}")
    for field, value in flow.call("GET", f"/v1/sessions/{session_id}").items():  # the same board, plus `mitre`
        assert body[field] == value, field
    shown = body["mitre"]
    assert (body["session_status"], shown["stage"], shown["written"], shown["run_target"]) == (
        "completed",
        "complete",
        2,
        4,
    )
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
        # Picked per technique by the controls job itself (owner 2026-11-24): the reason names the technique and
        # its MITRE mitigation. Mutation: leave content.mitre out of the job's card and the sentence picker runs.
        assert re.match(r"prevent: T\d{4}(\.\d{3})? .+ \(MITRE M\d{4}", scenario["controls"][0]["match_reason"])
    assert len(flow.chat.asked(AiTask.PICK_CONTROLS)) == 1  # the set's one pick, from the mitigations' links
    assert (metadata["relevant_actors_selected"], metadata["valid_paths_found"]) == (1, 4)
    assert metadata["it_ot_crossing_required"] is True and metadata["it_ot_crossing_met"] is True
    assert [(actor["mitre_id"], actor["relevance"]) for actor in metadata["relevant_actors"]] == [("G0101", 5)]
    assert metadata["relevant_actors"][0]["evidence_quote"] and "matched_fields" in metadata["relevant_actors"][0]
    assert "reason" not in metadata["relevant_actors"][0]  # the AI's unchecked words are never shown
    _check_mitre_results_show_groups_and_techniques(flow, session_id, scenarios)
    stored_removed = _run(session_id)["mitre"]["groups_removed_over_share"]  # the set's $inc, 0 included
    assert metadata["groups_removed_over_share"] == stored_removed

    get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": {"timings.controls_s": 999.0}})
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    assert _run(session_id)["timings"] == {}  # the next set's times only, as the shared next set
    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    first_plan, further_round = (json.loads(prompt) for prompt in flow.chat.asked(AiTask.MITRE_PLAN))
    assert "planned_already" not in first_plan and flow.chat.writer_calls == 2  # one call a set
    assert len(further_round["planned_already"]) == 4  # asked at the end of the set that left no open path
    assert len(flow.chat.asked(AiTask.MITRE_ACTOR_SELECTION)) == 1
    board_times = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["timings"]
    # The next set's own threats time too, as the shared next set's: the click until writing began and the
    # further round it asked (owner 2026-11-23; it was null).
    assert board_times["threats"] is not None and board_times["scenarios"] is not None, board_times
    cards = _cards(session_id)
    assert [card["path_id"] for card in cards] == ["mitre-1", "mitre-2", "mitre-3", "mitre-4"]
    leads = [card["content"]["mitre"]["relevant_groups"][0]["mitre_id"] for card in cards]
    assert leads.count("G0101") == 2, leads
    stored = _run(session_id)["mitre"]  # the round found nothing new (the same 4 again): the plan is complete
    assert (stored["paths_complete"], stored["further_rounds"], len(stored["paths"])) == (True, 1, 4)
    assert flow.mitre_details(session_id)["scenarios_left"] == 0
    assert flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["scenario_count"]["remaining"] == 0
    done = _ask_next_set_with_nothing_left(flow, session_id)
    assert (done["status"], done["written"], done["dropped"]) == ("nothing_left", 4, 0)
    assert done["message"].endswith(MitreMessage.PLANNER_FOUND_EVERY_PATH)


def test_a_path_that_failed_its_checks_is_never_written_again(flow: MitreFlow) -> None:
    """P1 names a group MITRE does not document: asked twice (the one re-ask), dropped, and P2 written in its
    place; the next set writes P3 and never asks for P1 again."""
    flow.chat.failing = ("P1",)
    session_id = flow.start()
    flow.work()
    assert flow.chat.titles_written() == ["P0", "P1", "P1", "P2"]
    assert _run(session_id)["mitre"]["failed_path_ids"] == ["mitre-2"]
    assert flow.mitre_details(session_id)["result"]["metadata"]["failed_scenarios"] == 1
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    assert flow.chat.titles_written() == ["P0", "P1", "P1", "P2", "P3"]
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-3", "mitre-4"]
    assert _run(session_id)["counts"]["remaining"] == 0


def test_a_next_set_whose_paths_all_fail_ends_partial_and_keeps_the_runs_cards(flow: MitreFlow) -> None:
    """The first set writes P0 and P1; the next set's P2 and P3 both fail their checks, so it writes nothing. The
    run keeps its 2 cards and its result: the set ends partial (delivered 0), as the shared next set does.
    Mutation: fail the run for any set that wrote nothing and the session reads failed with no result."""
    flow.chat.failing = ("P2", "P3")
    session_id = flow.start()
    flow.work()
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    board = flow.call("GET", f"/v1/sessions/{session_id}")
    assert board["session_status"] == "completed" and board["progress"]["scenarios"] == "COMPLETE"
    summary = board["progress"]["last_next_set"]
    assert (summary["outcome"], summary["delivered"], summary["remaining"]) == ("partial", 0, 0)
    assert len(flow.mitre_details(session_id)["result"]["scenarios"]) == 2
    assert _run(session_id)["mitre"]["failed_path_ids"] == ["mitre-3", "mitre-4"]
    done = _ask_next_set_with_nothing_left(flow, session_id)  # never scenarios_abandoned (owner 2026-11-23)
    assert (done["status"], done["written"], done["dropped"]) == ("nothing_left", 2, 2)
    assert "2 scenarios written, 2 dropped by the MITRE checks" in done["message"]


def test_the_run_stops_at_total_scenario_count_and_a_spare_path_stands_in_for_a_dropped_one(
    flow: MitreFlow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOTAL_SCENARIO_COUNT=3 over 4 valid paths: P1 is dropped, P2 and then P3 stand in, and the run ends at 3
    cards with P3 never asked twice. Mutation: run_target = len(paths) and the run targets 4."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", 3)
    flow.chat.failing = ("P1",)
    session_id = flow.start()
    flow.work()
    shown = flow.mitre_details(session_id)
    assert (shown["written"], shown["run_target"], shown["scenarios_left"]) == (2, 3, 1)
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-3", "mitre-4"]
    assert flow.mitre_details(session_id)["scenarios_left"] == 0 and _run(session_id)["counts"]["planned"] == 3
    done = _ask_next_set_with_nothing_left(flow, session_id)  # all 4 paths used: 3 written, 1 dropped
    assert (done["status"], done["written"], done["dropped"]) == ("nothing_left", 3, 1)
    assert len(flow.chat.asked(AiTask.MITRE_PLAN)) == 1  # a counted run asks once: never a further round


def _grid_plan(title: str, category: str, technique_ids: list[str]) -> dict[str, Any]:
    return {
        "title": title,
        "objective": "Disrupt the grid",
        "category": category,
        "technique_ids": technique_ids,
        "supporting_systems": [SCADA],
    }


def test_an_all_paths_run_asks_for_further_paths_until_a_round_adds_none(flow: MitreFlow) -> None:
    """TOTAL_SCENARIO_COUNT=0, no number asked: the first plan gives 2 paths and the first set writes them; that
    set, left with no open path, asks the planner for further ones (planned_already) at its end and keeps the 1
    new (its copy dropped), so the board shows 1 left; the next set writes it and its round adds none: the plan
    is complete and next-set is 409. Mutation: ask the round only inside a later next-set and the board shows 0
    left with the plan still open (a client following the board stops early)."""
    first = [
        _grid_plan("P0", "Tampering", ["T1566", "T0831"]),
        _grid_plan("P1", "Denial of Service", ["T1566", "T0813"]),
    ]
    further = [_grid_plan("Q0", "Tampering", ["T1566", "T0831"]), _grid_plan("Q1", "Spoofing", ["T1078", "T0831"])]

    def answer(user_prompt: str) -> dict[str, Any]:
        return {"plans": further if "planned_already" in json.loads(user_prompt) else first}

    flow.chat.responders[AiTask.MITRE_PLAN] = answer
    session_id = flow.start()
    flow.work()
    shown, stored = flow.mitre_details(session_id), _run(session_id)
    assert (shown["written"], shown["run_target"], shown["scenarios_left"]) == (2, 3, 1)
    assert flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["scenario_count"]["remaining"] == 1
    assert [path["path_id"] for path in stored["mitre"]["paths"]] == ["mitre-1", "mitre-2", "mitre-3"]
    assert (stored["mitre"]["paths_complete"], stored["counts"]["planned"], stored["counts"]["remaining"]) == (
        False,
        3,
        1,
    )
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    planner_inputs = [json.loads(prompt) for prompt in flow.chat.asked(AiTask.MITRE_PLAN)]
    assert [inputs.get("paths_requested") for inputs in planner_inputs] == ["all", "all further", "all further"]
    assert len(planner_inputs[2]["planned_already"]) == 3
    stored = _run(session_id)["mitre"]
    assert (stored["paths_complete"], stored["further_rounds"], stored["planner_stopped_at_round_cap"]) == (
        True,
        2,
        False,
    )
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-2", "mitre-3"]
    metadata = flow.mitre_details(session_id)["result"]["metadata"]
    assert (metadata["valid_paths_found"], metadata["planner_further_rounds"], metadata["paths_complete"]) == (
        3,
        2,
        True,
    )
    assert _ask_next_set_with_nothing_left(flow, session_id)["status"] == "nothing_left"


def test_a_further_round_lost_to_an_outage_is_retried_after_the_cards_are_saved(flow: MitreFlow) -> None:
    """The first set's end-of-set round hits an AI outage: its 2 cards are already saved and their controls
    queued; the job is retried, writes nothing again and asks the round, which adds the new path. Mutation:
    treat the lost round as "none left" and the run stops at 2."""
    first = [
        _grid_plan("P0", "Tampering", ["T1566", "T0831"]),
        _grid_plan("P1", "Denial of Service", ["T1566", "T0813"]),
    ]
    further = [_grid_plan("Q1", "Spoofing", ["T1078", "T0831"])]
    outages = [1]

    def answer(user_prompt: str) -> dict[str, Any]:
        if "planned_already" not in json.loads(user_prompt):
            return {"plans": first}
        if outages:
            outages.pop()
            raise Unavailable("the AI is down")
        return {"plans": further}

    flow.chat.responders[AiTask.MITRE_PLAN] = answer
    session_id = flow.start()
    flow.work()
    assert _run(session_id)["status"] == Status.QUEUED and len(_cards(session_id)) == 2  # retried, nothing lost
    get_mongodb()[Collection.SESSIONS].update_one(
        {"_id": session_id}, {"$set": {"job.due_at": utc_now() - timedelta(seconds=1)}}
    )
    TASKS[TaskName.WRITE_MITRE_SCENARIOS].apply(args=(session_id, 1), task_id="retry")
    assert flow.chat.writer_calls == 1 and flow.mitre_details(session_id)["scenarios_left"] == 1
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-2", "mitre-3"]


def test_create_leaves_the_further_round_to_the_next_set_that_runs_short(
    flow: MitreFlow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MITRE_PLANNER_MAX_FURTHER_ROUNDS=1 (as in .env), 3 planned paths, sets of 2: create writes 2 and leaves 1
    open, so it asks no further round (no AI call for a set the user may never ask for); the next set, 1 open
    for a set of 2, asks the round first and writes the open path and the round's new one. Mutation: ask the
    round at the end of a set left with fewer open paths than NEXT_SET_SIZE and create makes a second planner
    call."""
    first = [
        _grid_plan("P0", "Tampering", ["T1566", "T0831"]),
        _grid_plan("P1", "Denial of Service", ["T1566", "T0813"]),
        _grid_plan("P2", "Spoofing", ["T1078", "T0831"]),
    ]
    monkeypatch.setattr(get_settings(), "mitre_planner_max_further_rounds", 1)
    further = [_grid_plan("Q1", "Elevation of Privilege", ["T1078", "T0813"])]

    def answer(user_prompt: str) -> dict[str, Any]:
        return {"plans": further if "planned_already" in json.loads(user_prompt) else first}

    flow.chat.responders[AiTask.MITRE_PLAN] = answer
    session_id = flow.start()
    flow.work()
    assert len(flow.chat.asked(AiTask.MITRE_PLAN)) == 1 and flow.mitre_details(session_id)["scenarios_left"] == 1
    assert _run(session_id)["mitre"]["paths_complete"] is False  # the board still offers the next set
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    assert len(flow.chat.asked(AiTask.MITRE_PLAN)) == 2
    assert flow.chat.titles_written() == ["P0", "P1", "P2", "Q1"]


def test_further_rounds_stop_at_their_cap(flow: MitreFlow, monkeypatch: pytest.MonkeyPatch) -> None:
    """MITRE_PLANNER_MAX_FURTHER_ROUNDS=1: the first plan has 1 path for a set of 2, so the one round is asked
    before writing and adds a path; the set writes both and the plan is complete at the cap and says so.
    Mutation: ignore the cap and paths_complete stays False."""
    monkeypatch.setattr(get_settings(), "mitre_planner_max_further_rounds", 1)
    first = [_grid_plan("P0", "Tampering", ["T1566", "T0831"])]
    further = [_grid_plan("Q1", "Spoofing", ["T1078", "T0813"])]

    def answer(user_prompt: str) -> dict[str, Any]:
        return {"plans": further if "planned_already" in json.loads(user_prompt) else first}

    flow.chat.responders[AiTask.MITRE_PLAN] = answer
    session_id = flow.start()
    flow.work()
    stored = _run(session_id)["mitre"]
    assert (stored["paths_complete"], stored["planner_stopped_at_round_cap"], len(stored["paths"])) == (True, True, 2)
    assert flow.chat.titles_written() == ["P0", "Q1"]  # the set is full: the round's path written with it
    assert flow.mitre_details(session_id)["scenarios_left"] == 0
    assert len(flow.chat.asked(AiTask.MITRE_PLAN)) == 2


def test_the_run_never_writes_past_total_scenario_count(flow: MitreFlow, monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTAL_SCENARIO_COUNT=3, sets of 2: the next set writes only the 1 card left, not 2."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", 3)
    session_id = flow.start()
    flow.work()
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    flow.work()
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-2", "mitre-3"]
    assert flow.chat.titles_written() == ["P0", "P1", "P2"]
    assert flow.mitre_details(session_id)["scenarios_left"] == 0


def test_a_retried_set_writes_only_what_its_first_try_did_not_save(flow: MitreFlow) -> None:
    """The AI is down while the set's one writer call runs: nothing is saved, the job is retried and writes each
    path once."""
    flow.chat.outage_once = "P1"
    session_id = flow.start()
    first_try = flow.work()
    assert first_try[0][0] == TaskName.WRITE_MITRE_SCENARIOS and _run(session_id)["status"] == Status.QUEUED
    assert _cards(session_id) == []
    get_mongodb()[Collection.SESSIONS].update_one(
        {"_id": session_id}, {"$set": {"job.due_at": utc_now() - timedelta(seconds=1)}}
    )
    TASKS[TaskName.WRITE_MITRE_SCENARIOS].apply(args=(session_id, 1), task_id="retry")
    assert [card["path_id"] for card in _cards(session_id)] == ["mitre-1", "mitre-2"]
    assert flow.chat.writer_calls == 2 and _run(session_id)["status"] == Status.DONE
    assert _run(session_id)["mitre"]["stage"] == MitreStage.COMPLETE


def test_a_replay_answers_the_same_run_and_another_body_under_its_key_is_refused(flow: MitreFlow) -> None:
    key = uuid.uuid4().hex
    started = flow.call("POST", "/v1/mitre_create_session", 202, key=key, **GRID)
    replayed = flow.call("POST", "/v1/mitre_create_session", 200, key=key, **GRID)
    assert replayed["session_id"] == started["session_id"] and len(flow.sent) == 1
    assert set(replayed) == set(started)  # a replay answers the same shape: the run's current board
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
    flow.call("GET", f"/v1/mitre_sessions/{other}/results", 404)
    flow.call("POST", f"/v1/mitre_sessions/{other}/scenarios/next-set", 404)
    flow.call("POST", f"/v1/mitre_sessions/{other}/accept", 404, mode="all")
    flow.call("POST", f"/v1/mitre_sessions/{other}/scenarios/reject", 404, scenario_ids=["x"])
    flow.call("POST", f"/v1/mitre_sessions/{other}/regenerate/scenarios", 404, scenario_ids=["x"])
    flow.call("POST", f"/v1/mitre_sessions/{other}/scenarios/x/promote-to-library", 404)


def _first_set(flow: MitreFlow) -> tuple[str, list[str]]:
    """A MITRE run with its first set written and its controls picked: the run and its two scenario ids."""
    session_id = flow.start()
    flow.work()
    scenario_ids = []
    for scenario in flow.mitre_details(session_id)["result"]["scenarios"]:
        scenario_ids.append(scenario["scenario_id"])
    return session_id, scenario_ids


def test_a_mitre_run_is_reviewed_with_the_group_6_answers(flow: MitreFlow) -> None:
    """Accept, reject and promote answer as their group 6 twins; promote proposes the risk title as an AI threat
    of the library type the writer copied, and only once the scenario is accepted."""
    session_id, (first, second) = _first_set(flow)
    run_url = f"/v1/mitre_sessions/{session_id}"
    accepted = flow.call("POST", f"{run_url}/accept", mode="subset", scenario_ids=[first])
    assert set(accepted) == set(views.AcceptResult.model_fields) and accepted["accepted"] == [first]
    rejected = flow.call("POST", f"{run_url}/scenarios/reject", scenario_ids=[second])
    assert set(rejected) == set(views.RejectResult.model_fields) and rejected["rejected"] == [second]
    count = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["scenario_count"]
    assert (count["accepted"], count["rejected"], count["pending_review"]) == (1, 1, 0)
    shown = flow.call("GET", f"/v1/sessions/{session_id}/results")["scenarios"][0]["scenario"]
    assert (shown["threat_name"], shown["threat_type"]) == (
        "Unauthorized changes disrupt pumping",
        "Unauthorised access",
    )
    refused = flow.call("POST", f"{run_url}/scenarios/{second}/promote-to-library", 409)
    assert refused["reason"] == ConflictReason.SCENARIO_NOT_ACCEPTED
    promoted = flow.call("POST", f"{run_url}/scenarios/{first}/promote-to-library")
    assert set(promoted) == set(views.PromotionResult.model_fields)
    (proposed,) = promoted["results"]
    assert (proposed["threat"], proposed["threat_type"]) == (
        "Unauthorized changes disrupt pumping",
        "Unauthorised access",
    )
    assert proposed["outcome"] in (PromotionOutcome.INSERTED, PromotionOutcome.EXISTING)  # one name a test database
    # Owner 2026-11-24: a MITRE threat is saved OT when its path has an ICS technique, else IT.
    cards = flow.call("GET", f"/v1/sessions/{session_id}/results")["scenarios"]
    card = next(shown for shown in cards if shown["scenario_id"] == first)
    attacks_ot = any(technique["domain"] == "ics" for technique in card["attack_techniques"])
    if proposed["outcome"] == PromotionOutcome.INSERTED:
        assert proposed["asset_type"] == ("OT" if attacks_ot else "IT")


def test_a_regenerated_mitre_scenario_is_its_next_version_over_the_earlier_one(flow: MitreFlow) -> None:
    """The path is written again (no other path), saved as version 2 replacing version 1, which stays readable;
    the board's last_regen says one replaced. Mutation: save without superseding and two current cards remain."""
    session_id, (first, _) = _first_set(flow)
    started = flow.call("POST", f"/v1/mitre_sessions/{session_id}/regenerate/scenarios", 202, scenario_ids=[first])
    assert set(started) == set(views.RunActionStarted.model_fields) and started["status"] == ActionStatus.REGENERATING
    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    assert flow.chat.titles_written() == ["P0", "P1", "P0"]
    versions = _cards(session_id)[:2]
    assert [(card["version"], card["replaces"]) for card in versions] == [(1, None), (2, first)]
    assert versions[0]["superseded_by"] == versions[1]["_id"] and versions[1]["superseded_by"] is None
    progress = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]
    assert (progress["last_regen"]["replaced"], progress["last_regen"]["outcome"]) == (1, "complete")
    # The regenerate's own threats and writing times, as the shared regenerate's (owner 2026-11-23).
    assert set(_run(session_id)["timings"]) >= {"threats_s", "scenarios_s"}
    assert progress["timings"]["threats"] is not None and progress["timings"]["scenarios"] is not None
    assert flow.mitre_details(session_id)["written"] == 2
    lease = SimpleNamespace(
        record={"job": {"batch": [{"path_id": "mitre-1", "replaces": first}]}}, record_id=session_id
    )
    assert mitre_tasks.find_cards_to_rewrite(lease, get_threat_scenario_repository()) == ({}, 1)  # never written twice


def test_a_mitre_rewrite_that_fails_its_checks_keeps_the_earlier_version(flow: MitreFlow) -> None:
    session_id, (first, _) = _first_set(flow)
    flow.chat.failing = ("P0",)
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/regenerate/scenarios", 202, scenario_ids=[first])
    assert flow.work() == [(TaskName.WRITE_MITRE_SCENARIOS, states.SUCCESS)]
    card = get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})
    assert card["superseded_by"] is None and card["regenerate_error"]["code"] == ErrorCode.GENERATION_FAILED
    last_regen = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["last_regen"]
    assert (last_regen["replaced"], last_regen["outcome"]) == (0, "partial")


def test_a_next_set_with_no_open_path_and_the_plan_still_open_says_it_asks_the_planner_first(flow: MitreFlow) -> None:
    """An "all paths" plan still open with no open path (its end-of-set round not asked yet): the next set starts
    (202 generating, remaining 0) and says its job asks the planner first. Mutation: answer nothing_left when
    remaining is 0 and the plan, still open, is never asked for more."""
    session_id, _ = _first_set(flow)
    opened = {"counts.remaining": 0, "mitre.paths_complete": False}
    get_mongodb()[Collection.SESSIONS].update_one({"_id": session_id}, {"$set": opened})
    started = flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    assert (started["status"], started["remaining"]) == (ActionStatus.GENERATING, 0)
    written = _run(session_id)["counts"]["written"]
    assert started["message"] == MitreMessage.SET_PLANNING_FIRST.format(written=written, dropped=0)


def test_the_mitre_next_set_answers_as_the_group_6_next_set(flow: MitreFlow) -> None:
    session_id, _ = _first_set(flow)
    before = _run(session_id)["counts"]
    started = flow.call("POST", f"/v1/mitre_sessions/{session_id}/scenarios/next-set", 202)
    assert set(started) == set(MitreNextSetStarted.model_fields) and started["status"] == ActionStatus.GENERATING
    # The 202 carries the run's counts as the click finds them too (owner 2026-11-23: never null on a next set).
    counted = (started["remaining"], started["written"], started["dropped"])
    assert counted == (before["remaining"], before["written"], 0) and started["remaining"] > 0, started
    size = min(get_settings().next_set_size, before["remaining"])
    assert started["message"] == MitreMessage.SET_STARTED.format(
        size=size, remaining=before["remaining"], written=before["written"], dropped=0
    )
    flow.work()
    last_next_set = flow.call("GET", f"/v1/sessions/{session_id}")["progress"]["last_next_set"]
    assert (last_next_set["requested"], last_next_set["delivered"], last_next_set["outcome"]) == (2, 2, "complete")


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
        "threat_scenario_description": "Unauthorized control of the SCADA server",
        "threat_type": "Unauthorised access",
        "threat_type_id": 2,
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
    # The API's threat_id: the shared "ai:<name>" key of the threat, never the path's number (owner 2026-11-23).
    assert card["content"]["threat"]["key"] == "ai:unauthorized control of the scada server"
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
    picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0859", "Operator authentication", "prevent"))
    )
    record = picker.pick(card)[card["_id"]]
    assert [item["control_id"] for item in record["items"]] == [MFA_OT.control_id]
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]


# ----------------------------------------------------------------------------- controls per technique (2026-11-24)


def picking_per_technique(*picks: tuple[str, str, str, str]) -> Any:
    """The AI's per-technique answer: per (slot, technique, control name, effect), the label the prompt gives that
    control; a name the prompt does not list is answered as the label itself."""

    def answer(user_prompt: str) -> dict[str, Any]:
        asked = scenarios_in(user_prompt)
        by_slot: dict[str, list[dict[str, Any]]] = {item["slot"]: [] for item in asked}
        for slot, technique, name, effect in picks:
            item = next(entry for entry in asked if entry["slot"] == slot)
            labels = {}
            for listed in item["TECHNIQUES"]:
                for control in listed["CONTROLS"]:
                    labels.setdefault(control["name"], control["label"])
            by_slot[slot].append({"technique": technique, "label": labels.get(name, name), "effect": effect})
        return {"scenarios": [{"slot": slot, "picks": picks_of} for slot, picks_of in by_slot.items()]}

    return answer


TECHNIQUE_NAMES = {
    "T0859": "Valid Accounts",
    "T0809": "Data Destruction",
    "T0886": "Remote Services",
    "T0800": "X",
    "T1070.004": "File Deletion",
}
MITIGATION_NAMES = {"M0932": "Multi-factor Authentication", "M0953": "Data Backup", "M0930": "Network Segmentation"}


def _mitre_card(
    mitigated_by: dict[str, list[str]], targeted: dict[str, str] | None = None, inherited: dict[str, str] | None = None
) -> dict[str, Any]:
    """A MITRE card on the SCADA server (OT) and the Historian (IT): each technique with its MITRE mitigations, and
    the system a technique targets (MITRE systems_targeted) when given."""
    scenario = {
        "scenario_title": "Operator accounts abused",
        "threat_scenario_description": "Unauthorized control of the SCADA server",
        "threat_type": "Unauthorised access",
        "threat_type_id": 2,
        "threat_scenario": "Zeta logs in to the SCADA server and wipes the Historian.",
        "risk_statement": "Loss of control of the SCADA server could stop transmission.",
        "assumptions": [],
        "category": "Spoofing",
        "supporting_systems": ["SCADA server", "Historian"],
        "relevant_groups": [{"name": "Zeta", "mitre_id": "G0101"}],
        "attack_techniques": [
            {"mitre_id": technique, "name": TECHNIQUE_NAMES[technique], "domain": "ics", "stix_id": "x"}
            for technique in mitigated_by
        ],
        "mitigations": [
            {
                "technique": technique,
                "technique_name": TECHNIQUE_NAMES[technique],
                "mitigations": [
                    {"mitre_id": m, "name": MITIGATION_NAMES.get(m, "None"), "text": f"MITRE: {m} for {technique}"}
                    for m in mitigations
                ],
            }
            | ({"inherited_from": (inherited or {})[technique]} if technique in (inherited or {}) else {})
            for technique, mitigations in mitigated_by.items()
        ],
        "systems_targeted": [
            {"technique": technique, "supporting_system": system, "mitre_assets": []}
            for technique, system in (targeted or {}).items()
        ],
    }
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": _OT_CONTEXT.to_record()}
    return mitre_session.build_mitre_card(run, {"path_id": "mitre-1", "path_rank": 1}, scenario, 1)


@pytest.fixture
def technique_picker(monkeypatch: pytest.MonkeyPatch) -> Picking:
    """The pick's fake models, and no MITRE link stored yet."""
    picker = Picking()
    monkeypatch.setattr(attack_controls, "get_scenario_chat_model", lambda: picker.chat)
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    return picker


def _offered(picker: Picking) -> dict[str, list[tuple[str, str]]]:
    """Each technique's offered (control name, the ID of the MITRE mitigation it is linked to) in the last pick
    prompt, slot 1."""
    return {
        technique["id"]: [(control["name"], control["mitigation"]) for control in technique["CONTROLS"]]
        for technique in _asked_techniques(picker)
    }


def _asked_techniques(picker: Picking) -> list[dict[str, Any]]:
    (item,) = scenarios_in(picker.chat.asked(AiTask.PICK_CONTROLS)[-1])
    return list(item["TECHNIQUES"])


def test_a_mitre_cards_controls_come_per_technique_from_its_own_mitigations(technique_picker: Picking) -> None:
    """Owner 2026-11-24: each technique offers only the controls linked to ITS MITRE mitigations, of the IT/OT type
    of the system it acts on; a pick of another technique's control is dropped; every control names its
    technique and mitigation. Mutation: offer the card's links to every technique and Offline backup is kept
    for Valid Accounts."""
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card({"T0859": ["M0932"], "T0809": ["M0953"]}, targeted={"T0859": "SCADA server"})
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS,
        picking_per_technique(
            ("SC1", "T0859", "Operator authentication", "prevent"),
            ("SC1", "T0859", "Offline backup", "detect"),
            ("SC1", "T0809", "Offline backup", "recover"),
        ),
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert _offered(technique_picker) == {
        "T0859": [("Operator authentication", "M0932")],
        "T0809": [("Offline backup", "M0953")],
    }
    # Each mitigation in MITRE's own words for THAT technique: the AI holds a control to what MITRE says it does.
    assert _asked_techniques(technique_picker)[0]["MITIGATIONS"] == [
        {"id": "M0932", "name": "Multi-factor Authentication", "mitre_says": "MITRE: M0932 for T0859"}
    ]
    assert [item["control_id"] for item in record["items"]] == [MFA_OT.control_id, BACKUP_OT.control_id]
    assert record["items"][0]["rationale"] == "prevent: T0859 Valid Accounts (MITRE M0932 Multi-factor Authentication)"
    assert {item["match"] for item in record["items"]} == {ControlMatch.EXACT}
    assert [drop["reason"] for drop in record["dropped"]] == [ControlPickDrop.NOT_THIS_TECHNIQUE]
    assert record["made_with"]["picked_by"] == ControlLinks.PICKED_BY_TECHNIQUE
    assert [state["state"] for state in record["technique_states"]] == [TechniqueControlState.MATCHED] * 2


def test_a_sub_technique_without_mitigations_is_defended_through_its_parents(technique_picker: Picking) -> None:
    """Owner 2026-11-24: T1070.004 File Deletion has no MITRE mitigation of its own; it carries its parent T1070's,
    and each control it gets says so. Mutation: drop mitigations_from and the reason no longer names the parent."""
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card({"T1070.004": ["M0953"]}, inherited={"T1070.004": "T1070"})
    assert card["content"]["attack"]["techniques"][0]["mitigations_from"] == "T1070"
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T1070.004", "Offline backup", "recover"))
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert _offered(technique_picker) == {"T1070.004": [("Offline backup", "M0953")]}
    (asked,) = _asked_techniques(technique_picker)
    assert asked["mitigations_of_parent"] == "T1070"
    assert asked["MITIGATIONS"] == [{"id": "M0953", "name": "Data Backup", "mitre_says": "MITRE: M0953 for T1070.004"}]
    expected = "recover: T1070.004 File Deletion (MITRE M0953 Data Backup, for parent T1070)"
    assert [item["rationale"] for item in record["items"]] == [expected]
    assert record["technique_states"] == [{"id": "T1070.004", "state": TechniqueControlState.MATCHED}]


def test_a_control_defending_two_techniques_is_shown_once_with_both_reasons(technique_picker: Picking) -> None:
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    link_controls("M0930", (MFA_IT.control_id, 70.0))
    card = _mitre_card({"T0859": ["M0932"], "T0886": ["M0930"]})
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS,
        picking_per_technique(
            ("SC1", "T0859", "Operator authentication", "prevent"),
            ("SC1", "T0886", "Operator authentication", "prevent"),
        ),
    )
    record = technique_picker.pick(card)[card["_id"]]
    (item,) = record["items"]
    assert "T0859 Valid Accounts" in item["rationale"] and "T0886 Remote Services" in item["rationale"]
    assert [state["state"] for state in record["technique_states"]] == [TechniqueControlState.MATCHED] * 2


def test_at_most_controls_per_technique_are_kept(technique_picker: Picking) -> None:
    """CONTROLS_PER_TECHNIQUE (.env, 2): a third pick on one technique is dropped."""
    link_controls("M0932", (MFA_IT.control_id, 90.0), (FILTER.control_id, 80.0), (BACKUP_OT.control_id, 70.0))
    card = _mitre_card({"T0859": ["M0932"]})
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS,
        picking_per_technique(
            ("SC1", "T0859", "Operator authentication", "prevent"),
            ("SC1", "T0859", "Zone filter", "contain"),
            ("SC1", "T0859", "Offline backup", "recover"),
        ),
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert len(record["items"]) == get_settings().controls_per_technique == 2
    assert record["dropped"][0]["reason"] == ControlPickDrop.TOO_MANY_FOR_TECHNIQUE.format(most=2)


def test_a_card_without_a_linked_control_is_topped_up_by_the_search(technique_picker: Picking) -> None:
    """No mitigation, or only a non-defence: no_known_defence; a prepared mitigation without a linked control:
    no_library_control; one never prepared: not_prepared; only a control of the wrong IT/OT type for the system
    the technique acts on: type_mismatch. Nothing to choose from: the AI is not asked, each gap is named, and the
    card still shows the library search's nearest control (owner 2026-11-24: controls are never zero).
    Mutation: skip the top-up and the card shows no control."""
    not_a_defence = sorted(ControlLinks.NOT_MITIGATIONS)[0]
    link_controls("M0953")  # prepared, linked to no control
    link_controls("M0932", (BACKUP_OT.control_id, 80.0))  # only an OT control, for a technique on the IT Historian
    card = _mitre_card(
        {"T0800": [], "T0859": ["M0932", not_a_defence], "T0809": ["M0953"], "T0886": ["M0930"]},
        targeted={"T0859": "Historian"},
    )
    card["content"]["attack"]["techniques"].append(
        {"id": "T0890", "name": "Only a non-defence", "source": "ics", "mitigations": [not_a_defence]}
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert technique_picker.chat.asked(AiTask.PICK_CONTROLS) == []
    (item,) = record["items"]  # MIN_CONTROLS is 1 in the tests
    assert item["match"] == ControlMatch.NEAREST and item["score"] is not None
    assert item["rationale"].startswith("Nearest by the library search, too few MITRE-linked controls fitted: ")
    assert record["query"]
    assert {state["id"]: state["state"] for state in record["technique_states"]} == {
        "T0800": TechniqueControlState.NO_KNOWN_DEFENCE,
        "T0859": TechniqueControlState.TYPE_MISMATCH,
        "T0809": TechniqueControlState.NO_LIBRARY_CONTROL,
        "T0886": TechniqueControlState.NOT_PREPARED,
        "T0890": TechniqueControlState.NO_KNOWN_DEFENCE,
    }


def test_an_unreadable_answer_keeps_each_techniques_best_mitre_link(technique_picker: Picking) -> None:
    """No meaning search for a MITRE card: its techniques keep their best-linked control, labelled nearest and
    saying so. Mutation: fall back to the search and a control linked to no mitigation of the card appears."""
    link_controls("M0932", (FILTER.control_id, 60.0), (MFA_IT.control_id, 90.0))
    card = _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})
    before = metrics.CONTROL_PICKS.labels(ControlLinks.PICKED_BY_LINK)._value.get()
    technique_picker.chat.queue(AiTask.PICK_CONTROLS, TruncatedAiAnswer("the answer was cut off"))
    record = technique_picker.pick(card)[card["_id"]]
    (item,) = record["items"]
    assert item["control_id"] == MFA_OT.control_id and item["match"] == ControlMatch.NEAREST
    assert item["rationale"].endswith("picked by the MITRE link score")
    assert record["made_with"]["picked_by"] == ControlLinks.PICKED_BY_LINK
    assert metrics.CONTROL_PICKS.labels(ControlLinks.PICKED_BY_LINK)._value.get() == before + 1


def test_an_unreadable_answer_gives_every_technique_its_nearest_mitre_link(technique_picker: Picking) -> None:
    """Owner 2026-11-24: every step gets a control, a sub-technique on its parent's mitigations too; each is NEAREST.
    Mutation: skip inherited techniques and Offline backup is not shown for T1070.004."""
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card(
        {"T0859": ["M0932"], "T1070.004": ["M0953"]},
        targeted={"T0859": "SCADA server"},
        inherited={"T1070.004": "T1070"},
    )
    technique_picker.chat.queue(AiTask.PICK_CONTROLS, TruncatedAiAnswer("the answer was cut off"))
    record = technique_picker.pick(card)[card["_id"]]
    assert [item["control_id"] for item in record["items"]] == [MFA_OT.control_id, BACKUP_OT.control_id]
    assert {item["match"] for item in record["items"]} == {ControlMatch.NEAREST}
    assert record["technique_states"] == [
        {"id": "T0859", "state": TechniqueControlState.NEAREST},
        {"id": "T1070.004", "state": TechniqueControlState.NEAREST},
    ]


def test_a_technique_the_ai_finds_no_fit_for_shows_its_nearest_mitre_link(technique_picker: Picking) -> None:
    """Owner 2026-11-24: if there is no exact match the nearest is shown. The AI picks for T0859 only: T0809 gets
    its best MITRE link, NEAREST and saying so, after the exact pick. Mutation: leave T0809 empty and one item is
    shown."""
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card({"T0809": ["M0953"], "T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0859", "Operator authentication", "prevent"))
    )
    record = technique_picker.pick(card)[card["_id"]]
    exact, nearest = record["items"]
    assert (exact["control_id"], exact["match"]) == (MFA_OT.control_id, ControlMatch.EXACT)
    assert (nearest["control_id"], nearest["match"]) == (BACKUP_OT.control_id, ControlMatch.NEAREST)
    assert nearest["rationale"].endswith("(MITRE M0953 Data Backup), picked by the MITRE link score")
    assert {state["id"]: state["state"] for state in record["technique_states"]} == {
        "T0809": TechniqueControlState.NEAREST,
        "T0859": TechniqueControlState.MATCHED,
    }


def test_an_exact_pick_keeps_its_own_it_ot_copy_over_an_earlier_nearest_one(technique_picker: Picking) -> None:
    """T0809 acts on the IT Historian and T0859 on the OT SCADA server; both link to Operator authentication. The
    AI picks the OT copy for T0859 only, so T0809's nearest is the IT copy, earlier in the path: the item is the OT
    copy, EXACT, so remediation applies it to the OT system. Mutation: keep the first row and the IT copy is
    stored."""
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    card = _mitre_card(
        {"T0809": ["M0932"], "T0859": ["M0932"]}, targeted={"T0809": "Historian", "T0859": "SCADA server"}
    )
    technique_picker.chat.queue(AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0859", "C2", "prevent")))
    record = technique_picker.pick(card)[card["_id"]]
    labels = {technique["id"]: technique["CONTROLS"][0]["label"] for technique in _asked_techniques(technique_picker)}
    assert labels == {"T0809": "C1", "T0859": "C2"}  # one label per IT/OT copy
    (item,) = record["items"]
    assert (item["control_id"], item["match"]) == (MFA_OT.control_id, ControlMatch.EXACT)
    assert {state["id"]: state["state"] for state in record["technique_states"]} == {
        "T0809": TechniqueControlState.NEAREST,
        "T0859": TechniqueControlState.MATCHED,
    }


def test_a_card_short_of_min_controls_is_topped_up_once_per_control(
    technique_picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MIN_CONTROLS=3: a card with one MITRE-linked control gets the search's nearest up to 3, never one it already
    shows (or its IT/OT twin). Mutation: top up without the twin check and Operator authentication is listed
    twice."""
    monkeypatch.setattr(get_settings(), "min_controls", 3)
    monkeypatch.setattr(get_settings(), "nearest_controls", 3)
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    card = _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0859", "Operator authentication", "prevent"))
    )
    record = technique_picker.pick(card)[card["_id"]]
    names = [item["name"] for item in record["items"]]
    assert names[0] == "Operator authentication" and len(names) == len(set(names))
    assert 1 < len(names) <= 3 and record["items"][0]["match"] == ControlMatch.EXACT
    assert {item["match"] for item in record["items"][1:]} == {ControlMatch.NEAREST}
    assert [item["rank"] for item in record["items"]] == list(range(1, len(names) + 1))


def test_a_card_stored_before_mitres_words_were_kept_is_judged_by_the_mitigations_name(
    technique_picker: Picking,
) -> None:
    """A card stored before 2026-11-24 has no MITRE text: its mitigation goes without mitre_says (never a blank the
    prompt would hold every control to). Mutation: send mitre_says "" and the asked mitigation has it."""
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card({"T0809": ["M0953"]})
    for technique in card["content"]["mitre"]["mitigations"]:
        for mitigation in technique["mitigations"]:
            del mitigation["text"]
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0809", "Offline backup", "recover"))
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert _asked_techniques(technique_picker)[0]["MITIGATIONS"] == [{"id": "M0953", "name": "Data Backup"}]
    assert [item["control_id"] for item in record["items"]] == [BACKUP_OT.control_id]


def test_an_effect_a_controls_domain_cannot_have_is_corrected(
    technique_picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner 2026-11-24: a backup control restores or limits, it never prevents. The AI's "prevent" is kept as
    "recover", noted and counted. Mutation: keep the AI's effect and the reason says prevent."""
    monkeypatch.setitem(ControlLinks.EFFECTS_BY_DOMAIN, BACKUP_OT.domain, ("recover", "contain"))
    link_controls("M0953", (BACKUP_OT.control_id, 80.0))
    card = _mitre_card({"T0809": ["M0953"]})
    before = metrics.CONTROL_PICKS.labels(ControlLinks.EFFECT_CORRECTED)._value.get()
    technique_picker.chat.queue(
        AiTask.PICK_CONTROLS, picking_per_technique(("SC1", "T0809", "Offline backup", "prevent"))
    )
    record = technique_picker.pick(card)[card["_id"]]
    assert [item["rationale"] for item in record["items"]] == [
        f"recover: T0809 {TECHNIQUE_NAMES['T0809']} (MITRE M0953 Data Backup)"
    ]
    (pick,) = record["picks"]
    assert pick["effect"] == "recover" and pick["effect_corrected_from"] == "prevent"
    assert metrics.CONTROL_PICKS.labels(ControlLinks.EFFECT_CORRECTED)._value.get() == before + 1


def test_the_switch_off_picks_a_mitre_cards_controls_per_sentence_again(
    technique_picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MITRE_CONTROLS_BY_TECHNIQUE=false is the rollback: the sentence picker, as before 2026-11-24."""
    monkeypatch.setattr(get_settings(), "mitre_controls_by_technique", False)
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    card = _mitre_card({"T0859": ["M0932"]})
    technique_picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    record = technique_picker.pick(card)[card["_id"]]
    assert "SENTENCES" in scenarios_in(technique_picker.chat.asked(AiTask.PICK_CONTROLS)[-1])[0]
    assert record["items"][0]["rationale"].startswith("prevent: Zeta logs in")


@pytest.mark.parametrize("name", ["controls_per_technique", "controls_per_technique_candidates"])
def test_a_per_technique_size_below_one_is_refused(name: str) -> None:
    with pytest.raises(ValidationError):
        get_settings().model_validate({**get_settings().model_dump(), name: 0})


def test_the_engine_gets_the_assets_facts_and_its_own_it_or_ot_types() -> None:
    """Every column tsg_GetAssetContext returns reaches the engine: the named ones renamed, the platform's
    recorded type beside the engine's IT or OT, any other (target_rto_hours, asset_priority) under its own name.
    Mutation: keep a fixed list of facts and the others are dropped."""
    asset = mitre_session.build_engine_asset_context(_OT_CONTEXT)
    assert (asset["asset_name"], asset["asset_type"], asset["sector"], asset["subsector"]) == (
        "Grid Control Centre",
        "OT",
        "Energy",
        "Electricity",
    )
    assert (
        asset["service_name"] == "Electricity transmission"
        and "Runs the transmission grid" in asset["asset_description"]
    )
    assert (asset["recorded_asset_type"], asset["target_rto_hours"], asset["asset_priority"]) == (
        "Control system",
        4.0,
        "High",
    )
    assert not {"id", "cii_asset_description", "critical_service", "sub_sector"} & set(asset)
    systems = asset["supporting_systems"]
    assert [(system["name"], system["type"]) for system in systems] == [("SCADA server", "OT"), ("Historian", "IT")]
    assert not {"id", "alias", "category_code"} & set(systems[0]) and systems[0]["technology_used"]


def test_a_regenerate_keeps_its_own_lead_group_at_the_share_cap(flow: MitreFlow) -> None:
    """Zeta leads 1 of the 2 written cards: its share of 2 (0.5) is used. Regenerating Zeta's card replaces it, so
    Zeta is still offered and named again. Mutation: count the card being replaced and Zeta is over its share,
    left out of the candidates or removed from the new version."""
    session_id, scenario_ids = _first_set(flow)
    cards = {card["_id"]: card for card in _cards(session_id)}
    zeta_card = next(
        sid for sid in scenario_ids if cards[sid]["content"]["mitre"]["relevant_groups"][0]["mitre_id"] == "G0101"
    )
    flow.call("POST", f"/v1/mitre_sessions/{session_id}/regenerate/scenarios", 202, scenario_ids=[zeta_card])
    flow.work()
    new_version = next(card for card in _cards(session_id) if card.get("replaces") == zeta_card)
    assert new_version["content"]["mitre"]["relevant_groups"][0]["mitre_id"] == "G0101"


def test_the_mitre_route_shows_the_title_a_card_was_saved_under(flow: MitreFlow) -> None:
    """Two paths whose scenarios get the same title: the second card is saved under a unique title, and the MITRE
    route shows that title as /results does. Mutation: show content.mitre's own title and both read the same."""
    same = [_grid_plan("Same", "Tampering", ["T1566", "T0831"]), _grid_plan("Same", "Spoofing", ["T1078", "T0813"])]
    flow.chat.responders[AiTask.MITRE_PLAN] = lambda _prompt: {"plans": same}
    session_id = flow.start()
    flow.work()
    shown = [scenario["scenario_title"] for scenario in flow.mitre_details(session_id)["result"]["scenarios"]]
    results = flow.call("GET", f"/v1/sessions/{session_id}/results")["scenarios"]
    saved = [result["scenario"]["scenario_title"] for result in results]
    assert len(set(shown)) == 2 and sorted(shown) == sorted(saved), (shown, saved)


def test_a_mitre_card_carries_the_librarys_category_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A MITRE card's STRIDE category gets the threat library's id, as a planned card's does, so /results shows
    threat_category_id. Mutation: leave it None and every MITRE card reads as uncategorised."""
    library = SimpleNamespace(category_ids=((11, "Spoofing"), (12, "Tampering")))
    cache = SimpleNamespace(get_threat_library=lambda: library)
    monkeypatch.setattr(mitre_session, "get_library_cache", lambda: cache)
    assert (mitre_session.library_category_id(" spoofing "), mitre_session.library_category_id("Repudiation")) == (
        11,
        None,
    )
    scenario = {
        "scenario_title": "T",
        "threat_scenario_description": "R",
        "threat_scenario": "S.",
        "risk_statement": "Risk.",
        "assumptions": [],
        "category": "Tampering",
        "supporting_systems": ["SCADA server"],
        "relevant_groups": [{"name": "Zeta", "mitre_id": "G0101"}],
        "attack_techniques": [],
        "mitigations": [],
    }
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": _OT_CONTEXT.to_record()}
    content = mitre_session.build_mitre_card(run, {"path_id": "mitre-1", "path_rank": 1}, scenario, 1)["content"]
    assert (content["category_id"], content["threat"]["category_id"]) == (12, 12)
