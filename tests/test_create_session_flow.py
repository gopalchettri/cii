"""A run made by POST /v1/create_session, end to end: started on the SQL test database, written and its
controls picked by the real Celery tasks on the test MongoDB with fake AI models, then every existing run and
review API used on it, each answer read back through its response model; a second run is cancelled and deleted."""

import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, TypeVar

import pytest
from celery import states
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy import Engine

from app.core.config import get_settings
from app.core.constants import (
    ActionStatus,
    AiTask,
    AttackMessage,
    Collection,
    ConflictReason,
    ControlMatchStatus,
    EvidenceMode,
    Header,
    IntelSource,
    PromotionOutcome,
    RunPipeline,
    ScenarioStatus,
    SessionState,
    Status,
    TaskName,
    TechniqueControlState,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.crud import admin as admin_crud
from app.crud import scenarios as scenario_crud
from app.crud.attack import get_attack_repository
from app.crud.library import SqlOperationRepository, ThreatRepository
from app.domain.scenario import attack_controls
from app.schemas import jobs as job_views
from app.schemas import scenarios as views
from app.worker import jobs
from app.worker.scenario import controls_job, plan_progress, write_job
from app.worker.scenario import tasks as scenario_tasks
from tests.fakes import FakeEmbeddings
from tests.service_builders import use_scenario_parts
from tests.test_attack_controls import CONTROLS, MFA_IT, MFA_OT, WORDS, scenarios_in
from tests.test_attack_controls import _link as link_controls
from tests.test_attack_writer import USED, AttackAi, _graphs, _risks
from tests.test_control_mapping import _ScoresByText, _snapshot
from tests.test_promotion import REVIEWER, _remove_promoted_rows

Model = TypeVar("Model", bound=BaseModel)
GRID = {"asset_id": 103, "supporting_system_id": [321, 322]}  # an OT asset with an OT and an IT system
BILLING = {"asset_id": 105, "supporting_system_id": [323]}
TASKS = {TaskName.WRITE_SCENARIOS: scenario_tasks.write_scenarios, TaskName.MAP_CONTROLS: scenario_tasks.map_controls}
#: Each written statement's first sentence: it names the OT system, so its control is the OT copy.
S1 = "Sandworm Team could log in to the SCADA master station with stolen operator accounts."
CITED = "MITRE ATT&CK records that Sandworm Team uses Valid Accounts [1]."


class FlowAi(AttackAi):
    """The attack writer's fake on the SQL test database's asset; its picker gives each scenario's first
    sentence the authentication control."""

    def __init__(self, threat_type: str) -> None:
        super().__init__()
        self.other_risks = _risks(3)
        self.edit = lambda item, slot, answer: (
            item
            | {
                "threat_type": threat_type,
                "entry_point": "SCADA master station",
                "scenario_statement": f"{S1} It then alters set points ({item['scenario_title']}).",
            }
        )
        self.responders[AiTask.PICK_CONTROLS] = self._pick

    @staticmethod
    def _pick(prompt: str) -> dict[str, Any]:
        picked = []
        for item in scenarios_in(prompt):
            label = next(control["label"] for control in item["CONTROLS"] if control["name"] == MFA_IT.name)
            picked.append({"slot": item["slot"], "picks": [{"sentence": "S1", "label": label, "effect": "prevent"}]})
        return {"scenarios": picked}


class Flow:
    """The API as one caller uses it and the workers behind it: each message a call or a task sends is
    delivered to its real Celery task."""

    def __init__(self, client: TestClient, api_key: str, chat: FlowAi) -> None:
        self._client, self.chat = client, chat
        self._headers = {
            Header.API_KEY: api_key,
            Header.USER_ID: REVIEWER,
            Header.ENTITY_ID: "86",
            Header.TENANT_ID: "DESC",
        }
        self.sent: list[tuple[Any, ...]] = []
        self._delivered = 0

    def call(self, method: str, path: str, model: type[Model], status: int = 200, **body: Any) -> Model:
        """The call's answer, read back through its response model."""
        headers = self._headers | {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
        response = self._client.request(method, path, json=body or None, headers=headers)
        assert response.status_code == status, response.text
        return model.model_validate(response.json())

    def refuse(self, method: str, path: str, status: int = 409, **body: Any) -> dict[str, Any]:
        """The problem a refused call answers with."""
        response = self._client.request(method, path, json=body or None, headers=self._headers)
        assert response.status_code == status, response.text
        return dict(response.json())

    def work(self) -> list[tuple[str, str]]:
        """Deliver every message sent and not yet delivered, in order: each task and how it ended."""
        ran = []
        while self._delivered < len(self.sent):
            task, record_id, epoch = self.sent[self._delivered]
            self._delivered += 1
            result = TASKS[task].apply(args=(record_id, epoch), task_id=f"task-{self._delivered}")
            ran.append((task, result.state))
            assert len(ran) < 20, ran
        return ran

    def list_ai_calls(self) -> list[AiTask]:
        """The AI calls made since the last look, re-asks included."""
        made = [task for task, _ in self.chat.calls]
        self.chat.calls.clear()
        return made


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = admin_crud.create_api_client(get_mongodb(), f"flow-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def flow(client: TestClient, api_key: str, sql_test_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[Flow]:
    """Both test assets free of runs; the asset facts and the threat library from the SQL test database; MITRE
    ATT&CK imported and M0932 linked to the authentication control; the AI models, the control library and the
    job queue the test's own."""
    for collection in (Collection.SESSIONS, Collection.SCENARIOS):
        get_mongodb()[collection].delete_many({"entity_id": 86, "asset_id": {"$in": [103, 105]}})
    for collection in (Collection.ATTACK, Collection.CONTROL_LINKS):
        get_mongodb()[collection].delete_many({})
    get_attack_repository().create_indexes()
    for source, docs in _graphs().items():
        get_attack_repository().replace_source(source, docs, "v1")
    link_controls("M0932", (MFA_IT.control_id, 90.0))
    procedures = StoredProcedureClient(sql_test_engine)
    threats = ThreatRepository(procedures, SqlOperationRepository(procedures))
    library = threats.get_threat_library()
    made = Flow(client, api_key, FlowAi(library.types[0].name))
    send = lambda *args, **_priority: made.sent.append(args)  # noqa: E731 - every job message, in order
    quiet = lambda _record_id: None  # noqa: E731 - no live update
    monkeypatch.setattr(scenario_crud, "get_stored_procedure_client", lambda: procedures)
    use_scenario_parts(
        monkeypatch, threats=threats, threat_library=lambda: library, send_job=send, publish_session_status=quiet
    )
    for module in (jobs, write_job, controls_job):
        monkeypatch.setattr(module, "send_job", send)
    for module in (plan_progress, controls_job):
        monkeypatch.setattr(module, "publish_session_status", quiet)
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, quiet)
    monkeypatch.setattr(write_job, "get_scenario_chat_model", lambda: made.chat)
    monkeypatch.setattr(write_job, "get_library_cache", lambda: SimpleNamespace(get_threat_library=lambda: library))
    monkeypatch.setattr(attack_controls, "get_scenario_chat_model", lambda: made.chat)
    snapshot = _snapshot(*CONTROLS, embeddings=FakeEmbeddings(WORDS))
    monkeypatch.setattr(controls_job, "get_library_search", lambda: SimpleNamespace(snapshot=lambda: snapshot))
    monkeypatch.setattr(controls_job, "get_rerank_model", lambda: _ScoresByText({}))
    monkeypatch.setattr(get_settings(), "rerank_base_url", "")  # a local reranker: one scenario at a time
    monkeypatch.setattr(get_settings(), "initial_set_size", 2)
    monkeypatch.setattr(get_settings(), "next_set_size", 2)
    yield made
    _remove_promoted_rows(sql_test_engine)


def _assert_attack_confirmed(shown: views.ScenarioView, title: str | None = None) -> None:
    """The scenario shows its group acting, the recorded use it cites, and a library control picked for its
    first sentence: the OT copy of the linked control, with how it helps and the sentence as its reason."""
    assert shown.status == ScenarioStatus.DONE and shown.scenario is not None
    assert title is None or shown.scenario.scenario_title == title
    assert shown.scenario.scenario_statement is not None and shown.scenario.scenario_statement.endswith(CITED)
    (actor,) = shown.actors
    assert (actor.actor_id, actor.actor_name, actor.role) == (None, "Sandworm Team", "acting")
    assert actor.selection_reason == "G0034: It has attacked power grids."
    assert shown.evidence_mode == EvidenceMode.SOURCE_DOCUMENTED
    (cited,) = shown.evidence
    assert (cited.n, cited.ref, cited.kind, cited.source) == (1, "T0859", "technique", IntelSource.ATTACK_ICS)
    assert cited.facts == [USED, "Report: https://example.test/report"] and cited.url.endswith("/T0859")
    assert cited.mitigations == ["Multi-factor Authentication", "Access Management"]
    assert (shown.controls_status, shown.control_match_status) == (Status.DONE, ControlMatchStatus.EXACT)
    (control,) = shown.controls
    assert (control.control_id, control.control_code, control.itot) == (MFA_OT.control_id, "AC-7", "OT")
    assert (control.match_type, control.match_reason) == ("EXACT", f"prevent: {S1}")
    assert shown.threat.is_threat_ai_generated and shown.threat.threat_catalogue_id is None


def _stored(session_id: str) -> list[dict[str, Any]]:
    found = get_mongodb()[Collection.SCENARIOS].find({"session_id": session_id})
    return sorted(found, key=lambda card: (card["path_id"], card["version"]))


@pytest.mark.parametrize(
    ("total", "written", "exhausted"),
    [(4, 4, ConflictReason.TARGET_REACHED), (0, 5, ConflictReason.NOTHING_LEFT)],
    ids=["a scenario count", "no scenario count"],
)
def test_every_existing_api_works_on_a_run_made_by_create_session(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, total: int, written: int, exhausted: str
) -> None:
    """2 written and 3 more risks listed: with TOTAL_SCENARIO_COUNT 4 one is a spare, with 0 all 5 are the
    run's. Every set costs one write call and one pick call."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", total)
    started = flow.call("POST", "/v1/create_session", views.RunBoard, 202, **GRID)
    session_id, run_url = started.session_id, f"/v1/sessions/{started.session_id}"
    assert (started.session_status, started.asset_name) == (SessionState.ACTIVE, "Grid control centre")
    assert flow.sent == [(TaskName.WRITE_SCENARIOS, session_id, 1)]
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})["pipeline"] == RunPipeline.ATTACK

    # The first set: the write task, then one control mapping message for the whole set.
    assert flow.work() == [(TaskName.WRITE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    assert flow.list_ai_calls() == [AiTask.WRITE_SCENARIO, AiTask.PICK_CONTROLS]
    board = flow.call("GET", run_url, views.RunBoard)
    count = board.progress.scenario_count
    assert (count.total, count.served, count.pending_review) == (written, 2, 2) and board.error is None
    results = flow.call("GET", f"{run_url}/results", views.RunResults)
    assert results.total == 2 and results.progress == board.progress
    first, second = results.scenarios
    _assert_attack_confirmed(first, "Loss of grid control 1")
    _assert_attack_confirmed(second, "Loss of grid control 2")
    systems = first.scenario.supporting_systems_involved if first.scenario else []
    assert [(system.supporting_system, system.is_entry_point) for system in systems] == [
        ("SCADA master station", True),
        ("Process historian", False),
    ]
    one = flow.call("GET", f"{run_url}/scenarios/{first.scenario_id}", views.ScenarioView)
    assert one == first
    listed = flow.call("GET", "/v1/entities/86/scenarios", views.ScenarioList)
    assert {first.scenario_id, second.scenario_id} <= {shown.scenario_id for shown in listed.scenarios}
    trace = flow.call("GET", f"{run_url}/plan-trace", views.PlanTraceView)
    assert (trace.counts.paths, trace.counts.selected, trace.counts.not_selected) == (5, written, 5 - written)
    assert (trace.counts.ai_threats, trace.counts.first_set) == (5, 2)
    assert (trace.writing.served, trace.writing.still_to_write, trace.writing.given_up) == (2, written - 2, 0)
    card = _stored(session_id)[0]
    assert card["content"]["attack"]["techniques"] == [
        {"id": "T0859", "name": "Valid Accounts", "source": IntelSource.ATTACK_ICS, "mitigations": ["M0801", "M0932"]}
    ]
    assert card["controls"]["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]

    # Review: accept the first, rewrite the second (version 2 served), reject the new version.
    accepted = flow.call("POST", f"{run_url}/accept", views.AcceptResult, scenario_ids=[first.scenario_id])
    assert (accepted.accepted, accepted.skipped, accepted.controls_pending) == ([first.scenario_id], [], [])
    action = flow.call(
        "POST", f"{run_url}/regenerate/scenarios", views.RunActionStarted, 202, scenario_ids=[second.scenario_id]
    )
    assert (action.status, action.epoch) == (ActionStatus.REGENERATING, 2)
    assert flow.work() == [(TaskName.WRITE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
    assert flow.list_ai_calls() == [AiTask.WRITE_SCENARIO, AiTask.PICK_CONTROLS]
    results = flow.call("GET", f"{run_url}/results", views.RunResults)
    assert [shown.scenario_id for shown in results.scenarios][0] == first.scenario_id and results.total == 2
    rewritten = results.scenarios[1]
    _assert_attack_confirmed(rewritten)
    assert (rewritten.version, rewritten.scenario_id) != (1, second.scenario_id)
    assert rewritten.scenario is not None and "rewritten" in (rewritten.scenario.scenario_title or "")
    (replaced,) = rewritten.replaced_scenarios
    assert (replaced.scenario_id, replaced.replaced_by) == (second.scenario_id, rewritten.scenario_id)
    assert rewritten.threat.threat_name == second.threat.threat_name  # the slot keeps its threat
    rejected = flow.call(
        "POST", f"{run_url}/scenarios/reject", views.RejectResult, scenario_ids=[rewritten.scenario_id]
    )
    assert (rejected.rejected, rejected.skipped) == ([rewritten.scenario_id], [])

    # Next sets: the listed risks, in the AI's order, until none is left to write.
    for epoch in range(3, 3 + -(-(written - 2) // 2)):  # NEXT_SET_SIZE 2 at a time
        action = flow.call("POST", f"{run_url}/scenarios/next-set", views.RunActionStarted, 202)
        assert (action.status, action.epoch) == (ActionStatus.GENERATING, epoch)
        assert flow.work() == [(TaskName.WRITE_SCENARIOS, states.SUCCESS), (TaskName.MAP_CONTROLS, states.SUCCESS)]
        assert flow.list_ai_calls() == [AiTask.WRITE_SCENARIO, AiTask.PICK_CONTROLS]
    assert flow.refuse("POST", f"{run_url}/scenarios/next-set")["reason"] == exhausted
    results = flow.call("GET", f"{run_url}/results", views.RunResults)
    assert results.total == written
    for shown, risk in zip(results.scenarios[2:], _risks(3), strict=False):
        _assert_attack_confirmed(shown, risk["title"])
        assert shown.scenario is not None and risk["title"] in (shown.scenario.risk_statement or "")
    count = results.progress.scenario_count
    assert (count.total, count.served, count.accepted) == (written, written, 1)

    # The accepted scenario's AI threat goes to the curators.
    promoted = flow.call("POST", f"{run_url}/scenarios/{first.scenario_id}/promote-to-library", views.PromotionResult)
    (proposed,) = promoted.results
    assert (proposed.threat, proposed.outcome) == (first.threat.threat_name, PromotionOutcome.INSERTED)
    assert proposed.threat_type == first.threat.threat_type and proposed.threat_catalogue_id is not None

    # A second run is cancelled while queued (its write task then does nothing) and deleted; then the first.
    assert flow.refuse("POST", f"{run_url}/cancel")["reason"] == ConflictReason.NOTHING_TO_CANCEL
    working = flow.call("GET", "/v1/jobs", job_views.JobList).total  # other tests' runs of the entity too
    other = flow.call("POST", "/v1/create_session", views.RunBoard, 202, **BILLING)
    assert flow.call("GET", "/v1/jobs", job_views.JobList).total == working + 1
    cancelled = flow.call("POST", f"/v1/sessions/{other.session_id}/cancel", views.RunBoard)
    assert cancelled.session_status == SessionState.CANCELLED
    assert flow.call("GET", "/v1/jobs", job_views.JobList).total == working
    assert flow.work() == [(TaskName.WRITE_SCENARIOS, states.IGNORED)]
    assert (flow.list_ai_calls(), _stored(other.session_id)) == ([], [])
    gone = flow.call("DELETE", f"/v1/sessions/{other.session_id}", job_views.SessionDeleted)
    assert (gone.scenarios, gone.remediation_plans) == (0, 0)
    gone = flow.call("DELETE", run_url, job_views.SessionDeleted)
    assert (gone.session_id, gone.scenarios) == (session_id, written + 1)  # each slot's card and the version replaced
    assert flow.refuse("GET", run_url, 404)["status"] == 404 and _stored(session_id) == []


def test_a_next_set_or_rewrite_asks_for_the_attack_data_and_never_for_the_evidence_snapshot(
    flow: Flow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An attack run searches no evidence: external intelligence on with nothing indexed refuses a
    POST /v1/sessions run's write job, never this run's; with no ICS matrix stored nothing could confirm
    this OT asset's techniques, so the write job is refused before it is queued, Enterprise still imported.
    Mutation: ask only whether any ATT&CK data is stored, and both jobs are queued to write scenarios that
    are all refused."""
    started = flow.call("POST", "/v1/create_session", views.RunBoard, 202, **GRID)
    run_url = f"/v1/sessions/{started.session_id}"
    flow.work()
    first, second = flow.call("GET", f"{run_url}/results", views.RunResults).scenarios
    nothing_indexed = SimpleNamespace(get=lambda *_, **__: None)
    use_scenario_parts(monkeypatch, switch=SimpleNamespace(is_on=lambda **_: True), intel_snapshots=nothing_indexed)
    flow.call("POST", f"{run_url}/regenerate/scenarios", views.RunActionStarted, 202, scenario_ids=[first.scenario_id])
    assert flow.work()[0] == (TaskName.WRITE_SCENARIOS, states.SUCCESS)
    get_attack_repository().delete(source=IntelSource.ATTACK_ICS)  # as before its first import
    assert get_attack_repository().has_data()
    sent = len(flow.sent)
    for refused in (
        flow.refuse("POST", f"{run_url}/scenarios/next-set"),
        flow.refuse("POST", f"{run_url}/regenerate/scenarios", scenario_ids=[second.scenario_id]),
    ):
        assert (refused["reason"], refused["detail"]) == (ConflictReason.INTEL_NO_DATA, AttackMessage.NO_DATA)
    assert len(flow.sent) == sent
