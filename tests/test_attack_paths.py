"""Attack paths (BLUEPRINT M10 P1-P5): T-PATH-01..06. The freeze runs the real job on the test MongoDB with
fake AI models; everything else runs in memory."""

import hashlib
import random
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    Collection,
    ErrorCode,
    PathChoice,
    PlanMessage,
    RunActionKind,
    RunActionOutcome,
    Status,
    Step,
    TaskName,
    UnselectedReason,
)
from app.core.database import get_mongodb
from app.core.exceptions import PlanRefused
from app.engine.scenarios.attack_paths.path_ranking import rank_paths
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai
from app.engine.scenarios.finding.threat_prompts import PLANNER_PROMPT_VERSION
from app.models.threats import AttackPath, PlannedThreat, ThreatFindings
from app.worker import jobs
from app.worker.tasks import scenarios as scenario_tasks
from tests.planner_samples import ADMIN_ABUSE, CONTEXT, LOG_WIPE, S, finder, planned, planner_chat

LANDSCAPE = describe_asset_for_ai(CONTEXT, 30_000)


def findings_of(*threats: PlannedThreat) -> ThreatFindings:
    return ThreatFindings(threats=list(threats), audits=[], folded=[], notes=[], landscape=LANDSCAPE)


def one_step(key: str, category: S, systems: tuple[int, ...], impact: int) -> AttackPath:
    return AttackPath((planned(key, key, systems, categories=(category,), impact=impact),))


def test_each_kind_of_attack_on_each_route_is_one_path_and_its_other_threats_stay_with_it() -> None:
    """G216 (owner 2026-10-13, "5 is too less ... some logic is wrong"): at asset level, threats are grouped
    by kind of attack AND by route, the systems each was judged on; each group is ONE one-step path around its
    strongest threat, the others kept as also_applies (names, no codes). Another route is another scenario.
    The AI never joins threats (G114), and no AI is called."""
    strong = planned("lib:1", "T0839: Firmware change", (321, 322), impact=3)
    second = planned("lib:4", "Logic overwrite", (321, 322), impact=2)
    weak = planned("lib:2", "Log wipe", (321,), impact=1)
    on_asset = planned("lib:3", "Grid data theft", (), categories=(S.INFORMATION_DISCLOSURE,))
    plan = AttackPathSelector(target=0).build_plan(findings_of(weak, strong, second, on_asset))
    groups = {(p["category"], tuple(p["systems"])): (p["steps"], p["also_applies"]) for p in plan["paths"]}
    assert groups == {
        (S.TAMPERING, (321,)): (["lib:2"], []),  # its own route: its own scenario
        (S.TAMPERING, (321, 322)): (["lib:1"], ["Logic overwrite"]),  # the strongest; the other stays
        (S.INFORMATION_DISCLOSURE, ()): (["lib:3"], []),  # judged on no system: the asset itself
    }
    assert len({p["path_id"] for p in plan["paths"]}) == 3 and all("links" not in p for p in plan["paths"])
    assert [t["key"] for t in plan["threats"]] == ["lib:2", "lib:1", "lib:4", "lib:3"]  # every threat, once


def test_a_threat_counts_in_every_kind_it_fits_and_each_kind_prefers_an_untaken_threat() -> None:
    """G216: run 816b94cb had threats fitting Repudiation whose main kind was Spoofing, and no Repudiation
    scenario. Each kind a threat fits is a group; a group is written around a threat no earlier group took,
    and the scenario is written and shown as its group's kind."""
    login = planned("lib:1", "Fake operator login", (321,), categories=(S.SPOOFING, S.REPUDIATION), impact=3)
    wipe = planned("lib:2", "Log wipe", (321,), categories=(S.REPUDIATION,), impact=1)
    plan = AttackPathSelector(target=0).build_plan(findings_of(login, wipe))
    by_kind = {p["category"]: (p["steps"], p["also_applies"], p["categories"][0]) for p in plan["paths"]}
    assert by_kind == {
        S.SPOOFING: (["lib:1"], [], S.SPOOFING),
        S.REPUDIATION: (["lib:2"], ["Fake operator login"], S.REPUDIATION),  # lib:1 was taken by Spoofing
    }
    alone = planned("lib:5", "Ladder logic change", (321,), categories=(S.TAMPERING, S.DENIAL_OF_SERVICE))
    paths = AttackPathSelector(target=0).build_plan(findings_of(alone))["paths"]
    assert [(p["category"], p["steps"]) for p in paths] == [
        (S.TAMPERING, ["lib:5"]),
        (S.DENIAL_OF_SERVICE, ["lib:5"]),  # only one threat: told once per kind, as that kind
    ]
    assert paths[0]["path_id"] != paths[1]["path_id"]


def test_a_path_takes_its_id_categories_systems_impact_and_confidence_from_its_steps() -> None:
    """T-PATH-02: the card's category is the last step's; the path's categories start with the first's."""
    phishing = planned("lib:7", "Phishing", (322,), categories=(S.SPOOFING,), impact=1, confidence=90.0)
    wipe = planned(
        "ai:wipe", "Wipe", (321,), categories=(S.TAMPERING, S.REPUDIATION), impact=3, confidence=60.0
    )
    path = AttackPath((phishing, wipe))  # a chain an owner-approved rule could make (none today)
    assert path.path_id == hashlib.sha256(b"lib:7|ai:wipe").hexdigest()[:16]
    assert path.categories == (S.SPOOFING, S.TAMPERING, S.REPUDIATION)
    assert (path.systems, path.impact, path.confidence, path.from_library) == ((321, 322), 3, 60.0, False)
    findings = replace(findings_of(wipe), category_ids={"tampering": 5, "spoofing": 1})
    record, as_repudiation = AttackPathSelector(target=0).build_plan(findings)["paths"]  # every kind (G216)
    on_route = AttackPath((wipe,), scope="Tampering@system:321")  # the kind and the route name the path
    assert record["path_id"] == on_route.path_id != AttackPath((wipe,)).path_id != as_repudiation["path_id"]
    assert record["steps"] == ["ai:wipe"] and record["systems"] == [321]
    assert as_repudiation["category"] == S.REPUDIATION and as_repudiation["steps"] == ["ai:wipe"]
    assert record["category"] == S.TAMPERING and record["categories"] == [S.TAMPERING, S.REPUDIATION]
    assert record["category_id"] == 5  # the library's id, kept for the results (G207)
    assert (record["rank"], record["served"], record["attempts"], record["abandoned"]) == (1, None, 0, False)


def test_paths_are_ranked_by_critical_risk_then_new_systems_then_new_kinds_then_significance() -> None:
    """T-PATH-03 (G223: one pick at a time for the most coverage, recomputed after each pick)."""
    weak_spoofing = one_step("lib:1", S.SPOOFING, (321,), impact=1)
    strong_spoofing = one_step("lib:2", S.SPOOFING, (321,), impact=3)
    tampering = one_step("lib:3", S.TAMPERING, (322,), impact=2)
    on_asset = one_step("lib:5", S.TAMPERING, (), impact=3)
    new_system = one_step("lib:4", S.TAMPERING, (323,), impact=1)
    ranked = rank_paths([weak_spoofing, new_system, on_asset, tampering, strong_spoofing])
    assert ranked == [
        (strong_spoofing, PathChoice.PATH_COVERAGE),  # HIGH: a critical threat first, and a new system
        (on_asset, PathChoice.CATEGORY_COVERAGE),  # HIGH too: before any MEDIUM, though it adds no system
        (tampering, PathChoice.PATH_COVERAGE),  # a system not covered yet; the stronger of two first
        (new_system, PathChoice.PATH_COVERAGE),  # the weakest path, but on a system not covered yet
        (weak_spoofing, PathChoice.RISK_SIGNIFICANCE),  # adds nothing new: last
    ]


def test_equal_paths_rank_library_first_then_by_library_id_whatever_the_input_order() -> None:
    """T-PATH-04."""
    paths = [one_step("ai:z", S.TAMPERING, (321,), 2), one_step("lib:9", S.TAMPERING, (321,), 2)]
    paths.append(one_step("lib:3", S.TAMPERING, (321,), 2))
    expected = [path.steps[0].key for path, _ in rank_paths(paths)]
    assert expected == ["lib:3", "lib:9", "ai:z"]
    for seed in range(5):
        shuffled = random.Random(seed).sample(paths, len(paths))  # noqa: S311 — test data, not security
        assert [path.steps[0].key for path, _ in rank_paths(shuffled)] == expected


def test_the_target_keeps_the_most_relevant_paths_and_never_pads() -> None:
    """T-PATH-05."""
    threats = [
        planned("lib:1", "One", (321,), categories=(S.SPOOFING,), impact=3),
        planned("lib:2", "Two", (322,), categories=(S.TAMPERING,), impact=1),
    ]
    plan = AttackPathSelector(target=1).build_plan(findings_of(*threats))
    assert [(p["steps"], p["selected"]) for p in plan["paths"]] == [(["lib:1"], True), (["lib:2"], False)]
    assert plan["paths"][1]["unselected_reason"] == UnselectedReason.TARGET_REACHED and plan["target"] == 1
    assert len(AttackPathSelector(target=5).build_plan(findings_of(*threats))["paths"]) == 2


def _queued_run() -> str:
    """A run waiting for its threats job, on an asset of its own (one active run per asset)."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    job = {
        "task": TaskName.FIND_THREATS,
        "epoch": 1,
        "attempts": 0,
        "due_at": now,
        "task_id": None,
        "error": None,
    }
    get_mongodb()[Collection.SESSIONS].insert_one(
        {
            "_id": record_id,
            "entity_id": 86,
            "asset_id": uuid.uuid4().int % 1_000_000_000,
            "status": Status.QUEUED,
            "step": Step.THREATS,
            "active": True,
            "context": CONTEXT.to_record(),
            "counts": {},
            "last_action": {"kind": RunActionKind.START, "outcome": RunActionOutcome.RUNNING},
            "job": job,
            "updated_at": now,
        }
    )
    return record_id


def _stored_run(record_id: str) -> dict[str, Any]:
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})
    assert run is not None
    return run


def _threats_task() -> Any:
    return SimpleNamespace(
        name=TaskName.FIND_THREATS, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    sends: list[tuple[Any, ...]] = []
    monkeypatch.setattr(jobs, "send_job", lambda *args: sends.append(args))
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _record_id: None)
    return sends


def test_the_plan_is_frozen_and_handed_to_scenario_writing_in_one_write(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """T-PATH-06: same epoch, attempts reset; G196: the first set (INITIAL_SET_SIZE, here 1) is the
    best-ranked path, the write stage's set and batch; the other waits for a next set."""
    monkeypatch.setattr(get_settings(), "initial_set_size", 1)
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(chat))
    selector = AttackPathSelector(target=0)  # type: ignore[arg-type]
    monkeypatch.setattr(scenario_tasks, "get_attack_path_selector", lambda: selector)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, scenario_tasks.plan_run)
    run = _stored_run(record_id)
    assert (run["status"], run["step"], run["active"]) == (Status.QUEUED, Step.SCENARIOS, True)
    assert (run["job"]["task"], run["job"]["epoch"], run["job"]["attempts"]) == (
        TaskName.WRITE_SCENARIOS,
        1,
        0,
    )
    plan = run["plan"]
    assert plan["prompt_version"] == PLANNER_PROMPT_VERSION and plan["frozen_at"] is not None
    assert sorted(threat["name"] for threat in plan["threats"]) == sorted([LOG_WIPE.name, ADMIN_ABUSE.name])
    best = min(plan["paths"], key=lambda path: path["rank"])["path_id"]
    assert run["job"]["set"] == [best] and run["job"]["batch"] == [{"path_id": best, "replaces": None}]
    assert run["plan_note"] == PlanMessage.PLAN_NOTE.format(planned=2, written=0, remaining=2)
    assert run["counts"]["planned"] == 2 and sent == [(TaskName.WRITE_SCENARIOS, record_id, 1)]
    # G104: what made the plan, so a later reviewer can tell why this plan and not another.
    assert set(plan["made_with"]) == {"chat_models", "embedding_model", "rerank_model", "library"}
    assert plan["made_with"]["chat_models"][0] == get_settings().chat_model


def test_a_plan_with_no_path_ends_the_run_at_once(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """G103: nothing applies → the run is done in the same write; no writer job is queued for nothing."""
    chat = planner_chat({})
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(chat))
    selector = AttackPathSelector(target=0)  # type: ignore[arg-type]
    monkeypatch.setattr(scenario_tasks, "get_attack_path_selector", lambda: selector)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, scenario_tasks.plan_run)
    run = _stored_run(record_id)
    assert (run["status"], run["active"], run["last_action"]["outcome"]) == (
        Status.DONE,
        False,
        RunActionOutcome.COMPLETE,
    )
    assert run["plan"]["paths"] == [] and run["plan_note"] == PlanMessage.PLAN_NOTE.format(
        planned=0, written=0, remaining=0
    )
    assert sent == []


def test_a_run_with_a_category_not_assessed_ends_partial(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """G113 (spec v4.0 §7.3.7): a category the AI could not judge is a gap, never a complete run."""
    chat = planner_chat({})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if "category: Spoofing" in user else gate(user)
    )
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(chat))
    selector = AttackPathSelector(target=0)  # type: ignore[arg-type]
    monkeypatch.setattr(scenario_tasks, "get_attack_path_selector", lambda: selector)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, scenario_tasks.plan_run)
    run = _stored_run(record_id)
    assert run["plan"]["not_assessed"] == [S.SPOOFING]
    assert (run["status"], run["last_action"]["outcome"]) == (Status.DONE, RunActionOutcome.PARTIAL)


def test_a_refused_plan_fails_the_run_with_its_own_code(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """T-PATH-06: no live actor → the run fails actor_library_empty, frees the asset, and is never retried."""
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(planner_chat({}), actors=()))
    record_id = _queued_run()
    with pytest.raises(PlanRefused):
        jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, scenario_tasks.plan_run)
    run = _stored_run(record_id)
    assert run["status"] == Status.FAILED and run["active"] is False and "plan" not in run
    assert run["job"]["error"] == {
        "code": ErrorCode.ACTOR_LIBRARY_EMPTY,
        "message": PlanMessage.ACTOR_LIBRARY_EMPTY,
    }
    assert sent == []
