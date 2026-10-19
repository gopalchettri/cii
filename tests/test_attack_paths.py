"""Attack paths: grouping, ranking, the target and the frozen plan. The freeze runs the real job on the test
MongoDB with fake AI models; everything else runs in memory."""

import hashlib
import random
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    Collection,
    ErrorCode,
    Lease,
    PlanMessage,
    RunActionKind,
    RunActionOutcome,
    Status,
    Step,
    TaskName,
    UnselectedReason,
)
from app.core.database import get_mongodb
from app.core.exceptions import PlanRefused, Unavailable
from app.domain.scenario.plan import (
    PLANNER_PROMPT_VERSION,
    attack_path_categories,
    attack_path_confidence,
    attack_path_from_library,
    attack_path_id,
    attack_path_impact,
    attack_path_systems,
    build_plan,
    describe_asset_for_ai,
    rank_paths,
)
from app.domain.scenario.write import held_repeat_of
from app.models.scenario.plan import AttackPath, PlannedThreat, ThreatFindings
from app.worker import jobs
from app.worker.scenario import plan_job as plan_job_module
from app.worker.scenario.plan_job import PLAN_JOB_FIELDS, PlanJob
from tests.planner_samples import ADMIN_ABUSE, CONTEXT, LOG_WIPE, THREATS, S, finder, planned, planner_chat

LANDSCAPE = describe_asset_for_ai(CONTEXT, 30_000)


def findings_of(*threats: PlannedThreat) -> ThreatFindings:
    return ThreatFindings(threats=list(threats), audits=[], landscape=LANDSCAPE)


def one_step(key: str, category: S, systems: tuple[int, ...], impact: int) -> AttackPath:
    return AttackPath((planned(key, key, systems, categories=(category,), impact=impact),))


def test_each_kind_of_attack_on_each_route_is_one_path_and_its_other_threats_stay_with_it() -> None:
    """Threats are grouped by kind of attack and by route (the systems each was judged on); each group is one
    path around its strongest threat, the others kept as also_applies (names, no codes)."""
    strong = planned("lib:1", "T0839: Firmware change", (321, 322), impact=3)
    second = planned("lib:4", "Logic overwrite", (321, 322), impact=2)
    weak = planned("lib:2", "Log wipe", (321,), impact=1)
    on_asset = planned("lib:3", "Grid data theft", (), categories=(S.INFORMATION_DISCLOSURE,))
    plan = build_plan(findings_of(weak, strong, second, on_asset), 0)
    groups = {(p["category"], tuple(p["systems"])): (p["steps"], p["also_applies"]) for p in plan["paths"]}
    assert groups == {
        (S.TAMPERING, (321,)): (["lib:2"], []),  # its own route: its own scenario
        (S.TAMPERING, (321, 322)): (["lib:1"], ["Logic overwrite"]),  # the strongest; the other stays
        (S.INFORMATION_DISCLOSURE, ()): (["lib:3"], []),  # judged on no system: the asset itself
    }
    assert len({p["path_id"] for p in plan["paths"]}) == 3 and all("links" not in p for p in plan["paths"])
    assert [t["key"] for t in plan["threats"]] == ["lib:2", "lib:1", "lib:4", "lib:3"]  # every threat, once


def test_a_threat_counts_in_every_kind_it_fits_and_each_kind_prefers_an_untaken_threat() -> None:
    """Each kind a threat fits is a group, told by a threat no earlier group took, and shown as that kind."""
    login = planned("lib:1", "Fake operator login", (321,), categories=(S.SPOOFING, S.REPUDIATION), impact=3)
    wipe = planned("lib:2", "Log wipe", (321,), categories=(S.REPUDIATION,), impact=1)
    plan = build_plan(findings_of(login, wipe), 0)
    by_kind = {p["category"]: (p["steps"], p["also_applies"], p["categories"][0]) for p in plan["paths"]}
    assert by_kind == {
        S.SPOOFING: (["lib:1"], [], S.SPOOFING),
        S.REPUDIATION: (["lib:2"], ["Fake operator login"], S.REPUDIATION),  # lib:1 was taken by Spoofing
    }
    alone = planned("lib:5", "Ladder logic change", (321,), categories=(S.TAMPERING, S.DENIAL_OF_SERVICE))
    paths = build_plan(findings_of(alone), 0)["paths"]
    assert [(p["category"], p["steps"]) for p in paths] == [
        (S.TAMPERING, ["lib:5"]),
        (S.DENIAL_OF_SERVICE, ["lib:5"]),  # only one threat: told once per kind, as that kind
    ]
    assert paths[0]["path_id"] != paths[1]["path_id"]


def test_a_path_takes_its_id_categories_systems_impact_and_confidence_from_its_steps() -> None:
    """The card's category is the last step's; the path's categories start with the first's."""
    phishing = planned("lib:7", "Phishing", (322,), categories=(S.SPOOFING,), impact=1, confidence=90.0)
    wipe = planned(
        "ai:wipe", "Wipe", (321,), categories=(S.TAMPERING, S.REPUDIATION), impact=3, confidence=60.0
    )
    path = AttackPath((phishing, wipe))  # a chain an owner-approved rule could make (none today)
    assert attack_path_id(path) == hashlib.sha256(b"lib:7|ai:wipe").hexdigest()[:16]
    assert attack_path_categories(path) == (S.SPOOFING, S.TAMPERING, S.REPUDIATION)
    assert (
        attack_path_systems(path),
        attack_path_impact(path),
        attack_path_confidence(path),
        attack_path_from_library(path),
    ) == ((321, 322), 3, 60.0, False)
    findings = replace(findings_of(wipe), category_ids={"tampering": 5, "spoofing": 1})
    record, as_repudiation = build_plan(findings, 0)["paths"]  # every kind
    on_route = AttackPath((wipe,), scope="Tampering@system:321")  # the kind and the route name the path
    assert (
        record["path_id"]
        == attack_path_id(on_route)
        != attack_path_id(AttackPath((wipe,)))
        != as_repudiation["path_id"]
    )
    assert record["steps"] == ["ai:wipe"] and record["systems"] == [321]
    assert as_repudiation["category"] == S.REPUDIATION and as_repudiation["steps"] == ["ai:wipe"]
    assert record["category"] == S.TAMPERING and record["categories"] == [S.TAMPERING, S.REPUDIATION]
    assert record["category_id"] == 5  # the library's id, kept for the results
    assert (record["rank"], record["served"], record["attempts"], record["abandoned"]) == (1, None, 0, False)


def test_paths_are_ranked_by_impact_then_confidence_then_stride_order() -> None:
    weak_spoofing = one_step("lib:1", S.SPOOFING, (321,), impact=1)
    strong_spoofing = one_step("lib:2", S.SPOOFING, (321,), impact=3)
    strong_tampering = one_step("lib:5", S.TAMPERING, (), impact=3)
    medium = one_step("lib:3", S.TAMPERING, (322,), impact=2)
    surer = AttackPath((planned("lib:4", "lib:4", (323,), impact=1, confidence=95.0),))
    ranked = rank_paths([weak_spoofing, surer, strong_tampering, medium, strong_spoofing])
    assert ranked == [strong_spoofing, strong_tampering, medium, surer, weak_spoofing]


def test_equal_paths_rank_library_first_then_by_library_id_whatever_the_input_order() -> None:
    paths = [one_step("ai:z", S.TAMPERING, (321,), 2), one_step("lib:9", S.TAMPERING, (321,), 2)]
    paths.append(one_step("lib:3", S.TAMPERING, (321,), 2))
    expected = [path.steps[0].key for path in rank_paths(paths)]
    assert expected == ["lib:3", "lib:9", "ai:z"]
    for seed in range(5):
        shuffled = random.Random(seed).sample(paths, len(paths))  # noqa: S311 — test data, not security
        assert [path.steps[0].key for path in rank_paths(shuffled)] == expected


def test_the_target_keeps_the_most_relevant_paths_and_never_pads() -> None:
    threats = [
        planned("lib:1", "One", (321,), categories=(S.SPOOFING,), impact=3),
        planned("lib:2", "Two", (322,), categories=(S.TAMPERING,), impact=1),
    ]
    plan = build_plan(findings_of(*threats), 1)
    assert [(p["steps"], p["selected"]) for p in plan["paths"]] == [(["lib:1"], True), (["lib:2"], False)]
    assert plan["paths"][1]["unselected_reason"] == UnselectedReason.TARGET_REACHED and plan["target"] == 1
    assert len(build_plan(findings_of(*threats), 5)["paths"]) == 2


def test_a_path_repeating_a_held_scenario_is_dropped_before_the_target_and_the_next_is_selected() -> None:
    """The same threat (by key, or by name) as the same kind on the same systems as a scenario the asset
    holds never enters the plan; the target fills with the next path and the ranks close up."""
    threats = [
        planned("lib:1", "T0001: One", (321,), categories=(S.SPOOFING,), impact=3),
        planned("lib:2", "Two", (322,), categories=(S.TAMPERING,), impact=2),
        planned("ai:3", "Three", (323,), categories=(S.TAMPERING,), impact=2),
        planned("lib:4", "Four", (324,), categories=(S.TAMPERING,), impact=1),
    ]

    def held_card(threat: dict[str, str], category: S, systems: list[int]) -> dict[str, Any]:
        content = {"threat": threat, "category": category, "systems": [{"id": s} for s in systems]}
        return {"_id": f"held-{len(held)}", "content": content}

    held: list[dict[str, Any]] = []
    held.append(held_card({"key": "lib:1"}, S.SPOOFING, [321]))  # by key
    held.append(held_card({"key": "ai:old", "name": "three"}, S.TAMPERING, [323]))  # by name
    held.append(held_card({"key": "lib:2"}, S.SPOOFING, [322]))  # another kind
    held.append(held_card({"key": "lib:4"}, S.TAMPERING, []))  # other systems
    plan = build_plan(
        findings_of(*threats), 1, lambda path, threat: held_repeat_of(path, threat, held) is not None
    )
    assert [(p["steps"], p["rank"], p["selected"]) for p in plan["paths"]] == [
        (["lib:2"], 1, True),
        (["lib:4"], 2, False),
    ]
    assert [threat["key"] for threat in plan["threats"]] == ["lib:1", "lib:2", "ai:3", "lib:4"]  # all listed


def _queued_run(attempts: int = 0) -> str:
    """A run waiting for its threats job, on an asset of its own (one active run per asset)."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    job = {
        "task": TaskName.FIND_THREATS,
        "epoch": 1,
        "attempts": attempts,
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


def _plan_job(threat_finder: Any) -> Any:
    """The plan job as the app builds it, planning with `threat_finder`."""
    switch, scenarios = container.get_intelligence_switch(), container.get_threat_scenario_repository()
    return PlanJob(threat_finder, switch, scenarios).plan_threat_scenario_session


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
    """Same epoch, attempts reset; the first set (INITIAL_SET_SIZE, here 1) is the best-ranked path, the
    write stage's set and batch; the other waits for a next set."""
    monkeypatch.setattr(get_settings(), "initial_set_size", 1)
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    plan = _plan_job(finder(chat))
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
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
    # What made the plan, so a later reviewer can tell why this plan and not another.
    assert set(plan["made_with"]) == {"chat_models", "embedding_model", "rerank_model", "library"}
    assert plan["made_with"]["chat_models"][0] == get_settings().chat_model


def test_a_plan_with_no_path_ends_the_run_at_once(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """Nothing applies: the run is done in the same write; no writer job is queued for nothing."""
    chat = planner_chat({})
    plan = _plan_job(finder(chat))
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
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


def test_a_plan_whose_every_path_the_asset_already_holds_ends_complete_with_nothing_to_write(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """Every path repeats a held scenario: none is planned, the run ends complete, no writer job is queued."""
    monkeypatch.setattr(plan_job_module, "held_repeat_of", lambda path, threat, held: "held-scenario")
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    plan = _plan_job(finder(chat))
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    run = _stored_run(record_id)
    assert (run["status"], run["last_action"]["outcome"]) == (Status.DONE, RunActionOutcome.COMPLETE)
    assert run["plan"]["paths"] == [] and len(run["plan"]["threats"]) == 2 and sent == []


def test_a_last_attempt_that_checks_not_one_threat_fails_the_run_as_an_ai_outage(
    sent: list[tuple[Any, ...]],
) -> None:
    """Not one gate reply usable on the job's last attempt: the run fails unavailable, never "none apply"."""
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = lambda _: {"verdicts": "?"}
    plan = _plan_job(finder(chat))
    record_id = _queued_run(attempts=Lease.MAX_ATTEMPTS - 1)  # the claim makes it the last
    with pytest.raises(Unavailable):
        jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    run = _stored_run(record_id)
    assert (run["status"], run["active"]) == (Status.FAILED, False) and "plan" not in run
    assert run["job"]["error"] == {"code": ErrorCode.UNAVAILABLE, "message": PlanMessage.AI_COULD_NOT_ANSWER}
    assert chat.asked(AiTask.GAP_FILL) == [] and sent == []


def test_a_refused_plan_fails_the_run_with_its_own_code(sent: list[tuple[Any, ...]]) -> None:
    """No type links a live actor: the run fails actor_library_empty, frees the asset, is never retried."""
    unlinked = tuple(replace(threat, linked_actors=()) for threat in THREATS)
    refusing = finder(planner_chat({}), threats=unlinked)
    plan = _plan_job(refusing)
    record_id = _queued_run()
    with pytest.raises(PlanRefused):
        jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    run = _stored_run(record_id)
    assert run["status"] == Status.FAILED and run["active"] is False and "plan" not in run
    assert run["job"]["error"] == {
        "code": ErrorCode.ACTOR_LIBRARY_EMPTY,
        "message": PlanMessage.ACTOR_LIBRARY_EMPTY,
    }
    assert sent == []
