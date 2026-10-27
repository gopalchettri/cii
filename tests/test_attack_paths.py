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
    Decision,
    ErrorCode,
    Lease,
    PlanMessage,
    PlanStage,
    PromptVersion,
    RunActionKind,
    RunActionOutcome,
    ScenarioStatus,
    Status,
    Step,
    TaskName,
    UnselectedReason,
)
from app.core.database import get_mongodb
from app.core.exceptions import PlanRefused, Unavailable
from app.domain.scenario.plan import (
    attack_path_categories,
    attack_path_confidence,
    attack_path_from_library,
    attack_path_id,
    attack_path_impact,
    attack_path_systems,
    build_plan,
    describe_asset_for_ai,
    merge_same_threats,
    rank_paths,
    take_turns,
)
from app.domain.scenario.plan_trace import build_plan_trace
from app.models.scenario.plan import AttackPath, KindPlace, PlannedThreat, ThreatFindings
from app.worker import jobs
from app.worker.scenario.plan_job import PLAN_JOB_FIELDS, PlanJob
from tests.planner_samples import ADMIN_ABUSE, CONTEXT, LOG_WIPE, THREATS, S, finder, planned, planner_chat

LANDSCAPE = describe_asset_for_ai(CONTEXT, 30_000)


def findings_of(*threats: PlannedThreat) -> ThreatFindings:
    return ThreatFindings(threats=list(threats), audits=[], landscape=LANDSCAPE)


def one_step(key: str, category: S, systems: tuple[int, ...], impact: int) -> AttackPath:
    return AttackPath((planned(key, key, systems, categories=(category,), impact=impact),))


def test_every_threat_is_its_own_asset_level_path_none_grouped_under_another() -> None:
    """Owner 2026-10-19: one asset-level scenario per distinct threat per kind of attack, its systems the
    entry points. Two threats on the same kind and systems are two scenarios, never one that names the
    other as also_applies; a threat on several systems is one scenario, never one per system."""
    strong = planned("lib:1", "T0839: Firmware change", (321, 322), impact=3)
    second = planned("lib:4", "Logic overwrite", (321, 322), impact=2)
    weak = planned("lib:2", "Log wipe", (321,), impact=1)
    on_asset = planned("lib:3", "Grid data theft", (), categories=(S.INFORMATION_DISCLOSURE,))
    plan = build_plan(findings_of(weak, strong, second, on_asset), 0)
    assert [(p["steps"], p["category"], p["systems"], p["also_applies"]) for p in plan["paths"]] == [
        (["lib:1"], S.TAMPERING, [321, 322], []),
        (["lib:4"], S.TAMPERING, [321, 322], []),  # the same kind and systems: its own scenario
        (["lib:3"], S.INFORMATION_DISCLOSURE, [], []),  # judged on no system: the asset itself
        (["lib:2"], S.TAMPERING, [321], []),
    ]
    assert len({p["path_id"] for p in plan["paths"]}) == 4 and all("links" not in p for p in plan["paths"])
    assert [t["key"] for t in plan["threats"]] == ["lib:2", "lib:1", "lib:4", "lib:3"]  # every threat, once


def test_a_threat_is_a_path_for_every_kind_it_fits_and_distinct_threats_come_first() -> None:
    """Each kind a threat was accepted for is its own scenario (another consequence for the asset), shown as
    that kind; every threat's strongest kind comes before any threat's next one, so the first sets tell
    distinct threats."""
    login = planned("lib:1", "Fake operator login", (321,), categories=(S.SPOOFING, S.REPUDIATION), impact=3)
    wipe = planned("lib:2", "Log wipe", (321,), categories=(S.REPUDIATION,), impact=1)
    plan = build_plan(findings_of(login, wipe), 0)
    assert [(p["steps"], p["category"], p["categories"][0]) for p in plan["paths"]] == [
        (["lib:1"], S.SPOOFING, S.SPOOFING),
        (["lib:2"], S.REPUDIATION, S.REPUDIATION),  # lib:2's only kind before lib:1's second
        (["lib:1"], S.REPUDIATION, S.REPUDIATION),
    ]
    alone = planned("lib:5", "Ladder logic change", (321,), categories=(S.TAMPERING, S.DENIAL_OF_SERVICE))
    paths = build_plan(findings_of(alone), 0)["paths"]
    assert [(p["category"], p["steps"]) for p in paths] == [
        (S.TAMPERING, ["lib:5"]),
        (S.DENIAL_OF_SERVICE, ["lib:5"]),  # only one threat: told once per kind, as that kind
    ]
    assert paths[0]["path_id"] != paths[1]["path_id"]


def test_each_kind_enters_through_its_own_systems_with_its_own_impact_and_confidence() -> None:
    """A threat accepted as two kinds on different systems keeps each verdict through the merge: each kind's
    scenario enters only through the systems the gate named for it."""
    tampering = planned(
        "lib:5", "Logic change", (321,), impact=3, kind_places=((S.TAMPERING, KindPlace((321,), 3, 80.0)),)
    )
    denial = planned(
        "lib:5",
        "Logic change",
        (322,),
        categories=(S.DENIAL_OF_SERVICE,),
        impact=1,
        kind_places=((S.DENIAL_OF_SERVICE, KindPlace((322,), 1, 50.0)),),
    )
    (merged,) = merge_same_threats([tampering, denial])
    assert merged.systems == (321, 322)  # the union, for the evidence search
    paths = build_plan(findings_of(merged), 0)["paths"]
    assert [(p["category"], p["systems"], p["impact"], p["confidence"]) for p in paths] == [
        (S.TAMPERING, [321], 3, 80.0),
        (S.DENIAL_OF_SERVICE, [322], 1, 50.0),
    ]


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


def _turn(path_id: str, systems: list[int], entry_points: list[int]) -> dict[str, Any]:
    return {"path_id": path_id, "systems": systems, "entry_points": entry_points}


def test_paths_take_turns_over_the_systems_each_through_a_way_in_the_gate_named() -> None:
    """SYS1, SYS2, SYS3, SYS4, the asset itself, then SYS1 again: each turn the best path left that an
    attacker could get in through that system. The cabinet attack involves SYS2 and SYS3 but gets in through
    SYS3 only, so SYS2's turn passes it by; a group of all four takes the turn of one of its ways in; a
    system with nothing left to get in through is skipped, never filled."""
    ranked = [
        _turn("ransomware", [1, 2, 3, 4], [1, 4]),
        _turn("login", [1, 4], [1, 4]),
        _turn("cabinet", [2, 3], [3]),
        _turn("timing", [2, 3], [2, 3]),
        _turn("alerts", [1, 4], [1, 4]),
        _turn("flood", [2, 3], [2, 3]),
        _turn("asset", [], []),
    ]
    dealt = take_turns(ranked, [1, 2, 3, 4])
    assert [(record["path_id"], record["entry_system"]) for record in dealt] == [
        ("ransomware", 1),
        ("timing", 2),
        ("cabinet", 3),
        ("login", 4),
        ("asset", None),
        ("alerts", 1),
        ("flood", 2),
    ]
    assert all(  # the whole sequence: every turn's system is one of that path's ways in
        record["entry_system"] in record["entry_points"]
        or (record["entry_system"] is None and not record["systems"])
        for record in dealt
    )
    skipped = take_turns([_turn("a", [1, 2], [1]), _turn("b", [1], [1]), _turn("c", [3], [3])], [1, 2, 3])
    assert [(record["path_id"], record["entry_system"]) for record in skipped] == [
        ("a", 1),
        ("c", 3),
        ("b", 1),
    ]
    # SYS1's turn passes over the one path SYS4 could take, while it has another of its own
    shared = [_turn("r1", [1, 4], [1, 4]), _turn("r2", [1], [1]), _turn("r3", [1], [1])]
    assert [(record["path_id"], record["entry_system"]) for record in take_turns(shared, [1, 2, 3, 4])] == [
        ("r2", 1),
        ("r1", 4),
        ("r3", 1),
    ]


def test_the_plan_stores_each_paths_ways_in_and_turn_and_the_trace_counts_them() -> None:
    """The stronger threat gets in through the Historian only, so the SCADA server's first turn goes to the
    weaker one; the ranks follow the turns, and the trace counts each system's turns and each group."""
    place = KindPlace((321, 322), 3, 70.0, None, (322,))
    via_historian = planned(
        "lib:1", "Firmware change", (321, 322), impact=3, kind_places=((S.TAMPERING, place),)
    )
    on_scada = planned("lib:2", "Log wipe", (321,), impact=1)
    findings = findings_of(via_historian, on_scada)
    plan = build_plan(findings, 0)
    assert [
        (p["steps"], p["systems"], p["entry_points"], p["entry_system"], p["rank"]) for p in plan["paths"]
    ] == [
        (["lib:2"], [321], [321], 321, 1),
        (["lib:1"], [321, 322], [322], 322, 2),
    ]
    trace = build_plan_trace(findings, plan, 2)
    assert trace["turns"] == {"SCADA server": 1, "Historian": 1}
    assert trace["groups"] == {"SCADA server": 1, "SCADA server + Historian": 1}
    # every system is listed, 0 when no path gets in through it, and two systems named alike stay apart
    alike = replace(LANDSCAPE, system_names=dict.fromkeys(LANDSCAPE.system_names, "HMI"))
    only_scada = {"paths": [p | {"entry_system": 321} for p in plan["paths"]], "threats": plan["threats"]}
    trace = build_plan_trace(replace(findings, landscape=alike), only_scada, 2)
    assert trace["turns"] == {"HMI (SYS1)": 2, "HMI (SYS2)": 0}


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


def _queued_run(attempts: int = 0) -> str:
    """A run waiting for its threats job, on an asset of its own."""
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
    return PlanJob(threat_finder, container.get_intelligence_switch()).plan_threat_scenario_session


def _threats_task() -> Any:
    return SimpleNamespace(
        name=TaskName.FIND_THREATS, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    sends: list[tuple[Any, ...]] = []
    monkeypatch.setattr(jobs, "send_job", lambda *args, **_priority: sends.append(args))
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
    assert (run["status"], run["step"]) == (Status.QUEUED, Step.SCENARIOS)
    assert (run["job"]["task"], run["job"]["epoch"], run["job"]["attempts"]) == (
        TaskName.WRITE_SCENARIOS,
        1,
        0,
    )
    plan = run["plan"]
    assert plan["prompt_version"] == PromptVersion.PLANNER and plan["frozen_at"] is not None
    assert sorted(threat["name"] for threat in plan["threats"]) == sorted([LOG_WIPE.name, ADMIN_ABUSE.name])
    best = min(plan["paths"], key=lambda path: path["rank"])["path_id"]
    assert run["job"]["set"] == [best] and run["job"]["batch"] == [{"path_id": best, "replaces": None}]
    assert run["plan_note"] == PlanMessage.PLAN_NOTE.format(planned=2, written=0, remaining=2)
    assert run["counts"]["planned"] == 2 and sent == [(TaskName.WRITE_SCENARIOS, record_id, 1)]
    # What made the plan, so a later reviewer can tell why this plan and not another.
    assert set(plan["made_with"]) == {"chat_models", "embedding_model", "rerank_model", "library"}
    assert plan["made_with"]["chat_models"][0] == get_settings().chat_model
    # Its trace, saved in the same write: each stage's counts add up.
    counts = run["plan_trace"]["counts"]
    assert (counts["threats"], counts["paths"], counts["selected"], counts["first_set"]) == (2, 2, 2, 1)
    assert counts["already_held"] == 0 and counts["gate_accepted"] == 2
    lost = (
        "not_judged",
        "not_relevant",
        "needs_unrecorded",
        "asset_type_mismatch",
        "needs_unrecorded_elsewhere",
    )
    assert counts["gate_asked"] == counts["gate_accepted"] + sum(counts[name] for name in lost)


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
    assert (run["status"], "active" in run, run["last_action"]["outcome"]) == (
        Status.DONE,
        False,
        RunActionOutcome.COMPLETE,
    )
    assert run["plan"]["paths"] == [] and run["plan_note"] == PlanMessage.PLAN_NOTE.format(
        planned=0, written=0, remaining=0
    )
    assert sent == []


def test_another_session_of_the_asset_never_takes_a_path_away(
    monkeypatch: pytest.MonkeyPatch, sent: list[tuple[Any, ...]]
) -> None:
    """D15 (owner 2026-10-20): an earlier session of the asset holds a scenario on each path, one pending and
    matched by key, one accepted and matched by name; the second session still plans both and queues its
    first set: nothing is traced as held."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    plan = _plan_job(finder(chat))
    earlier = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, earlier, 1, plan, fields=PLAN_JOB_FIELDS)
    first = _stored_run(earlier)
    sessions, scenarios = get_mongodb()[Collection.SESSIONS], get_mongodb()[Collection.SCENARIOS]
    sessions.update_one({"_id": earlier}, {"$set": {"status": Status.DONE}})
    names = {threat["key"]: threat["name"] for threat in first["plan"]["threats"]}
    assert len(first["plan"]["paths"]) == 2
    held_ids = []
    for number, path in enumerate(first["plan"]["paths"]):
        key = path["steps"][0]
        threat = {"key": key} if number == 0 else {"key": "ai:other", "name": names[key]}
        systems = [{"id": system_id} for system_id in path["systems"]]
        held = {"session_id": earlier, "entity_id": first["entity_id"], "asset_id": first["asset_id"]}
        held_ids.append(str(uuid.uuid4()))  # a card id as the app makes them (uuid5, with its dashes)
        held |= {"_id": held_ids[-1], "path_id": path["path_id"], "superseded_by": None}
        held |= {"status": ScenarioStatus.DONE, "decision": [Decision.PENDING, Decision.ACCEPTED][number]}
        held |= {"content": {"threat": threat, "category": path["category"], "systems": systems}}
        scenarios.insert_one(held)
    sent.clear()
    record_id = _queued_run()
    sessions.update_one({"_id": record_id}, {"$set": {"asset_id": first["asset_id"]}})
    try:
        jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    finally:  # bare cards: an entity's scenario list in a later test would trip on them
        scenarios.delete_many({"session_id": earlier})
    run = _stored_run(record_id)
    planned = [path["steps"] for path in run["plan"]["paths"]]
    assert planned == [path["steps"] for path in first["plan"]["paths"]]
    assert len(sent) == 1 and run["job"]["set"] == [path["path_id"] for path in run["plan"]["paths"]]
    trace = run["plan_trace"]
    assert (trace["counts"]["paths"], trace["counts"]["already_held"], trace["counts"]["first_set"]) == (
        2,
        0,
        2,
    )
    assert not [drop for drop in trace["drops"] if drop["stage"] == PlanStage.HELD]


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
    assert (run["status"], "active" in run) == (Status.FAILED, False) and "plan" not in run
    assert run["job"]["error"] == {"code": ErrorCode.UNAVAILABLE, "message": PlanMessage.AI_COULD_NOT_ANSWER}
    assert chat.asked(AiTask.GAP_FILL) == [] and sent == []


def test_a_refused_plan_fails_the_run_with_its_own_code(sent: list[tuple[Any, ...]]) -> None:
    """No type links a live actor: the run fails actor_library_empty and is never retried."""
    unlinked = tuple(replace(threat, linked_actors=()) for threat in THREATS)
    refusing = finder(planner_chat({}), threats=unlinked)
    plan = _plan_job(refusing)
    record_id = _queued_run()
    with pytest.raises(PlanRefused):
        jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    run = _stored_run(record_id)
    assert run["status"] == Status.FAILED and "active" not in run and "plan" not in run
    assert run["job"]["error"] == {
        "code": ErrorCode.ACTOR_LIBRARY_EMPTY,
        "message": PlanMessage.ACTOR_LIBRARY_EMPTY,
    }
    assert sent == []
