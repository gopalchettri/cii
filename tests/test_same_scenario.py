"""G213 (owner 2026-10-12: "merge into one"): scenarios that are the same attacker action with the same harm,
differing only in the system used, become one scenario on all those systems; the others' threats stay as
also_applies. Code decides who joins (a system the kept threat was never judged on stays apart), never the
AI alone; a scenario on the asset itself is never merged; an unreadable answer merges nothing and says so."""

import dataclasses
from collections.abc import Callable
from typing import Any

import pytest

from app.core.constants import AiTask, PlanMessage, StrideCategory
from app.core.exceptions import Unavailable
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.engine.scenarios.attack_paths.same_scenario import SameScenarioCheck, _read_groups
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai
from app.engine.scenarios.finding.threat_prompts import same_scenario_prompt
from app.models.threats import PlannedThreat, ThreatFindings
from tests.fakes import FakeChatModel, items_in
from tests.planner_samples import CONTEXT, planned, system_row
from tests.test_scenario_writing import _brief_of, _plan_threat

S = StrideCategory
#: SYS1 "SCADA server" (321), SYS2 "Historian" (322), SYS3 "Telecom" (323).
THREE = dataclasses.replace(CONTEXT, systems=[*CONTEXT.systems, system_row(323, "SYS3", "Telecom")])
LANDSCAPE = describe_asset_for_ai(THREE, 30_000)


def _disclosure(key: str, name: str, systems: tuple[int, ...], impact: int) -> PlannedThreat:
    return planned(key, name, systems, categories=(S.INFORMATION_DISCLOSURE,), impact=impact)


def _plan(chat: FakeChatModel, *threats: PlannedThreat) -> dict[str, Any]:
    findings = ThreatFindings(threats=list(threats), audits=[], folded=[], notes=[], landscape=LANDSCAPE)
    return AttackPathSelector(0, same_scenarios=SameScenarioCheck(chat)).build_plan(findings)


def _grouping(*groups: list[str]) -> Callable[[str], dict[str, Any]]:
    """An AI answer naming the given scenarios (by threat name) as one."""

    def answer(user_prompt: str) -> dict[str, Any]:
        slots = {item["threat"]: item["slot"] for item in items_in(user_prompt, "SCENARIOS")}
        return {
            "same": [{"paths": [slots[name] for name in group], "reason": "One leak."} for group in groups]
        }

    return answer


def test_scenarios_that_mean_the_same_become_one_on_all_their_systems() -> None:
    """Asset 1207 (session f0c52f04): "Exposure of operational grid data" was written three times, once per
    system. Interception applies on every system; the AI finds it on SCADA and the infostealer on Telecom one
    scenario: one, on both, around interception, the infostealer kept as also_applies; the leak stays."""
    interception = _disclosure("lib:1", "Interception", (321, 322, 323), impact=3)
    leak = _disclosure("lib:2", "Data leak", (322,), impact=2)
    infostealer = _disclosure("lib:3", "Infostealer", (323,), impact=2)
    chat = FakeChatModel()
    chat.responders[AiTask.SAME_SCENARIO] = _grouping(["Interception", "Infostealer"])
    plan = _plan(chat, interception, leak, infostealer)
    by_systems = {tuple(path["systems"]): (path["steps"], path["also_applies"]) for path in plan["paths"]}
    assert by_systems == {(321, 323): (["lib:1"], ["Infostealer"]), (322,): (["lib:2"], ["Interception"])}
    assert PlanMessage.SCENARIOS_MERGED.format(before=3, after=2) in plan["notes"]
    merged = next(path for path in plan["paths"] if path["systems"] == [321, 323])
    assert plan["merged"] == [  # kept with the AI's reason (G213 review: checked, then thrown away)
        {
            "path_id": merged["path_id"],
            "systems": [321, 323],
            "threats": ["Interception", "Infostealer"],
            "reason": "One leak.",
        }
    ]
    shown = items_in(chat.asked(AiTask.SAME_SCENARIO)[0], "SCENARIOS")
    assert [item["system"] for item in shown] == ['SYS1 "SCADA server"', 'SYS2 "Historian"', 'SYS3 "Telecom"']


def test_a_member_on_a_system_the_kept_threat_never_applied_on_stays_apart() -> None:
    """Code decides who joins: grouped with the others, the leak on the Historian stays its own scenario,
    because interception was never judged on the Historian (G211: its type may not fit there)."""
    interception = _disclosure("lib:1", "Interception", (321, 323), impact=3)
    leak = _disclosure("lib:2", "Data leak", (322,), impact=2)
    infostealer = _disclosure("lib:3", "Infostealer", (323,), impact=2)
    chat = FakeChatModel()
    chat.responders[AiTask.SAME_SCENARIO] = _grouping(["Interception", "Data leak", "Infostealer"])
    plan = _plan(chat, interception, leak, infostealer)
    assert sorted(tuple(path["systems"]) for path in plan["paths"]) == [(321, 323), (322,)]


def test_a_group_whose_members_one_threat_cannot_cover_is_merged_in_parts() -> None:
    """G213 review: one group of four, two threats each covering two systems, merged only one pair; the
    leftovers now merge among themselves, each merge recorded. Four systems, two scenarios."""
    four = dataclasses.replace(THREE, systems=[*THREE.systems, system_row(324, "SYS4", "Gateway")])
    a = _disclosure("lib:1", "Interception", (321, 322), impact=3)
    b = _disclosure("lib:2", "Data leak", (322,), impact=2)
    c = _disclosure("lib:3", "Infostealer", (323, 324), impact=3)
    d = _disclosure("lib:4", "Sniffing", (324,), impact=2)
    chat = FakeChatModel()
    chat.responders[AiTask.SAME_SCENARIO] = _grouping(
        ["Interception", "Data leak", "Infostealer", "Sniffing"]
    )
    findings = ThreatFindings(
        threats=[a, b, c, d], audits=[], folded=[], notes=[], landscape=describe_asset_for_ai(four, 30_000)
    )
    plan = AttackPathSelector(0, same_scenarios=SameScenarioCheck(chat)).build_plan(findings)
    assert sorted(path["systems"] for path in plan["paths"]) == [[321, 322], [323, 324]]
    assert len(plan["merged"]) == 2


def test_an_outage_is_raised_so_the_job_retries() -> None:
    """Never a silent no-merge: only an unreadable answer is noted; a provider that is down fails the job,
    which retries."""
    chat = FakeChatModel()

    def down(_: str) -> dict[str, Any]:
        raise Unavailable("down")

    chat.responders[AiTask.SAME_SCENARIO] = down
    with pytest.raises(Unavailable):
        _plan(
            chat, _disclosure("lib:2", "Data leak", (321,), 2), _disclosure("lib:3", "Infostealer", (322,), 2)
        )


def test_a_scenario_on_the_asset_itself_is_never_asked_or_merged() -> None:
    """The asset itself is a place of its own; a kind of attack with one system scenario costs no call."""
    on_asset = _disclosure("lib:1", "Grid data theft", (), impact=3)
    on_scada = _disclosure("lib:2", "Data leak", (321,), impact=2)
    chat = FakeChatModel()
    plan = _plan(chat, on_asset, on_scada)
    assert len(plan["paths"]) == 2 and chat.calls == []


def test_an_unreadable_answer_merges_nothing_and_says_so() -> None:
    """Never a failed run: asked, re-asked with its problems, then every scenario kept, noted on the plan."""
    chat = FakeChatModel()
    chat.responders[AiTask.SAME_SCENARIO] = lambda _: {"same": "?"}
    plan = _plan(
        chat, _disclosure("lib:2", "Data leak", (321,), 2), _disclosure("lib:3", "Infostealer", (322,), 2)
    )
    assert len(plan["paths"]) == 2 and len(chat.calls) == 2
    assert plan["notes"] == [PlanMessage.SAME_SCENARIO_NOT_CHECKED.format(categories=1)]


def test_a_group_names_known_scenarios_only_each_once_with_a_reason() -> None:
    """Any JSON may come back: a bad group is re-asked, never a crash."""
    slots = ["P1", "P2", "P3"]
    for answer in (
        {"same": [{"paths": ["P1"], "reason": "r"}]},  # one scenario is no group
        {"same": [{"paths": ["P1", "P9"], "reason": "r"}]},  # unknown
        {"same": [{"paths": ["P1", "P2"], "reason": "r"}, {"paths": ["P2", "P3"], "reason": "r"}]},  # reused
        {"same": [{"paths": ["P1", "P1"], "reason": "r"}]},  # repeated
        {"same": [{"paths": ["P1", "P2"], "reason": " "}]},  # no reason
        {"same": ["P1"]},
    ):
        assert _read_groups(answer, slots)[1], answer
    assert _read_groups({"same": [{"paths": ["P3", "P1"], "reason": "One."}]}, slots) == (
        [(["P3", "P1"], "One.")],
        [],
    )


def test_the_question_asks_for_the_same_action_and_the_same_harm() -> None:
    prompt = same_scenario_prompt("LANDSCAPE", S.REPUDIATION, [{"slot": "P1"}])[1]
    assert "the same attacker action leading to the same harm" in prompt
    assert "if in doubt, keep them separate" in prompt and '{"same": []}' in prompt


def test_a_merged_scenarios_brief_offers_every_system_as_its_entry_point() -> None:
    brief = _brief_of(_plan_threat(systems=(321, 322)))
    assert brief.entry_point_options == ("SCADA server", "Historian") and brief.other_systems == ()
