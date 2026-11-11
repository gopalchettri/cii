"""A threat that needs something no recorded fact mentions is never planned (code decides, not the AI's
obedience); the attacker's preparation is not a threat; and each scenario is built on its group's strongest
threat."""

import dataclasses
from collections.abc import Callable
from typing import Any

from app.core.constants import AiTask, CandidateRejection, PlanStage, StrideCategory
from app.domain.scenario import plan as plan_module
from app.domain.scenario.plan import build_plan
from app.models.scenario.plan import ActorPick, AttackPlace, Drop, PlannedThreat
from tests.fakes import FakeEmbeddings, FakeRerankModel, items_in
from tests.planner_samples import (
    CONTEXT,
    LOG_WIPE,
    RANSOMWARE,
    WORDS,
    drops_for,
    finder,
    gap_fill_for_elevation,
    gap_fill_prompt,
    gap_filled,
    gate_prompt,
    judged,
    planned,
    planner_chat,
)
from tests.test_attack_paths import findings_of
from tests.test_threat_finding import _PROPOSAL, _TYPE_MATCHES


def _gate_needing(relevant: dict[str, list[str]], needs: dict[str, list[str]]) -> Callable[[str], Any]:
    """The sample gate, which also says what a threat needs that nothing recorded mentions."""
    gate = judged(relevant)

    def answer(user_prompt: str) -> dict[str, Any]:
        threats = {item["slot"]: item["threat"] for item in items_in(user_prompt, "CANDIDATES")}
        verdicts = gate(user_prompt)["verdicts"]
        return {"verdicts": [v | {"needs": needs.get(threats[v["slot"]], [])} for v in verdicts]}

    return answer


def test_a_threat_that_needs_something_not_recorded_is_never_planned() -> None:
    relevant = {RANSOMWARE.name: ["SYS1"], LOG_WIPE.name: ["SYS1"]}
    chat = planner_chat(relevant)
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing(relevant, {RANSOMWARE.name: ["USB ports"]})
    findings = finder(chat).find_threats(CONTEXT)
    assert [threat.name for threat in findings.threats] == [LOG_WIPE.name]  # needs nothing: kept


def test_an_ai_proposal_that_needs_something_not_recorded_is_refused_too() -> None:
    """The proposal is judged by the same gate, so the same rule refuses it."""
    proposal = _PROPOSAL | {"threat": "Jump server hijack"}
    chat = planner_chat({})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing(
        {proposal["threat"]: ["SYS1"]}, {proposal["threat"]: ["jump server"]}
    )
    findings = finder(chat, FakeRerankModel(_TYPE_MATCHES)).find_threats(CONTEXT)
    assert any(proposal["threat"] in user for user in chat.asked(AiTask.RELEVANCE_GATE))
    assert findings.threats == []


def test_the_gate_asks_for_needs_and_never_takes_preparation_for_an_attack() -> None:
    prompt = gate_prompt([{"slot": "R1"}])
    assert '"needs": []' in prompt and 'A threat with anything in "needs" is not used' in prompt
    assert "preparation done elsewhere" in prompt and "is not a threat to this asset" in prompt
    assert 'removable media), list it in "needs"' in prompt  # one instruction for a missing component
    assert "removable media), it is not relevant" not in prompt
    proposal_prompt = gap_fill_prompt([StrideCategory.TAMPERING])
    assert "removable media), it is not relevant" in proposal_prompt and '"needs"' not in proposal_prompt


def test_each_threat_is_its_own_scenario_ranked_by_impact_and_confidence_with_no_ai_call() -> None:
    """Every accepted threat is a scenario (owner 2026-10-19: asset level, none hidden under another), in
    turns over the systems, each turn the most relevant left: impact, then confidence, then the tie-break."""
    strongest = planned("lib:1", "Firmware change", (321,), impact=3, confidence=90.0)
    other = planned("lib:2", "Logic overwrite", (321,), impact=3, confidence=70.0)
    alone = planned("lib:3", "Log wipe", (322,), categories=(StrideCategory.SPOOFING,), impact=1)
    plan = build_plan(findings_of(other, strongest, alone), 0)
    assert [(path["category"], path["steps"], path["entry_system"]) for path in plan["paths"]] == [
        (StrideCategory.TAMPERING, ["lib:1"], 321),  # SYS1's turn
        (StrideCategory.SPOOFING, ["lib:3"], 322),  # SYS2's turn, though the weakest
        (StrideCategory.TAMPERING, ["lib:2"], 321),  # SYS1's next turn
    ]
    assert all(path["also_applies"] == [] for path in plan["paths"])


def test_a_listed_need_refuses_the_threat_under_every_category() -> None:
    """A need is a fact about the asset, whatever "relevant" says: one verdict per threat, so a threat
    judged not relevant with a need is refused for it under Tampering and Denial of Service alike, and the
    categories it empties still get the one gap fill."""
    chat = planner_chat({})  # the ransomware is filed under Tampering and Denial of Service
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing({}, {RANSOMWARE.name: ["backup server"]})
    findings = finder(chat).find_threats(CONTEXT)
    assert RANSOMWARE.name not in [threat.name for threat in findings.threats]
    for category in (StrideCategory.TAMPERING, StrideCategory.DENIAL_OF_SERVICE):
        codes = [drop.reason for drop in drops_for(findings, category) if drop.threat_key == "lib:1"]
        assert codes == [CandidateRejection.NEEDS_UNRECORDED], category
        assert category in gap_filled(chat), category


S = StrideCategory
SPOOFING_WHY = "A former vendor account still active could be used to log in as an operator."
PRIVILEGE_WHY = "The same account could be added to the operator role and gain engineer rights."
#: An IT asset whose SYS1 "SCADA server" (321) is OT and SYS2 "Historian" (322) is IT.
MIXED = dataclasses.replace(
    CONTEXT,
    asset=CONTEXT.asset | {"category_code": "IT"},
    systems=[CONTEXT.systems[0], CONTEXT.systems[1] | {"category_code": "IT"}],
)


def _judged(category: StrideCategory, reason: str, key: str = "lib:233") -> PlannedThreat:
    """A gate verdict: the threat accepted under one category with that category's reason."""
    return planned(key, "Shared, stale or orphaned account misuse", categories=(category,), reason=reason)


def _merge_into(kept: PlannedThreat, twin: PlannedThreat, drops: list[Drop] | None = None) -> PlannedThreat:
    return plan_module._merge_threat_into_another(kept, twin, MIXED, [] if drops is None else drops)


def test_a_fold_keeps_each_categorys_own_reason() -> None:
    merged = _merge_into(
        _judged(S.SPOOFING, SPOOFING_WHY), _judged(S.ELEVATION_OF_PRIVILEGE, PRIVILEGE_WHY, "ai:x")
    )
    assert merged.categories == (S.SPOOFING, S.ELEVATION_OF_PRIVILEGE)
    record = merged.to_record({})
    assert record["reason"] == SPOOFING_WHY  # the main category's
    assert record["reasons"] == {S.SPOOFING: SPOOFING_WHY, S.ELEVATION_OF_PRIVILEGE: PRIVILEGE_WHY}
    folded = _merge_into(merged, _judged(S.SPOOFING, "another reworded reason", key="ai:y"))
    assert folded.reasons[S.SPOOFING] == SPOOFING_WHY  # the kept one's wins a category both have


def test_every_categorys_reason_survives_any_fold_order() -> None:
    """The recurrence guard: whatever order threats are folded in, each kind reads its own reason."""
    verdicts = [_judged(S.SPOOFING, "s"), _judged(S.TAMPERING, "t"), _judged(S.ELEVATION_OF_PRIVILEGE, "e")]
    for first in range(3):
        merged, *others = verdicts[first:] + verdicts[:first]
        for other in others:
            merged = _merge_into(merged, other)
        assert {kind: merged.reasons[kind] for kind in merged.categories} == {
            S.SPOOFING: "s",
            S.TAMPERING: "t",
            S.ELEVATION_OF_PRIVILEGE: "e",
        }


def test_a_fold_keeps_the_kept_threats_path_and_unites_the_systems() -> None:
    spoofing = _judged(S.SPOOFING, SPOOFING_WHY)
    spoofing = dataclasses.replace(spoofing, main_place=AttackPlace((321,), (321,), 3, 90.0))
    privilege = _judged(S.ELEVATION_OF_PRIVILEGE, PRIVILEGE_WHY, "ai:x")
    privilege = dataclasses.replace(
        privilege, systems=(322,), main_place=AttackPlace((322,), (322,), 1, 40.0)
    )
    for kept, other in ((spoofing, privilege), (privilege, spoofing)):
        merged = _merge_into(kept, other)
        assert merged.main_place == kept.main_place and merged.systems == (321, 322)


def test_one_ai_name_under_two_categories_is_one_threat_in_stride_order_with_no_merge_drop() -> None:
    tampering = planned("ai:wipe", "Wipe", (321,), categories=(S.TAMPERING,))
    denial = planned("ai:wipe", "Wipe", (322,), categories=(S.DENIAL_OF_SERVICE,), impact=3)
    drops: list[Drop] = []
    (merged,) = plan_module._merge_duplicate_threats(
        [tampering, denial], FakeEmbeddings(WORDS), CONTEXT, drops
    )  # type: ignore[arg-type]
    assert (
        merged.categories == (S.TAMPERING, S.DENIAL_OF_SERVICE) and merged.main_place == tampering.main_place
    )
    assert (merged.systems, merged.impact, drops) == ((321, 322), 3, [])


def test_a_shared_category_twin_still_counts_when_another_twin_misfits() -> None:
    """Each fold on its own: twin A shares Spoofing on the IT system; twin B brings Tampering through the IT
    system the OT library threat cannot fit, so only B is refused, and the path stays the library's."""
    library = planned("lib:1", "L", (321,), categories=(S.SPOOFING,), confidence=70.0, asset_type="OT")
    shared = planned("ai:a", "A", (322,), categories=(S.SPOOFING,), confidence=90.0)
    misfit = planned("ai:b", "B", (322,), categories=(S.TAMPERING,))
    drops: list[Drop] = []
    merged = _merge_into(_merge_into(library, shared, drops), misfit, drops)
    assert (merged.systems, merged.confidence, merged.categories) == ((321, 322), 90.0, (S.SPOOFING,))
    assert merged.main_place == library.main_place
    mismatch = Drop("lib:1", "L", S.TAMPERING, PlanStage.MERGE, CandidateRejection.ASSET_TYPE_MISMATCH)
    assert drops == [mismatch]


def test_a_twin_under_two_categories_fits_through_its_main_ways_in_or_not_at_all() -> None:
    """The AI twin is Tampering through the OT system and Denial of Service through the IT one; the IT
    library threat fits only the IT system, so neither category is taken."""
    library = planned("lib:1", "X", (322,), categories=(S.SPOOFING,), asset_type="IT")
    twin = planned("ai:x", "X", (321, 322), categories=(S.TAMPERING, S.DENIAL_OF_SERVICE))
    twin = dataclasses.replace(twin, main_place=AttackPlace((321,), (321,), 2, 70.0))
    drops: list[Drop] = []
    merged = _merge_into(library, twin, drops)
    assert merged.categories == (S.SPOOFING,) and merged.systems == (322,)
    assert [drop.kind for drop in drops] == [S.TAMPERING, S.DENIAL_OF_SERVICE]


def test_the_first_folded_twin_naming_an_attacker_gives_the_pick() -> None:
    """The library threat names none; twin B (fits) names Q, folded first; twin A (fits partly) names P."""
    library = planned("lib:1", "L", (321,), categories=(S.SPOOFING,), asset_type="OT")
    library = dataclasses.replace(library, actor_pick=ActorPick(None, "None could."))
    fits = planned(
        "ai:b", "B", (321,), categories=(S.INFORMATION_DISCLOSURE,), actor_pick=ActorPick("Q", "Q can.")
    )
    partly = planned("ai:a", "A", (321, 322), categories=(S.TAMPERING,), actor_pick=ActorPick("P", "P can."))
    merged = _merge_into(_merge_into(library, fits), partly)
    assert merged.actor_pick == ActorPick("Q", "Q can.")
    assert merged.categories == (S.SPOOFING, S.INFORMATION_DISCLOSURE, S.TAMPERING)
