"""A threat that needs something no recorded fact mentions is never planned (code decides, not the AI's
obedience); the attacker's preparation is not a threat; and each scenario is built on its group's strongest
threat."""

from collections.abc import Callable
from typing import Any

from app.core.constants import AiTask, CandidateRejection, StrideCategory
from app.domain.scenario.plan import build_plan, gap_fill_prompt, relevance_gate_prompt
from tests.fakes import FakeRerankModel, items_in
from tests.planner_samples import (
    CONTEXT,
    LOG_WIPE,
    RANSOMWARE,
    audit_of,
    finder,
    gap_fill_for_elevation,
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
    prompt = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [{"slot": "R1"}])[1]
    assert '"needs": []' in prompt and 'A threat with anything in "needs" is not used' in prompt
    assert "preparation done elsewhere" in prompt and "is not a threat to this asset" in prompt
    assert 'removable media), list it in "needs"' in prompt  # one instruction for a missing component
    assert "removable media), it is not relevant" not in prompt
    proposal_prompt = gap_fill_prompt("LANDSCAPE", StrideCategory.TAMPERING, 3, ())[1]
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


def test_a_listed_need_under_one_category_refuses_the_threat_under_every_category() -> None:
    """A need is a fact about the asset, whatever "relevant" says: refused under Tampering (judged not
    relevant, with a need), the threat is refused under Denial of Service too, and each emptied category
    still gets its one gap fill."""
    relevant = {RANSOMWARE.name: ["SYS1"]}  # filed under Tampering and Denial of Service
    needing = _gate_needing({}, {RANSOMWARE.name: ["backup server"]})
    chat = planner_chat(relevant)
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        needing(user) if "category: Tampering" in user else judged(relevant)(user)
    )
    findings = finder(chat).find_threats(CONTEXT)
    assert RANSOMWARE.name not in [threat.name for threat in findings.threats]
    for category in (StrideCategory.TAMPERING, StrideCategory.DENIAL_OF_SERVICE):
        codes = [
            r["code"]
            for r in audit_of(findings, category).rejected
            if r["library_id"] == RANSOMWARE.catalogue_id
        ]
        assert codes == [CandidateRejection.NEEDS_UNRECORDED], category
        assert any(f"category: {category}" in user for user in chat.asked(AiTask.GAP_FILL)), category
