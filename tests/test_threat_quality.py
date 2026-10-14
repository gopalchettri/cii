"""G209 (owner 2026-10-12: about 20-25 scenarios "without losing the quality"): a threat that needs something
no recorded fact mentions is never planned (code decides, not the AI's obedience); the attacker's
preparation is not a threat; and each scenario is built on the threat the AI judges best for its system."""

from collections.abc import Callable
from typing import Any

from app.core.constants import AiTask, CandidateRejection, GapFillOutcome, PlanMessage, StrideCategory
from app.engine.scenarios.attack_paths.best_threat import BestThreatPicker, _read_pick
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.engine.scenarios.finding.threat_prompts import (
    best_threat_prompt,
    gap_fill_prompt,
    relevance_gate_prompt,
)
from tests.fakes import FakeChatModel, items_in
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
from tests.test_threat_finding import _PROPOSAL


def _gate_needing(relevant: dict[str, list[str]], needs: dict[str, list[str]]) -> Callable[[str], Any]:
    """The sample gate, which also says what a threat needs that nothing recorded mentions."""
    gate = judged(relevant)

    def answer(user_prompt: str) -> dict[str, Any]:
        threats = {item["slot"]: item["threat"] for item in items_in(user_prompt, "CANDIDATES")}
        verdicts = gate(user_prompt)["verdicts"]
        return {"verdicts": [v | {"needs": needs.get(threats[v["slot"]], [])} for v in verdicts]}

    return answer


def test_a_threat_that_needs_something_not_recorded_is_never_planned() -> None:
    """Live run 70dc270b: 14 accepted threats assumed a SIEM, USB ports or a helpdesk the asset never records,
    though the prompt said never to assume one. Now code refuses any verdict whose "needs" is not empty."""
    relevant = {RANSOMWARE.name: ["SYS1"], LOG_WIPE.name: ["SYS1"]}
    chat = planner_chat(relevant)
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing(relevant, {RANSOMWARE.name: ["USB ports"]})
    findings = finder(chat).find_threats(CONTEXT)
    assert RANSOMWARE.name not in [threat.name for threat in findings.threats]
    assert LOG_WIPE.name in [threat.name for threat in findings.threats]  # needs nothing: kept
    refused = [r for a in findings.audits for r in a.rejected if r["library_id"] == RANSOMWARE.catalogue_id]
    assert refused and all(r["code"] == CandidateRejection.NEEDS_UNRECORDED for r in refused)
    assert all(r["needs"] == ["USB ports"] for r in refused)  # the reviewer sees why


def test_an_ai_proposal_that_needs_something_not_recorded_is_refused_too() -> None:
    """The gap-fill proposal is judged by the same gate, so the same rule refuses it."""
    proposal = _PROPOSAL | {"threat": "Jump server hijack"}
    chat = planner_chat({})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    # relevant=false WITH a need (the gate's other answer channel): still a need refusal, with its list
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing({}, {"Jump server hijack": ["jump server"]})
    elevation = audit_of(finder(chat).find_threats(CONTEXT), StrideCategory.ELEVATION_OF_PRIVILEGE)
    assert elevation.gap_fill == GapFillOutcome.REJECTED
    refused = [r for r in elevation.rejected if r["code"] == CandidateRejection.NEEDS_UNRECORDED]
    assert [r["needs"] for r in refused] == [
        ["jump server"]
    ]  # the reviewer sees why, as for a library threat


def test_a_listed_need_refuses_the_threat_whatever_relevant_says() -> None:
    """G209 review: told both "not relevant" and "list it in needs", the AI may answer relevant=false WITH a
    need; the record must still say needs_unrecorded, the code every category's refusal follows."""
    relevant = {RANSOMWARE.name: ["SYS1"]}
    chat = planner_chat(relevant)
    chat.responders[AiTask.RELEVANCE_GATE] = _gate_needing({}, {RANSOMWARE.name: ["backup server"]})
    findings = finder(chat).find_threats(CONTEXT)
    refused = [r for a in findings.audits for r in a.rejected if r["library_id"] == RANSOMWARE.catalogue_id]
    assert refused and all(r["code"] == CandidateRejection.NEEDS_UNRECORDED for r in refused)
    assert all(r["needs"] == ["backup server"] for r in refused)


def test_the_gate_asks_for_needs_and_never_takes_preparation_for_an_attack() -> None:
    """Live run 70dc270b: "Search open technical databases" and "Obtain capabilities" were accepted."""
    prompt = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [{"slot": "R1"}])[1]
    assert '"needs": []' in prompt and 'A threat with anything in "needs" is not used' in prompt
    assert "preparation done elsewhere" in prompt and "is not a threat to this asset" in prompt
    # one instruction for a missing component, never two that disagree (G209 review)
    assert (
        'removable media), list it in "needs"' in prompt
        and "removable media), it is not relevant" not in prompt
    )
    proposal_prompt = gap_fill_prompt("LANDSCAPE", StrideCategory.TAMPERING, 3)[1]
    assert "removable media), it is not relevant" in proposal_prompt and '"needs"' not in proposal_prompt


def _picking(name: str) -> Callable[[str], dict[str, Any]]:
    """A pick that names `name` best."""

    def answer(user_prompt: str) -> dict[str, Any]:
        slot = next(item["slot"] for item in items_in(user_prompt, "CANDIDATES") if item["threat"] == name)
        return {"best": [slot], "reason": "It changes the controller logic on SYS1."}

    return answer


def test_each_scenario_is_built_on_the_threat_the_ai_judges_best_for_the_asset() -> None:
    """Live run e4e70ea7: impact is HIGH for most threats, so numbers picked "AML.T0073 Impersonation" for a
    repudiation scenario. Now the AI picks by meaning; a group of one asks nothing."""
    strongest = planned("lib:1", "Firmware change", (321,), impact=3, confidence=90.0)
    best = planned("lib:2", "Logic overwrite", (321,), impact=3, confidence=70.0)
    alone = planned("lib:3", "Log wipe", (322,), categories=(StrideCategory.SPOOFING,), impact=1)
    chat = FakeChatModel()
    chat.responders[AiTask.BEST_THREAT] = _picking("Logic overwrite")
    plan = AttackPathSelector(0, BestThreatPicker(chat)).build_plan(findings_of(strongest, best, alone))
    by_category = {path["category"]: (path["steps"], path["also_applies"]) for path in plan["paths"]}
    assert by_category == {
        StrideCategory.TAMPERING: (["lib:2"], ["Firmware change"]),
        StrideCategory.SPOOFING: (["lib:3"], []),
    }
    assert [task for task, _ in chat.calls] == [AiTask.BEST_THREAT] and plan["notes"] == []
    prompt = chat.calls[0][1]
    assert "the asset itself" in prompt and "Firmware change" in prompt and "lib:" not in prompt
    assert 'the asset itself, through SYS1 "SCADA server"' in prompt  # the group's route (G216)


def test_an_unreadable_pick_keeps_the_strongest_and_says_so() -> None:
    """Never a failed run for this step: an answer naming no listed threat, asked again, keeps the group in
    strength order, and the plan notes it."""
    strongest = planned("lib:1", "Firmware change", (321,), impact=3, confidence=90.0)
    other = planned("lib:2", "Logic overwrite", (321,), impact=3, confidence=70.0)
    chat = FakeChatModel()
    chat.responders[AiTask.BEST_THREAT] = lambda _: {"best": ["C9", "C9"], "reason": "x"}
    plan = AttackPathSelector(0, BestThreatPicker(chat)).build_plan(findings_of(strongest, other))
    assert [path["steps"] for path in plan["paths"]] == [["lib:1"]]
    assert plan["notes"] == [PlanMessage.BEST_THREAT_NOT_PICKED.format(groups=1)]
    assert len(chat.calls) == 2  # asked, then asked once more with its problems


def test_the_pick_question_names_the_kind_of_attack_and_the_system() -> None:
    prompt = best_threat_prompt(
        "LANDSCAPE", StrideCategory.REPUDIATION, 'SYS2 "Historian"', [{"slot": "C1"}]
    )[1]
    assert "STRIDE category: Repudiation" in prompt and 'judged to apply to SYS2 "Historian"' in prompt
    assert '"best": ["C2", "C5", "C1"]' in prompt


def test_a_pick_names_listed_threats_only_each_once_with_a_reason() -> None:
    """Any JSON may come back: a repeated, unknown or non-text slot, or no reason, is re-asked, never a
    crash."""
    slots = {"C1", "C2"}
    for answer in (
        {"best": ["C1", "C1"], "reason": "r"},
        {"best": ["C3"], "reason": "r"},
        {"best": [["C1"]], "reason": "r"},
        {"best": [], "reason": "r"},
        {"best": ["C2"], "reason": " "},
    ):
        assert _read_pick(answer, slots)[1], answer
    assert _read_pick({"best": ["C2", "C1"], "reason": "Fits SYS1."}, slots) == (["C2", "C1"], [])


def test_a_threat_refused_for_a_need_under_one_category_is_refused_under_every_category() -> None:
    """Live run b0c3908f: the helpdesk fraud was refused under one category (its helpdesk unrecorded) and
    accepted under another, where the AI forgot to say so. What a threat needs is a fact about the asset."""
    relevant = {RANSOMWARE.name: ["SYS1"]}  # filed under Tampering and Denial of Service
    gate = _gate_needing(relevant, {RANSOMWARE.name: ["backup server"]})
    chat = planner_chat(relevant)
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        gate(user) if "category: Tampering" in user else judged(relevant)(user)
    )
    findings = finder(chat).find_threats(CONTEXT)
    assert RANSOMWARE.name not in [threat.name for threat in findings.threats]
    for category in (StrideCategory.TAMPERING, StrideCategory.DENIAL_OF_SERVICE):
        audit = audit_of(findings, category)
        codes = [r["code"] for r in audit.rejected if r["library_id"] == RANSOMWARE.catalogue_id]
        assert codes == [CandidateRejection.NEEDS_UNRECORDED] and audit.relevant == 0, category
        # left with nothing, each category still gets its one AI gap-fill (G209 review: Denial of Service,
        # emptied by the refusal under Tampering, was never asked)
        assert audit.gap_fill == GapFillOutcome.NONE_APPLIES, category
