"""G229 P1 (owner 2026-10-13): actors relevant and diverse but defensible, decided inside the existing
relevance gate call and checked in code: the gate's pick from the threat's own list acts with its reason;
among attackers the gate rated as suitable as its pick, the one acting for fewer threats of the run is
preferred; a lower-rated attacker is never forced in; an unlisted pick is refused (the ranking decides,
noted); no attacker AI call."""

from typing import Any

from app.core.constants import AiTask, AttackerCheck, StrideCategory
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai
from app.engine.scenarios.finding.gate_verdicts import actor_pick
from app.engine.scenarios.finding.relevance_gate import RelevanceGate
from app.engine.scenarios.finding.threat_prompts import relevance_gate_prompt
from app.engine.scenarios.threat_list.attacker_choice import choose_actors, unranked_notes
from app.models.actor_choice import ActorCandidates, ActorPick
from app.models.threats import CategoryAudit, PlannedThreat
from tests.fakes import FakeChatModel, items_in
from tests.planner_samples import (
    AFFILIATE,
    CONTEXT,
    GANG,
    INSIDER,
    PHISHING,
    RANSOMWARE,
    S,
    finder,
    planner_chat,
)

LINKED = ActorCandidates((GANG, AFFILIATE, INSIDER))  # one type's linked actors, best search rank first


def _threat(key: str, pick: ActorPick | None, impact: int = 3) -> PlannedThreat:
    return PlannedThreat(
        key=key, catalogue_id=int(key.split(":")[1]), type_id=1, type_name="Malware", name=key,
        categories=(S.TAMPERING,), systems=(321,), impact=impact, confidence=80.0, reason="It applies.",
        actor_pick=pick,
    )  # fmt: skip


def _pick(name: str | None, *rated: tuple[str, str], why: str = "Has the access.") -> ActorPick:
    return ActorPick(name, why, tuple(sorted(rated)))


def _acting(threats: list[PlannedThreat]) -> list[str]:
    return [threat.actors[0].name for threat in threats]


def test_threats_of_one_type_with_different_facts_get_different_actors() -> None:
    """The gate judges each threat on its own facts; code keeps each pick (different access, different actor),
    with its reason, never the search ranking's first."""
    insider = _threat("lib:1", _pick(INSIDER.name, (INSIDER.name, "HIGH"), why="Holds the admin login."))
    gang = _threat("lib:2", _pick(GANG.name, (GANG.name, "HIGH"), why="Reaches it from the internet."))
    chosen = choose_actors([insider, gang], [LINKED, LINKED], gate_judged=True)
    assert _acting(chosen) == [INSIDER.name, GANG.name]
    assert [threat.attacker_check for threat in chosen] == [AttackerCheck.CHOSEN] * 2
    assert chosen[0].attacker_check_reason == "Holds the admin login."
    # Alternates are the next linked actors, best rank first, never the acting one.
    assert [actor.name for actor in chosen[0].actors[1:]] == [GANG.name, AFFILIATE.name]


def test_the_same_actor_stays_when_it_alone_is_the_most_suitable_for_each_threat() -> None:
    """Repetition by fit is kept: no other attacker is rated as suitable, so nothing is balanced."""
    first = _threat("lib:1", _pick(INSIDER.name, (INSIDER.name, "HIGH"), (GANG.name, "MEDIUM")), impact=3)
    second = _threat("lib:2", _pick(INSIDER.name, (INSIDER.name, "HIGH"), (GANG.name, "MEDIUM")), impact=2)
    chosen = choose_actors([first, second], [LINKED, LINKED], gate_judged=True)
    assert _acting(chosen) == [INSIDER.name, INSIDER.name]
    assert [threat.attacker_check for threat in chosen] == [AttackerCheck.CHOSEN] * 2


def test_equally_suitable_attackers_are_balanced_and_a_lower_rated_one_never_forced() -> None:
    """Search order and habit no longer decide: the highest-impact threat is decided first; a later one whose
    pick another equally rated attacker could take goes to the less-used one (BALANCED, said on the card);
    when the other is rated lower, the pick stays, however often it is used."""
    tie = (GANG.name, "HIGH"), (AFFILIATE.name, "HIGH")
    lead = _threat("lib:1", _pick(GANG.name, *tie), impact=3)
    balanced = _threat("lib:2", _pick(GANG.name, *tie), impact=2)
    lower = _threat("lib:3", _pick(GANG.name, (GANG.name, "HIGH"), (AFFILIATE.name, "MEDIUM")), impact=1)
    chosen = choose_actors([lower, balanced, lead], [LINKED] * 3, gate_judged=True)
    assert _acting(chosen) == [GANG.name, AFFILIATE.name, GANG.name]
    assert [threat.attacker_check for threat in chosen] == [
        AttackerCheck.CHOSEN, AttackerCheck.BALANCED, AttackerCheck.CHOSEN,
    ]  # fmt: skip
    assert "equally suitable (HIGH)" in chosen[1].attacker_check_reason
    # Whatever order they come in, the higher-impact threat keeps the gate's own pick.
    low, high = _threat("lib:4", _pick(GANG.name, *tie), impact=1), _threat("lib:5", _pick(GANG.name, *tie))
    assert _acting(choose_actors([low, high], [LINKED] * 2, gate_judged=True)) == [AFFILIATE.name, GANG.name]
    record = chosen[1].to_record()["actor_selection"]
    assert record["picked"] == GANG.name and record["chosen_id"] == AFFILIATE.actor_id
    assert {item["name"]: item["suitability"] for item in record["candidates"]} == {
        GANG.name: "HIGH", AFFILIATE.name: "HIGH", INSIDER.name: "LOW",
    }  # fmt: skip


def test_a_pick_off_the_list_or_without_a_reason_is_refused_and_the_ranking_decides_noted() -> None:
    """Code validates against the eligible list: an unlisted name, or no reason, is no pick; a rating for an
    unlisted name is dropped. No re-ask: an attacker answer never costs an AI call."""
    listed = [GANG.name, INSIDER.name]
    assert actor_pick({"attacker": "APT99", "attacker_reason": "Famous."}, listed) is None
    assert actor_pick({"attacker": GANG.name, "attacker_reason": ""}, listed) is None
    rated = {"attacker": "ransomware GANG", "attacker_reason": "Reaches it.", "suitability": {"X": "HIGH"}}
    assert actor_pick(rated, listed) == ActorPick(GANG.name, "Reaches it.", ())
    unpicked = choose_actors([_threat("lib:1", None)], [LINKED], gate_judged=True)
    assert unpicked[0].attacker_check == AttackerCheck.NOT_CHECKED and _acting(unpicked) == [GANG.name]
    assert len(unranked_notes(unpicked)) == 1
    # A threat the gate never judged (an AI proposal, a hand-written one) is ranked, not flagged.
    ranked = choose_actors([_threat("lib:1", None)], [LINKED], gate_judged=False)
    assert ranked[0].attacker_check == AttackerCheck.RANKED and unranked_notes(ranked) == []


def test_the_gate_lists_each_threats_attackers_and_the_vetted_pool_when_none_is_linked() -> None:
    """The existing gate call carries the choice: its rule, the RETURN fields, the linked actors as the
    library lists them, and the vetted pool for a type that links none."""
    _, prompt = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [])
    assert "never default to the first name, a well-known attacker" in prompt
    assert '"attacker_reason"' in prompt and '"suitability"' in prompt
    seen: list[dict[str, Any]] = []

    def gate(user_prompt: str) -> dict[str, Any]:
        items = items_in(user_prompt, "CANDIDATES")
        seen.extend(items)
        return {"verdicts": [{"slot": item["slot"], "relevant": False, "systems": [], "reason": "No.",
                              "confidence": 10} for item in items]}  # fmt: skip

    chat = FakeChatModel()
    chat.responders[AiTask.RELEVANCE_GATE] = gate
    vetted = [GANG.name, INSIDER.name]
    gate_check = RelevanceGate(chat, describe_asset_for_ai(CONTEXT, 30_000), unlinked_attackers=vetted)  # type: ignore[arg-type]
    gate_check.judge_library_threats(S.TAMPERING, [RANSOMWARE, PHISHING], CategoryAudit(S.TAMPERING))
    by_threat = {item["threat"]: item["attackers"] for item in seen}
    assert by_threat[RANSOMWARE.name] == [actor.name for actor in RANSOMWARE.linked_actors]
    assert by_threat[PHISHING.name] == vetted  # its type links none


def test_planning_uses_the_gates_picks_and_makes_no_attacker_call() -> None:
    """End to end through the planner: each acting attacker is the gate's pick with its reason (systems by
    name, never alias); the only AI tasks are the planning ones that existed (no attacker task at all)."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    answer = chat.responders[AiTask.RELEVANCE_GATE]

    def picking(user_prompt: str) -> dict[str, Any]:
        verdicts = answer(user_prompt)["verdicts"]
        for verdict in verdicts:
            if verdict["relevant"]:
                verdict |= {"attacker": INSIDER.name, "attacker_reason": "Holds SYS1's admin login.",
                            "suitability": {INSIDER.name: "HIGH"}}  # fmt: skip
        return {"verdicts": verdicts}

    chat.responders[AiTask.RELEVANCE_GATE] = picking
    findings = finder(chat).find_threats(CONTEXT)
    (ransomware,) = [threat for threat in findings.threats if threat.name == RANSOMWARE.name]
    assert ransomware.actors[0].name == INSIDER.name and ransomware.attacker_check == AttackerCheck.CHOSEN
    assert ransomware.attacker_check_reason == "Holds SCADA server's admin login."
    assert {task for task, _ in chat.calls} <= {AiTask.RELEVANCE_GATE, AiTask.GAP_FILL, AiTask.SAME_ATTACK}
    assert not any("attacker" in task.value for task in AiTask)
