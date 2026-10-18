"""Who acts for a threat: the relevance gate's pick from the threat's own list, with its reason; among the
attackers it rated as suitable as its pick, the one acting for fewer threats of the run; never a lower-rated
one; an unlisted pick is no pick. No attacker AI call."""

from typing import Any

from app.core.constants import AiTask, AttackerCheck, StrideCategory
from app.domain.scenario.plan import actor_pick, choose_actors, relevance_gate_prompt
from app.models.scenario.plan import ActorCandidates, ActorPick, PlannedThreat
from tests.fakes import items_in
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
    """Each pick is kept with its reason, never the search ranking's first; only the acting one is planned."""
    insider = _threat("lib:1", _pick(INSIDER.name, (INSIDER.name, "HIGH"), why="Holds the admin login."))
    gang = _threat("lib:2", _pick(GANG.name, (GANG.name, "HIGH"), why="Reaches it from the internet."))
    chosen = choose_actors([insider, gang], [LINKED, LINKED], gate_judged=True)
    assert _acting(chosen) == [INSIDER.name, GANG.name]
    assert [threat.attacker_check for threat in chosen] == [AttackerCheck.CHOSEN] * 2
    assert chosen[0].attacker_check_reason == "Holds the admin login." and len(chosen[0].actors) == 1


def test_the_same_actor_stays_when_it_alone_is_the_most_suitable_for_each_threat() -> None:
    first = _threat("lib:1", _pick(INSIDER.name, (INSIDER.name, "HIGH"), (GANG.name, "MEDIUM")), impact=3)
    second = _threat("lib:2", _pick(INSIDER.name, (INSIDER.name, "HIGH"), (GANG.name, "MEDIUM")), impact=2)
    chosen = choose_actors([first, second], [LINKED, LINKED], gate_judged=True)
    assert _acting(chosen) == [INSIDER.name, INSIDER.name]
    assert [threat.attacker_check for threat in chosen] == [AttackerCheck.CHOSEN] * 2


def test_equally_suitable_attackers_are_balanced_and_a_lower_rated_one_never_forced() -> None:
    """The highest-impact threat is decided first; a later one whose pick an equally rated attacker could take
    goes to the less-used one (BALANCED, said on the card); one rated lower never takes it."""
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
    low, high = _threat("lib:4", _pick(GANG.name, *tie), impact=1), _threat("lib:5", _pick(GANG.name, *tie))
    assert _acting(choose_actors([low, high], [LINKED] * 2, gate_judged=True)) == [AFFILIATE.name, GANG.name]


def test_a_pick_off_the_list_or_without_a_reason_is_no_pick_and_the_first_candidate_acts() -> None:
    """An unlisted name, or no reason, is no pick; a rating for an unlisted name is dropped; no re-ask."""
    listed = [GANG.name, INSIDER.name]
    assert actor_pick({"attacker": "APT99", "attacker_reason": "Famous."}, listed) is None
    assert actor_pick({"attacker": GANG.name, "attacker_reason": ""}, listed) is None
    rated = {"attacker": "ransomware GANG", "attacker_reason": "Reaches it.", "suitability": {"X": "HIGH"}}
    assert actor_pick(rated, listed) == ActorPick(GANG.name, "Reaches it.", ())
    unpicked = choose_actors([_threat("lib:1", None)], [LINKED], gate_judged=True)
    assert unpicked[0].attacker_check == AttackerCheck.NOT_CHECKED and _acting(unpicked) == [GANG.name]
    ranked = choose_actors([_threat("lib:1", None)], [LINKED], gate_judged=False)  # a hand-written threat
    assert ranked[0].attacker_check == AttackerCheck.RANKED


def test_the_gate_lists_each_threats_linked_attackers_and_the_vetted_pool_when_none_is_linked() -> None:
    _, prompt = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [])
    assert "never default to the first name, a well-known attacker" in prompt
    assert '"attacker_reason"' in prompt and '"suitability"' in prompt
    chat = planner_chat({})
    answer, seen = chat.responders[AiTask.RELEVANCE_GATE], {}

    def recording(user_prompt: str) -> dict[str, Any]:
        seen.update({item["threat"]: item["attackers"] for item in items_in(user_prompt, "CANDIDATES")})
        return answer(user_prompt)

    chat.responders[AiTask.RELEVANCE_GATE] = recording
    finder(chat).find_threats(CONTEXT)
    assert seen[RANSOMWARE.name] == [actor.name for actor in RANSOMWARE.linked_actors]
    assert seen[PHISHING.name] == sorted([GANG.name, AFFILIATE.name, INSIDER.name])  # its type links none


def test_planning_uses_the_gates_picks_and_makes_no_attacker_call() -> None:
    """Each acting attacker is the gate's pick with its reason (systems by name, never alias)."""
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
    assert {task for task, _ in chat.calls} <= {AiTask.RELEVANCE_GATE, AiTask.GAP_FILL}
