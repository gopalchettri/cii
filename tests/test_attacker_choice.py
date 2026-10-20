"""Who acts for a threat: the relevance gate's pick from its type's linked actors, with its reason, else the
top-ranked linked actor; none when the gate finds none plausible; an unlisted pick is no pick. A hand-written
scenario takes its threat's linked actors, else its type's, else the whole library's. No attacker AI call."""

import dataclasses
from typing import Any

from app.core.constants import AiTask, AttackerCheck, LibraryStatus, StrideCategory
from app.domain.remediation.manual import pick_manual_attacker
from app.domain.scenario.plan import actor_pick, choose_actor, merge_two_threats, relevance_gate_prompt
from app.models.scenario.plan import ActorPick, PlannedThreat
from tests.fakes import items_in
from tests.planner_samples import (
    AFFILIATE,
    CONTEXT,
    CREW,
    EXFILTRATION,
    GANG,
    INSIDER,
    LOG_WIPE,
    PHISHING,
    RANSOMWARE,
    S,
    finder,
    library_search,
    planned,
    planner_chat,
)

LINKED = (GANG, AFFILIATE, INSIDER)  # one type's linked actors, best search rank first


def _threat(key: str, pick: ActorPick | None) -> PlannedThreat:
    return PlannedThreat(
        key=key, catalogue_id=int(key.split(":")[1]), type_id=1, type_name="Malware", name=key,
        categories=(S.TAMPERING,), systems=(321,), impact=3, confidence=80.0, reason="It applies.",
        actor_pick=pick,
    )  # fmt: skip


def test_threats_of_one_type_with_different_facts_get_different_actors() -> None:
    """Each pick is kept with its reason, never the search ranking's first; only the acting one is planned."""
    insider = choose_actor(_threat("lib:1", ActorPick(INSIDER.name, "Holds the admin login.")), LINKED)
    gang = choose_actor(_threat("lib:2", ActorPick(GANG.name, "Reaches it from the internet.")), LINKED)
    assert [insider.actors[0].name, gang.actors[0].name] == [INSIDER.name, GANG.name]
    assert insider.attacker_check == gang.attacker_check == AttackerCheck.CHOSEN
    assert insider.attacker_check_reason == "Holds the admin login." and len(insider.actors) == 1


def test_no_usable_pick_takes_the_top_linked_actor_and_none_fits_names_no_one() -> None:
    """An unlisted name, or no reason, is no pick; no re-ask. None plausible: no attacker, so not planned."""
    listed = [GANG.name, INSIDER.name]
    assert actor_pick({"attacker": "APT99", "attacker_reason": "Famous."}, listed) is None
    assert actor_pick({"attacker": GANG.name, "attacker_reason": ""}, listed) is None
    assert actor_pick({"attacker": "ransomware GANG", "attacker_reason": "Reaches it."}, listed) == ActorPick(
        GANG.name, "Reaches it."
    )
    unpicked = choose_actor(_threat("lib:1", None), LINKED)
    assert unpicked.attacker_check == AttackerCheck.NOT_CHECKED and unpicked.actors[0].name == GANG.name
    none_fits = choose_actor(_threat("lib:1", ActorPick(None, "No listed attacker reaches it.")), LINKED)
    assert none_fits.actors == () and none_fits.attacker_check == AttackerCheck.NONE_FITS


def test_the_gate_lists_each_threats_linked_attackers_and_never_judges_one_whose_type_links_none() -> None:
    _, prompt = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [])
    assert "never default to the first name, a well-known attacker" in prompt
    assert '"attacker_reason"' in prompt and '"suitability"' not in prompt
    chat = planner_chat({PHISHING.name: ["SYS1"]})
    answer, seen = chat.responders[AiTask.RELEVANCE_GATE], {}

    def recording(user_prompt: str) -> dict[str, Any]:
        seen.update({item["threat"]: item["attackers"] for item in items_in(user_prompt, "CANDIDATES")})
        return answer(user_prompt)

    chat.responders[AiTask.RELEVANCE_GATE] = recording
    finder(chat).find_threats(CONTEXT)
    assert seen[RANSOMWARE.name] == [actor.name for actor in RANSOMWARE.linked_actors]
    seen.clear()
    unlinked = dataclasses.replace(PHISHING, linked_actors=())
    findings = finder(chat, threats=(RANSOMWARE, unlinked)).find_threats(CONTEXT)
    assert PHISHING.name not in seen and findings.threats == []


def test_planning_uses_the_gates_picks_and_makes_no_attacker_call() -> None:
    """Each acting attacker is the gate's pick with its reason (systems by name, never alias); a threat the
    gate finds no attacker for is not planned."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], PHISHING.name: ["SYS1"]})
    answer = chat.responders[AiTask.RELEVANCE_GATE]

    def picking(user_prompt: str) -> dict[str, Any]:
        verdicts = answer(user_prompt)["verdicts"]
        for item, verdict in zip(items_in(user_prompt, "CANDIDATES"), verdicts, strict=True):
            if item["threat"] == RANSOMWARE.name:
                verdict |= {"attacker": INSIDER.name, "attacker_reason": "Holds SYS1's admin login."}
            elif item["threat"] == PHISHING.name:
                verdict |= {"attacker": None, "attacker_reason": "No listed attacker reaches SYS1."}
        return {"verdicts": verdicts}

    chat.responders[AiTask.RELEVANCE_GATE] = picking
    findings = finder(chat).find_threats(CONTEXT)
    (ransomware,) = findings.threats
    assert ransomware.actors[0].name == INSIDER.name and ransomware.attacker_check == AttackerCheck.CHOSEN
    assert ransomware.attacker_check_reason == "Holds SCADA server's admin login."
    assert {task for task, _ in chat.calls} <= {AiTask.RELEVANCE_GATE, AiTask.GAP_FILL}


def test_a_hand_written_threat_takes_its_linked_actors_else_its_types_else_the_whole_librarys() -> None:
    unlinked = dataclasses.replace(PHISHING, linked_actors=())
    search, _ = library_search(threats=(unlinked, LOG_WIPE, EXFILTRATION))
    snapshot = search.snapshot()

    def acting(**threat: Any) -> tuple[str, bool]:
        content = {"threat": threat | {"type": "Theft", "name": "Login"}, "statement": "A crew phishes."}
        (acting_actor,) = pick_manual_attacker(snapshot, {"content": content})
        return acting_actor["name"], acting_actor["closest"]

    active = LibraryStatus.ACTIVE
    assert acting(library_id=LOG_WIPE.catalogue_id, library_status=active) == (INSIDER.name, False)
    assert acting(type_id=EXFILTRATION.type_id) == (GANG.name, False)  # a new threat of a live type
    # Its type links no actor, or a new type: the whole library's nearest, flagged.
    assert acting(library_id=PHISHING.catalogue_id, library_status=active) == (CREW.name, True)
    assert acting(type_id=None) == (CREW.name, True)


def test_one_kinds_none_fits_never_vetoes_the_attacker_another_kind_named() -> None:
    """A threat merged across kinds keeps a pick that names an attacker over one that says none fits, in
    either order; a "none fits" still beats no pick at all."""
    named = planned("lib:1", "Ransomware", actor_pick=ActorPick(GANG.name, "It needs a crew."))
    none_fits = planned(
        "lib:1", "Ransomware", categories=(S.DENIAL_OF_SERVICE,), actor_pick=ActorPick(None, "None could.")
    )
    for kept, other in ((named, none_fits), (none_fits, named)):
        merged = merge_two_threats(kept, other)
        assert merged.actor_pick == ActorPick(GANG.name, "It needs a crew.")
        assert choose_actor(merged, LINKED).attacker_check == AttackerCheck.CHOSEN
    unpicked = dataclasses.replace(named, actor_pick=None)
    assert merge_two_threats(unpicked, none_fits).actor_pick == ActorPick(None, "None could.")
