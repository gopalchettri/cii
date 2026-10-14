"""Who acts for each threat (G229, owner 2026-10-13: "diverse but defensible threat actor assignments",
with no AI call added). The relevance gate named its pick from the threat's own listed attackers, why, and
how suitable it judged each one (finding/gate_verdicts.py). Code keeps that pick, except that among the
attackers the gate rated as suitable as its pick, one acting for fewer threats of this run so far is
preferred (threats decided highest impact first): a repeat then comes from fit, never from search order or
habit, and balancing never puts a less suitable attacker in. No usable pick: the search ranking decides,
flagged; "none fits": the nearest acts, flagged. The next linked actors, best fit first, are the alternates
(owner 2026-10-10). A threat the gate never judged (an AI proposal, a hand-written one) is not balanced: no
rating says another is as suitable. Pure."""

import dataclasses
from collections import Counter

from app.core.constants import ActorRole, Actors, AttackerCheck, PlanMessage
from app.models.actor_choice import ActorCandidates, ActorPick
from app.models.library import LibraryActor
from app.models.threats import PlannedActor, PlannedThreat


def choose_actors(
    threats: list[PlannedThreat], candidates: list[ActorCandidates], gate_judged: bool
) -> list[PlannedThreat]:
    """Every threat with its acting attacker, alternates and the audit of how they were chosen.
    `gate_judged`: the library threats came through the relevance gate (planning), so a missing pick is
    flagged as one the gate failed to give."""
    used: Counter[int] = Counter()
    decided: dict[int, PlannedThreat] = {}
    order = sorted(
        range(len(threats)), key=lambda i: (-threats[i].impact, -threats[i].confidence, threats[i].key)
    )
    for index in order:
        threat, options = threats[index], candidates[index]
        missing = AttackerCheck.NOT_CHECKED if gate_judged and threat.from_library else AttackerCheck.RANKED
        acting, check, reason = _acting(threat.actor_pick, options.order, used, missing)
        used[acting.actor_id] += 1
        decided[index] = _decided(threat, options, acting, check, reason)
    return [decided[index] for index in range(len(threats))]


def unranked_notes(threats: list[PlannedThreat]) -> list[str]:
    """One plan note when the gate gave no usable attacker for some threats (the search ranking chose)."""
    count = sum(threat.attacker_check == AttackerCheck.NOT_CHECKED for threat in threats)
    return [PlanMessage.ATTACKERS_RANKED_ONLY.format(threats=count)] if count else []


def _acting(
    pick: ActorPick | None, order: tuple[LibraryActor, ...], used: Counter[int], missing: AttackerCheck
) -> tuple[LibraryActor, AttackerCheck, str]:
    """(who acts, how it was decided, the reason the card shows)."""
    by_name = {actor.name: actor for actor in order}
    if pick is None or (pick.name is not None and pick.name not in by_name):
        return order[0], missing, ""
    if pick.name is None:
        return order[0], AttackerCheck.NONE_FITS, pick.reason
    rated = dict(pick.suitability)
    level = rated.get(pick.name, "HIGH")  # its own pick, unrated: the gate judged it the most plausible
    tier = [actor for actor in order if actor.name == pick.name or rated.get(actor.name) == level]
    best = min(tier, key=lambda actor: (used[actor.actor_id], actor.name != pick.name, actor.name))
    if best.name == pick.name:
        return best, AttackerCheck.CHOSEN, pick.reason
    balanced = PlanMessage.ATTACKER_BALANCED.format(chosen=best.name, picked=pick.name, level=level)
    return best, AttackerCheck.BALANCED, balanced


def _decided(
    threat: PlannedThreat,
    options: ActorCandidates,
    acting: LibraryActor,
    check: AttackerCheck,
    reason: str,
) -> PlannedThreat:
    alternates = (
        () if options.closest else [actor for actor in options.order if actor != acting][: Actors.MAX - 1]
    )
    pick = threat.actor_pick
    selection = {
        "candidates": [
            {
                "id": actor.actor_id,
                "name": actor.name,
                "suitability": pick.level_of(actor.name) if pick else None,
            }
            for actor in options.order
        ],
        "picked": pick.name if pick else None,
        "chosen_id": acting.actor_id,
        "check": check,
    }
    return dataclasses.replace(
        threat,
        actors=(
            PlannedActor(
                acting.actor_id, acting.name, ActorRole.ACTING, below_threshold=options.below_threshold
            ),
            *[PlannedActor(actor.actor_id, actor.name, ActorRole.ALTERNATE) for actor in alternates],
        ),
        closest_attacker=options.closest,
        attacker_options=options.order if options.closest else (),
        attacker_check=check,
        attacker_check_reason=reason,
        actor_selection=selection,
        actor_pick=None,  # decided: the audit keeps what the gate said
    )
