"""Reading one relevance-gate verdict (v1 threat_identification/relevance.py), checked in code: the systems by
alias, a yes/no, an impact and confidence, always a reason, and (G229, owner 2026-10-13) the attacker it
judged most plausible among the slot's own listed attackers, read leniently so a bad attacker answer never
costs a re-ask: no AI call is added for the attacker."""

from collections.abc import Sequence
from typing import Any

from app.core.constants import ThreatFinding
from app.engine.shared.ask_ai import answer_item_problems
from app.engine.shared.names import name_match_key
from app.models.actor_choice import ActorPick
from app.models.planner_replies import RelevanceVerdict
from app.models.threats import Verdict


def parse_verdict(
    item: dict[str, Any], aliases: dict[str, int], listed: Sequence[str] = ()
) -> tuple[Verdict | None, list[str]]:
    """One verdict, checked: known aliases only, a yes/no, an impact for a relevant threat, a confidence of
    0-100 and always a reason (a rejection's too). A rejection's impact is never read, so never judged.
    `listed`: the attackers the slot showed; a relevant verdict's pick is read from those only."""
    slot, systems = item["slot"], item.get("systems") or []
    impact = str(item.get("impact") or "").upper()
    confidence, reason = item.get("confidence"), str(item.get("reason") or "").strip()
    problems = []
    # Any JSON may come back: a list or object in place of an alias is a problem to re-ask, never a crash.
    if not isinstance(systems, list) or any(
        not isinstance(alias, str) or alias not in aliases for alias in systems
    ):
        problems.append(f"{slot}: systems must be listed aliases only (SYS1, SYS2 ...)")
    if not isinstance(item.get("relevant"), bool):
        problems.append(f"{slot}: relevant must be true or false")
    if item.get("relevant") is True and impact not in ThreatFinding.IMPACT_RANK:
        problems.append(f"{slot}: impact must be HIGH, MEDIUM or LOW")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float) or not 0 <= confidence <= 100:
        problems.append(f"{slot}: confidence must be a number from 0 to 100")
    if not reason:
        problems.append(f"{slot}: every verdict needs its reason, a rejection's too")
    needs = item.get("needs") or []
    if not isinstance(needs, list) or any(not isinstance(need, str) for need in needs):
        problems.append(f"{slot}: needs must be a list of names ([] when everything it needs is recorded)")
    if problems:
        return None, problems
    shown = {**item, "impact": impact if item["relevant"] else None, "systems": systems, "needs": needs}
    if problems := answer_item_problems(RelevanceVerdict, shown, slot):
        return None, problems
    return Verdict(
        relevant=item["relevant"],
        systems=tuple(sorted({aliases[alias] for alias in systems})),
        reason=reason[: ThreatFinding.REASON_MAX_CHARS],
        impact=ThreatFinding.IMPACT_RANK.get(impact, 0),
        confidence=float(confidence or 0),
        needs=_needs(needs),
        actor_pick=actor_pick(item, listed) if item["relevant"] else None,
    ), []


def actor_pick(item: dict[str, Any], listed: Sequence[str]) -> ActorPick | None:
    """The gate's attacker pick, or None (the search ranking decides): no listed attacker, no reason, or a
    name that is not on the slot's own list. A rating only for a listed name, HIGH or MEDIUM."""
    by_key = {name_match_key(name): name for name in listed}
    reason = str(item.get("attacker_reason") or "").strip()[: ThreatFinding.REASON_MAX_CHARS]
    named = item.get("attacker")
    name = None if named is None else by_key.get(name_match_key(str(named)))
    if not by_key or not reason or (named is not None and name is None):
        return None
    rated = item.get("suitability")
    levels = {
        by_key[key]: str(level).upper()
        for given, level in (rated.items() if isinstance(rated, dict) else ())
        if (key := name_match_key(str(given))) in by_key and str(level).upper() in ("HIGH", "MEDIUM")
    }
    return ActorPick(name, reason, tuple(sorted(levels.items())))


def _needs(names: list[str]) -> tuple[str, ...]:
    """What a verdict says its threat needs that nothing recorded mentions, blanks dropped and bounded."""
    kept = [" ".join(name.split())[: ThreatFinding.NEED_MAX_CHARS] for name in names if name.strip()]
    return tuple(kept[: ThreatFinding.NEEDS_MAX_ITEMS])
