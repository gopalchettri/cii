"""The real named groups a card shows beside its acting actor (G230, owner 2026-10-14: "Name the real group,
also similar from the database as well. If not relevant from the database use near possible"). No AI call:
picked in code from the evidence index's groups (GroupMap), in this order:
1. real: groups of the acting actor's kind that used a technique of the card's own evidence;
2. similar: groups of that kind that used another technique the same search found;
3. nearest, only when 1 and 2 found none: groups of that kind whose techniques share the most attacker goals
   (tactics) with the evidence.
An actor of a kind ATT&CK records no group of (an insider, a vendor), or one no group of its kind is known
for, gets the groups known for the attack (steps 1 and 2, any kind), marked as not of its kind. Within a
step (G232, owner 2026-10-14: UAE first): a group that attacked the deployment's country, then its region,
then the asset's sector, then the one behind more of the techniques (nearest: sharing more goals), then by
name; each group once, with why it is near; at most KnownGroups.SHOWN. Pure."""

import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import asdict, replace

from app.core.constants import GroupRelevance, KnownGroupMatch, KnownGroups, ThreatGroupKind
from app.models.external_intelligence.known_groups import GroupMap, GroupUse, KnownGroup, Nearness

#: A word in the library actor's name -> the group kinds that fit it; the first rule that matches. No rule:
#: any kind fits (an external attacker). An empty set: ATT&CK records no group of that kind (an insider).
_ACTOR_KINDS: tuple[tuple[re.Pattern[str], frozenset[ThreatGroupKind]], ...] = (
    (re.compile(r"insider|vendor|third[- ]party|supplier|contractor|employee|\buser\b", re.I), frozenset()),
    (re.compile(r"nation|state|\bapt\b", re.I), frozenset({ThreatGroupKind.NATION_STATE})),
    (re.compile(r"ransomware", re.I), frozenset({ThreatGroupKind.RANSOMWARE, ThreatGroupKind.CYBERCRIMINAL})),
    (re.compile(r"hacktivist", re.I), frozenset({ThreatGroupKind.HACKTIVIST})),
    (re.compile(r"crim", re.I), frozenset({ThreatGroupKind.CYBERCRIMINAL, ThreatGroupKind.RANSOMWARE})),
)


_NOTHING_NEAR = Nearness()  # no country, no sector: nothing ranks a group nearer


def fitting_kinds(actor: str) -> frozenset[ThreatGroupKind] | None:
    """The group kinds that fit a library actor; None: any kind."""
    return next((kinds for rule, kinds in _ACTOR_KINDS if rule.search(actor)), None)


def pick_known_groups(
    actor: str,
    evidence: Sequence[str],
    related: Sequence[str],
    groups: GroupMap,
    near: Nearness = _NOTHING_NEAR,
) -> tuple[KnownGroup, ...]:
    """`actor`: the acting actor's name; `evidence`: the card's evidence ids; `related`: every id the search
    considered (a group behind the evidence too is kept once, as real); `near`: the country and sectors that
    rank the groups of a step."""
    kinds = fitting_kinds(actor)
    fits: Callable[[GroupUse], bool] = (lambda _: True) if kinds is None else (lambda use: use.kind in kinds)
    found = _ranked(groups, evidence, KnownGroupMatch.USED_THIS_TECHNIQUE, near)
    found += _ranked(groups, related, KnownGroupMatch.USED_RELATED_TECHNIQUE, near)
    chosen = [group for group in found if fits(group)] or _nearest(groups, evidence, fits, near)
    if not chosen:
        chosen = [replace(group, fits_actor=False) for group in found]
    once: dict[str, KnownGroup] = {}
    for group in chosen:
        once.setdefault(group.name, group)
    return tuple(once.values())[: KnownGroups.CANDIDATES]  # G235: the card picks SHOWN of them once written


def _ranked(
    groups: GroupMap, refs: Sequence[str], match: KnownGroupMatch, near: Nearness
) -> list[KnownGroup]:
    """The groups behind these techniques, the nearest first, then those behind more of them, then by name;
    each by its first use."""
    behind: Counter[str] = Counter()
    first: dict[str, GroupUse] = {}
    for ref in dict.fromkeys(refs):
        for use in groups.by_technique.get(ref, ()):
            first.setdefault(use.name, use)
            behind[use.name] += 1
    return _shown(first, near, match, behind)


def _nearest(
    groups: GroupMap, evidence: Sequence[str], fits: Callable[[GroupUse], bool], near: Nearness
) -> list[KnownGroup]:
    """Groups of the actor's kind sharing the most attacker goals with the evidence, each shown by a technique
    it is behind that shares one."""
    goals = frozenset().union(*(groups.tactics.get(ref, frozenset()) for ref in evidence))
    if not goals:
        return []
    shown: dict[str, GroupUse] = {}
    for ref, uses in sorted(groups.by_technique.items()):
        if groups.tactics.get(ref, frozenset()) & goals:
            for use in uses:
                if fits(use):
                    shown.setdefault(use.name, use)
    shared = Counter({name: len(groups.group_tactics.get(name, frozenset()) & goals) for name in shown})
    return _shown(shown, near, KnownGroupMatch.NEAREST, shared)


def _shown(
    uses: dict[str, GroupUse], near: Nearness, match: KnownGroupMatch, weight: Counter[str]
) -> list[KnownGroup]:
    """Each group as shown, with why it is near: the country first, then the region, then the sector, then
    the heavier `weight`, then by name."""
    relevance = {name: near.of(use) for name, use in uses.items()}

    def order(name: str) -> tuple[object, ...]:
        tiers = tuple(level not in relevance[name] for level in GroupRelevance)
        # G236: among equals, a group that used the attack itself before one linked through its malware.
        return (*tiers, -weight[name], bool(uses[name].through), name.casefold())

    return [
        KnownGroup(**asdict(uses[name]), match=match, relevance=relevance[name])
        for name in sorted(uses, key=order)
    ]
