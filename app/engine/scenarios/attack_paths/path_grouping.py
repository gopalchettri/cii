"""One attack path per kind of attack per attack route, at asset level (owner 2026-10-13: "requirement is to
create the scenario's at asset level", then "5 is too less ... some logic is wrong": a route of systems, and
every kind of attack a threat fits, G216). The threats found are grouped by each STRIDE category they fit
(their own first) and by their route: the set of systems the relevance check judged them on, none for the
asset itself. Each group becomes ONE path on the asset through that route, written around the best threat
no earlier group took, and the group's other threats stay with it as `also_applies`, never lost. So an asset
has at most 6 x (its routes) paths; TOTAL_SCENARIO_COUNT caps them when set. The groups are code: the same
threats give the same groups on every run; only which threat a group is written around may come from the AI
(`preferred`, best_threat.py)."""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from app.core.constants import STRIDE_DEFINITIONS, StrideCategory
from app.engine.shared.names import threat_name_without_code
from app.models.threats import AttackPath, PlannedThreat

#: A path's scope when it is on no listed system: the asset itself.
ASSET_ITSELF = "asset"
_STRIDE_ORDER = list(STRIDE_DEFINITIONS)
#: One group: (its STRIDE place, its route: the sorted systems, () for the asset itself).
GroupKey = tuple[int, tuple[int, ...]]


def threat_groups(threats: Sequence[PlannedThreat]) -> dict[GroupKey, list[PlannedThreat]]:
    """Each kind of attack on each route with its threats, strongest first; in STRIDE order, then route. A
    threat is in every kind of attack it fits (a Spoofing threat that also fits Repudiation is in both)."""
    groups: defaultdict[GroupKey, list[PlannedThreat]] = defaultdict(list)
    for threat in threats:
        route = tuple(sorted(threat.systems))
        for category in dict.fromkeys(threat.categories):
            groups[(_STRIDE_ORDER.index(category), route)].append(threat)
    return {key: sorted(members, key=_strength) for key, members in sorted(groups.items())}


def group_by_attack(
    threats: Sequence[PlannedThreat], preferred: Mapping[GroupKey, Sequence[str]] | None = None
) -> list[tuple[AttackPath, list[str]]]:
    """(path, the group's other threat names, best first) per group. `preferred`: a group's best threats by
    key, best first, as chosen by meaning (BestThreatPicker, G209); the rest follow strongest first. A group
    takes its first threat no earlier group took (a threat fits several kinds, so two scenarios rarely tell
    one threat); only a group with no other threat takes one already taken."""
    taken: set[str] = set()
    grouped: list[tuple[AttackPath, list[str]]] = []
    for (place, route), strongest_first in threat_groups(threats).items():
        first = list((preferred or {}).get((place, route), ()))
        ranked = sorted(strongest_first, key=lambda t: first.index(t.key) if t.key in first else len(first))
        best = next((threat for threat in ranked if threat.key not in taken), ranked[0])
        taken.add(best.key)
        path = path_on(best, route, _STRIDE_ORDER[place])
        others = [threat_name_without_code(threat.name) for threat in ranked if threat.key != best.key]
        grouped.append((path, others))
    return grouped


def path_on(
    threat: PlannedThreat, systems: tuple[int, ...], kind: StrideCategory | None = None
) -> AttackPath:
    """A one-step path written around `threat` as the `kind` of attack (its own first category when None) on
    `systems` (sorted), or on the asset itself when there is none. The kind leads the path's categories, so
    the scenario is written and shown as that kind; its scope (and so its id) names the kind and exactly
    those systems, so the same threat on other systems, or as another kind, is another path."""
    systems = tuple(sorted(systems))
    kind = kind or threat.categories[0]
    categories = (kind, *(category for category in threat.categories if category != kind))
    scope = ASSET_ITSELF if not systems else "system" + ("s" if len(systems) > 1 else "") + ":"
    if systems:
        scope += ",".join(map(str, systems))
    step = replace(threat, systems=systems, categories=categories)
    return AttackPath((step,), scope=f"{kind}@{scope}")


def _strength(threat: PlannedThreat) -> tuple[Any, ...]:
    """Most significant first (impact, then the relevance check's confidence), then the paths' own tie-break:
    library before AI, the lowest library id."""
    return (-threat.impact, -threat.confidence, *AttackPath((threat,)).tie_break())
