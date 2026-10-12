"""One attack path per kind of attack on each system ("logically it should not be more than
20-25"). The threats found are grouped by their own STRIDE category and by each system they involve, or the
asset itself when they involve none; each group becomes ONE path, written around its strongest threat, and the
group's other threats stay with it as `also_applies`, never lost. So an asset with N systems has at most
6 x (N + 1) paths, however many threats a large library holds. The groups are code: the same threats give
the same groups on every run; only which threat a group is written around may come from the AI (`preferred`,
best_threat.py). Paths that are one attack with one harm through different systems are then merged into one
on all of them (same_scenario.py, G213)."""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from app.core.constants import STRIDE_DEFINITIONS
from app.engine.shared.names import threat_name_without_code
from app.models.threats import AttackPath, PlannedThreat

#: A path's scope when its threat involves no listed system: the asset itself.
ASSET_ITSELF = "asset"
_STRIDE_ORDER = list(STRIDE_DEFINITIONS)
#: One group: (its STRIDE place, on the asset itself, the system id; 0 for the asset itself).
GroupKey = tuple[int, bool, int]


def threat_groups(threats: Sequence[PlannedThreat]) -> dict[GroupKey, list[PlannedThreat]]:
    """Each kind of attack on each system, or on the asset itself, with its threats, strongest first; in
    STRIDE order, then system id, then the asset itself."""
    groups: defaultdict[GroupKey, list[PlannedThreat]] = defaultdict(list)
    for threat in threats:
        category = _STRIDE_ORDER.index(threat.categories[0])
        for system in threat.systems or (None,):
            groups[(category, system is None, system or 0)].append(threat)
    return {key: sorted(members, key=_strength) for key, members in sorted(groups.items())}


def group_by_attack_and_system(
    threats: Sequence[PlannedThreat], preferred: Mapping[GroupKey, Sequence[str]] | None = None
) -> list[tuple[AttackPath, list[str]]]:
    """(path, the group's other threat names, best first) per group. `preferred`: a group's best threats by
    key, best first, as chosen by meaning (BestThreatPicker, G209); the rest follow strongest first. A group
    takes its first threat no earlier group took (so two scenarios rarely tell one threat twice); only a
    group with no other threat takes one already taken."""
    taken: set[str] = set()
    grouped: list[tuple[AttackPath, list[str]]] = []
    for key, strongest_first in threat_groups(threats).items():
        _, on_asset, system = key
        first = list((preferred or {}).get(key, ()))
        ranked = sorted(strongest_first, key=lambda t: first.index(t.key) if t.key in first else len(first))
        best = next((threat for threat in ranked if threat.key not in taken), ranked[0])
        taken.add(best.key)
        path = path_on(best, () if on_asset else (system,))
        others = [threat_name_without_code(threat.name) for threat in ranked if threat.key != best.key]
        grouped.append((path, others))
    return grouped


def path_on(threat: PlannedThreat, systems: tuple[int, ...]) -> AttackPath:
    """A one-step path written around `threat` on `systems` (sorted), or on the asset itself when there is
    none; its scope (and so its id) names exactly those systems, so the same threat on other systems is
    another path."""
    systems = tuple(sorted(systems))
    scope = ASSET_ITSELF if not systems else "system" + ("s" if len(systems) > 1 else "") + ":"
    if systems:
        scope += ",".join(map(str, systems))
    return AttackPath((replace(threat, systems=systems),), scope=scope)


def _strength(threat: PlannedThreat) -> tuple[Any, ...]:
    """Most significant first (impact, then the relevance check's confidence), then the paths' own tie-break:
    library before AI, the lowest library id."""
    return (-threat.impact, -threat.confidence, *AttackPath((threat,)).tie_break())
