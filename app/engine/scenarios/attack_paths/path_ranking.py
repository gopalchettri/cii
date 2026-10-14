"""Path ranking: the order in which TOTAL_SCENARIO_COUNT keeps paths (path_selector.select_up_to_target).
Every valid path is kept and ranked; this only ORDERS paths that passed every gate, it never creates one.

One pick at a time, each the path adding the most to what the paths already picked cover, recomputed after
every pick (G223, owner 2026-10-13: "Maximize meaningful threat coverage within that limit"):
1. a HIGH-impact threat not yet covered (critical risk first: never given up for more systems);
2. the most supporting systems not yet covered (every system weighs the same: no criticality is recorded);
3. a kind of attack not yet covered: the kind the path is told as, its first category (G216);
4. a threat not yet covered;
then impact, confidence, STRIDE order and the paths' own tie-break (AttackPath.tie_break): every run gives the
same order. So the first set and every cut of the ranking cover the most within their size. (Before: a first
pass took the strongest path per kind counting all its threat's categories, so a Spoofing path "covered"
Repudiation and both Repudiation paths were cut by the limit; and it ignored systems, run 82f22cc3.)"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.core.constants import SCOPE_RANK, STRIDE_DEFINITIONS, PathChoice, ThreatFinding
from app.core.tracing import detail_top, record_detail, step_detail_enabled, traced
from app.models.threats import AttackPath

_HIGH = ThreatFinding.IMPACT_RANK["HIGH"]
_STRIDE_PLACE = {category: place for place, category in enumerate(STRIDE_DEFINITIONS)}


def _relevance(path: AttackPath) -> int:
    """G232: how near the country its threats' groups are (SCOPE_RANK: 2 country, 1 region, 0 none)."""
    return max(SCOPE_RANK.get((step.country_relevance or {}).get("scope", ""), 0) for step in path.steps)


@dataclass
class _Covered:
    """What the paths picked so far cover."""

    systems: set[int] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    threats: set[str] = field(default_factory=set)

    def gains(self, path: AttackPath) -> tuple[bool, int, bool, bool]:
        """(a HIGH-impact threat not yet covered, systems not yet covered, a kind not yet covered, a threat
        not yet covered)."""
        new_threat = any(step.key not in self.threats for step in path.steps)
        new_systems = len(set(path.systems) - self.systems)
        return (
            path.impact >= _HIGH and new_threat,
            new_systems,
            path.categories[0] not in self.kinds,
            new_threat,
        )

    def order(self, path: AttackPath) -> tuple[Any, ...]:
        """Smallest first: the most coverage gained, then (G232) the nearer the deployment's country its
        threats' groups are, then the most significant, then STRIDE order and the tie-break."""
        critical, systems, kind, threat = self.gains(path)
        significance = (-path.impact, -path.confidence, _STRIDE_PLACE[path.categories[0]])
        return (
            not critical,
            -systems,
            not kind,
            not threat,
            -_relevance(path),
            *significance,
            *path.tie_break(),
        )

    def why(self, path: AttackPath) -> PathChoice:
        _, systems, kind, _ = self.gains(path)
        if systems:
            return PathChoice.PATH_COVERAGE
        return PathChoice.CATEGORY_COVERAGE if kind else PathChoice.RISK_SIGNIFICANCE

    def add(self, path: AttackPath) -> None:
        self.systems.update(path.systems)
        self.kinds.add(path.categories[0])
        self.threats.update(step.key for step in path.steps)


@traced("paths.rank")
def rank_paths(paths: Sequence[AttackPath]) -> list[tuple[AttackPath, PathChoice]]:
    """Every path, most relevant first, each with why it got its place. A pure function of `paths`: shuffled
    input, a retry or a re-plan always gives the same ranking."""
    left = sorted(paths, key=lambda path: path.path_id)
    covered = _Covered()
    ranking: list[tuple[AttackPath, PathChoice]] = []
    while left:  # ponytail: n^2 over a run's paths (tens), fine; a heap if runs ever reach thousands
        best = min(left, key=covered.order)
        ranking.append((best, covered.why(best)))
        covered.add(best)
        left.remove(best)
    if step_detail_enabled():
        _trace_final_order(ranking)
    return ranking


def _trace_final_order(ranking: list[tuple[AttackPath, PathChoice]]) -> None:
    """The first detail_top() places: why each got its place, its systems, impact and confidence."""
    record_detail(
        "final order",
        given={"paths": len(ranking)},
        produced={
            f"{place} {' -> '.join(step.name for step in path.steps)}": (
                f"{choice} {path.categories[0]} systems {list(path.systems)} impact {path.impact} "
                f"conf {path.confidence:g}"
            )
            for place, (path, choice) in enumerate(ranking[: detail_top()], start=1)
        },
    )
