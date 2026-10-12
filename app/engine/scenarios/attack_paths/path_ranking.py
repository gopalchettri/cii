"""Path ranking (v1 core/path_selection.py ported as it is). Every valid path is kept and
ranked; this only ORDERS paths that passed every gate, it never creates one. The scenario target then
cuts the ranking (path_selector.select_up_to_target).

* Pass 1, category coverage: in STRIDE order, the strongest path containing each category not yet covered.
* Pass 2, system coverage: repeatedly, the path adding the most systems not covered yet: a scenario merged
  from one attack through several systems (G213) first, then one path per system not yet covered; a path on
  the asset itself adds none and waits for pass 3. (v1's extra bonus for a new multi-system route went with
  G210: covering more systems already ranks such a path first.)
* Pass 3, significance: every other path, most significant first.
Every tie breaks the same way on every run (AttackPath.tie_break)."""

from collections.abc import Sequence
from typing import Any

from app.core.constants import STRIDE_DEFINITIONS, PathChoice, StrideCategory
from app.core.tracing import detail_top, record_detail, step_detail_enabled, traced
from app.models.threats import AttackPath


def _strength(path: AttackPath, category: StrideCategory) -> tuple[Any, ...]:
    return (path.categories[0] != category, -path.impact, -path.confidence, *path.tie_break())


def _significance(path: AttackPath) -> tuple[Any, ...]:
    return (-path.impact, -path.confidence, *path.tie_break())


def _path_name(path: AttackPath) -> str:
    return " -> ".join(step.name for step in path.steps)


def _category_pass(paths: Sequence[AttackPath]) -> list[AttackPath]:
    picked: dict[StrideCategory, AttackPath] = {}  # in pick order: the category each path was picked for
    covered: set[StrideCategory] = set()
    for category in STRIDE_DEFINITIONS:
        if category in covered:
            continue
        candidates = [path for path in paths if category in path.categories and path not in picked.values()]
        if candidates:
            best = min(candidates, key=lambda path: _strength(path, category))
            picked[category] = best
            covered.update(best.categories)
    if step_detail_enabled():
        produced = {str(category): _path_name(path) for category, path in picked.items()}
        record_detail("pass 1 · category coverage", given={"paths": len(paths)}, produced=produced)
    return list(picked.values())


def _coverage_pass(paths: Sequence[AttackPath], picked: list[AttackPath]) -> list[AttackPath]:
    added: list[AttackPath] = []
    gained: dict[str, str] = {}  # the step trace's gain per pick (DEBUG_STEP_DETAIL only)
    while True:
        chosen = [*picked, *added]
        covered = {system for path in chosen for system in path.systems}
        rest = [path for path in paths if path not in chosen]
        if not rest:
            break
        gains = {path.path_id: len(set(path.systems) - covered) for path in rest}
        best = min(rest, key=lambda path: (-gains[path.path_id], *_significance(path)))
        if not gains[best.path_id]:
            break
        added.append(best)
        if step_detail_enabled():
            gained[_path_name(best)] = f"new systems {gains[best.path_id]}"
    record_detail("pass 2 · system coverage", given={"already_picked": len(picked)}, produced=gained)
    return added


@traced("paths.rank")
def rank_paths(paths: Sequence[AttackPath]) -> list[tuple[AttackPath, PathChoice]]:
    """Every path, most relevant first, each with why it got its place. A pure function of `paths`: shuffled
    input, a retry or a re-plan always gives the same ranking."""
    ordered = sorted(paths, key=lambda path: path.path_id)
    by_category = _category_pass(ordered)
    by_coverage = _coverage_pass(ordered, by_category)
    taken = {path.path_id for path in (*by_category, *by_coverage)}
    by_significance = sorted((path for path in ordered if path.path_id not in taken), key=_significance)
    ranking = (
        [(path, PathChoice.CATEGORY_COVERAGE) for path in by_category]
        + [(path, PathChoice.PATH_COVERAGE) for path in by_coverage]
        + [(path, PathChoice.RISK_SIGNIFICANCE) for path in by_significance]
    )
    if step_detail_enabled():
        _trace_final_order(ranking)
    return ranking


def _trace_final_order(ranking: list[tuple[AttackPath, PathChoice]]) -> None:
    """The first detail_top() places: why each got its place, its impact and confidence."""
    record_detail(
        "final order",
        given={"paths": len(ranking)},
        produced={
            f"{place} {_path_name(path)}": f"{choice} impact {path.impact} conf {path.confidence:g}"
            for place, (path, choice) in enumerate(ranking[: detail_top()], start=1)
        },
    )
