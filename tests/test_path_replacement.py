"""G229 (owner 2026-10-13): a path given up for good is replaced, within TOTAL_SCENARIO_COUNT, by the reserve
that adds the most (a HIGH-impact threat not yet covered, new systems, a new kind, a new threat), with
intelligence on never one whose search already found nothing; no reserve with TOTAL_SCENARIO_COUNT 0; at most
the set's own paths x MAX_PATH_ATTEMPTS write calls. The write job's side: tests/test_replacement_job.py."""

from typing import Any

from app.core.constants import Generation, UnselectedReason
from app.engine.scenarios.attack_paths.path_replacement import best_reserve, budget_left

_REACHED = UnselectedReason.TARGET_REACHED


def _path(
    path_id: str, rank: int, systems: list[int], kind: str = "Tampering", selected: bool = True, **more: Any
) -> dict[str, Any]:
    return {
        "path_id": path_id,
        "rank": rank,
        "systems": systems,
        "categories": [kind],
        "steps": [f"lib:{path_id}"],
        "impact": 2,
        "selected": selected,
        "unselected_reason": None if selected else _REACHED,
        "abandoned": False,
        "served": None,
        "attempts": 0,
    } | more


def _reserve(path_id: str, rank: int, systems: list[int], kind: str = "Tampering", **more: Any) -> dict:
    return _path(path_id, rank, systems, kind, selected=False, **more)


def test_the_reserve_that_covers_what_the_failed_path_left_uncovered_wins_over_a_better_ranked_one() -> None:
    kept = _path("p1", 1, [1])
    failed = _path("p2", 2, [2], abandoned=True)
    same_system = _reserve("p3", 3, [1])
    new_system = _reserve("p4", 4, [2])
    assert best_reserve([kept, failed, same_system, new_system], {}, False) == new_system


def test_a_high_impact_threat_not_yet_covered_comes_before_new_systems() -> None:
    kept = _path("p1", 1, [1])
    new_systems = _reserve("p2", 2, [2, 3])
    critical = _reserve("p3", 3, [1], impact=3)
    assert best_reserve([kept, new_systems, critical], {}, False) == critical


def test_then_a_new_kind_then_a_new_threat_then_rank() -> None:
    kept = _path("p1", 1, [1], steps=["lib:a"])
    same_threat = _reserve("p2", 2, [1], steps=["lib:a"])
    new_threat = _reserve("p3", 3, [1])
    new_kind = _reserve("p4", 4, [1], "Spoofing")
    assert best_reserve([kept, same_threat, new_threat, new_kind], {}, False) == new_kind
    assert best_reserve([kept, same_threat, new_threat], {}, False) == new_threat
    assert (
        best_reserve([kept, same_threat, _reserve("p5", 5, [1], steps=["lib:a"])], {}, False) == same_threat
    )


def test_with_intelligence_on_a_reserve_whose_search_found_nothing_is_never_promoted() -> None:
    kept = _path("p1", 1, [1])
    found_nothing = _reserve("p2", 2, [2])
    unsearched = _reserve("p3", 3, [3])
    in_hand = _reserve("p4", 4, [4])
    threats = {
        "lib:p2": {"intel_search": {"snapshot_id": "s", "failure": None}, "evidence": []},
        "lib:p4": {"intel_search": {"snapshot_id": "s", "failure": None}, "evidence": [{"n": 1}]},
    }
    paths = [kept, found_nothing, unsearched, in_hand]
    assert best_reserve(paths, threats, True) == in_hand  # evidence in hand before a search still to make
    assert best_reserve(paths[:3], threats, True) == unsearched
    assert best_reserve(paths[:2], threats, True) is None
    assert best_reserve(paths[:2], threats, False) == found_nothing  # off: evidence plays no part


def test_no_reserve_with_no_limit_and_none_promoted_twice_or_brought_back() -> None:
    """TOTAL_SCENARIO_COUNT 0 selects every path (none is target_reached); a promoted reserve is selected; a
    replaced path's reason is replaced_after_failure: neither is ever a reserve, so no cycle."""
    every_path_selected = [_path("p1", 1, [1], abandoned=True), _path("p2", 2, [2])]
    assert best_reserve(every_path_selected, {}, False) is None
    replaced = _path(
        "p1", 1, [1], selected=False, abandoned=True,
        unselected_reason=UnselectedReason.REPLACED_AFTER_FAILURE,
    )  # fmt: skip
    promoted = _path("p3", 3, [1], replaces="p1")
    assert best_reserve([replaced, _path("p2", 2, [2]), promoted], {}, False) is None


def test_the_budget_is_the_sets_own_paths_times_the_attempts_and_a_replacement_brings_none() -> None:
    limit = 2 * Generation.MAX_PATH_ATTEMPTS
    written = _path("p1", 1, [1], served="s1", attempts=limit - 3)
    failing = _path("p2", 2, [2], attempts=1)
    assert budget_left([written, failing])  # limit - 3 + 1 + 1 spent
    promoted = _path("p3", 3, [3], attempts=1, replaces="p2")
    assert not budget_left([written, failing, promoted])  # its try counts; it adds no budget
