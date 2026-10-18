"""A path given up for good is replaced, within TOTAL_SCENARIO_COUNT, by the best-ranked path the count left
out; with intelligence on never one whose search already found nothing; none with TOTAL_SCENARIO_COUNT 0; at
most the set's own paths x MAX_PATH_ATTEMPTS write calls. The write job's side: test_replacement_job.py."""

from typing import Any

from app.core.constants import Generation, UnselectedReason
from app.domain.scenario.plan import best_reserve, budget_left

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


def test_the_reserve_is_the_best_ranked_path_the_scenario_count_left_out() -> None:
    kept = _path("p1", 1, [1])
    failed = _path("p2", 2, [2], abandoned=True)
    next_in_rank = _reserve("p3", 3, [1])
    later = _reserve("p4", 4, [2])
    assert best_reserve([kept, failed, later, next_in_rank], {}, False) == next_in_rank


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
    assert best_reserve(paths, threats, True) == unsearched  # by rank, once the empty search is left out
    assert best_reserve([kept, found_nothing, in_hand], threats, True) == in_hand
    assert best_reserve(paths[:2], threats, True) is None
    assert best_reserve(paths[:2], threats, False) == found_nothing  # off: evidence plays no part


def test_a_reserve_whose_attacker_no_check_supports_is_never_promoted() -> None:
    """Its brief would be refused (ATTACKER_UNSUPPORTED): promoting it only spends the write budget."""
    kept, unsupported, writable = _path("p1", 1, [1]), _reserve("p2", 2, [2]), _reserve("p3", 3, [1])
    threats = {"lib:p2": {"attacker_check": "none_fits", "actors": [{"role": "acting", "closest": True}]}}
    assert best_reserve([kept, unsupported, writable], threats, False) == writable
    assert best_reserve([kept, unsupported], threats, False) is None


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
