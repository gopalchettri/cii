"""A path given up for good is replaced, within TOTAL_SCENARIO_COUNT, by the best-ranked path the count left
out, else by a later set's best open path; at most the set's own paths x MAX_PATH_ATTEMPTS write calls. The
write job's side: test_replacement_job.py."""

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
    assert best_reserve([kept, failed, later, next_in_rank], {}, {"p1", "p2"}) == next_in_rank


def test_a_reserve_whose_attacker_no_check_supports_is_never_promoted() -> None:
    """Its brief would be refused (ATTACKER_UNSUPPORTED): promoting it only spends the write budget."""
    kept, unsupported, writable = _path("p1", 1, [1]), _reserve("p2", 2, [2]), _reserve("p3", 3, [1])
    threats = {"lib:p2": {"attacker_check": "none_fits", "actors": [{"role": "acting", "closest": True}]}}
    assert best_reserve([kept, unsupported, writable], threats, {"p1"}) == writable
    assert best_reserve([kept, unsupported], threats, {"p1"}) is None


def test_with_no_reserve_a_later_sets_best_open_path_is_pulled_forward() -> None:
    """TOTAL_SCENARIO_COUNT 0 selects every path (none is target_reached): the spare is the best-ranked
    selected path still open outside the set, its attacker supported; a written, given-up or in-set path never
    is."""
    failed, in_set = _path("p1", 1, [1], abandoned=True), _path("p2", 2, [2])
    written, next_best, after = _path("p3", 3, [3], served="s3"), _path("p4", 4, [4]), _path("p5", 5, [5])
    every_path = [failed, in_set, written, after, next_best]
    assert best_reserve(every_path, {}, {"p1", "p2"}) == next_best
    threats = {"lib:p4": {"attacker_check": "none_fits", "actors": [{"role": "acting", "closest": True}]}}
    assert best_reserve(every_path, threats, {"p1", "p2"}) == after
    assert best_reserve(every_path, {}, {"p1", "p2", "p4", "p5"}) is None  # nothing open outside the set


def test_none_promoted_twice_or_brought_back() -> None:
    """A promoted spare is in the set; a replaced path's reason is replaced_after_failure: neither is ever a
    spare again, so no cycle."""
    replaced = _path(
        "p1", 1, [1], selected=False, abandoned=True,
        unselected_reason=UnselectedReason.REPLACED_AFTER_FAILURE,
    )  # fmt: skip
    promoted = _path("p3", 3, [1], replaces="p1")
    assert best_reserve([replaced, _path("p2", 2, [2]), promoted], {}, {"p1", "p2", "p3"}) is None


def test_the_budget_is_the_sets_own_paths_times_the_attempts_and_a_replacement_brings_none() -> None:
    limit = 2 * Generation.MAX_PATH_ATTEMPTS
    written = _path("p1", 1, [1], served="s1", attempts=limit - 3)
    failing = _path("p2", 2, [2], attempts=1)
    assert budget_left([written, failing])  # limit - 3 + 1 + 1 spent
    promoted = _path("p3", 3, [3], attempts=1, replaces="p2")
    assert not budget_left([written, failing, promoted])  # its try counts; it adds no budget
