"""One rule for what a next set can still write: the plan's `remaining` (the status, its
`awaiting_next_set` and the console's "Generate next set") and the next-set call agree. Pure."""

import itertools
from typing import Any

from app.core.constants import ConflictReason, ErrorCode, FindingCode, UnselectedReason
from app.domain.scenario.plan import plan_counts, set_and_first_batch, set_summary


def _path(path_id: str, rank: int, **state: Any) -> dict[str, Any]:
    return {"path_id": path_id, "rank": rank, "selected": True, "served": None, "attempts": 0,
            "abandoned": False, "steps": [f"lib:{rank}"], **state}  # fmt: skip


_OUTAGE = {"abandoned": True, "attempts": 5, "abandoned_reason": ErrorCode.UNAVAILABLE}
_RULE = {"abandoned": True, "attempts": 1, "abandoned_reason": FindingCode.SCENARIO_MISMATCH}


def test_remaining_counts_the_open_selected_paths_and_a_given_up_one_is_never_tried_again() -> None:
    written = _path("p1", 1, served="s1")
    outage = _path("p2", 2, **_OUTAGE)
    rule = _path("p3", 3, **_RULE)
    replaced = _path("p4", 4, **_OUTAGE, selected=False, replaced_by="p5",
                     unselected_reason=UnselectedReason.REPLACED_AFTER_FAILURE)  # fmt: skip
    open_path = _path("p6", 6)
    assert plan_counts([written, outage, rule, replaced, open_path])["remaining"] == 1
    assert set_and_first_batch([written, outage, rule, replaced, open_path], 6)[0] == ["p6"]
    assert plan_counts([written, outage, rule, replaced])["remaining"] == 0
    assert set_and_first_batch([written, outage, rule, replaced], 6)[0] == []


def test_remaining_is_zero_exactly_when_a_next_set_asks_for_nothing() -> None:
    """The recurrence guard: every mix of path states, the two rules agree."""
    states = [
        {},
        {"served": "s"},
        _OUTAGE,
        {**_OUTAGE, "abandoned_reason": ErrorCode.EVIDENCE_NOT_FOUND},
        _RULE,
        {**_OUTAGE, "served": "s"},
        {"selected": False, "unselected_reason": UnselectedReason.TARGET_REACHED},
        {**_OUTAGE, "selected": False, "replaced_by": "x"},
    ]
    for combination in itertools.product(range(len(states)), repeat=3):
        paths = [_path(f"p{rank}", rank, **states[index]) for rank, index in enumerate(combination, start=1)]
        assert (plan_counts(paths)["remaining"] == 0) == (set_and_first_batch(paths, 6)[0] == []), combination


def test_a_finished_sets_summary_says_why_it_fell_short_or_was_the_last() -> None:
    """What the set delivered of its selected paths, why it fell short, and what is left."""
    more = [_path("p1", 1, served="s1"), _path("p2", 2)]
    assert set_summary(more[:1], more, "complete") == {
        "outcome": "complete", "delivered": 1, "reason": None, "remaining": 1,
    }  # fmt: skip
    given_up = [_path("p1", 1, served="s1"), _path("p2", 2, **_RULE)]
    assert set_summary(given_up, given_up, "partial")["reason"] == ConflictReason.SCENARIOS_ABANDONED
    last = [_path("p1", 1, served="s1"), _path("p2", 2, selected=False)]
    assert set_summary(last[:1], last, "complete")["reason"] == ConflictReason.TARGET_REACHED
    replaced = _path("p1", 1, **_RULE, selected=False, replaced_by="p2", served=None)
    reserve = _path("p2", 2, served="s2", replaces="p1")
    summary = set_summary([replaced, reserve], [replaced, reserve], "complete")
    assert (summary["delivered"], summary["reason"]) == (1, ConflictReason.TARGET_REACHED)
