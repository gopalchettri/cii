"""The plan scheduler (BLUEPRINT M11 R7, BUILD_PLAN S47; v1 treatment_schedule.py's own checks first): the
owner-approved golden example, every repair and every consistency warning. Pure, no store."""

from typing import Any

from app.core.constants import PlanWarning
from app.domain.remediation.scheduler import schedule

WINDOW = {"timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31", "total_days": 92}


def _act(action_id: str, days: int, deps: tuple[str, ...] = (), **fields: Any) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "action": f"Do {action_id}",
        "owner": "OT Security",
        "priority": "High",
        "dependencies": ", ".join(deps) or "None",
        "depends_on": list(deps),
        "duration_days": days,
        "implements_controls": [],
        "success_criteria": "Done.",
    } | fields


def _plan(*actions: dict[str, Any], codes: tuple[str, ...] = (), coverage: str = "gaps") -> dict[str, Any]:
    controls = [{"control_code": code} for code in codes]
    return {
        "controls_to_be_implemented": {"control_coverage": coverage, "controls": controls},
        "remediation_action_plan": list(actions),
        "action_plan": "",
    }


def _snapshot(
    window: dict[str, Any] | None = WINDOW, mapped: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "risk_assessment": {"assessment_window": window},
        "existing_controls": {"library_mapped": mapped or []},
    }


def _golden() -> dict[str, Any]:
    """A1 and A2 start together, A3 waits for A1, A4 for A2 and A3."""
    return _plan(_act("A1", 14), _act("A2", 10), _act("A3", 21, ("A1",)), _act("A4", 5, ("A2", "A3")))


def test_the_owner_approved_example() -> None:
    """40 days on the critical path A1 → A3 → A4 (the parallel A2 is not added); inclusive dates: A1 runs 1-14
    October and A3 starts the day after; the plan ends 9 November 2026."""
    plan = _golden()
    assert schedule(plan, _snapshot()) == []
    assert (plan["mitigation_timeline_days"], plan["mitigation_end_date_planned"]) == (40, "2026-11-09")
    assert plan["critical_path"] == ["A1", "A3", "A4"]
    assert plan["mitigation_timeline"] == "2026-10-01 → 2026-11-09 (40 days, critical path A1 → A3 → A4)"
    actions = plan["remediation_action_plan"]
    assert (actions[0]["start_date"], actions[0]["end_date"]) == ("2026-10-01", "2026-10-14")
    assert actions[2]["timeline"] == "2026-10-15 → 2026-11-04 (21 days, after A1 completes)"


def test_without_a_window_the_dates_are_null_and_one_warning_says_so() -> None:
    plan = _golden()
    assert schedule(plan, _snapshot(window=None)) == [PlanWarning.NO_WINDOW.format(total=40)]
    assert all(action["start_date"] is None for action in plan["remediation_action_plan"])
    assert plan["remediation_action_plan"][3]["timeline"] == "5 days, after A2 and A3 complete"
    assert plan["mitigation_timeline"] == "40 days in total (critical path A1 → A3 → A4)"


def test_durations_and_references_are_repaired_never_refused() -> None:
    """Below 1 → 1 day, above 3,650 → capped; forward, self and unknown references dropped with one warning
    per distinct reference; a repeated action_id belongs to its first holder."""
    plan = _plan(
        _act("A1", 0, ("A2", "A2")),
        _act("A2", 5000, ("A2",)),
        _act("A1", 3, ("Z9",)),
        _act("A4", 2, ("A1",)),
    )
    warnings = schedule(plan, _snapshot(window=None))
    actions = plan["remediation_action_plan"]
    assert [action["duration_days"] for action in actions] == [1, 3650, 3, 2]
    assert [action["depends_on"] for action in actions] == [[], [], [], ["A1"]]
    for expected in (
        PlanWarning.DURATION_REPAIRED.format(action="A1", value=0),
        PlanWarning.DURATION_CAPPED.format(action="A2", days=5000, limit=3650),
        PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A1", reference="A2"),
        PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A2", reference="A2"),
        PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A1", reference="Z9"),
        PlanWarning.ACTION_ID_REPEATED.format(action="A1", action_id="A1", position=0),
    ):
        assert warnings.count(expected) == 1, expected
    assert plan["mitigation_timeline_days"] == 3650 and actions[3]["timeline"] == "2 days, after A1 completes"


def test_the_prose_must_match_the_ids() -> None:
    plan = _plan(
        _act("A1", 2), _act("A2", 2, dependencies="Waits for A1"), _act("A3", 2, ("A1",), dependencies="None")
    )
    warnings = schedule(plan, _snapshot())
    assert PlanWarning.DEPENDENCY_PROSE_EXTRA.format(action="A2", named="A1") in warnings
    assert PlanWarning.DEPENDENCY_PROSE_NONE.format(action="A3", ids="A1") in warnings


def test_sequence_urgency_window_and_stated_days() -> None:
    """Ids out of sequence; an action listed after later-starting work; a High action waiting on a Low one;
    the plan past its window (110 days from 1 October ends 18 January); the paragraph naming another day
    count."""
    plan = _plan(_act("A1", 50, priority="Low"), _act("A3", 60, ("A1",)), _act("A2", 5))
    plan["action_plan"] = "The work takes 30 days."
    warnings = schedule(plan, _snapshot())
    assert PlanWarning.IDS_OUT_OF_SEQUENCE.format(count=3, ids=["A1", "A3", "A2"]) in warnings
    assert PlanWarning.OUT_OF_ORDER.format(action="A2", latest=50, start=0) in warnings
    less_urgent = PlanWarning.LESS_URGENT_PREREQUISITE.format(
        prerequisite="A1", prerequisite_priority="Low", action="A3", priority="High"
    )
    assert less_urgent in warnings
    assert PlanWarning.PAST_WINDOW.format(end="2027-01-18", days=18, deadline="2026-12-31") in warnings
    assert PlanWarning.STATED_DAYS.format(stated="30", total=110) in warnings


def test_dates_past_the_calendar_are_clamped_with_a_warning() -> None:
    plan = _plan(_act("A1", 3650), _act("A2", 3650, ("A1",)))
    warnings = schedule(plan, _snapshot(window={**WINDOW, "timeline_start_date": "9990-01-01"}))
    assert plan["remediation_action_plan"][1]["end_date"] == "9999-12-31"
    assert any(warning.startswith("the 7300-day schedule runs past") for warning in warnings)


def test_control_delivery_is_matched_case_blind_and_written_back_canonical() -> None:
    """v1's own check: a code echoed in another case is the recommended one; a mapped control the register
    covers may be verified on a "gaps" plan, an uncovered mapped one may not; a recommended control no action
    implements is named."""
    plan = _plan(
        _act("A1", 3, implements_controls=[" cii-cid-195 ", "cii-cid-220"]),
        _act("A2", 2, ("A1",), implements_controls=["CII-CID-198"]),
        codes=("CII-CID-195", "CII-CID-300"),
    )
    mapped = [
        {"control_code": "CII-CID-220", "covered_by_register": True},
        {"control_code": "CII-CID-198", "covered_by_register": False},
    ]
    warnings = schedule(plan, _snapshot(mapped=mapped))
    assert plan["remediation_action_plan"][0]["implements_controls"] == ["CII-CID-195", "CII-CID-220"]
    assert PlanWarning.IMPLEMENTS_UNKNOWN.format(action="A2", code="CII-CID-198") in warnings
    assert PlanWarning.CONTROL_NOT_IMPLEMENTED.format(code="CII-CID-300") in warnings
    assert PlanWarning.CONTROL_NOT_IMPLEMENTED.format(code="CII-CID-195") not in warnings


def test_a_plan_with_no_action_has_no_timeline() -> None:
    plan = _plan()
    assert schedule(plan, _snapshot()) == []
    timeline = (plan["mitigation_timeline"], plan["mitigation_timeline_days"], plan["critical_path"])
    assert timeline == (None, None, [])
