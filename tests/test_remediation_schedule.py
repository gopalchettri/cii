"""The plan scheduler: the owner's example, every repair and every window warning. Pure, no store."""

from datetime import date
from typing import Any

from app.core.constants import PlanWarning, Remediation
from app.domain.remediation.schedule import schedule_plan

WINDOW = {"timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31", "total_days": 92}


def _act(action_id: str, days: int, deps: tuple[str, ...] = ()) -> dict[str, Any]:
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
    }


def _plan(*actions: dict[str, Any]) -> dict[str, Any]:
    return {
        "controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
        "remediation_action_plan": list(actions),
        "action_plan": "",
    }


def _snapshot(window: dict[str, Any] | None = WINDOW) -> dict[str, Any]:
    return {"risk_assessment": {"assessment_window": window}}


def _owners_plan() -> dict[str, Any]:
    """A1 first; A2 and A3 wait for A1; A4 waits for A2 and A3."""
    return _plan(_act("A1", 2), _act("A2", 3, ("A1",)), _act("A3", 4, ("A1",)), _act("A4", 2, ("A2", "A3")))


def _dates(plan: dict[str, Any]) -> list[tuple[Any, Any, str]]:
    return [(a["start_date"], a["end_date"], a["timeline"]) for a in plan["remediation_action_plan"]]


def test_the_owners_schedule() -> None:
    """8 days on the critical path A1 → A3 → A4 (the parallel A2 is not added); inclusive dates from the
    window's start: A1 runs 1-2 October and its dependants start the day after."""
    plan = _owners_plan()
    assert schedule_plan(plan, _snapshot()) == []
    assert (plan["mitigation_timeline_days"], plan["mitigation_end_date_planned"]) == (8, "2026-10-08")
    assert plan["critical_path"] == ["A1", "A3", "A4"]
    assert plan["mitigation_timeline"] == "2026-10-01 → 2026-10-08 (8 days, critical path A1 → A3 → A4)"
    assert _dates(plan) == [
        ("2026-10-01", "2026-10-02", "2026-10-01 → 2026-10-02 (2 days)"),
        ("2026-10-03", "2026-10-05", "2026-10-03 → 2026-10-05 (3 days, after A1 completes)"),
        ("2026-10-03", "2026-10-06", "2026-10-03 → 2026-10-06 (4 days, after A1 completes)"),
        ("2026-10-07", "2026-10-08", "2026-10-07 → 2026-10-08 (2 days, after A2 and A3 complete)"),
    ]


def test_without_a_window_the_dates_are_null_and_one_warning_says_so() -> None:
    plan = _owners_plan()
    assert schedule_plan(plan, _snapshot(window=None)) == [PlanWarning.NO_WINDOW.format(total=8)]
    assert all(start is None and end is None for start, end, _ in _dates(plan))
    assert plan["remediation_action_plan"][3]["timeline"] == "2 days, after A2 and A3 complete"
    assert (plan["mitigation_timeline"], plan["mitigation_end_date_planned"]) == (
        "8 days in total (critical path A1 → A3 → A4)",
        None,
    )


def test_durations_and_dependencies_are_repaired_with_one_warning_each() -> None:
    """Below 1 → 1 day, above the limit → capped; a forward, self or unknown reference is dropped with one
    warning per distinct reference."""
    plan = _plan(
        _act("A1", 0, ("A2", "A2")), _act("A2", 5000, ("A2",)), _act("A3", 3, ("Z9",)), _act("A4", 2, ("A1",))
    )
    warnings = schedule_plan(plan, _snapshot(window=None))
    limit = Remediation.MAX_ACTION_DAYS
    assert sorted(warnings) == sorted(
        [
            PlanWarning.DURATION_REPAIRED.format(action="A1", value=0),
            PlanWarning.DURATION_CAPPED.format(action="A2", days=5000, limit=limit),
            PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A1", reference="A2"),
            PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A2", reference="A2"),
            PlanWarning.DEPENDENCY_NOT_EARLIER.format(action="A3", reference="Z9"),
            PlanWarning.NO_WINDOW.format(total=limit),
        ]
    )
    actions = plan["remediation_action_plan"]
    assert [action["duration_days"] for action in actions] == [1, limit, 3, 2]
    assert [action["depends_on"] for action in actions] == [[], [], [], ["A1"]]
    assert (plan["mitigation_timeline_days"], actions[3]["timeline"]) == (limit, "2 days, after A1 completes")


def test_a_repeated_action_id_belongs_to_its_first_holder() -> None:
    plan = _plan(_act("A1", 2), _act("A1", 3), _act("A3", 4, ("A1",)))
    warnings = schedule_plan(plan, _snapshot())
    assert warnings == [PlanWarning.ACTION_ID_REPEATED.format(action="A1", action_id="A1", position=0)]
    waiting = plan["remediation_action_plan"][2]
    assert (waiting["depends_on"], waiting["start_date"], waiting["end_date"]) == (
        ["A1"],
        "2026-10-03",
        "2026-10-06",
    )


def test_a_plan_past_its_window_says_by_how_many_days() -> None:
    """110 days from 1 October end on 18 January, 18 days after the window closes."""
    plan = _plan(_act("A1", 50), _act("A2", 60, ("A1",)))
    warnings = schedule_plan(plan, _snapshot())
    late = PlanWarning.PAST_WINDOW.format(end="2027-01-18", days="18 days", deadline="2026-12-31")
    assert warnings == [late] and plan["mitigation_end_date_planned"] == "2027-01-18"


def test_one_day_is_said_as_one_day_in_every_plan_text() -> None:
    """The live hand-written plan read "1 days after the mitigation window closes": one spelling for all."""
    late = _plan(_act("A1", 93))
    assert schedule_plan(late, _snapshot()) == [
        "the plan finishes 2027-01-01, 1 day after the mitigation window closes (2026-12-31)"
    ]
    assert late["mitigation_timeline"] == "2026-10-01 → 2027-01-01 (93 days, critical path A1)"
    single = _plan(_act("A1", 1))
    schedule_plan(single, _snapshot())
    assert single["mitigation_timeline"] == "2026-10-01 → 2026-10-01 (1 day, critical path A1)"
    schedule_plan(undated := _plan(_act("A1", 1)), _snapshot(window=None))
    assert undated["mitigation_timeline"] == "1 day in total (critical path A1)"


def test_dates_past_the_calendar_are_clamped_with_a_warning() -> None:
    anchor = date(9990, 1, 1)
    plan = _plan(_act("A1", 3650), _act("A2", 3650, ("A1",)))
    window = {**WINDOW, "timeline_start_date": anchor.isoformat()}
    warnings = schedule_plan(plan, _snapshot(window=window))
    assert plan["remediation_action_plan"][1]["end_date"] == date.max.isoformat()
    clamped = PlanWarning.PAST_CALENDAR.format(
        total=7300,
        anchor=anchor.isoformat(),
        fit=f"{(date.max - anchor).days + 1} days",
        last=date.max.isoformat(),
    )
    assert clamped in warnings
