"""Turns the AI's durations and prerequisites into offsets, the critical path, dates and timelines; pure."""

from datetime import date, timedelta
from typing import Any

from app.core.constants import PlanText, PlanWarning, Remediation


def schedule_plan(plan: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """Writes dates, timelines and the critical path onto the plan and its actions; returns warnings."""
    window = (snapshot.get("risk_assessment") or {}).get("assessment_window")
    actions = plan["remediation_action_plan"]
    action_ids = [str(action.get("action_id") or "").strip() for action in actions]
    names = [action_id or f"remediation_action_plan[{i}]" for i, action_id in enumerate(action_ids)]
    anchor = date.fromisoformat(window["timeline_start_date"]) if window else None
    warnings = _repair_durations(actions, names)
    prerequisites, dependency_warnings = _prerequisites(actions, names, action_ids)
    starts, finish, via = _offsets([action["duration_days"] for action in actions], prerequisites)
    _render_actions(actions, starts, anchor)
    total = max(finish)
    path = [names[position] for position in _critical_path(finish, via)]
    planned_end = _shift(anchor, total - 1) if anchor is not None else None
    _write_plan_timeline(plan, anchor, planned_end, total, path)
    return (
        warnings
        + dependency_warnings
        + _past_calendar(anchor, total)
        + _window_warnings(window, planned_end, total)
    )


def _repair_durations(actions: list[dict[str, Any]], names: list[str]) -> list[str]:
    """Clamps each duration_days to 1..Remediation.MAX_ACTION_DAYS in place; one warning per repair."""
    warnings = []
    for action, name in zip(actions, names, strict=True):
        days = action["duration_days"]
        if days < 1:
            warnings.append(PlanWarning.DURATION_REPAIRED.format(action=name, value=days))
            days = 1
        elif days > Remediation.MAX_ACTION_DAYS:
            limit = Remediation.MAX_ACTION_DAYS
            warnings.append(PlanWarning.DURATION_CAPPED.format(action=name, days=days, limit=limit))
            days = limit
        action["duration_days"] = days
    return warnings


def _prerequisites(
    actions: list[dict[str, Any]], names: list[str], action_ids: list[str]
) -> tuple[list[list[int]], list[str]]:
    """Keeps each depends_on to earlier actions (a repeated id belongs to its first holder); warnings."""
    positions_of: list[list[int]] = []
    warnings: list[str] = []
    first_holder: dict[str, int] = {}
    for index, (action, name, own_id) in enumerate(zip(actions, names, action_ids, strict=True)):
        accepted: list[int] = []
        for reference in dict.fromkeys(str(entry).strip() for entry in action["depends_on"]):
            earlier = None if reference and reference == own_id else first_holder.get(reference)
            if earlier is None:
                warnings.append(PlanWarning.DEPENDENCY_NOT_EARLIER.format(action=name, reference=reference))
            else:
                accepted.append(earlier)
        action["depends_on"] = [action_ids[position] for position in accepted]
        positions_of.append(accepted)
        if own_id and own_id in first_holder:
            position = first_holder[own_id]
            warnings.append(
                PlanWarning.ACTION_ID_REPEATED.format(action=name, action_id=own_id, position=position)
            )
        elif own_id:
            first_holder[own_id] = index
    return positions_of, warnings


def _offsets(
    durations: list[int], prerequisites: list[list[int]]
) -> tuple[list[int], list[int], list[int | None]]:
    """Each action's start and finish in days from the plan's start, and the prerequisite that sets it."""
    starts: list[int] = []
    finish: list[int] = []
    via: list[int | None] = []
    for days, deps in zip(durations, prerequisites, strict=True):
        start = max((finish[d] for d in deps), default=0)
        starts.append(start)
        finish.append(start + days)
        via.append(max(deps, key=lambda d: finish[d]) if deps else None)
    return starts, finish, via


def _critical_path(finish: list[int], via: list[int | None]) -> list[int]:
    """The longest chain of positions, walked back from the action that finishes last."""
    node: int | None = finish.index(max(finish))
    path: list[int] = []
    while node is not None:
        path.append(node)
        node = via[node]
    return path[::-1]


def _render_actions(actions: list[dict[str, Any]], starts: list[int], anchor: date | None) -> None:
    """Writes each action's inclusive start_date, end_date and timeline; no window gives null dates."""
    for action, start in zip(actions, starts, strict=True):
        days, deps = action["duration_days"], action["depends_on"]
        span = PlanText.DAYS.format(days=days) + ("s" if days != 1 else "")
        after = (PlanText.AFTER.format(ids=_joined(deps)) + ("s" if len(deps) == 1 else "")) if deps else ""
        if anchor is None:
            action["start_date"] = action["end_date"] = None
            action["timeline"] = PlanText.UNDATED.format(span=span, after=after)
            continue
        first, last = _shift(anchor, start), _shift(anchor, start + days - 1)
        action["start_date"], action["end_date"] = first.isoformat(), last.isoformat()
        action["timeline"] = PlanText.DATED.format(
            start=first.isoformat(), end=last.isoformat(), span=span, after=after
        )


def _write_plan_timeline(
    plan: dict[str, Any], anchor: date | None, planned_end: date | None, total: int, path: list[str]
) -> None:
    """Writes the plan's critical path, total days, planned end date and timeline sentence."""
    plan["critical_path"] = path
    plan["mitigation_timeline_days"] = total
    plan["mitigation_end_date_planned"] = planned_end.isoformat() if planned_end is not None else None
    chain = " → ".join(path)
    if anchor is not None and planned_end is not None:
        plan["mitigation_timeline"] = PlanText.PLAN_DATED.format(
            start=anchor.isoformat(), end=planned_end.isoformat(), total=total, chain=chain
        )
    else:
        plan["mitigation_timeline"] = PlanText.PLAN_UNDATED.format(total=total, chain=chain)


def _window_warnings(window: dict[str, Any] | None, planned_end: date | None, total: int) -> list[str]:
    """Warns when there is no window, or says by how many days the plan finishes after it closes."""
    if not window or planned_end is None:
        return [PlanWarning.NO_WINDOW.format(total=total)]
    deadline = date.fromisoformat(window["timeline_end_date"])
    if planned_end <= deadline:
        return []
    days = (planned_end - deadline).days
    return [
        PlanWarning.PAST_WINDOW.format(end=planned_end.isoformat(), days=days, deadline=deadline.isoformat())
    ]


def _shift(anchor: date, offset: int) -> date:
    """The anchor plus offset days, clamped to the calendar's last day."""
    try:
        return anchor + timedelta(days=offset)
    except OverflowError:
        return date.max


def _past_calendar(anchor: date | None, total: int) -> list[str]:
    """Warns when the schedule runs past the last representable date."""
    if anchor is None or total <= 0 or total - 1 <= (date.max - anchor).days:
        return []
    fit, last = (date.max - anchor).days + 1, date.max.isoformat()
    return [PlanWarning.PAST_CALENDAR.format(total=total, anchor=anchor.isoformat(), fit=fit, last=last)]


def _joined(ids: list[str]) -> str:
    """The ids as English: "A1", "A1 and A2", "A1, A2 and A3"."""
    return ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + f" and {ids[-1]}"
