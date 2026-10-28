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
    limit = Remediation.MAX_ACTION_DAYS
    warnings: list[str] = []
    for action, name in zip(actions, names, strict=True):
        days = action["duration_days"]
        if days < 1:
            warnings.append(PlanWarning.DURATION_REPAIRED.format(action=name, value=days))
        elif days > limit:
            warnings.append(PlanWarning.DURATION_CAPPED.format(action=name, days=days, limit=limit))
        action["duration_days"] = min(max(days, 1), limit)
    prerequisites, dependency_warnings = _prerequisites(actions, names, action_ids)
    total, path = _date_actions(actions, prerequisites, anchor)
    critical_path = [names[position] for position in path]
    return warnings + dependency_warnings + _date_plan(plan, critical_path, total, anchor, window)


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
            earlier = None if reference == own_id else first_holder.get(reference)
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


def _date_actions(
    actions: list[dict[str, Any]], prerequisites: list[list[int]], anchor: date | None
) -> tuple[int, list[int]]:
    """Writes each action's inclusive dates and timeline; returns the total days and the critical path."""
    finish: list[int] = []
    via: list[int | None] = []
    for action, positions in zip(actions, prerequisites, strict=True):
        start = max((finish[p] for p in positions), default=0)
        days, ids = action["duration_days"], action["depends_on"]
        finish.append(start + days)
        via.append(max(positions, key=lambda p: finish[p]) if positions else None)
        span = _spell_days(days)
        after = ""
        if ids:
            listed = ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + f" and {ids[-1]}"
            after = PlanText.AFTER.format(ids=listed) + ("s" if len(ids) == 1 else "")
        if anchor is None:
            action["start_date"] = action["end_date"] = None
            action["timeline"] = PlanText.UNDATED.format(span=span, after=after)
            continue
        first, last = _shift(anchor, start).isoformat(), _shift(anchor, start + days - 1).isoformat()
        action["start_date"], action["end_date"] = first, last
        action["timeline"] = PlanText.DATED.format(start=first, end=last, span=span, after=after)
    path: list[int] = []
    node: int | None = finish.index(max(finish))
    while node is not None:
        path.append(node)
        node = via[node]
    return max(finish), path[::-1]


def _date_plan(
    plan: dict[str, Any],
    critical_path: list[str],
    total: int,
    anchor: date | None,
    window: dict[str, Any] | None,
) -> list[str]:
    """Writes the plan's critical path, days, end date and timeline; warns past the calendar or the window's
    end, when it has one."""
    chain = " → ".join(critical_path)
    plan["critical_path"] = critical_path
    plan["mitigation_timeline_days"] = total
    if anchor is None or not window:
        plan["mitigation_end_date_planned"] = None
        plan["mitigation_timeline"] = PlanText.PLAN_UNDATED.format(total=_spell_days(total), chain=chain)
        return [PlanWarning.NO_WINDOW.format(total=total)]
    planned_end = _shift(anchor, total - 1)
    end = planned_end.isoformat()
    plan["mitigation_end_date_planned"] = end
    plan["mitigation_timeline"] = PlanText.PLAN_DATED.format(
        start=anchor.isoformat(), end=end, total=_spell_days(total), chain=chain
    )
    warnings = []
    fit = (date.max - anchor).days + 1
    if total > fit:
        last, anchored = date.max.isoformat(), anchor.isoformat()
        warnings.append(
            PlanWarning.PAST_CALENDAR.format(total=total, anchor=anchored, fit=_spell_days(fit), last=last)
        )
    if not window.get("timeline_end_date"):  # a start alone: dated, but no deadline to finish by
        return warnings
    deadline = date.fromisoformat(window["timeline_end_date"])
    if planned_end > deadline:
        late = _spell_days((planned_end - deadline).days)
        warnings.append(PlanWarning.PAST_WINDOW.format(end=end, days=late, deadline=deadline.isoformat()))
    return warnings


def _spell_days(days: int) -> str:
    """A count of days as every plan text says it: "1 day", "2 days"."""
    return PlanText.DAYS.format(days=days) + ("s" if days != 1 else "")


def _shift(anchor: date, offset: int) -> date:
    """The anchor plus offset days, clamped to the calendar's last day."""
    try:
        return anchor + timedelta(days=offset)
    except OverflowError:
        return date.max
