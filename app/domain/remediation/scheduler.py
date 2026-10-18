"""The plan's dates (BLUEPRINT M11 R7; BUILD_PLAN S47; a port of v1 treatment_schedule.py). The AI gives
each action a duration and what it waits for; code turns that into offsets, the critical path, inclusive
dates from the mitigation window's start and timeline sentences, so the dates can never contradict each
other. It repairs, never blocks: every repair is a warning. Keyed by action POSITION, never by the AI's
ids. Pure, no IO."""

import re
from datetime import date, timedelta
from typing import Any

from app.core.constants import PlanText, PlanWarning, Remediation
from app.domain.remediation.schedule_checks import schedule_warnings
from app.models.remediation.plan import ActionSchedule

_ACTION_REF = re.compile(r"\bA\d+\b")


def schedule(plan: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """Dates, timelines and the critical path written onto `plan` and its actions (in place); the warnings."""
    window = (snapshot.get("risk_assessment") or {}).get("assessment_window")
    actions = plan["remediation_action_plan"]
    action_ids = [str(action.get("action_id") or "").strip() for action in actions]
    names = [action_id or f"remediation_action_plan[{i}]" for i, action_id in enumerate(action_ids)]
    anchor = date.fromisoformat(window["timeline_start_date"]) if window else None
    durations, warnings = _durations(actions, names)
    prerequisites, dependency_warnings = _prerequisites(actions, names, action_ids)
    starts, finish, via = _offsets(durations, prerequisites)
    waits_for = [[names[p] for p in deps] for deps in prerequisites]
    _render(actions, durations, waits_for, starts, anchor)
    total = max(finish, default=0)
    path = [names[p] for p in _critical_path(finish, via)]
    planned_end = _shift(anchor, total - 1) if anchor is not None and actions else None
    _write_plan_timeline(plan, anchor, planned_end, total, path)
    computed = ActionSchedule(
        tuple(action_ids),
        tuple(names),
        tuple(tuple(deps) for deps in prerequisites),
        tuple(starts),
        total,
        planned_end,
        date.fromisoformat(window["timeline_end_date"]) if window else None,
    )
    warnings += dependency_warnings + _past_calendar(anchor, total)
    return warnings + schedule_warnings(plan, snapshot, computed)


def _durations(actions: list[dict[str, Any]], names: list[str]) -> tuple[list[int], list[str]]:
    """Whole days in 1..Remediation.MAX_ACTION_DAYS, written back onto each action; one warning per repair (a
    silently invented duration is a plan length nobody agreed to)."""
    durations, warnings = [], []
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
        durations.append(days)
    return durations, warnings


def _prerequisites(
    actions: list[dict[str, Any]], names: list[str], action_ids: list[str]
) -> tuple[list[list[int]], list[str]]:
    """Each action's depends_on reduced to EARLIER actions, as positions (written back as ids): a forward,
    self, unknown or repeated-id reference is dropped with one warning per distinct reference; a repeated
    action_id belongs to its first holder. A position cannot collide or point forward, so one forward pass
    is sound."""
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
        action["depends_on"] = [action_ids[p] for p in accepted]
        warnings += _prose_warnings(action, name, own_id, action["depends_on"])
        positions_of.append(accepted)
        if own_id and own_id in first_holder:
            position = first_holder[own_id]
            warnings.append(
                PlanWarning.ACTION_ID_REPEATED.format(action=name, action_id=own_id, position=position)
            )
        elif own_id:
            first_holder[own_id] = index
    return positions_of, warnings


def _prose_warnings(action: dict[str, Any], name: str, own_id: str, accepted: list[str]) -> list[str]:
    """The `dependencies` sentence a reviewer reads must tell the same story as the ids the schedule uses."""
    prose = str(action.get("dependencies") or "").strip()
    warnings = [
        PlanWarning.DEPENDENCY_PROSE_EXTRA.format(action=name, named=named)
        for named in dict.fromkeys(_ACTION_REF.findall(prose))
        if named != own_id and named not in accepted
    ]
    if accepted and prose.casefold().rstrip(".") == "none":
        warnings.append(PlanWarning.DEPENDENCY_PROSE_NONE.format(action=name, ids=_joined(accepted)))
    return warnings


def _offsets(
    durations: list[int], prerequisites: list[list[int]]
) -> tuple[list[int], list[int], list[int | None]]:
    """(start, finish, the prerequisite that sets the start) per action. Offsets are days from the plan's
    start, exclusive: a 14-day action starting at 0 finishes at 14, where its dependant starts."""
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
    """The longest chain (never the sum: parallel work is not added), walked back from the action that
    finishes last; every step goes to a strictly earlier position, so the walk always ends."""
    if not finish:
        return []
    node: int | None = finish.index(max(finish))
    path: list[int] = []
    while node is not None:
        path.append(node)
        node = via[node]
    return path[::-1]


def _render(
    actions: list[dict[str, Any]],
    durations: list[int],
    waits_for: list[list[str]],
    starts: list[int],
    anchor: date | None,
) -> None:
    """Each action's start_date, end_date (inclusive: a 14-day action from 1 Oct ends 14 Oct) and timeline; no
    window → null dates and the duration alone. Today's date is never used."""
    for action, days, deps, start in zip(actions, durations, waits_for, starts, strict=True):
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
    has_actions = bool(plan["remediation_action_plan"])
    plan["critical_path"] = path
    plan["mitigation_timeline_days"] = total if has_actions else None
    plan["mitigation_end_date_planned"] = planned_end.isoformat() if planned_end is not None else None
    chain = " → ".join(path)
    if not has_actions:
        plan["mitigation_timeline"] = None
    elif anchor is not None and planned_end is not None:
        plan["mitigation_timeline"] = PlanText.PLAN_DATED.format(
            start=anchor.isoformat(), end=planned_end.isoformat(), total=total, chain=chain
        )
    else:
        plan["mitigation_timeline"] = PlanText.PLAN_UNDATED.format(total=total, chain=chain)


def _shift(anchor: date, offset: int) -> date:
    """`anchor + offset` days, clamped to the calendar's last day instead of failing (a warning says so)."""
    try:
        return anchor + timedelta(days=offset)
    except OverflowError:
        return date.max


def _past_calendar(anchor: date | None, total: int) -> list[str]:
    if anchor is None or total <= 0 or total - 1 <= (date.max - anchor).days:
        return []
    fit, last = (date.max - anchor).days + 1, date.max.isoformat()
    return [PlanWarning.PAST_CALENDAR.format(total=total, anchor=anchor.isoformat(), fit=fit, last=last)]


def _joined(ids: list[str]) -> str:
    return ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + f" and {ids[-1]}"
