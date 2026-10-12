"""What only the finished schedule can show (BLUEPRINT M11 R7 step 7; BUILD_PLAN S47; v1
treatment_schedule.py): ids in sequence, start order, urgent work never waiting on less urgent
prerequisites, the plan inside the mitigation window, the action_plan paragraph agreeing with the computed
total, and every recommended control delivered by an action. Warnings only, never a block. Pure, no IO."""

import re
from typing import Any

from app.core.constants import ActionPriority, ControlCoverage, PlanWarning
from app.models.remediation import ActionSchedule

#: Critical = 0 … Low = 3: the enum's own order, the ranking the approved prompt states.
_PRIORITY_RANK = {priority.value: rank for rank, priority in enumerate(ActionPriority)}
_URGENT = {ActionPriority.CRITICAL.value, ActionPriority.HIGH.value}
_STATED_DAYS = re.compile(r"(?<![\d.])(\d+)[\s-]*(?:calendar[\s-]+)?days?\b", re.IGNORECASE)


def schedule_warnings(plan: dict[str, Any], snapshot: dict[str, Any], schedule: ActionSchedule) -> list[str]:
    actions = plan["remediation_action_plan"]
    return (
        _sequence_warnings(actions, schedule)
        + _window_warnings(schedule, bool(actions))
        + _stated_days_warnings(plan, schedule, bool(actions))
        + _control_delivery_warnings(plan, snapshot, schedule.names)
    )


def _sequence_warnings(actions: list[dict[str, Any]], schedule: ActionSchedule) -> list[str]:
    """Ids A1..An in order; nothing listed after work that starts later; an urgent action's prerequisite at
    least as urgent (a prerequisite blocks it, so it is on its critical path)."""
    ids = list(schedule.action_ids)
    warnings = []
    if ids != [f"A{number}" for number in range(1, len(ids) + 1)]:
        warnings.append(PlanWarning.IDS_OUT_OF_SEQUENCE.format(count=len(ids), ids=ids))
    priorities = [str(action.get("priority") or "") for action in actions]
    latest = 0
    for index, name in enumerate(schedule.names):
        start = schedule.starts[index]
        if start < latest:
            warnings.append(PlanWarning.OUT_OF_ORDER.format(action=name, latest=latest, start=start))
        latest = max(latest, start)
        rank = _PRIORITY_RANK.get(priorities[index])
        if priorities[index] not in _URGENT or rank is None:
            continue
        warnings += [
            PlanWarning.LESS_URGENT_PREREQUISITE.format(
                prerequisite=schedule.names[d],
                prerequisite_priority=priorities[d],
                action=name,
                priority=priorities[index],
            )
            for d in schedule.prerequisites[index]
            if _PRIORITY_RANK.get(priorities[d], rank) > rank
        ]
    return warnings


def _window_warnings(schedule: ActionSchedule, has_actions: bool) -> list[str]:
    """No window: the schedule is unbounded (a register deadline nobody supplied, not a plan defect). A plan
    finishing after the window's last day says by how many days."""
    if not has_actions:
        return []
    if schedule.deadline is None:
        return [PlanWarning.NO_WINDOW.format(total=schedule.total)]
    end, deadline = schedule.planned_end, schedule.deadline
    if end is not None and end > deadline:
        days = (end - deadline).days
        return [PlanWarning.PAST_WINDOW.format(end=end.isoformat(), days=days, deadline=deadline.isoformat())]
    return []


def _stated_days_warnings(plan: dict[str, Any], schedule: ActionSchedule, has_actions: bool) -> list[str]:
    """The paragraph is the AI's prose and may do its own arithmetic: day counts none of which is the computed
    critical path mean the plan contradicts itself."""
    stated = {int(number) for number in _STATED_DAYS.findall(str(plan.get("action_plan") or ""))}
    if has_actions and stated and schedule.total not in stated:
        listed = ", ".join(str(number) for number in sorted(stated))
        return [PlanWarning.STATED_DAYS.format(stated=listed, total=schedule.total)]
    return []


def _control_delivery_warnings(
    plan: dict[str, Any], snapshot: dict[str, Any], names: tuple[str, ...]
) -> list[str]:
    """Every recommended control delivered by some action; an action names only a control of this plan: a
    recommended one, a mapped one the register already covers (it is verified), or with "covered" any mapped
    one. Codes are matched case-blind and written back in the plan's own spelling."""
    to_implement = plan["controls_to_be_implemented"]
    recommended = [str(control["control_code"]) for control in to_implement["controls"]]
    known = {code.strip().casefold(): code for code in recommended}
    verifies_mapped = to_implement["control_coverage"] == ControlCoverage.COVERED
    for mapped in (snapshot.get("existing_controls") or {}).get("library_mapped") or []:
        if mapped.get("control_code") and (verifies_mapped or mapped.get("covered_by_register")):
            known.setdefault(str(mapped["control_code"]).strip().casefold(), str(mapped["control_code"]))
    warnings: list[str] = []
    delivered: set[str] = set()
    for name, action in zip(names, plan["remediation_action_plan"], strict=True):
        codes = []
        for echoed in (str(code).strip() for code in action["implements_controls"]):
            canonical = known.get(echoed.casefold())
            if canonical is None:
                warnings.append(PlanWarning.IMPLEMENTS_UNKNOWN.format(action=name, code=echoed))
            codes.append(canonical or echoed)
        action["implements_controls"] = codes
        delivered.update(codes)
    missing = [code for code in recommended if code not in delivered]
    return warnings + [PlanWarning.CONTROL_NOT_IMPLEMENTED.format(code=code) for code in missing]
