"""The remediation planner (BUILD_PLAN S49; BLUEPRINT M11 R5-R7; v1 treatment.run_treatment_generation):
one AI call writes a plan version's judgement, then code makes it exact. The recommended controls are only
the scenario's library controls the register does not already hold, stamped from the library row (the AI
never sees an id); the strategy and the register's echoes are code's; the dates are the scheduler's. Where
the plan and its rules disagree, a warning stands beside it, never a silent repair. Pure apart from the one
AI call."""

from typing import Any

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import (
    ActionPriority,
    AiTask,
    ControlCoverage,
    ErrorCode,
    PlanWarning,
    Remediation,
    RemediationMessage,
    RiskLevel,
)
from app.core.exceptions import JobFailed
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.remediation.prompts import PLAN_PROMPT_VERSION, plan_prompt
from app.engine.remediation.scheduler import schedule
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_and_check
from app.engine.shared.names import shorten_text
from app.models.remediation import FinishedPlan, PlanDraft

_URGENT_LEVELS = frozenset(level.casefold() for level in (RiskLevel.CRITICAL, RiskLevel.HIGH))
_URGENT_PRIORITIES = frozenset((ActionPriority.CRITICAL, ActionPriority.HIGH))


class RemediationPlanner:
    def __init__(self, chat: ChatModel) -> None:
        self._chat = chat

    @traced("remediation.plan")
    def plan(self, snapshot: dict[str, Any]) -> FinishedPlan:
        """One plan version from its frozen snapshot. Raises JobFailed `generation_failed` when the answer is
        still unusable after its one re-ask, `invalid_plan` when it has no action; an outage (Unavailable)
        is raised as it is, so the job retries."""
        try:
            draft: PlanDraft = ask_ai_and_check(
                self._chat,
                AiTask.REMEDIATION_PLAN,
                plan_prompt(snapshot, self._chat.max_prompt_chars),
                _read_answer,
            )
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            reason = shorten_text(str(exc), Remediation.REASON_MAX_CHARS)
            message = RemediationMessage.PLAN_UNUSABLE.format(reason=reason)
            raise JobFailed(ErrorCode.GENERATION_FAILED, message) from exc
        return finish(draft, snapshot)


def finish(draft: PlanDraft, snapshot: dict[str, Any]) -> FinishedPlan:
    """The plan as stored, and its warnings in v1's order. Every check reads the plan the reviewer will see:
    a control removed here is never reported by the scheduler as "recommended but not implemented", and a
    Critical plan whose only urgent control was removed is warned about."""
    plan = draft.model_dump(mode="json")
    if not plan["remediation_action_plan"]:
        raise JobFailed(ErrorCode.INVALID_PLAN, RemediationMessage.PLAN_WITHOUT_ACTION)
    # Code's keys last, so nothing the AI wrote can stand in for the strategy or the register's facts.
    plan |= {"treatment_strategy": Remediation.STRATEGY, **snapshot["register"]}
    table = plan["controls_to_be_implemented"]
    mapped = snapshot["existing_controls"]["library_mapped"]
    dropped, in_register = _library_controls(table, mapped)
    covered = table["control_coverage"] == ControlCoverage.COVERED
    warnings = list(snapshot["warnings"])
    if covered and table["controls"]:
        warnings.append(PlanWarning.COVERED_WITH_CONTROLS)
    warnings += schedule(plan, snapshot)
    warnings += _urgency_warnings(plan, snapshot["risk_assessment"]["risk_level"])
    if covered and not mapped:
        warnings.append(PlanWarning.COVERED_WITHOUT_LIBRARY)
    return FinishedPlan(plan, tuple(warnings + dropped + in_register), PLAN_PROMPT_VERSION)


def _library_controls(table: dict[str, Any], mapped: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Keeps a recommended control only when it is one of the scenario's library controls that the register
    does not hold, once, and stamps the library row's id, canonical code, name and domain on it. The code
    is folded (the AI echoes it: a case slip is not an invented control). The warnings: removed as unknown
    or repeated; removed as already in the register."""
    by_code = {row["control_code"].strip().casefold(): row for row in mapped}
    kept: list[dict[str, Any]] = []
    seen: set[int] = set()
    dropped: list[str] = []
    in_register: list[str] = []
    for control in table["controls"]:
        row = by_code.get(control["control_code"].strip().casefold())
        if row is None:
            dropped.append(PlanWarning.CONTROL_NOT_IN_LIBRARY.format(code=control["control_code"]))
        elif row["covered_by_register"]:
            in_register.append(PlanWarning.CONTROL_IN_REGISTER.format(code=row["control_code"]))
        elif row["control_id"] in seen:
            dropped.append(PlanWarning.CONTROL_LISTED_TWICE.format(code=row["control_code"]))
        else:
            seen.add(row["control_id"])
            library = {key: row[key] for key in ("control_id", "control_code", "control_name", "domain")}
            kept.append(control | library)
    table["controls"] = kept
    every_one_covered = bool(mapped) and all(row["covered_by_register"] for row in mapped)
    if every_one_covered and table["control_coverage"] == ControlCoverage.GAPS:
        in_register.append(PlanWarning.ALL_COVERED_BUT_GAPS)
    if step_detail_enabled():
        _trace_library_controls(kept, mapped, dropped, in_register)
    return dropped, in_register


def _trace_library_controls(
    kept: list[dict[str, Any]], mapped: list[dict[str, Any]], dropped: list[str], in_register: list[str]
) -> None:
    record_detail(
        "library controls",
        given={"mapped": ", ".join(row["control_code"] for row in mapped) or "none"},
        produced={
            "kept": ", ".join(control["control_code"] for control in kept) or "none",
            "dropped": " | ".join(dropped) or "none",
            "already_in_register": " | ".join(in_register) or "none",
        },
    )


def _urgency_warnings(plan: dict[str, Any], level: str | None) -> list[str]:
    """A Critical or High register risk whose plan carries no Critical or High control or action ignores the
    register's verdict (prompt rule 4). The four known labels only, case-blind: any other label the AI places
    on the ladder itself and names the level it used in action_plan, for the reviewer (owner, 2026-10-11)."""
    if (level or "").strip().casefold() not in _URGENT_LEVELS:
        return []
    rows = plan["controls_to_be_implemented"]["controls"] + plan["remediation_action_plan"]
    if any(row["priority"] in _URGENT_PRIORITIES for row in rows):
        return []
    return [PlanWarning.URGENCY_NOT_REFLECTED.format(level=level)]


def _read_answer(answer: dict[str, Any]) -> tuple[PlanDraft | None, list[str]]:
    problems = answer_item_problems(PlanDraft, answer, "the reply")
    return (None, problems) if problems else (PlanDraft.model_validate(answer), [])
