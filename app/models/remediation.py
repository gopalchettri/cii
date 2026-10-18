"""Remediation plans: the AI's answer contract (`PlanDraft`, v1's
TreatmentPlanGenerated under the approved prompt) and what the API shows of a plan record."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Annotated, Any, ClassVar

from pydantic import AfterValidator, BaseModel

from app.core.constants import (
    ActionPriority,
    AnswerProblem,
    ControlCoverage,
    ControlType,
    Decision,
    LibraryStatus,
    RemediationProgress,
    Status,
    StrideCategory,
    YesNo,
)


def _given(value: str) -> str:
    if not value.strip():
        raise ValueError(AnswerProblem.TEXT_REQUIRED)
    return value


#: Text the plan cannot do without: an empty one is a broken answer (asked again once).
Given = Annotated[str, AfterValidator(_given)]


class DraftControl(BaseModel):
    control_type: ControlType
    control_name: Given
    description: str
    priority: ActionPriority
    control_code: Given  # a library_mapped code, verbatim; code stamps the library id


class DraftControls(BaseModel):
    control_coverage: ControlCoverage
    controls: list[DraftControl]


class DraftAction(BaseModel):
    """One action as the AI writes it: judgement only (what, who, how urgent, how long, what it waits for).
    Dates and timelines are code's (app/domain/remediation/scheduler.py)."""

    action_id: str
    action: Given
    owner: Given
    priority: ActionPriority
    dependencies: str
    depends_on: list[str]
    duration_days: int  # repaired by the scheduler when below 1 or above Remediation.MAX_ACTION_DAYS
    implements_controls: list[str]
    success_criteria: Given


class PlanDraft(BaseModel):
    """The plan AI's answer (approved prompt, docs/REMEDIATION_PROMPT_DRAFT.md §3); a broken one is asked
    again once, then the version fails `generation_failed`."""

    title: Given
    controls_to_be_implemented: DraftControls
    remediation_action_plan: list[DraftAction]
    action_plan: Given
    mitigation_owner: Given
    applicable_to_all_subsystems: YesNo


@dataclass(frozen=True)
class ActionSchedule:
    """The scheduler's arithmetic for one plan, by action POSITION, never by the AI's ids (a repeated id could
    otherwise make an action its own prerequisite or overwrite another's finish): what the checks read."""

    action_ids: tuple[str, ...]  # as the AI wrote them
    names: tuple[str, ...]  # what a warning calls each action: its id, else its position
    prerequisites: tuple[tuple[int, ...], ...]  # earlier positions only
    starts: tuple[int, ...]  # days from the plan's start
    total: int  # the critical path's length in days
    planned_end: date | None  # inclusive; None without a mitigation window
    deadline: date | None  # the window's last day


@dataclass(frozen=True)
class ThreatIdentity:
    """A hand-written scenario's threat as the library knows it (BLUEPRINT M05 Rule L2). `status` None: the
    wording is new and is proposed to the library (Rule L4) before the scenario is saved."""

    category: StrideCategory | None
    type_id: int | None  # None: a new type
    type_name: str
    catalogue_id: int | None  # None: a new threat, or a wording a curator rejected
    threat_name: str
    status: LibraryStatus | None
    category_id: int | None = None  # the category's library id (the results' threat_category_id)


@dataclass(frozen=True)
class FinishedPlan:
    """One plan version's result (BLUEPRINT M11 R6-R7): the plan as stored and shown, every warning in its
    fixed order, and the prompt that wrote it."""

    plan: dict[str, Any]
    warnings: tuple[str, ...]
    prompt_version: str


class PlanRequested(BaseModel):
    """202 of a regenerate: the version being written. Keep session_id and scenario_id: every plan call takes
    them in its address (/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan...)."""

    remediation_id: str
    session_id: str
    scenario_id: str
    version: int
    status: Status


class PlanStarted(PlanRequested):
    """202 of `POST /v1/remediation` (200 on a replay of a hand-written request), with v1's two flags."""

    is_manual: bool  # the scenario's own kind (a person wrote it), not an echo of the request
    replayed: bool = False  # this Idempotency-Key had already saved this scenario: nothing new was saved


class Progress(BaseModel):
    generation: Status  # the latest version's
    review: Decision  # the record's
    overall: RemediationProgress


class RemediationStatus(BaseModel):
    """#15, and every `remediation.updated` event (one model, so they can never differ). The latest version's
    status and error live at the top of the record (BLUEPRINT M11 R3)."""

    remediation_id: str
    entity_id: int
    scenario_id: str
    session_id: str
    latest_version: int
    latest_status: Status
    accepted_version: int | None = None
    decision: Decision
    progress: Progress
    error: dict[str, str] | None = None
    updated_at: datetime

    #: What a status read loads of the record: never a version's snapshot or plan.
    RECORD_FIELDS: ClassVar[dict[str, int]] = {
        "entity_id": 1,
        "scenario_id": 1,
        "session_id": 1,
        "status": 1,
        "decision": 1,
        "accepted_version": 1,
        "job.epoch": 1,
        "job.error": 1,
        "updated_at": 1,
    }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "RemediationStatus":
        status, decision = Status(record["status"]), Decision(record["decision"])
        job = record.get("job") or {}
        return cls(
            remediation_id=record["_id"],
            entity_id=record["entity_id"],
            scenario_id=record["scenario_id"],
            session_id=record["session_id"],
            latest_version=job["epoch"],
            latest_status=status,
            accepted_version=record.get("accepted_version"),
            decision=decision,
            progress=Progress(generation=status, review=decision, overall=_overall(status, decision)),
            error=job.get("error"),
            updated_at=record["updated_at"],
        )


def _overall(status: Status, decision: Decision) -> RemediationProgress:
    """The first that applies: the latest version failed, is being written, or waits for review; then the
    record's decision."""
    if status == Status.FAILED:
        return RemediationProgress.FAILED
    if status == Status.CANCELLED:
        return RemediationProgress.CANCELLED
    if status in (Status.QUEUED, Status.RUNNING):
        return RemediationProgress.GENERATING
    if decision == Decision.PENDING:
        return RemediationProgress.AWAITING_REVIEW
    return RemediationProgress.ACCEPTED if decision == Decision.ACCEPTED else RemediationProgress.REJECTED
