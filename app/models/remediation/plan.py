"""Remediation plans: the AI's answer contract (`PlanDraft`) and what the API shows of a plan record."""

from datetime import date, datetime
from typing import Annotated, Any, ClassVar

from pydantic import AfterValidator, BaseModel, BeforeValidator

from app.core.constants import (
    LEGACY_STATUS_NAMES,
    ActionPriority,
    AnswerProblem,
    ControlCoverage,
    ControlType,
    ControlValidation,
    Decision,
    GapKind,
    ImplementationStatus,
    RemediationProgress,
    Status,
    YesNo,
)
from app.models.jobs.views import RetryNotice, retry_notice_of


def _given(value: str) -> str:
    """Blank text is refused."""
    if not value.strip():
        raise ValueError(AnswerProblem.TEXT_REQUIRED)
    return value


#: Text the plan cannot do without: an empty one is a broken answer (asked again once).
Given = Annotated[str, AfterValidator(_given)]


def _the_controls(value: Any) -> Any:
    """The answer's {control_coverage, controls} read as its controls: code sets the coverage."""
    return value.get("controls", value) if isinstance(value, dict) else value


class DraftControl(BaseModel):
    control_type: ControlType
    control_name: Given
    description: str
    priority: ActionPriority
    control_code: Given  # a library_mapped code, verbatim; code stamps the library id


class DraftAction(BaseModel):
    """One action as the AI writes it: what, who, how urgent, how long, what it waits for (code dates it)."""

    action_id: str
    action: Given
    owner: Given
    priority: ActionPriority
    dependencies: str
    depends_on: list[str]
    duration_days: int  # repaired by the scheduler when below 1 or above Remediation.MAX_ACTION_DAYS
    implements_controls: list[str]
    supporting_systems: list[str] = []  # the affected systems it works on, by name; code checks them
    success_criteria: Given


class DraftValidation(BaseModel):
    """The AI's check of one identified control against this scenario's risk."""

    control_code: Given  # a library_mapped code, verbatim
    validation: ControlValidation
    replacement_code: str | None = None  # "replaced": a library_alternatives code, verbatim
    reason: Given  # why; for an implemented control, how the existing control already reduces this risk


class PlanDraft(BaseModel):
    """The plan AI's answer; a broken one is asked again once, then the version fails `generation_failed`."""

    title: str = ""  # a fallback only: code names the plan from its controls' domains (glm leaves it out)
    control_validation: list[DraftValidation]
    controls_to_be_implemented: Annotated[list[DraftControl], BeforeValidator(_the_controls)]
    remediation_action_plan: list[DraftAction]
    action_plan: Given
    mitigation_owner: Given
    uncovered_risks: list[str] = []  # parts of the risk no checked control reduces
    applicable_to_all_subsystems: YesNo | None = None  # no longer asked: code sets it from the risk flag


class PlanRequested(BaseModel):
    """202 of a regenerate: the version being written. Keep session_id and scenario_id: every plan call takes
    them in its address (/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan...)."""

    remediation_id: str
    session_id: str
    scenario_id: str
    version: int
    status: Status


class PlanStarted(PlanRequested):
    """202 of `POST /v1/remediation` (200 on a replay of a hand-written request; 202 when that replay writes
    an outage-failed version again), with v1's two flags."""

    is_manual: bool  # the scenario's own kind (a person wrote it), not an echo of the request
    replayed: bool = False  # this Idempotency-Key had already saved this scenario: nothing new was saved


class PlanTimings(BaseModel):
    """The latest version's seconds per activity, once each is done: its controls, then its plan."""

    controls: float | None = None  # the scenario read, its controls found (mapped if needed), alternatives
    plan: float | None = None  # the AI writing the plan, code's fix-up and its schedule


class Progress(BaseModel):
    __module__ = "app.models.remediation"  # pins the OpenAPI name

    generation: Status  # the latest version's
    review: Decision  # the record's
    overall: RemediationProgress
    retrying: RetryNotice | None = None  # the generation waiting to try again after an outage
    timings: PlanTimings = PlanTimings()


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
        "job.retry": 1,
        "job.waiting": 1,
        "job.timings": 1,
        "updated_at": 1,
    }

    @classmethod
    def from_record(cls, record: dict[str, Any], scenario_accepted: bool) -> "RemediationStatus":
        """The status of a stored record whose scenario is (or is no longer) accepted."""
        status, decision = shown_plan_status(record), Decision(record["decision"])
        job = record.get("job") or {}
        seconds = job.get("timings") or {}
        return cls(
            remediation_id=record["_id"],
            entity_id=record["entity_id"],
            scenario_id=record["scenario_id"],
            session_id=record["session_id"],
            latest_version=job["epoch"],
            latest_status=status,
            accepted_version=record.get("accepted_version"),
            decision=decision,
            progress=Progress(
                generation=status,
                review=decision,
                overall=_overall(status, decision, scenario_accepted),
                retrying=retry_notice_of(status, job.get("retry")),
                timings=PlanTimings(controls=seconds.get("controls_s"), plan=seconds.get("plan_s")),
            ),
            error=job.get("error"),
            updated_at=record["updated_at"],
        )


def _overall(status: Status, decision: Decision, scenario_accepted: bool) -> RemediationProgress:
    """First that applies: the latest version failed, is being written or awaits a review it may still get;
    else the decision."""
    if status == Status.FAILED:
        return RemediationProgress.FAILED
    if status == Status.CANCELLED:
        return RemediationProgress.CANCELLED
    if status in (Status.QUEUED, Status.RUNNING):
        return RemediationProgress.GENERATING
    if decision == Decision.PENDING:
        return RemediationProgress.AWAITING_REVIEW if scenario_accepted else RemediationProgress.READ_ONLY
    return RemediationProgress.ACCEPTED if decision == Decision.ACCEPTED else RemediationProgress.REJECTED


def shown_plan_status(record: dict[str, Any]) -> Status:
    """The latest version's status as shown (every reader projects job.waiting): queued while its job waits
    for another job, though each look briefly claims it (running)."""
    status = Status(record["status"])
    return Status.QUEUED if status == Status.RUNNING and (record.get("job") or {}).get("waiting") else status


def version_status(record: dict[str, Any], item: dict[str, Any]) -> Status:
    """A version's status: the latest version's lives at the top of the record, an older one's on its item."""
    latest = item["version"] == record["job"]["epoch"]
    return shown_plan_status(record) if latest else Status(item["status"])


def _renamed_status(value: Any) -> Any:
    """An older stored plan's status under its current name ("missing" is "not_implemented")."""
    return LEGACY_STATUS_NAMES.get(value, value) if isinstance(value, str) else value


StatusShown = Annotated[ImplementationStatus, BeforeValidator(_renamed_status)]


class SystemRef(BaseModel):
    """A supporting system of the scenario's asset."""

    supporting_system_id: int
    name: str


class PlanControlView(BaseModel):
    control_id: int
    control_code: str
    control_name: str
    control_type: ControlType
    domain: str | None = None
    description: str
    priority: ActionPriority
    implementation_status: StatusShown = ImplementationStatus.NOT_IMPLEMENTED
    required_systems: list[SystemRef] = []  # the affected systems it is still needed on


class PlanActionView(BaseModel):
    action_id: str
    action: str
    owner: str
    priority: ActionPriority
    dependencies: str
    depends_on: list[str]
    duration_days: int
    start_date: date | None = None  # null without a mitigation window
    end_date: date | None = None
    timeline: str
    implements_controls: list[str]
    supporting_systems: list[SystemRef] = []  # the affected systems it works on
    success_criteria: str


class ControlAssessmentView(BaseModel):
    """One control the plan weighed (identified for the scenario, or the library alternative replacing one):
    its check against the risk, where it stands on the affected systems and whether the plan recommends it."""

    control_id: int
    control_code: str
    control_name: str
    domain: str | None = None
    match: str | None = None  # exact, nearest or given (identified), alternative (a replacement)
    implementation_status: StatusShown
    recommended: bool
    protected_systems: list[SystemRef] = []  # the affected systems an existing control is already on
    required_systems: list[SystemRef] = []  # the affected systems it is still needed on
    validation: ControlValidation | None = None  # an identified control's check: retained, replaced, flagged
    validation_reason: str | None = None  # why; for an implemented one, how it already reduces the risk
    replaced_by: str | None = None  # the alternative's code, when replaced
    replaces: list[str] = []  # an alternative's: the identified controls it replaces


class UnresolvedGapView(BaseModel):
    """A gap the plan could not close with a checked library control, reported apart from its controls."""

    kind: GapKind
    control_code: str | None = None
    detail: str


class PlanView(BaseModel):
    title: str
    treatment_strategy: str
    control_coverage: ControlCoverage
    controls_to_be_implemented: list[PlanControlView]
    actions: list[PlanActionView]
    action_plan: str
    mitigation_owner: str
    applicable_to_all_subsystems: YesNo | None = None  # kept for v1's callers: Yes when the risk is on all
    critical_path: list[str]
    mitigation_timeline: str | None = None
    mitigation_timeline_days: int | None = None
    mitigation_end_date_planned: date | None = None
    risk_identification_date: datetime | None = None
    risk_owner: str | None = None
    impacted_business_division: str | None = None
    prompt_version: str
    control_assessment: list[ControlAssessmentView] = []
    unresolved_gaps: list[UnresolvedGapView] = []

    @classmethod
    def from_stored(cls, plan: dict[str, Any], prompt_version: str) -> "PlanView":
        """The stored plan keeps its {control_coverage, controls} table; the API shows it flat."""
        table = plan["controls_to_be_implemented"]
        shown = {
            "control_coverage": table["control_coverage"],
            "controls_to_be_implemented": table["controls"],
            "actions": plan["remediation_action_plan"],
            "prompt_version": prompt_version,
        }
        return cls.model_validate(plan | shown)


class VersionView(BaseModel):
    version: int
    status: Status
    decision: Decision
    decided_by: str | None = None
    decided_at: datetime | None = None
    review_comment: str | None = None
    requested_by: str | None = None
    requested_at: datetime
    completed_at: datetime | None = None
    error: dict[str, str] | None = None
    plan: PlanView | None = None
    warnings: list[str]

    @classmethod
    def from_item(cls, item: dict[str, Any], record: dict[str, Any]) -> "VersionView":
        """One stored version; the latest version's status and error live at the top of the record."""
        latest = item["version"] == record["job"]["epoch"]
        plan = item.get("plan")
        return cls.model_validate(
            item
            | {
                "status": version_status(record, item),
                "error": record["job"].get("error") if latest else item.get("error"),
                "plan": None if plan is None else PlanView.from_stored(plan, item["prompt_version"]),
            }
        )


class ScenarioSummary(BaseModel):
    """The planned scenario as its reviewer reads it beside the plan."""

    scenario_id: str
    title: str | None = None
    statement: str | None = None
    risk_statement: str | None = None
    category: str | None = None
    threat: dict[str, Any] | None = None
    actors: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []


class RemediationResult(RemediationStatus):
    """#16: the status, then the shown version (the accepted one, else the newest done one, as in v1 where
    approving an old version made it the active one) with its plan and warnings, the scenario and the register
    echo; `versions` only when the history is asked for."""

    shown_version: int | None = None
    plan: PlanView | None = None
    warnings: list[str] = []
    scenario: ScenarioSummary | None = None
    # Not `register`: that name is pydantic's own (ABCMeta.register) and a field must not shadow it.
    register_data: dict[str, Any] = {}
    versions: list[VersionView] | None = None

    @classmethod
    def from_records(
        cls,
        record: dict[str, Any],
        scenario: dict[str, Any] | None,
        scenario_accepted: bool,
        include_history: bool,
    ) -> "RemediationResult":
        """The result of a stored record and its scenario (still accepted or not)."""
        item = shown_item(record)
        shown = None if item is None else VersionView.from_item(item, record)
        versions = [VersionView.from_item(v, record) for v in record["versions"]] if include_history else None
        summary = None
        if scenario is not None:
            content = scenario.get("content") or {}
            summary = ScenarioSummary(
                scenario_id=scenario["_id"],
                **{
                    key: content.get(key)
                    for key in ("title", "statement", "risk_statement", "category", "threat")
                },
                actors=[
                    {key: actor.get(key) for key in ("name", "role")} for actor in content.get("actors") or []
                ],
                controls=(scenario.get("controls") or {}).get("items") or [],
            )
        return cls(
            **RemediationStatus.from_record(record, scenario_accepted).model_dump(),
            shown_version=None if shown is None else shown.version,
            plan=None if shown is None else shown.plan,
            warnings=[] if shown is None else shown.warnings,
            scenario=summary,
            register_data=record.get("register") or {},
            versions=versions,
        )


def shown_item(record: dict[str, Any]) -> dict[str, Any] | None:
    """The version shown: the accepted one, else the newest done one; None while no version is done."""
    done = [item for item in record["versions"] if version_status(record, item) == Status.DONE]
    accepted = [item for item in done if item["version"] == record.get("accepted_version")]
    return (accepted or done[-1:] or [None])[0]


class RemediationSummary(BaseModel):
    """One plan in a list (#17)."""

    remediation_id: str
    scenario_id: str
    session_id: str
    asset_id: int | None = None
    source: str | None = None
    title: str | None = None
    risk_level: str | None = None
    latest_version: int
    latest_status: Status
    accepted_version: int | None = None
    decision: Decision
    created_at: datetime
    updated_at: datetime

    #: What a list reads of each record: never a version.
    RECORD_FIELDS: ClassVar[dict[str, int]] = dict.fromkeys(
        (
            "scenario_id",
            "session_id",
            "asset_id",
            "source",
            "title",
            "risk_level",
            "job.epoch",
            "job.waiting",
            "status",
            "accepted_version",
            "decision",
            "created_at",
            "updated_at",
        ),
        1,
    )

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "RemediationSummary":
        """The list item of a stored record."""
        fields = {key: record.get(key) for key in cls.model_fields if key in record}
        return cls.model_validate(
            fields
            | {
                "remediation_id": record["_id"],
                "latest_version": record["job"]["epoch"],
                "latest_status": shown_plan_status(record),
            }
        )


class RemediationList(BaseModel):
    items: list[RemediationSummary]
    total: int
