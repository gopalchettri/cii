"""What the API shows of a remediation plan: the shown version's
plan in one typed shape (dates YYYY-MM-DD, all computed by code), the scenario summary, the register echo, the
history (never a snapshot), and a list item. Built from the stored record."""

from datetime import date, datetime
from typing import Any, ClassVar

from pydantic import BaseModel

from app.core.constants import ActionPriority, ControlCoverage, ControlType, Decision, Status, YesNo
from app.models.remediation import RemediationStatus


class PlanControlView(BaseModel):
    control_id: int
    control_code: str
    control_name: str
    control_type: ControlType
    domain: str | None = None
    description: str
    priority: ActionPriority


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
    success_criteria: str


class PlanView(BaseModel):
    title: str
    treatment_strategy: str
    control_coverage: ControlCoverage
    controls_to_be_implemented: list[PlanControlView]
    actions: list[PlanActionView]
    action_plan: str
    mitigation_owner: str
    applicable_to_all_subsystems: YesNo
    critical_path: list[str]
    mitigation_timeline: str | None = None
    mitigation_timeline_days: int | None = None
    mitigation_end_date_planned: date | None = None
    risk_identification_date: datetime | None = None
    risk_owner: str | None = None
    impacted_business_division: str | None = None
    prompt_version: str

    @classmethod
    def from_stored(cls, plan: dict[str, Any], prompt_version: str) -> "PlanView":
        """The stored plan keeps the AI's own layout (its answer contract); the API shows it flat."""
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
        """The latest version's status and error live at the top of the record (R3); an older one's on it."""
        latest = item["version"] == record["job"]["epoch"]
        plan = item.get("plan")
        return cls.model_validate(
            item
            | {
                "status": record["status"] if latest else item["status"],
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

    @classmethod
    def from_record(cls, scenario: dict[str, Any]) -> "ScenarioSummary":
        content = scenario.get("content") or {}
        return cls(
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
        cls, record: dict[str, Any], scenario: dict[str, Any] | None, include_history: bool
    ) -> "RemediationResult":
        item = shown_item(record)
        shown = None if item is None else VersionView.from_item(item, record)
        versions = [VersionView.from_item(v, record) for v in record["versions"]] if include_history else None
        return cls(
            **RemediationStatus.from_record(record).model_dump(),
            shown_version=None if shown is None else shown.version,
            plan=None if shown is None else shown.plan,
            warnings=[] if shown is None else shown.warnings,
            scenario=None if scenario is None else ScenarioSummary.from_record(scenario),
            register_data=record.get("register") or {},
            versions=versions,
        )


def shown_item(record: dict[str, Any]) -> dict[str, Any] | None:
    """The version shown: the accepted one, else the newest done one; None while no version is done. The
    latest version's status lives at the top of the record (R3). Only this one is built into a view (review
    S56)."""
    latest = record["job"]["epoch"]
    done = [
        item
        for item in record["versions"]
        if (record["status"] if item["version"] == latest else item["status"]) == Status.DONE
    ]
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
        fields = {key: record.get(key) for key in cls.model_fields if key in record}
        return cls.model_validate(
            fields
            | {
                "remediation_id": record["_id"],
                "latest_version": record["job"]["epoch"],
                "latest_status": record["status"],
            }
        )


class RemediationList(BaseModel):
    items: list[RemediationSummary]
    total: int
