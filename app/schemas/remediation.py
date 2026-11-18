"""The remediation API's request and response models."""

import re
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from app.core.constants import (
    LEGACY_STATUS_NAMES,
    ActionPriority,
    ControlCoverage,
    ControlType,
    ControlValidation,
    Decision,
    GapKind,
    ImplementationStatus,
    Limits,
    Remediation,
    RemediationProgress,
    Review,
    Status,
    YesNo,
)
from app.schemas.jobs import RetryNotice, retry_notice_of
from app.schemas.scenarios import SqlId, StartRunRequest

Doc = dict[str, Any]  # a stored record or snapshot
_CODE_SHAPE = re.compile(r"[A-Za-z0-9]+(?:[-_./][A-Za-z0-9]+)+")
_PUNCTUATION_OR_SPACE = re.compile(r"[\W_]+")


def _blank_is_absent(value: Any) -> Any:
    return None if isinstance(value, str) and not value.strip() else value


Blank = BeforeValidator(_blank_is_absent)
_Score = Annotated[Decimal, Field(ge=0, max_digits=15, decimal_places=4)]
# ponytail: a JSON number arrives as a float, so a score written with more than 15 significant digits may be
# rounded before this check; a register sending such scores sends them as strings.
Rating = Annotated[_Score | None, Blank, WithJsonSchema({"type": ["number", "null"], "minimum": 0})]


def _calendar_date(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.strip()).date()
        except ValueError:
            return value  # pydantic answers with its own date error
    return value


CalendarDate = Annotated[date | None, Blank, BeforeValidator(_calendar_date)]


_Code = Annotated[Annotated[str, Field(max_length=Remediation.CONTROL_CODE_MAX_CHARS)] | None, Blank]
_ControlText = Annotated[Annotated[str, Field(max_length=500)] | None, Blank]
_Name = Annotated[Annotated[str, Field(max_length=Remediation.NAME_MAX_CHARS)] | None, Blank]
_Justification = Annotated[Annotated[str, Field(max_length=1_000)] | None, Blank]
_ThreatName = Annotated[Annotated[str, Field(max_length=500)] | None, Blank]
_TypeName = Annotated[Annotated[str, Field(max_length=300)] | None, Blank]
_RecordId = Annotated[Annotated[str, Field(max_length=Review.MAX_ID_CHARS)] | None, Blank]
_Comment = Annotated[Annotated[str, Field(max_length=Remediation.COMMENT_MAX_CHARS)] | None, Blank]
_LibraryId = Annotated[Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)] | None, Blank]


class ControlRef(BaseModel):
    """One control: its library id, code or name, or any mix. A plain string is a reference too: its text is
    the name, and also the code when it looks like one. Whether it exists is the library's question (S46)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    control_id: _LibraryId = None
    control_code: _Code = None
    control_name: _ControlText = None

    @model_validator(mode="before")
    @classmethod
    def accept_a_plain_string(cls, value: Any) -> Any:
        """A plain string becomes a reference: the name, and the code when it looks like one."""
        if not isinstance(value, str):
            return value
        text = value.strip()
        looks_like_a_code = (
            len(text) <= Remediation.CONTROL_CODE_MAX_CHARS
            and _CODE_SHAPE.fullmatch(text) is not None
            and any(character.isdigit() for character in text)
        )
        return {"control_code": text if looks_like_a_code else None, "control_name": text}

    @model_validator(mode="after")
    def check_it_names_a_control(self) -> "ControlRef":
        """An entry that names no control is refused."""
        if self.control_id is None and not self.control_code and not self.control_name:
            raise ValueError("A control entry must name the control: send control_id, control_code or control_name.")
        return self

    def key(self) -> tuple[str, Any]:
        """The strongest key it carries (id, code, then case-blind name): one key names one control."""
        if self.control_id is not None:
            return "control_id", self.control_id
        if self.control_code:
            return "control_code", self.control_code.casefold()
        return "control_name", (self.control_name or "").casefold()


def _drop_blank_entries(entries: Any) -> Any:
    if not isinstance(entries, list):
        return entries
    return [entry for entry in entries if _blank_is_absent(entry) is not None]


def _first_of_each(entries: list[ControlRef]) -> list[ControlRef]:
    kept: dict[tuple[str, Any], ControlRef] = {}
    for entry in entries:
        kept.setdefault(entry.key(), entry)
    return list(kept.values())


def _none_is_empty(value: Any) -> Any:
    return [] if _blank_is_absent(value) is None else value


RegisterControls = Annotated[
    list[ControlRef],
    BeforeValidator(_drop_blank_entries),
    AfterValidator(_first_of_each),
    Field(max_length=Remediation.MAX_CONTROL_REFS),
]
_SystemIds = Annotated[
    list[SqlId],
    BeforeValidator(_none_is_empty),
    WithJsonSchema(
        {
            "anyOf": [
                {"type": "array", "items": {"type": "integer", "exclusiveMinimum": 0, "maximum": Limits.MAX_SQL_INT}},
                {"type": "null"},
            ]
        }
    ),
]
SYSTEM_LISTS = ("supporting_systems_applicable_to_risk", "supporting_systems_applicable_to_existing_controls")
_REMOVED_FLAGS = {
    "all_supporting_systems_applicable": SYSTEM_LISTS[0],
    "existing_controls_all_supporting_system_applicable": SYSTEM_LISTS[1],
    "existing_controls_all_subsystems": SYSTEM_LISTS[1],
}
ScenarioControls = Annotated[
    list[ControlRef], BeforeValidator(_drop_blank_entries), Field(max_length=Remediation.MAX_CONTROL_REFS)
]


def _has_letters(name: str | None) -> str | None:
    if name is not None and not _PUNCTUATION_OR_SPACE.sub("", name):
        raise ValueError("A name must contain letters or digits.")
    return name


_CategoryName = Annotated[_Name, AfterValidator(_has_letters)]
_TypeNameText = Annotated[_TypeName, AfterValidator(_has_letters)]
_ThreatNameText = Annotated[_ThreatName, AfterValidator(_has_letters)]


_Statement = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=Remediation.STATEMENT_MAX_CHARS)
]


class ManualScenario(StartRunRequest):
    """A hand-written scenario (Rule R2), v1's `manual_scenario` (owner, 2026-10-15): the asset and systems as
    a run start names them (the same checks), the entity, the threat by library row in v1's six flat fields,
    and the two statements. The type and the threat are each named by id, name or both; the category is
    optional (else the threat's, else the type's). It has no title (A-11): `scenario_title` is refused."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)
    FIELD_PREFIX: ClassVar[str] = "body.manual_scenario"

    entity_id: SqlId = Field(description="The caller's entity, as v1 sends it: must equal X-Entity-Id (403).")
    threat_category_id: _LibraryId = None
    threat_category_name: _CategoryName = None
    threat_type_id: _LibraryId = None
    threat_type_name: _TypeNameText = None
    threat_id: _LibraryId = None
    threat_name: _ThreatNameText = None
    threat_scenario: _Statement  # " " is not a statement: stripped, then at least one character
    risk_statement: _Statement
    mapped_controls: Annotated[ScenarioControls | None, Blank] = None  # none → mapped as a generated one

    @model_validator(mode="after")
    def check_the_threat_is_named(self) -> "ManualScenario":
        """The type and the threat are each named by id or name."""
        if self.threat_type_id is None and not self.threat_type_name:
            raise ValueError("Name the threat type: send threat_type_id, threat_type_name or both.")
        if self.threat_id is None and not self.threat_name:
            raise ValueError("Name the threat: send threat_id, threat_name or both.")
        return self


_SYSTEMS_EXAMPLE: dict[str, Any] = {
    "supporting_systems_applicable_to_risk": [214, 215],
    "supporting_systems_applicable_to_existing_controls": [214],
}
_REGISTER_EXAMPLE: dict[str, Any] = {
    "likelihood_rating": 4,
    "impact_rating": 5,
    "final_risk_rating": 20,
    "risk_level": "Critical",
    "risk_identification_date": "2026-10-26",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Power Generation Operations",
    "existing_controls_all_subsystems_justification": "Controls are deployed on corporate IT systems only.",
    "mitigation_start_date": "2026-11-01",
    "mitigation_end_date": "2026-12-31",
}

PLAN_REQUEST_EXAMPLES: list[JsonValue] = [
    {
        "is_manual": False,
        "session_id": "<session_id>",
        "scenario_id": "<accepted scenario_id>",
        **_SYSTEMS_EXAMPLE,
        "existing_controls": [{"control_code": "CID-0365", "control_name": "Denial of Service (DoS) Protection"}],
        **_REGISTER_EXAMPLE,
    },
    {
        "is_manual": True,
        "manual_scenario": {
            "asset_id": 88,
            "entity_id": 69,
            "supporting_system_id": [214, 215],
            "threat_category_name": "Tampering",
            "threat_type_name": "Malware/Ransomware",
            "threat_name": "Ransomware encrypts the historian server",
            "threat_scenario": "An attacker phishes an engineer, moves to the historian and encrypts it.",
            "risk_statement": "Operators lose process history and plant reporting stops for days.",
            "mapped_controls": [{"control_code": "CID-0005", "control_name": "Decommissioning"}],
        },
        **_SYSTEMS_EXAMPLE,
        "existing_controls": [
            {"control_code": "CID-0001", "control_name": "Asset Inventories"},
            {"control_code": "CID-0002", "control_name": "Asset Governance"},
        ],
        **_REGISTER_EXAMPLE,
    },
]
_SCENARIO_FIELDS = {"is_manual", "session_id", "scenario_id", "manual_scenario"}


class PlanRequest(BaseModel):
    """Body of `POST /v1/remediation`: v1's ONE request for both kinds of scenario (owner, 2026-10-15), each
    kind sending its own half (mixing them is a 422), and the register's data."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": PLAN_REQUEST_EXAMPLES})

    supporting_systems_applicable_to_risk: _SystemIds = Field(
        default_factory=list,
        description="The supporting systems of the scenario's asset the risk applies to; none (null, blank "
        "or []): the risk is on the asset itself, on no supporting system. A repeat is dropped.",
    )
    supporting_systems_applicable_to_existing_controls: _SystemIds = Field(
        default_factory=list,
        description="The supporting systems of the scenario's asset the existing controls are on, one list "
        "for them all; none (null, blank or []): they are on no supporting system. Only the systems the risk "
        "applies to count; a repeat is dropped.",
    )
    existing_controls: Annotated[RegisterControls | None, Blank] = None
    likelihood_rating: Rating = None
    impact_rating: Rating = None
    final_risk_rating: Rating = None  # taken as-is, never re-derived
    risk_level: _Name = None  # Critical, High, Medium, Low, or the register's own
    risk_identification_date: Annotated[datetime | None, Blank] = None
    risk_owner: _Name = None
    impacted_business_division: _Name = None
    existing_controls_all_subsystems_justification: _Justification = None
    mitigation_start_date: CalendarDate = None
    mitigation_end_date: CalendarDate = None
    is_manual: bool = Field(
        description="false: the scenario already exists in TSG (send session_id + scenario_id). true: a "
        "person wrote it (send manual_scenario); TSG saves it and plans it."
    )
    session_id: _RecordId = Field(None, description="is_manual=false only: the run that holds the scenario.")
    scenario_id: _RecordId = Field(None, description="is_manual=false only: the accepted scenario to plan.")
    manual_scenario: ManualScenario | None = Field(
        None, description="is_manual=true only: the scenario a person wrote."
    )

    @model_validator(mode="before")
    @classmethod
    def refuse_the_old_flags(cls, value: Any) -> Any:
        """An old yes/no flag, whatever its value, is refused on its field with the list to send instead."""
        sent = [flag for flag in _REMOVED_FLAGS if isinstance(value, dict) and flag in value]
        if sent:
            raise ValidationError.from_exception_data(
                cls.__name__,
                [
                    InitErrorDetails(
                        type=PydanticCustomError(
                            "flag_removed",
                            (
                                f"{flag} is no longer accepted: send {_REMOVED_FLAGS[flag]}, "
                                "the list of the asset's supporting system ids, instead."
                            ),
                        ),
                        loc=(flag,),
                        input=value[flag],
                    )
                    for flag in sent
                ],
            )
        return value

    @field_validator("risk_identification_date")
    @classmethod
    def in_utc(cls, value: datetime | None) -> datetime | None:
        """An offset is applied (an instant, unlike the window's dates); a naive time is taken as UTC."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def check_the_window(self) -> "PlanRequest":
        """The mitigation window: a start alone, or a start and an end on or after it; never an end alone."""
        start, end = self.mitigation_start_date, self.mitigation_end_date
        if start is None and end is not None:
            raise ValueError("mitigation_end_date needs mitigation_start_date.")
        if start is not None and end is not None and end < start:
            raise ValueError("mitigation_end_date must be on or after mitigation_start_date.")
        return self

    @model_validator(mode="after")
    def check_one_kind(self) -> "PlanRequest":
        """Each kind sends its own half and never the other's."""
        if self.is_manual:
            if self.manual_scenario is None:
                raise ValueError("is_manual=true requires manual_scenario.")
            if self.session_id is not None or self.scenario_id is not None:
                raise ValueError("is_manual=true must not send session_id or scenario_id: TSG creates them.")
        else:
            if self.session_id is None or self.scenario_id is None:
                raise ValueError("is_manual=false requires session_id and scenario_id.")
            if self.manual_scenario is not None:
                raise ValueError("is_manual=false must not send manual_scenario.")
        return self

    def register(self) -> dict[str, Any]:
        """The register half as stored: exact decimal ratings, ISO dates, each listed system once in order."""
        stored = self.model_dump(mode="json", exclude=_SCENARIO_FIELDS)
        for rating in ("likelihood_rating", "impact_rating", "final_risk_rating"):
            value = getattr(self, rating)
            stored[rating] = None if value is None else str(value)
        for listed in SYSTEM_LISTS:
            stored[listed] = list(dict.fromkeys(stored[listed]))
        return stored


class ReviewRequest(BaseModel):
    """v1's one review call (owner, 2026-10-15): accept or reject a version."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"decision": "accepted"}, {"decision": "rejected", "version": 2}]},
    )

    version: Annotated[int, Field(gt=0)] | None = Field(
        None, description="The version to decide; leave it out for the newest finished one."
    )
    comment: _Comment = Field(None, description="Why (stored with the decision; up to 2,000 characters).")
    decision: Literal[Decision.ACCEPTED, Decision.REJECTED] = Field(
        description="accepted or rejected. Accepting a version makes it THE plan: an earlier accepted "
        "version goes back to pending."
    )


class RegenerateRequest(BaseModel):
    """Nothing: the latest version's register data is reused; any field → 422."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{}]})


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


_STATUS_READ = ("entity_id", "scenario_id", "session_id", "status", "decision", "accepted_version")
_STATUS_JOB = ("job.epoch", "job.error", "job.retry", "job.waiting", "job.timings", "updated_at")


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

    RECORD_FIELDS: ClassVar[dict[str, int]] = dict.fromkeys((*_STATUS_READ, *_STATUS_JOB), 1)

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
    """The latest version's status as shown: queued while its job waits for another job."""
    status = Status(record["status"])
    return Status.QUEUED if status == Status.RUNNING and (record.get("job") or {}).get("waiting") else status


def version_status(record: dict[str, Any], item: dict[str, Any]) -> Status:
    """A version's status: the latest version's lives at the top of the record, an older one's on its item."""
    latest = item["version"] == record["job"]["epoch"]
    return shown_plan_status(record) if latest else Status(item["status"])


def _renamed_status(value: Any) -> Any:
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
        cls, record: dict[str, Any], scenario: dict[str, Any] | None, scenario_accepted: bool, include_history: bool
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
                **{key: content.get(key) for key in ("title", "statement", "risk_statement", "category", "threat")},
                actors=[{key: actor.get(key) for key in ("name", "role")} for actor in content.get("actors") or []],
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


_SUMMARY_RUN = ("scenario_id", "session_id", "asset_id", "source", "title", "risk_level", "job.epoch")
_SUMMARY_STATE = ("job.waiting", "status", "accepted_version", "decision", "created_at", "updated_at")


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

    RECORD_FIELDS: ClassVar[dict[str, int]] = dict.fromkeys((*_SUMMARY_RUN, *_SUMMARY_STATE), 1)

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
