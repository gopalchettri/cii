"""What the API takes and shows for a run: its requests, status board, scenarios in TSG v1's results format
and review bodies (data shapes only; domain/scenario/results.py builds them)."""

from datetime import datetime
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from app.core.constants import (
    AbandonReason,
    ActionStatus,
    AiOutage,
    ControlMatchStatus,
    Generation,
    GroundingStatus,
    LibraryOutcome,
    Limits,
    PlanStage,
    PromotionOutcome,
    Review,
    ReviewFlag,
    ReviewMessage,
    RunKind,
    RunOverall,
    ScenarioStatus,
    ScopeType,
    SessionMessage,
    SessionState,
    StageState,
    Status,
    Step,
    TargetProblem,
    ThreatSource,
    ValidationStatus,
)
from app.models.external_intelligence.evidence_view import EvidenceView
from app.models.jobs.views import RetryNotice
from app.models.scenario.controls import ControlView

#: A SQL Server INT id: a number above 2,147,483,647 is refused here (422), not inside the procedure (500).
SqlId = Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)]


class StartRunRequest(BaseModel):
    """Body of POST /v1/sessions: one asset and its supporting systems. An unknown field is refused (422)."""

    # populate_by_name: code and tests build the model with the attribute name; the wire name is the alias.
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    #: Where these fields sit in the request body, for a refusal that names one.
    FIELD_PREFIX: ClassVar[str] = "body"

    asset_id: SqlId
    supporting_system_ids: list[SqlId] = Field(validation_alias="supporting_system_id")
    service_id: SqlId | None = None
    sector_id: SqlId | None = None
    subsector_id: SqlId | None = None

    @field_validator("supporting_system_ids", mode="before")
    @classmethod
    def accept_a_single_id(cls, value: object) -> object:
        """One id stands for a list of one."""
        return [value] if isinstance(value, int) else value

    @field_validator("supporting_system_ids")
    @classmethod
    def check_supporting_systems(cls, system_ids: list[int]) -> list[int]:
        """At least one, each once, and at most Generation.MAX_SUPPORTING_SYSTEMS (0 = no upper limit)."""
        if not system_ids:
            raise ValueError(SessionMessage.SYSTEMS_REQUIRED)
        if len(set(system_ids)) != len(system_ids):
            raise ValueError(SessionMessage.SYSTEMS_REPEATED)
        limit = Generation.MAX_SUPPORTING_SYSTEMS
        if limit and len(system_ids) > limit:
            raise ValueError(SessionMessage.TOO_MANY_SYSTEMS.format(limit=limit))
        return system_ids


class SessionStatus(BaseModel):
    """A run's state as stored, read in one projected read: the run checks and the status board read it."""

    session_id: str
    entity_id: int
    asset_id: int
    status: Status
    step: Step | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    last_action: dict[str, Any] | None = None
    error: dict[str, str] | None = None  # {code, message} once the run has failed
    updated_at: datetime
    kind: RunKind = RunKind.GENERATED
    user_id: str | None = None
    asset_name: str | None = None
    attempts: int = 0  # the job's tries so far: 0 = its stage has not started yet
    retry: dict[str, Any] | None = None  # the outage its stage waits out: RetryNotice's fields but the stage
    timings: dict[str, float] = Field(default_factory=dict)  # threats_s, scenarios_s, controls_s
    last_next_set: dict[str, Any] | None = None  # {outcome, requested, delivered}
    last_regen: dict[str, Any] | None = None  # {outcome, requested, replaced}
    cancelled: dict[str, Any] | None = None  # {at, user_id, client_id}: its owner stopped it
    epoch: int = 0  # its job's epoch: a next set or regenerate queues only while it is unchanged
    controls_retry: dict[str, Any] | None = None  # the outage its controls delivery waits out, as `retry`


def session_status_from_record(record: dict[str, Any]) -> SessionStatus:
    """The status of a tsg_sessions record read with SESSION_STATUS_FIELDS."""
    counts, job = record.get("counts") or {}, record.get("job") or {}
    step = record.get("step")
    # A done run still mapping its controls reads `controls` ("card first, controls later").
    if record["status"] == Status.DONE and counts.get("controls_waiting", 0) > 0:
        step = Step.CONTROLS
    return SessionStatus(
        session_id=record["_id"],
        entity_id=record["entity_id"],
        asset_id=record["asset_id"],
        status=record["status"],
        step=step,
        counts=counts,
        last_action=record.get("last_action"),
        error=job.get("error"),
        updated_at=record["updated_at"],
        kind=record.get("kind") or RunKind.GENERATED,
        user_id=record.get("user_id"),
        asset_name=((record.get("context") or {}).get("asset") or {}).get("name"),
        attempts=job.get("attempts") or 0,
        retry=job.get("retry"),
        timings=record.get("timings") or {},
        last_next_set=record.get("last_next_set"),
        last_regen=record.get("last_regen"),
        cancelled=record.get("cancelled"),
        epoch=job.get("epoch") or 0,
        controls_retry=(record.get("controls_delivery") or {}).get("retry"),
    )


# Review requests and responses.


def _check_ids_unique(scenario_ids: list[str]) -> list[str]:
    """Each scenario id once."""
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError(ReviewMessage.IDS_REPEATED)
    return scenario_ids


#: 1 to Review.MAX_IDS_PER_CALL scenario ids, each once and bounded in length (422 otherwise).
ScenarioIds = Annotated[
    list[Annotated[str, Field(min_length=1, max_length=Review.MAX_ID_CHARS)]],
    Field(min_length=1, max_length=Review.MAX_IDS_PER_CALL),
    AfterValidator(_check_ids_unique),
]


_EXAMPLE_IDS: list[JsonValue] = ["0c5dc06d-267d-5bb3-b9d3-1e027e1828e3"]


def _refused(value: Any, field: str, message: str = "") -> ValidationError:
    """A 422 on one accept body field: `message`, or pydantic's own "Field required" without one."""
    error = PydanticCustomError("accept_body", message) if message else "missing"
    return ValidationError.from_exception_data(
        "AcceptRequest", [InitErrorDetails(type=error, loc=(field,), input=value)]
    )


#: Swagger's named examples for accept, TSG v1's `mode` body first (the format the platform sends).
ACCEPT_REQUEST_EXAMPLES: dict[str, dict[str, Any]] = {
    "v1_subset": {"summary": "Accept some (v1)", "value": {"mode": "subset", "scenario_ids": _EXAMPLE_IDS}},
    "v1_all": {"summary": "Accept all (v1)", "value": {"mode": "all"}},
    "v1_replace": {
        "summary": "Accept a newer version in place of the accepted one (v1)",
        "value": {"mode": "subset", "scenario_ids": _EXAMPLE_IDS, "replace_accepted": True},
    },
    "v1_none": {"summary": "Accept nothing (v1)", "value": {"mode": "none"}},
    "v2_subset": {"summary": "Accept some (v2, also accepted)", "value": {"scenario_ids": _EXAMPLE_IDS}},
    "v2_all": {"summary": "Accept all (v2, also accepted)", "value": {"scenario_ids": "all"}},
}


class AcceptRequest(BaseModel):
    """Body of accept: TSG v1's `mode` body, or the v2 body (`scenario_ids` alone); an unknown field: 422."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [example["value"] for example in ACCEPT_REQUEST_EXAMPLES.values()]},
    )

    mode: Literal["all", "subset", "none"] | None = Field(
        default=None,
        description="all: accept every scenario; subset: accept the scenario_ids; none: accept nothing. "
        "Leave it out to send the v2 body (scenario_ids alone).",
    )
    scenario_ids: ScenarioIds | Literal["all"] | None = Field(
        default=None,
        description="With mode subset: the ids to accept; left out with mode all or none. "
        'Without mode (the v2 body): required, a list or "all".',
    )
    replace_accepted: bool = False

    @model_validator(mode="after")
    def read_the_v1_mode(self) -> Self:
        """v1's rules when `mode` is sent, then the v2 body: all → scenario_ids "all", none → no ids."""
        if self.mode is None:
            if "mode" in self.model_fields_set:
                raise _refused(None, "mode", ReviewMessage.MODE_VALUES)
            if self.scenario_ids is None:
                raise _refused(None, "scenario_ids")
            return self
        if self.mode == "subset":
            if not isinstance(self.scenario_ids, list):
                raise _refused(self.scenario_ids, "scenario_ids", ReviewMessage.SUBSET_NEEDS_IDS)
            return self
        if self.scenario_ids is not None:
            only_with_subset = ReviewMessage.ONLY_WITH_SUBSET.format(field="scenario_ids")
            raise _refused(self.scenario_ids, "scenario_ids", only_with_subset)
        if self.replace_accepted:
            only_with_subset = ReviewMessage.ONLY_WITH_SUBSET.format(field="replace_accepted")
            raise _refused(True, "replace_accepted", only_with_subset)
        if self.mode == "all":
            self.scenario_ids = "all"
        return self


class ScenarioIdsRequest(BaseModel):
    """Body of reject and regenerate: scenario ids only (no "all")."""

    model_config = ConfigDict(extra="forbid")

    scenario_ids: ScenarioIds


class TargetSkipped(BaseModel):
    scenario_id: str
    reason: TargetProblem


class AcceptResult(BaseModel):
    accepted: list[str]  # accepted now or before (a repeat lists them again)
    replaced: list[str]  # other versions sent back to pending by replace_accepted
    skipped: list[TargetSkipped]
    controls_pending: list[str]  # accepted, their controls still being mapped


class RejectResult(BaseModel):
    rejected: list[str]  # rejected now or before
    skipped: list[TargetSkipped]


class RunActionStarted(BaseModel):
    """202 for a next set or regenerate: follow GET /v1/sessions/{session_id} until its epoch shows."""

    session_id: str
    user_id: str | None  # the run's owner (not the caller)
    status: ActionStatus
    epoch: int


class PromotedThreat(BaseModel):
    threat: str
    threat_type: str
    threat_type_id: int | None  # None when nothing was written (curator_rejected)
    threat_catalogue_id: int | None
    outcome: PromotionOutcome


class PromotionResult(BaseModel):
    scenario_id: str
    results: list[PromotedThreat]


# The run's status board.


class ScenarioCount(BaseModel):
    total: int | None  # attack paths planned; None until the threats are found
    served: int  # scenarios written so far (each path's current version)
    remaining: int | None  # paths still to write, set by set
    complete: bool  # nothing is left to write
    pending_review: int
    accepted: int
    rejected: int


class StageTimings(BaseModel):
    """Seconds per stage, once it is complete (scenarios and controls: the last set's or regenerate's)."""

    threats: float | None
    scenarios: float | None
    controls: float | None


class Progress(BaseModel):
    threats: StageState
    scenarios: StageState
    controls: StageState
    overall: RunOverall
    timings: StageTimings
    error_message: dict[str, str]  # {} when all is well; else {stage: why}
    error_reason: AiOutage | None = None  # the run failed as the AI was down, unreachable, busy, timed out
    retrying: RetryNotice | None = None  # a stage waiting to try again after an outage; only while active
    last_next_set: dict[str, Any] | None
    last_regen: dict[str, Any] | None
    scenario_count: ScenarioCount


class RunError(BaseModel):
    """Why a run failed: its job's error code and message, and the AI outage that failed it, or why its job
    was given up (job_abandoned)."""

    code: str
    message: str
    # ai_down, ai_unreachable, ai_busy, ai_timed_out; job_abandoned: abandoned, never_started; else None.
    reason: AiOutage | AbandonReason | None = None


class RunBoard(BaseModel):
    session_id: str
    entity_id: int
    asset_id: int
    asset_name: str | None
    user_id: str | None
    session_status: SessionState
    progress: Progress
    updated_at: datetime
    error: RunError | None = None  # only once the run has failed


# A scenario in TSG v1's results format.


class SystemInvolved(BaseModel):
    """One supporting system of the asset on a scenario: every system is listed, applicable or not."""

    supporting_system_id: int
    supporting_system: str
    is_entry_point: bool
    justification: str = ""  # the writer's one sentence: why it applies, or why not
    is_applicable: bool = True  # the scenario's route goes through it


class ScenarioText(BaseModel):
    """v1's `scenario` object, then v2's own parts."""

    threat_category: str | None
    contributing_categories: list[str]
    threat_type: str | None
    threat_name: str | None
    supporting_systems_involved: list[SystemInvolved]
    scenario_title: str | None
    scenario_statement: str | None  # the writer's statement alone
    risk_statement: str | None
    assumptions: list[str]
    # STANDALONE: no link between systems claimed; ASSUMED: it relies on a link the platform does not record.
    route_status: str | None
    also_applies: list[str]  # other threats of the same kind of attack on the same system, strongest first


class ThreatBlock(BaseModel):
    threat_id: str | None  # the plan's key: "lib:<catalogue id>" or "ai:<name>"
    threat_category: str | None
    threat_category_id: int | None
    threat_type: str | None
    threat_name: str | None
    threat_type_id: int | None
    library_threat_type: str | None
    library_threat_name: str | None  # None for a threat the library does not hold
    grounding_status: GroundingStatus | None  # v1's verified / unverified
    threat_catalogue_id: int | None
    is_threat_type_ai_generated: bool  # never: the AI's threats are of library types
    is_threat_ai_generated: bool | None
    grounding_score: float | None  # the relevance check's confidence, 0-100
    score: float | None
    scope_rank: int | None  # the path's rank in the plan, 1 = most relevant


class ActorView(BaseModel):
    actor_id: int | None
    actor_name: str | None
    role: str | None  # acting
    closest_match: bool  # no actor is linked to the threat's type: the nearest library actor acts
    selection: str | None = None  # the acting attacker only: how it was chosen (chosen, balanced ...)
    selection_reason: str | None = None


class ScopeView(BaseModel):
    scope_key: str  # "A", or "A+<system id>+..." for the systems the scenario goes through
    scope_type: ScopeType
    supporting_system_ids: list[int]
    evidence: list[str]  # always []: kept so the response keeps its shape; why_applies is never shown


class LibraryEntry(BaseModel):
    name: str
    status: LibraryOutcome


class LibraryView(BaseModel):
    """A hand-written card's threat and type as the library holds them, and v1's sentence when it is news."""

    threat: LibraryEntry
    threat_type: LibraryEntry
    message: str | None


class ScenarioView(BaseModel):
    """A scenario: v1's fields in v1's order under v1's names, then v2's own."""

    scenario_id: str
    scenario: ScenarioText | None  # None on a failure card: its reason is in validation_errors
    threat: ThreatBlock
    actors: list[ActorView]
    controls: list[ControlView]
    accepted: bool
    # Another accepted version of this path: accepting this one replaces it (accept with replace_accepted).
    replaces_accepted_version: str | None = None
    accepted_by: str | None
    accepted_at: datetime | None
    rejected_by: str | None
    rejected_at: datetime | None
    validation_status: ValidationStatus
    validation_errors: list[str]  # warnings (never blocking an accept); on a failure card, its reason
    validation_notes: list[str]  # the plan check's words: information only
    generation_epoch: int | None  # the run's write job that wrote it
    scenario_number: int  # v1's name for the version: 1, then +1 per regenerate
    gen_started_at: datetime | None
    gen_finished_at: datetime | None
    gen_seconds: float | None
    scenario_source: RunKind
    library: LibraryView | None  # a hand-written card only: where its threat stands in the threat library
    controls_unavailable: bool  # never: a scenario carries its controls
    controls_mapped: bool
    controls_mapping_exhausted: bool  # the controls job gave up: a regenerate tries again
    controls_mapping_exhaustion_reason: str | None
    replaced_scenarios: list["ScenarioView"] = Field(default_factory=list)  # older versions, newest first
    scope: ScopeView | None
    actor: str | None  # the acting attacker's name
    threat_source: ThreatSource | None
    threat_type_source: ThreatSource | None
    review_flags: list[ReviewFlag]
    control_match_status: ControlMatchStatus | None
    session_id: str
    version: int
    status: ScenarioStatus  # done, or failed: a failure card says why in `failure`
    failure: dict[str, Any] | None
    regenerate_error: dict[str, Any] | None  # why the last regenerate kept this version
    created_at: datetime
    controls_status: Status | None  # queued, running, done, failed or cancelled; None on a failure card
    # Why its controls wait or failed: {code, message} and, for an AI outage, its reason (ai_down, ...).
    controls_error: dict[str, Any] | None = None
    replaced_by: str | None  # the newer version, when this one was regenerated
    # An evidence story only: source-documented (or inferred), the evidence its [n] cite, the search.
    evidence_mode: str | None = None
    evidence: list[EvidenceView] = Field(default_factory=list)
    evidence_search: dict[str, Any] | None = None


class ScenarioList(BaseModel):
    scenarios: list[ScenarioView]
    total: int  # every match, for paging (offset + limit)


# How a run's plan was made.


class PlanDrop(BaseModel):
    """One candidate that left the plan: which threat, as which kind (None: every kind), where and why."""

    threat_key: str  # "lib:<id>" or "ai:<name>"
    threat_name: str
    kind: str | None
    stage: PlanStage
    reason: str  # a CandidateRejection, PlanLoss or AttackerCheck value
    detail: str  # what the gate said it needs, its reason, the threat it merged into, the held scenario...


class PlanCounts(BaseModel):
    """How many candidates entered and left each stage, in planning order (a slot: one threat, one kind)."""

    library_threats: int  # threats in the library
    type_fits_no_place: int  # threats whose asset type fits neither the asset nor a chosen system
    no_linked_actor: int  # threats whose type links no attacker
    gate_asked: int  # slots sent to the relevance gate
    not_judged: int  # slots whose gate batch was skipped
    not_relevant: int
    needs_unrecorded: int  # slots needing something no recorded fact mentions
    asset_type_mismatch: int  # slots on places their asset type does not fit
    needs_unrecorded_elsewhere: int  # slots of a threat that needs something under another kind
    gate_accepted: int  # slots kept after the gate and code's checks
    ai_threats: int  # gap-fill threats added
    gap_fill_lost: int  # gap-fill proposals not kept (a library repeat, no type, not relevant...)
    merged: int  # AI threats folded into a library or earlier AI threat
    unfit_after_merge: int  # slots a merge brought onto places their type does not fit
    no_attacker: int  # threats with no acting attacker
    threats: int  # threats planned
    paths: int  # asset-level scenarios found: one per threat per kind
    already_held: int  # 0 since D15 (other sessions never take a path away); kept for the v1 format
    not_selected: int  # left out by TOTAL_SCENARIO_COUNT
    selected: int
    first_set: int  # written first; the rest on "Next set"


class GivenUpPath(BaseModel):
    """A planned path the writer gave up, and why."""

    path_id: str
    threat_key: str
    kind: str
    rank: int
    reason: str | None  # the blocker or failure that gave it up
    repeats: str | None  # the held scenario it repeats, when that is why
    replaced_by: str | None  # the spare path written in its place


class WriteOutcomes(BaseModel):
    """What became of the planned paths so far."""

    served: int
    still_to_write: int
    given_up: int
    replaced: int  # given up and replaced by a spare
    given_up_paths: list[GivenUpPath]


class PlanTraceView(BaseModel):
    """GET /v1/sessions/{id}/plan-trace: how many candidates each planning stage took in and let out, each
    candidate left out with its reason, and what became of the planned paths."""

    session_id: str
    counts: PlanCounts
    landscape_cut: bool  # facts were shortened to fit the AI's prompt (every system kept its name)
    drops: list[PlanDrop]  # the most telling first, at most PlanTraceLimits.MAX_DROPS
    drops_total: int
    # The planned paths by the system each gets in through, in turn order, and by the systems each covers;
    # by name ({} for a plan made before paths took turns).
    turns: dict[str, int] = Field(default_factory=dict)
    groups: dict[str, int] = Field(default_factory=dict)
    writing: WriteOutcomes


class RunResults(BaseModel):
    """GET /v1/sessions/{id}/results: the run, its progress, then its scenarios."""

    session_id: str
    entity_id: int
    asset_id: int
    asset_name: str | None
    user_id: str | None
    progress: Progress
    error: RunError | None = None  # as the run's status shows it: only once the run has failed
    scenarios: list[ScenarioView]
    total: int  # every match, for paging (offset + limit)
