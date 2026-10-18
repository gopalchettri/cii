"""What the API takes and shows for a run: its requests, status board, scenarios in TSG v1's results format,
review bodies and coverage. Built from stored records alone: no database call here."""

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, ClassVar, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.core.constants import (
    CONTROLS_EXHAUSTED,
    ROUTE_WORDS,
    SCOPE_ASSET_KEY,
    STRIDE_DEFINITIONS,
    ActionStatus,
    BoardMessage,
    ControlMatch,
    ControlMatchStatus,
    CoverageGap,
    Decision,
    FindingSeverity,
    Generation,
    GroundingStatus,
    LibraryBanner,
    LibraryOutcome,
    LibraryStatus,
    Limits,
    PromotionOutcome,
    Review,
    ReviewFlag,
    ReviewMessage,
    Route,
    RunActionKind,
    RunActionOutcome,
    RunKind,
    RunOverall,
    ScenarioDisplay,
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
from app.models.controls import ControlView, control_view
from app.models.external_intelligence.evidence_view import EvidenceView, cited_evidence
from app.models.scenario.plan import attacker_unsupported

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
    timings: dict[str, float] = Field(default_factory=dict)  # threats_s, scenarios_s, controls_s
    last_next_set: dict[str, Any] | None = None  # {outcome, requested, delivered}
    last_regen: dict[str, Any] | None = None  # {outcome, requested, replaced}
    not_assessed: list[str] = Field(default_factory=list)  # categories the plan could not assess
    cancelled: dict[str, Any] | None = None  # {at, user_id, client_id}: its owner stopped it

    #: The session fields this body reads: never the plan's threats and paths, nor the context's facts.
    RECORD_FIELDS: ClassVar[dict[str, int]] = {
        "entity_id": 1,
        "asset_id": 1,
        "status": 1,
        "step": 1,
        "counts": 1,
        "last_action": 1,
        "job.error": 1,
        "job.attempts": 1,
        "updated_at": 1,
        "kind": 1,
        "user_id": 1,
        "context.asset.name": 1,
        "timings": 1,
        "last_next_set": 1,
        "last_regen": 1,
        "plan.not_assessed": 1,
        "cancelled": 1,
    }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "SessionStatus":
        """The status of a session record read with RECORD_FIELDS."""
        counts, job = record.get("counts") or {}, record.get("job") or {}
        step = record.get("step")
        # A done run still mapping its controls reads `controls` ("card first, controls later").
        if record["status"] == Status.DONE and counts.get("controls_waiting", 0) > 0:
            step = Step.CONTROLS
        return cls(
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
            timings=record.get("timings") or {},
            last_next_set=record.get("last_next_set"),
            last_regen=record.get("last_regen"),
            not_assessed=(record.get("plan") or {}).get("not_assessed") or [],
            cancelled=record.get("cancelled"),
        )


def running_action(kind: RunActionKind, started_at: datetime) -> dict[str, Any]:
    """A run's `last_action` as an action starts: its kind, still running, and when it started."""
    return {"kind": kind, "outcome": RunActionOutcome.RUNNING, "reason": None, "started_at": started_at}


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


class AcceptRequest(BaseModel):
    """Body of accept. An unknown field is refused (422): a misspelt `replace_acepted` must not pass."""

    model_config = ConfigDict(extra="forbid")

    scenario_ids: ScenarioIds | Literal["all"]
    replace_accepted: bool = False


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
    last_next_set: dict[str, Any] | None
    last_regen: dict[str, Any] | None
    scenario_count: ScenarioCount


class RunBoard(BaseModel):
    session_id: str
    entity_id: int
    asset_id: int
    asset_name: str | None
    user_id: str | None
    session_status: SessionState
    progress: Progress
    updated_at: datetime


_SESSION_STATE = {
    Status.QUEUED: SessionState.ACTIVE,
    Status.RUNNING: SessionState.ACTIVE,
    Status.DONE: SessionState.COMPLETED,
    Status.FAILED: SessionState.FAILED,
    Status.CANCELLED: SessionState.CANCELLED,
}
#: The stage the run's job is in: a queued job counts as running (its batch hand-overs queue it each time).
_STAGE_STATE = {
    Status.QUEUED: StageState.RUNNING,
    Status.RUNNING: StageState.RUNNING,
    Status.DONE: StageState.COMPLETE,
    Status.FAILED: StageState.ERROR,
    Status.CANCELLED: StageState.CANCELLED,
}


def build_board(run: SessionStatus) -> RunBoard:
    """The status body every caller sees: each stage, what to do now, times, errors and counts."""
    threats, scenarios = _job_stages(run)
    controls = _controls_stage(run, scenarios)
    progress = Progress(
        threats=threats,
        scenarios=scenarios,
        controls=controls,
        overall=_overall_state(run, threats, controls),
        timings=StageTimings(
            threats=_stage_seconds(run, "threats_s", threats),
            scenarios=_stage_seconds(run, "scenarios_s", scenarios),
            controls=_stage_seconds(run, "controls_s", controls),
        ),
        error_message=_stage_errors(run, controls),
        last_next_set=_action_summary(run, RunActionKind.NEXT_SET, run.last_next_set),
        last_regen=_action_summary(run, RunActionKind.REGENERATE, run.last_regen),
        scenario_count=_scenario_count(run, threats),
    )
    return RunBoard(
        session_id=run.session_id,
        entity_id=run.entity_id,
        asset_id=run.asset_id,
        asset_name=run.asset_name,
        user_id=run.user_id,
        session_status=_SESSION_STATE[run.status],
        progress=progress,
        updated_at=run.updated_at,
    )


def _job_stages(run: SessionStatus) -> tuple[StageState, StageState]:
    """(threats, scenarios): the job is in one of them; threats are PENDING before their first try only."""
    if run.step != Step.THREATS:  # scenarios, or controls (read while a done run maps them)
        return StageState.COMPLETE, _STAGE_STATE[run.status]
    if run.status == Status.QUEUED and run.attempts == 0:
        return StageState.PENDING, StageState.PENDING
    return _STAGE_STATE[run.status], StageState.PENDING


def _controls_stage(run: SessionStatus, scenarios: StageState) -> StageState:
    """RUNNING while controls are waiting or scenarios are being written; ERROR when a mapping failed."""
    counts = run.counts
    if counts.get("controls_waiting", 0):
        return StageState.RUNNING
    if not counts.get("written", 0):
        return StageState.COMPLETE if scenarios == StageState.COMPLETE else StageState.PENDING
    if scenarios == StageState.RUNNING:
        return StageState.RUNNING
    if counts.get("controls_failed", 0):
        return StageState.ERROR
    return StageState.CANCELLED if counts.get("controls_cancelled", 0) else StageState.COMPLETE


def _overall_state(run: SessionStatus, threats: StageState, controls: StageState) -> RunOverall:
    """What the reviewer does now: wait, review what is written, ask for the next set, or nothing."""
    session = _SESSION_STATE[run.status]
    if session == SessionState.FAILED:
        return RunOverall.ERROR
    if session == SessionState.CANCELLED:
        return RunOverall.CANCELLED
    if threats == StageState.PENDING:
        return RunOverall.PENDING
    if session == SessionState.ACTIVE:
        return RunOverall.IN_PROGRESS
    if run.counts.get("pending", 0):
        return RunOverall.AWAITING_REVIEW
    if run.counts.get("remaining", 0):
        return RunOverall.AWAITING_NEXT_SET
    return RunOverall.IN_PROGRESS if controls == StageState.RUNNING else RunOverall.COMPLETE


def _action_summary(
    run: SessionStatus, kind: RunActionKind, summary: dict[str, Any] | None
) -> dict[str, Any] | None:
    """The last next set or regenerate, with the outcome of the run's current action when it is that one."""
    action = run.last_action or {}
    if summary is None:
        return None
    if action.get("kind") == kind:
        return summary | {"outcome": action.get("outcome")}
    # Another action started: one still reading running never got its finish write, so its job failed.
    if summary.get("outcome") == RunActionOutcome.RUNNING:
        return summary | {"outcome": RunActionOutcome.FAILED}
    return summary


def _stage_seconds(run: SessionStatus, key: str, state: StageState) -> float | None:
    """A stage's seconds once it is complete, to 0.1 s (a float sum of rounded parts shows long tails)."""
    seconds = run.timings.get(key)
    return round(seconds, 1) if seconds is not None and state == StageState.COMPLETE else None


def _stage_errors(run: SessionStatus, controls: StageState) -> dict[str, str]:
    """Why a stage failed or is partial, by stage."""
    messages: dict[str, str] = {}
    if run.status == Status.FAILED and run.error:
        messages[str(run.step)] = run.error.get("message") or run.error.get("code") or ""
    if run.not_assessed:
        categories = ", ".join(run.not_assessed)
        messages.setdefault(str(Step.THREATS), BoardMessage.NOT_ASSESSED.format(categories=categories))
    if abandoned := run.counts.get("abandoned", 0):
        abandoned_text = BoardMessage.ABANDONED.format(abandoned=abandoned, session_id=run.session_id)
        messages.setdefault(str(Step.SCENARIOS), abandoned_text)
    if controls == StageState.ERROR:
        failed = run.counts["controls_failed"]
        manual = run.kind == RunKind.MANUAL  # only its plan job maps it, never the background
        unmatched = BoardMessage.CONTROLS_FAILED_MANUAL if manual else BoardMessage.CONTROLS_FAILED
        messages[str(Step.CONTROLS)] = unmatched.format(failed=failed)
    if run.cancelled:
        stage = str(run.step) if run.status == Status.CANCELLED else str(Step.CONTROLS)
        messages.setdefault(stage, _stopped_by(run.cancelled))
    if controls == StageState.CANCELLED:
        cancelled = BoardMessage.CONTROLS_CANCELLED.format(cancelled=run.counts["controls_cancelled"])
        messages.setdefault(str(Step.CONTROLS), cancelled)
    return messages


def _stopped_by(cancelled: dict[str, Any]) -> str:
    """Who cancelled the run and when, to the second, in UTC."""
    at = cancelled.get("at")
    when = at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(at, datetime) else str(at)
    return BoardMessage.CANCELLED.format(user=cancelled.get("user_id"), at=when)


def _scenario_count(run: SessionStatus, threats: StageState) -> ScenarioCount:
    """The scenario numbers; a hand-written run plans nothing, so its one scenario is its total."""
    counts = run.counts
    served = counts.get("written", 0)
    total: int | None = None
    if threats == StageState.COMPLETE:
        total = served if run.kind == RunKind.MANUAL else counts.get("planned", 0)
    remaining = None if total is None else counts.get("remaining", 0)
    return ScenarioCount(
        total=total,
        served=served,
        remaining=remaining,
        complete=remaining == 0,
        pending_review=counts.get("pending", 0),
        accepted=counts.get("accepted", 0),
        rejected=counts.get("rejected", 0),
    )


# A scenario in TSG v1's results format.

#: v1's words for where a hand-written threat stands (anything else: it is in the library).
_LIBRARY_OUTCOMES: Final[dict[str, LibraryOutcome]] = {
    LibraryStatus.PENDING: LibraryOutcome.INSERTED,
    LibraryStatus.CURATOR_REJECTED: LibraryOutcome.REJECTED_BY_CURATOR,
}


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
    scenario_statement: str | None  # the statement, then "Why this threat applies: ..."
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
    evidence: list[str]  # the writer's own why_applies; [] when none


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
    replaced_by: str | None  # the newer version, when this one was regenerated
    # An evidence story only: source-documented (or inferred), the evidence its [n] cite, the search.
    evidence_mode: str | None = None
    evidence: list[EvidenceView] = Field(default_factory=list)
    evidence_search: dict[str, Any] | None = None

    @classmethod
    def from_record(
        cls,
        record: dict[str, Any],
        accepted_elsewhere: str | None = None,
        older: list[dict[str, Any]] | None = None,
    ) -> "ScenarioView":
        """`accepted_elsewhere`: another accepted version of the path; `older`: its replaced versions."""
        content, controls = record.get("content") or {}, record.get("controls") or {}
        validation = _validation_fields(record)
        return cls(
            scenario_id=record["_id"],
            scenario=None if record["status"] == ScenarioStatus.FAILED else _scenario_text(content),
            threat=_threat_block(content),
            actors=[_actor_view(actor) for actor in content.get("actors") or []],
            controls=[control_view(item) for item in controls.get("items") or []],
            **_review_decision(record),
            replaces_accepted_version=accepted_elsewhere,
            **validation,
            scenario_source=record["source"],
            replaced_scenarios=[cls.from_record(version) for version in older or []],
            **_v1_fields(record, validation["validation_status"], bool(validation["validation_notes"])),
            session_id=record["session_id"],
            version=record["version"],
            status=record["status"],
            failure=record.get("failure"),
            regenerate_error=record.get("regenerate_error"),
            created_at=record["created_at"],
            controls_status=controls.get("status"),
            replaced_by=record.get("superseded_by"),
            evidence_mode=content.get("evidence_mode"),
            evidence=cited_evidence(content),
            evidence_search=content.get("intel_search"),
        )


class ScenarioList(BaseModel):
    scenarios: list[ScenarioView]
    total: int  # every match, for paging (offset + limit)


class RunResults(ScenarioList):
    """GET /v1/sessions/{id}/results: the run, its progress, then its scenarios."""

    session_id: str
    entity_id: int
    asset_id: int
    asset_name: str | None
    user_id: str | None
    progress: Progress
    coverage: dict[str, Any] | None = None  # each system and kind: its scenarios; why any has none


def _scenario_text(content: dict[str, Any]) -> ScenarioText:
    """What the scenario says, v1's route words included."""
    threat, route = content.get("threat") or {}, content.get("route") or {}
    statement, why = content.get("statement"), content.get("why_applies")
    shown = f"{statement}{ScenarioDisplay.WHY_APPLIES_JOIN}{why}" if statement and why else statement
    status = route.get("status")
    return ScenarioText(
        threat_category=content.get("category"),
        contributing_categories=content.get("contributing_categories") or [],
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        supporting_systems_involved=_systems_involved(content),
        scenario_title=content.get("title"),
        scenario_statement=shown,
        risk_statement=content.get("risk_statement"),
        assumptions=content.get("assumptions") or [],
        route_status=ROUTE_WORDS.get(str(status), str(status).upper()) if status else None,
        also_applies=content.get("also_applies") or [],
    )


def _systems_involved(content: dict[str, Any]) -> list[SystemInvolved]:
    """Every supporting system, applicable or not, with its reason; else the card's own systems."""
    if shown := content.get("system_applicability"):
        return [
            SystemInvolved(
                supporting_system_id=system["id"],
                supporting_system=system["name"],
                is_entry_point=bool(system.get("entry_point")),
                justification=system.get("reason") or "",
                is_applicable=bool(system.get("applicable")),
            )
            for system in shown
        ]
    return [
        SystemInvolved(
            supporting_system_id=system["id"],
            supporting_system=system["name"],
            is_entry_point=bool(system.get("entry_point")),
        )
        for system in content.get("systems") or []
    ]


def _grounding_status(threat: dict[str, Any]) -> GroundingStatus | None:
    """An active library threat is verified; an AI threat or one no curator approved yet is not."""
    if not threat:
        return None
    active = threat.get("library_status") in (None, LibraryStatus.ACTIVE)
    verified = threat.get("library_id") is not None and active
    return GroundingStatus.VERIFIED if verified else GroundingStatus.UNVERIFIED


def _threat_block(content: dict[str, Any]) -> ThreatBlock:
    """The threat as the library grounds it, with its own category."""
    threat, category = content.get("threat") or {}, content.get("category")
    library_id, confidence = threat.get("library_id"), threat.get("confidence")
    # The kind's id stands in for a threat stored without its category id only when the names match.
    name, own_id = threat.get("category") or category, threat.get("category_id")
    kinds_id = (
        content.get("category_id") if str(name or "").casefold() == str(category or "").casefold() else None
    )
    return ThreatBlock(
        threat_id=threat.get("key"),
        threat_category=name,
        threat_category_id=own_id if own_id is not None else kinds_id,
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        threat_type_id=threat.get("type_id"),
        library_threat_type=threat.get("type") if threat.get("type_id") is not None else None,
        library_threat_name=threat.get("name") if library_id is not None else None,
        grounding_status=_grounding_status(threat),
        threat_catalogue_id=library_id,
        is_threat_type_ai_generated=False,
        is_threat_ai_generated=threat.get("ai_generated"),
        grounding_score=confidence,
        score=confidence,
        scope_rank=threat.get("rank"),
    )


def _actor_view(actor: dict[str, Any]) -> ActorView:
    """One stored actor as the API shows it."""
    return ActorView(
        actor_id=actor.get("id"),
        actor_name=actor.get("name"),
        role=actor.get("role"),
        closest_match=bool(actor.get("closest")),
        selection=actor.get("selection"),
        selection_reason=actor.get("reason"),
    )


def _review_decision(record: dict[str, Any]) -> dict[str, Any]:
    """The decision as v1 showed it: accepted, and who decided which way, when."""
    decision, by, at = record.get("decision"), record.get("decided_by"), record.get("decided_at")
    accepted, rejected = decision == Decision.ACCEPTED, decision == Decision.REJECTED
    return {
        "accepted": accepted,
        "accepted_by": by if accepted else None,
        "accepted_at": at if accepted else None,
        "rejected_by": by if rejected else None,
        "rejected_at": at if rejected else None,
    }


def _validation_fields(record: dict[str, Any]) -> dict[str, Any]:
    """v1's validation fields: a failure card warns with its error; else the warnings and the notes."""
    findings, failure = record.get("findings") or [], record.get("failure")
    if record["status"] == ScenarioStatus.FAILED:
        reason = [str(failure["message"])] if failure else []
        status, errors = ValidationStatus.WARNING, reason
    else:
        warned = any(finding.get("severity") == FindingSeverity.WARNING for finding in findings)
        status = ValidationStatus.WARNING if warned else ValidationStatus.OK
        errors = _finding_messages(findings, FindingSeverity.WARNING)
    notes = _finding_messages(findings, FindingSeverity.NOTE)
    return {"validation_status": status, "validation_errors": errors, "validation_notes": notes}


def _finding_messages(findings: list[dict[str, Any]], severity: FindingSeverity) -> list[str]:
    """The messages of the findings of `severity`."""
    return [str(finding.get("message")) for finding in findings if finding.get("severity") == severity]


def _v1_fields(record: dict[str, Any], validation_status: ValidationStatus, notes: bool) -> dict[str, Any]:
    """v1's generation, library, controls, scope, source and flag fields; `notes`: the plan check kept one."""
    content, controls = record.get("content") or {}, record.get("controls") or {}
    threat = content.get("threat") or {}
    generated = record.get("source") != RunKind.MANUAL
    failed = record.get("status") == ScenarioStatus.FAILED
    match_status = _control_match_status(controls) if generated and not failed else None
    flags = _review_flags(threat, content, validation_status, notes, controls, match_status, generated)
    return {
        **_generation_fields(record),
        "scenario_number": record["version"],
        "library": None if generated else _library_view(threat),
        **_controls_flags(controls.get("status")),
        "scope": _scope_view(content) if generated else None,
        "actor": _acting_attacker_name(content, failed),
        "threat_source": _threat_source(threat, "library_id") if generated else None,
        "threat_type_source": _threat_source(threat, "type_id") if generated else None,
        "review_flags": flags,
        "control_match_status": match_status,
    }


def _control_match_status(controls: dict[str, Any]) -> ControlMatchStatus | None:
    """v1's summary of the controls: None when their mapping failed."""
    status = controls.get("status")
    if status == Status.FAILED:
        return None
    if status != Status.DONE:
        return ControlMatchStatus.PENDING
    matches = [item.get("match") for item in controls.get("items") or []]
    if not matches:
        return ControlMatchStatus.CONTROL_LIBRARY_GAP
    if ControlMatch.EXACT in matches or ControlMatch.GIVEN in matches:  # the author's own: no nearest offer
        return ControlMatchStatus.EXACT
    return ControlMatchStatus.NEAREST_ONLY


def _generation_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Which write job wrote it and when (None on a scenario saved without them)."""
    generation = record.get("generation") or {}
    started, finished = generation.get("started_at"), generation.get("finished_at")
    seconds = round((finished - started).total_seconds(), 2) if started and finished else None
    return {
        "generation_epoch": generation.get("epoch"),
        "gen_started_at": started,
        "gen_finished_at": finished,
        "gen_seconds": seconds if seconds is None or seconds >= 0 else None,
    }


def _controls_flags(status: str | None) -> dict[str, Any]:
    """v1's four controls flags for v2's one controls status."""
    exhausted = status == Status.FAILED
    return {
        "controls_unavailable": False,
        "controls_mapped": status == Status.DONE,
        "controls_mapping_exhausted": exhausted,
        "controls_mapping_exhaustion_reason": CONTROLS_EXHAUSTED if exhausted else None,
    }


def _scope_view(content: dict[str, Any]) -> ScopeView:
    """The asset, one system or a combination the scenario goes through."""
    ids = sorted(system["id"] for system in content.get("systems") or [])
    kind = ScopeType.ASSET if not ids else ScopeType.SYSTEM if len(ids) == 1 else ScopeType.COMBINATION
    why = content.get("why_applies")
    return ScopeView(
        scope_key="+".join([SCOPE_ASSET_KEY, *map(str, ids)]),
        scope_type=kind,
        supporting_system_ids=ids,
        evidence=[why] if why else [],
    )


def _acting_attacker_name(content: dict[str, Any], failed: bool) -> str | None:
    """The acting attacker's name; none on a failure card whose attacker no check supports."""
    acting = next((a for a in content.get("actors") or [] if a.get("role") == "acting"), None)
    if acting is None or (failed and attacker_unsupported(acting.get("selection"), acting)):
        return None
    return acting.get("name")


def _threat_source(threat: dict[str, Any], library_key: str) -> ThreatSource | None:
    """LIBRARY when the threat carries `library_key`, else AI_PROPOSED."""
    if not threat:
        return None
    return ThreatSource.LIBRARY if threat.get(library_key) is not None else ThreatSource.AI_PROPOSED


def _review_flags(
    threat: dict[str, Any],
    content: dict[str, Any],
    validation_status: ValidationStatus,
    notes: bool,
    controls: dict[str, Any],
    match_status: ControlMatchStatus | None,
    generated: bool,
) -> list[ReviewFlag]:
    """v1's flags in v1's order; a hand-written card carries PLAN_CHECK alone."""
    plan_check = [ReviewFlag.PLAN_CHECK] if notes else []
    if not generated:
        return plan_check
    flags = []
    if threat and threat.get("type_id") is None:
        flags.append(ReviewFlag.AI_PROPOSED_TYPE)
    if threat and threat.get("library_id") is None:
        flags.append(ReviewFlag.AI_PROPOSED_THREAT)
    if (content.get("route") or {}).get("status") == Route.UNKNOWN:
        flags.append(ReviewFlag.ASSUMED_ROUTE)
    if validation_status == ValidationStatus.WARNING:
        flags.append(ReviewFlag.VALIDATION_EXCEPTION)
    flags += plan_check
    if any(item.get("match") == ControlMatch.NEAREST for item in controls.get("items") or []):
        flags.append(ReviewFlag.NEAREST_CONTROL)
    if match_status == ControlMatchStatus.CONTROL_LIBRARY_GAP:
        flags.append(ReviewFlag.CONTROL_LIBRARY_GAP)
    return flags


def _library_view(threat: dict[str, Any]) -> LibraryView | None:
    """Where a hand-written card's threat stands in the library; None when the card names no threat."""
    if not threat.get("name"):
        return None
    status = _LIBRARY_OUTCOMES.get(str(threat.get("library_status")), LibraryOutcome.EXISTING)
    kind = LibraryOutcome.EXISTING if threat.get("type_id") is not None else LibraryOutcome.NOT_PROPOSED
    message = None
    if status == LibraryOutcome.REJECTED_BY_CURATOR:
        message = LibraryBanner.REJECTED.format(name=threat["name"])
    elif status == LibraryOutcome.INSERTED:
        message = LibraryBanner.PROPOSED
    return LibraryView(
        threat=LibraryEntry(name=threat["name"], status=status),
        threat_type=LibraryEntry(name=threat.get("type") or "", status=kind),
        message=message,
    )


# A run's coverage: per supporting system and kind of attack, the finished paths and why any has none.
# Worked out from the plan on each read, never stored; a path counts once its scenario is served.

_PATH_FIELDS = (
    "path_id", "systems", "categories", "selected", "abandoned", "served", "abandoned_reason", "replaced_by",
)  # fmt: skip
#: What the results read of a run to work its coverage out: a few small fields per path.
COVERAGE_FIELDS: dict[str, int] = {
    "plan.target": 1,
    **{f"plan.paths.{field}": 1 for field in _PATH_FIELDS},
    "context.systems.id": 1,
    "context.systems.name": 1,
}
_PathTest = Callable[[dict[str, Any]], bool]


def run_coverage(record: dict[str, Any]) -> dict[str, Any] | None:
    """The run's coverage from its plan (`record` read with COVERAGE_FIELDS); None before a plan exists."""
    plan = record.get("plan") or {}
    if not plan.get("paths"):
        return None
    systems = {system["id"]: system["name"] for system in (record.get("context") or {}).get("systems") or []}
    return coverage_record(plan["paths"], systems, plan.get("target") or 0)


def coverage_record(paths: list[dict[str, Any]], systems: dict[int, str], limit: int) -> dict[str, Any]:
    """Coverage of `paths` over `systems` (name by id) and every kind; `limit`: the plan's scenario limit."""
    finished = sorted((path for path in paths if path.get("served")), key=lambda path: path["path_id"])
    by_system = [
        {"id": system_id, "name": name, **_finished_fitting(finished, _on_system(system_id))}
        for system_id, name in sorted(systems.items())
    ]
    kinds = {str(kind): _finished_fitting(finished, _of_kind(kind)) for kind in STRIDE_DEFINITIONS}
    gaps = [
        {"system": system["name"], "reason": _gap_reason(paths, _on_system(system["id"]))}
        for system in by_system
        if not system["finished"]
    ] + [
        {"kind": kind, "reason": _gap_reason(paths, _of_kind(kind))}
        for kind, covered in kinds.items()
        if not covered["finished"]
    ]
    return {
        "limit": limit,
        "candidates": len(paths),
        "selected": sum(bool(path.get("selected")) and not path.get("abandoned") for path in paths),
        "finished": len(finished),
        "asset_itself": sum(path.get("systems") == [] for path in finished),
        "systems": by_system,
        "kinds": kinds,
        "not_covered": gaps,
        "given_up": _given_up_paths(paths),
    }


def _on_system(system_id: int) -> _PathTest:
    """Whether a path goes through `system_id`."""
    return lambda path: system_id in (path.get("systems") or [])


def _of_kind(kind: str) -> _PathTest:
    """Whether a path's kind (its first category) is `kind`."""
    return lambda path: (path.get("categories") or [None])[0] == kind


def _finished_fitting(finished: list[dict[str, Any]], fits: _PathTest) -> dict[str, Any]:
    """The finished paths that fit: how many and their ids, one each, in id order."""
    ids = list(dict.fromkeys(path["path_id"] for path in finished if fits(path)))
    return {"finished": len(ids), "path_ids": ids}


def _gap_reason(paths: list[dict[str, Any]], fits: _PathTest) -> CoverageGap:
    """Why nothing finished covers it: no relevant threat, still to write, failed, or over the limit."""
    fitting = [path for path in paths if fits(path)]
    if not fitting:
        return CoverageGap.NO_RELEVANT_THREAT
    if any(path.get("selected") and not path.get("abandoned") for path in fitting):
        return CoverageGap.AWAITING_NEXT_SET
    if any(path.get("abandoned") for path in fitting):
        return CoverageGap.SCENARIOS_FAILED
    return CoverageGap.LIMIT_REACHED


def _given_up_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every path given up for good, its reason, and the reserve that took its place (None: none could)."""
    return [
        {
            "path_id": path["path_id"],
            "reason": path.get("abandoned_reason"),
            "replaced_by": path.get("replaced_by"),
        }
        for path in sorted(paths, key=lambda path: path["path_id"])
        if path.get("abandoned")
    ]


def explain_given_up(
    given_up: list[dict[str, Any]], cards: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Each given-up path with its threat's name and reason sentence from its newest card in `cards`."""
    return [_explain_given_up_path(entry, cards.get(entry["path_id"])) for entry in given_up]


def _explain_given_up_path(entry: dict[str, Any], card: dict[str, Any] | None) -> dict[str, Any]:
    """A failure card's message, else the blocked draft's finding of that code, else its first blocker."""
    threat = message = None
    if card is not None:
        threat = ((card.get("content") or {}).get("threat") or {}).get("name")
        blockers = [f for f in card.get("findings") or [] if f.get("severity") == FindingSeverity.BLOCKER]
        same = [finding for finding in blockers if finding.get("code") == entry["reason"]]
        message = (card.get("failure") or {}).get("message") or ((same or blockers or [{}])[0]).get("message")
    return {
        "path_id": entry["path_id"],
        "threat": threat,
        "reason": entry["reason"],
        "message": message,
        "replaced_by": entry["replaced_by"],
    }
