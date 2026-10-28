"""Builds the API answers for scenario sessions and scenarios: the status board and scenarios in TSG v1's
results format, from stored records alone (no database call here)."""

from datetime import datetime
from typing import Any, Final

from app.core.constants import (
    CONTROLS_EXHAUSTED,
    ROUTE_WORDS,
    SCOPE_ASSET_KEY,
    AbandonReason,
    AiOutage,
    BoardMessage,
    ControlMatch,
    ControlMatchStatus,
    Controls,
    Decision,
    FindingSeverity,
    GroundingStatus,
    LibraryBanner,
    LibraryOutcome,
    LibraryStatus,
    ReviewFlag,
    Route,
    RunActionKind,
    RunActionOutcome,
    RunKind,
    RunOverall,
    ScenarioStatus,
    ScopeType,
    SessionState,
    StageState,
    Status,
    Step,
    ThreatSource,
    ValidationStatus,
    Writing,
)
from app.domain.scenario.plan import attacker_unsupported
from app.models.external_intelligence.evidence_view import cited_evidence
from app.models.jobs.views import controls_retry_notice_of, retry_notice_of
from app.models.scenario.controls import control_view
from app.models.scenario.views import (
    ActorView,
    LibraryEntry,
    LibraryView,
    Progress,
    RunBoard,
    RunError,
    ScenarioCount,
    ScenarioText,
    ScenarioView,
    ScopeView,
    SessionStatus,
    StageTimings,
    SystemInvolved,
    ThreatBlock,
)

# The run's status board.

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
        error_reason=_failed_reason(run),
        retrying=retry_notice_of(run.status, run.retry, run.step)
        or controls_retry_notice_of(run.counts, run.controls_retry),
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
        error=_run_error(run),
    )


def _job_stages(run: SessionStatus) -> tuple[StageState, StageState]:
    """(threats, scenarios): the job is in one of them; threats are PENDING before their first try only."""
    if run.step != Step.THREATS:  # scenarios, or controls (read while a done run maps them)
        return StageState.COMPLETE, _STAGE_STATE[run.status]
    if run.status == Status.QUEUED and run.attempts == 0:
        return StageState.PENDING, StageState.PENDING
    return _STAGE_STATE[run.status], StageState.PENDING


def _failed_reason(run: SessionStatus) -> AiOutage | None:
    """Which AI outage failed the run; None for any other failure."""
    reason = (run.error or {}).get("reason") if run.status == Status.FAILED else None
    return AiOutage(reason) if reason and reason in AiOutage else None


def _run_error(run: SessionStatus) -> RunError | None:
    """The failed run's job error: code, message, and its AI outage or give-up reason; None unless the run
    failed."""
    if run.status != Status.FAILED or not run.error:
        return None
    error, stored = run.error, run.error.get("reason")
    given_up = AbandonReason(stored) if stored and stored in AbandonReason else None
    reason = _failed_reason(run) or given_up
    return RunError(code=error.get("code", ""), message=error.get("message", ""), reason=reason)


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
    """What the reviewer does now: wait, review what is written, ask for the next set, or nothing; a terminal
    value (error, complete, cancelled) only once no control is still being matched."""
    session = _SESSION_STATE[run.status]
    if session == SessionState.FAILED:
        return RunOverall.IN_PROGRESS if controls == StageState.RUNNING else RunOverall.ERROR
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
    if run.counts.get("outage_cards", 0):  # a regenerate can still write them
        return RunOverall.AWAITING_REVIEW
    if controls == StageState.RUNNING:
        return RunOverall.IN_PROGRESS
    # From the count, not the stage: a cancel leaves controls failed for good as they are, reading ERROR.
    return RunOverall.CANCELLED if run.counts.get("controls_cancelled", 0) else RunOverall.COMPLETE


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
    if abandoned := run.counts.get("abandoned", 0):
        messages.setdefault(str(Step.SCENARIOS), BoardMessage.ABANDONED.format(abandoned=abandoned))
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
        complete=remaining == 0 and not counts.get("outage_cards", 0),
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


def build_scenario_view(
    record: dict[str, Any],
    accepted_elsewhere: str | None = None,
    older: list[dict[str, Any]] | None = None,
) -> ScenarioView:
    """A stored scenario in v1's format; `accepted_elsewhere`: another accepted version of the path; `older`:
    its replaced versions."""
    content, controls = record.get("content") or {}, record.get("controls") or {}
    validation = _validation_fields(record)
    return ScenarioView(
        scenario_id=record["_id"],
        scenario=None if record["status"] == ScenarioStatus.FAILED else _scenario_text(content),
        threat=_threat_block(content),
        actors=[_actor_view(actor) for actor in content.get("actors") or []],
        controls=[control_view(item) for item in controls.get("items") or []],
        **_review_decision(record),
        replaces_accepted_version=accepted_elsewhere,
        **validation,
        scenario_source=record["source"],
        replaced_scenarios=[build_scenario_view(version) for version in older or []],
        **_v1_fields(record, validation["validation_status"], bool(validation["validation_notes"])),
        session_id=record["session_id"],
        version=record["version"],
        status=record["status"],
        failure=record.get("failure"),
        regenerate_error=record.get("regenerate_error"),
        created_at=record["created_at"],
        controls_status=controls.get("status"),
        controls_error=_controls_error(controls),
        replaced_by=record.get("superseded_by"),
        evidence_mode=content.get("evidence_mode"),
        evidence=cited_evidence(content),
        evidence_search=content.get("intel_search"),
    )


def _scenario_text(content: dict[str, Any]) -> ScenarioText:
    """What the scenario says, v1's route words included."""
    threat, route = content.get("threat") or {}, content.get("route") or {}
    status = route.get("status")
    return ScenarioText(
        threat_category=content.get("category"),
        contributing_categories=content.get("contributing_categories") or [],
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        supporting_systems_involved=_systems_involved(content),
        scenario_title=content.get("title"),
        scenario_statement=content.get("statement"),
        risk_statement=content.get("risk_statement"),
        assumptions=[_with_platform_note(text) for text in content.get("assumptions") or [] if text.strip()],
        route_status=ROUTE_WORDS.get(str(status), str(status).upper()) if status else None,
        also_applies=content.get("also_applies") or [],
    )


def _with_platform_note(assumption: str) -> str:
    """The assumption with code's platform note once; one already carrying it is shown as stored."""
    if Writing.PLATFORM_NOTE.removeprefix(" - ").casefold() in assumption.casefold():
        return assumption
    return assumption.rstrip(". ") + Writing.PLATFORM_NOTE


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
        **_controls_flags(controls),
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


def _controls_error(controls: dict[str, Any]) -> dict[str, Any] | None:
    """Why a card's controls wait to be tried again or failed; None while they run or once they are mapped."""
    return controls.get("error") if controls.get("status") in (Status.QUEUED, Status.FAILED) else None


def _controls_flags(controls: dict[str, Any]) -> dict[str, Any]:
    """v1's four controls flags for v2's controls: exhausted once failed with no attempt left."""
    status, attempts = controls.get("status"), controls.get("attempts")
    # As the sweep reads it (FAILED_WITH_ATTEMPTS_LEFT): a failure with attempts left is tried again.
    attempts_left = isinstance(attempts, int) and attempts < Controls.MAX_ATTEMPTS
    exhausted = status == Status.FAILED and not attempts_left
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
    return ScopeView(
        scope_key="+".join([SCOPE_ASSET_KEY, *map(str, ids)]),
        scope_type=kind,
        supporting_system_ids=ids,
        evidence=[],
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
