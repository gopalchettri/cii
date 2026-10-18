"""Builds the API answers for scenario sessions and scenarios: the status board, scenarios in TSG v1's results
format and the coverage, from stored records alone (no database call here)."""

from collections.abc import Callable
from datetime import datetime
from typing import Any, Final

from app.core.constants import (
    CONTROLS_EXHAUSTED,
    ROUTE_WORDS,
    SCOPE_ASSET_KEY,
    STRIDE_DEFINITIONS,
    BoardMessage,
    ControlMatch,
    ControlMatchStatus,
    CoverageGap,
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
    ScenarioDisplay,
    ScenarioStatus,
    ScopeType,
    SessionState,
    StageState,
    Status,
    Step,
    ThreatSource,
    ValidationStatus,
)
from app.domain.scenario.plan import attacker_unsupported
from app.models.controls import control_view
from app.models.external_intelligence.evidence_view import cited_evidence
from app.models.scenario.views import (
    ActorView,
    LibraryEntry,
    LibraryView,
    Progress,
    RunBoard,
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
        replaced_by=record.get("superseded_by"),
        evidence_mode=content.get("evidence_mode"),
        evidence=cited_evidence(content),
        evidence_search=content.get("intel_search"),
    )


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
