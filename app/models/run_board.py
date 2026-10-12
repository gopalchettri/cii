"""A run's status as every caller sees it (owner 2026-10-12): each stage in one word, what to do now, each
stage's time, why anything failed, the last next set and regenerate, and the scenario numbers. Built by one
pure function from the stored run (one read, never the plan's paths), so GET /v1/sessions/{id},
POST /v1/sessions and every session.updated event carry the same body."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.core.constants import (
    BoardMessage,
    RunActionKind,
    RunActionOutcome,
    RunKind,
    RunOverall,
    SessionState,
    StageState,
    Status,
    Step,
)
from app.models.scenarios import SessionStatus


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
    threats, scenarios = _job_stages(run)
    controls = _controls_stage(run, scenarios)
    progress = Progress(
        threats=threats,
        scenarios=scenarios,
        controls=controls,
        overall=_overall(run, threats, controls),
        timings=StageTimings(
            threats=_seconds(run, "threats_s", threats),
            scenarios=_seconds(run, "scenarios_s", scenarios),
            controls=_seconds(run, "controls_s", controls),
        ),
        error_message=_error_message(run, controls),
        last_next_set=_summary(run, RunActionKind.NEXT_SET, run.last_next_set),
        last_regen=_summary(run, RunActionKind.REGENERATE, run.last_regen),
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
    """(threats, scenarios): the run's job is in one of them; threats are PENDING before their first try
    only."""
    if run.step != Step.THREATS:  # scenarios, or controls (read while a done run maps them)
        return StageState.COMPLETE, _STAGE_STATE[run.status]
    if run.status == Status.QUEUED and run.attempts == 0:
        return StageState.PENDING, StageState.PENDING
    return _STAGE_STATE[run.status], StageState.PENDING


def _controls_stage(run: SessionStatus, scenarios: StageState) -> StageState:
    """RUNNING while any scenario waits for its controls or more are being written; PENDING before the first
    is written; ERROR when one's mapping failed (tried again later); else COMPLETE (nothing left to map)."""
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


def _overall(run: SessionStatus, threats: StageState, controls: StageState) -> RunOverall:
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


def _summary(
    run: SessionStatus, kind: RunActionKind, summary: dict[str, Any] | None
) -> dict[str, Any] | None:
    """The last next set or regenerate. While it is the run's current action, its outcome is the action's own
    (running, or failed: a job failure writes only last_action); once another action started, one still
    reading running never got its finish write, so its job failed."""
    action = run.last_action or {}
    if summary is None:
        return None
    if action.get("kind") == kind:
        return summary | {"outcome": action.get("outcome")}
    if summary.get("outcome") == RunActionOutcome.RUNNING:
        return summary | {"outcome": RunActionOutcome.FAILED}
    return summary


def _seconds(run: SessionStatus, key: str, state: StageState) -> float | None:
    """A stage's seconds once it is complete, to 0.1 s: controls_s adds many rounded parts, and a float sum
    shows as 1500.3599999999997."""
    seconds = run.timings.get(key)
    return round(seconds, 1) if seconds is not None and state == StageState.COMPLETE else None


def _error_message(run: SessionStatus, controls: StageState) -> dict[str, str]:
    """Why a stage failed or is partial, by stage: the failed job's own message, a category the plan could
    not assess, paths given up on, controls not matched yet."""
    messages: dict[str, str] = {}
    if run.status == Status.FAILED and run.error:
        messages[str(run.step)] = run.error.get("message") or run.error.get("code") or ""
    if run.not_assessed:
        categories = ", ".join(run.not_assessed)
        messages.setdefault(str(Step.THREATS), BoardMessage.NOT_ASSESSED.format(categories=categories))
    if abandoned := run.counts.get("abandoned", 0):
        messages.setdefault(str(Step.SCENARIOS), BoardMessage.ABANDONED.format(abandoned=abandoned))
    if controls == StageState.ERROR:
        failed = run.counts["controls_failed"]
        messages[str(Step.CONTROLS)] = BoardMessage.CONTROLS_FAILED.format(failed=failed)
    if run.cancelled:  # G214: who stopped it and when, on the stage it stopped
        stage = str(run.step) if run.status == Status.CANCELLED else str(Step.CONTROLS)
        messages.setdefault(stage, _stopped_by(run.cancelled))
    if controls == StageState.CANCELLED:
        cancelled = BoardMessage.CONTROLS_CANCELLED.format(cancelled=run.counts["controls_cancelled"])
        messages.setdefault(str(Step.CONTROLS), cancelled)
    return messages


def _stopped_by(cancelled: dict[str, Any]) -> str:
    """Who cancelled the run and when (G214), to the second, in UTC (MongoDB keeps UTC)."""
    at = cancelled.get("at")
    when = at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(at, datetime) else str(at)
    return BoardMessage.CANCELLED.format(user=cancelled.get("user_id"), at=when)


def _scenario_count(run: SessionStatus, threats: StageState) -> ScenarioCount:
    """A hand-written run plans nothing: its one scenario is its total."""
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
