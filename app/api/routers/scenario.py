"""The scenario API: start a run, its status, its scenarios, one scenario and an entity's list (`router`);
accept and reject scenarios, regenerate them, write the run's next set and promote an accepted AI-proposed
threat to the library (`review_router`); a run's or a plan's live status over Server-Sent Events
(`events_router`). Each route makes one service call; the run check (404/403) is the valid_session
dependency."""

import asyncio
from collections.abc import AsyncIterator, Callable
from functools import partial
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi import Header as HeaderParam
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.dependencies import (
    Caller,
    CallersPlan,
    CallersRun,
    Limit,
    Offset,
    ScenarioId,
    SessionId,
    valid_session,
)
from app.container import get_remediation_plan_service, get_threat_scenario_service
from app.core.constants import (
    ApiTag,
    Decision,
    Event,
    Header,
    Limits,
    Realtime,
    SessionState,
    StageState,
    Status,
)
from app.core.exceptions import NotFound
from app.models.scenario.views import (
    AcceptRequest,
    AcceptResult,
    PromotionResult,
    RejectResult,
    RunActionStarted,
    RunBoard,
    RunResults,
    ScenarioIdsRequest,
    ScenarioList,
    ScenarioView,
    StartRunRequest,
)
from app.realtime.event_hub import EventHub
from app.realtime.publisher import remediation_channel, session_channel
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.services.scenario.threat_scenario_service import ThreatScenarioService

router = APIRouter(tags=[ApiTag.RUNS])
review_router = APIRouter(tags=[ApiTag.REVIEW])
events_router = APIRouter(tags=[ApiTag.LIVE_UPDATES])

Scenarios = Annotated[ThreatScenarioService, Depends(get_threat_scenario_service)]
Plans = Annotated[RemediationPlanService, Depends(get_remediation_plan_service)]

#: A plan's queued or running version; a run's job still at work.
_UNFINISHED = {Status.QUEUED, Status.RUNNING, SessionState.ACTIVE}


# Runs.


@router.post("/v1/sessions", status_code=202, response_model=RunBoard, summary="1. Start a run")
def start_run(
    body: StartRunRequest,
    response: Response,
    principal: Caller,
    scenarios: Scenarios,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> RunBoard:
    """Send `asset_id` and `supporting_system_id` (one id or a list; `service_id`, `sector_id`,
    `subsector_id` optional). 202 with the run's status; keep `session_id`. With an `Idempotency-Key`
    header a retry is safe (the same key and body: 200, the same run). 409 `active_session_exists`: the
    asset already has a run; 409 `intel_no_data`: external intelligence is on but nothing is imported
    yet (group 4)."""
    board, created = scenarios.create_threat_scenario_session(principal, body, idempotency_key)
    if not created:
        response.status_code = 200  # a replay of the same Idempotency-Key: the run it started
    return board


@router.get("/v1/sessions/{session_id}", response_model=RunBoard, summary="2. A run's progress")
def get_run_status(run: CallersRun, scenarios: Scenarios) -> RunBoard:
    """Poll until `progress.overall` says what to do: `awaiting_review` (group 6), `awaiting_next_set`,
    `complete`, `error` or `cancelled`. Each stage (threats, scenarios, controls) reads PENDING,
    RUNNING, COMPLETE or ERROR."""
    return scenarios.get_threat_scenario_session(run)


@router.get("/v1/sessions/{session_id}/results", response_model=RunResults, summary="3. A run's scenarios")
def list_run_scenarios(
    run: CallersRun,
    scenarios: Scenarios,
    include_replaced: bool = False,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RunResults:
    """The written scenarios: threat, actors, systems, evidence and controls. `include_replaced=true` adds
    the versions a regenerate replaced. Paged with `offset` and `limit`."""
    return scenarios.list_threat_scenarios_of_session(run, include_replaced, offset, limit)


@router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}",
    response_model=ScenarioView,
    summary="4. One scenario",
)
def get_scenario(run: CallersRun, scenario_id: ScenarioId, scenarios: Scenarios) -> ScenarioView:
    """One scenario of the run, in full."""
    return scenarios.get_threat_scenario(run.session_id, scenario_id)


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/scenarios",
    response_model=ScenarioList,
    summary="5. An entity's scenarios",
)
def list_entity_scenarios(
    listed_entity_id: int,
    principal: Caller,
    scenarios: Scenarios,
    decision: Decision | None = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> ScenarioList:
    """Every run's current scenarios of the entity, newest first; `decision` filters (pending, accepted,
    rejected). The entity must be the caller's (`X-Entity-Id`), else 403."""
    return scenarios.list_threat_scenarios_of_entity(principal, listed_entity_id, decision, offset, limit)


# Review.


@review_router.post(
    "/v1/sessions/{session_id}/accept", response_model=AcceptResult, summary="1. Accept scenarios"
)
def accept_scenarios(
    body: AcceptRequest, run: CallersRun, principal: Caller, scenarios: Scenarios
) -> AcceptResult:
    """Send `{"scenario_ids": ["..."]}` or `{"scenario_ids": "all"}`. An accepted scenario can get a
    remediation plan (group 7). `replace_accepted: true` lets a newer version replace an accepted one."""
    return scenarios.accept_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/reject", response_model=RejectResult, summary="2. Reject scenarios"
)
def reject_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, scenarios: Scenarios
) -> RejectResult:
    """Send `{"scenario_ids": ["..."]}`. Each answer row says what was done or why not."""
    return scenarios.reject_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/regenerate/scenarios",
    status_code=202,
    response_model=RunActionStarted,
    summary="3. Rewrite scenarios",
)
def regenerate_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, scenarios: Scenarios
) -> RunActionStarted:
    """Send `{"scenario_ids": ["..."]}`: each is written again in the background (202); follow it with
    `GET /v1/sessions/{session_id}`. The earlier version stays readable (`include_replaced=true`)."""
    return scenarios.regenerate_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/next-set",
    status_code=202,
    response_model=RunActionStarted,
    summary="4. Write the next set",
)
def write_next_set(run: CallersRun, principal: Caller, scenarios: Scenarios) -> RunActionStarted:
    """Writes more scenarios from the attack paths not written yet (202). 409 `nothing_left` when every
    path is written."""
    return scenarios.write_next_threat_scenario_set(principal, run)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
    response_model=PromotionResult,
    summary="5. Propose an AI-written threat to the library",
)
def promote_to_library(
    scenario_id: ScenarioId, run: CallersRun, principal: Caller, scenarios: Scenarios
) -> PromotionResult:
    """For an accepted scenario whose threat the AI proposed: it goes to the curators as pending
    (group 10), never straight into the library."""
    return scenarios.promote_threat_scenario_to_library(principal, run, scenario_id)


# Live updates: a run's or a plan's status now, then at every change, until the client closes or the record
# is deleted (one `.deleted` event, then the stream ends).


@events_router.get(
    "/v1/sessions/{session_id}/events",
    response_class=EventSourceResponse,
    dependencies=[Depends(valid_session)],  # before the stream: a 404, 403 or 503 is an ordinary response
    summary="1. A run's live status",
)
async def stream_session_events(
    session_id: SessionId, request: Request, scenarios: Scenarios
) -> AsyncIterator[ServerSentEvent]:
    """Server-Sent Events: `session.updated` (the body of `GET /v1/sessions/{session_id}`) now and at
    every change; `session.deleted` once when it is deleted. Swagger cannot show a stream: use
    `curl -N` or a browser EventSource."""
    reads = partial(scenarios.get_threat_scenario_session_live_status, session_id)
    gone = ServerSentEvent(event=Event.SESSION_DELETED, data={"session_id": session_id})
    channel = session_channel(session_id)
    async for event in _status_stream(request, channel, reads, (Event.SESSION_UPDATED, gone)):
        yield event


@events_router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/events",
    response_class=EventSourceResponse,
    summary="2. A plan's live status",
)
async def stream_remediation_events(
    plan: CallersPlan, request: Request, plans: Plans
) -> AsyncIterator[ServerSentEvent]:
    """The plan's status now (`remediation.updated`: the body of `.../treatment-plan/status`), then every
    change, until the client closes; `remediation.deleted` once, when its run is deleted."""
    remediation_id = plan.remediation_id
    reads = partial(plans.get_remediation_plan_live_status, remediation_id)
    channel = remediation_channel(remediation_id)
    gone = ServerSentEvent(event=Event.REMEDIATION_DELETED, data={"remediation_id": remediation_id})
    async for event in _status_stream(request, channel, reads, (Event.REMEDIATION_UPDATED, gone)):
        yield event


async def _status_stream(
    request: Request,
    channel: str,
    read_status: Callable[[], dict[str, Any] | None],
    events: tuple[Event, ServerSentEvent],
) -> AsyncIterator[ServerSentEvent]:
    """Subscribed first, read second: a change saved between the two is never missed. A message only says
    "this record changed" (or RESYNC: "read again"): the status is always read from MongoDB, so a status
    that a worker published late can never replace a newer one, and a burst of changes costs one read."""
    hub: EventHub = request.app.state.event_hub
    (event, gone), last_sent = events, None
    async with hub.listen(channel) as updates:
        while True:
            try:  # None: MongoDB cannot say; the next change announced brings it
                status = await asyncio.to_thread(read_status)
            except NotFound:  # deleted (G214): the watcher is told once, and nothing more can come
                yield gone
                return
            if status is not None and status != last_sent:
                yield ServerSentEvent(event=event, data=status, retry=Realtime.RETRY_MS)
                last_sent = status
            # An unfinished record is read again every Realtime.RECHECK_SECONDS even with no message: its last
            # change may never be announced (a failed publish, a failed read), and nothing comes after it.
            unfinished = last_sent is None or _unfinished(last_sent)
            try:
                await asyncio.wait_for(updates.get(), Realtime.RECHECK_SECONDS if unfinished else None)
            except TimeoutError:
                continue
            await asyncio.sleep(Realtime.COALESCE_SECONDS)  # a burst (a batch of saves) ends first: one read
            while not updates.empty():
                updates.get_nowait()  # one read covers every change announced meanwhile


def _unfinished(body: dict[str, Any]) -> bool:
    """A run whose job is at work or whose controls are still being matched (`session_status`, `progress`); a
    plan whose latest version is queued or running (`latest_status`)."""
    if (body.get("progress") or {}).get("controls") == StageState.RUNNING:
        return True
    return str(body.get("session_status") or body.get("latest_status")) in _UNFINISHED
