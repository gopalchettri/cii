"""The scenario API: runs, review and live updates."""

from collections.abc import AsyncIterator
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.deps import (
    Caller,
    CallersPlan,
    CallersRun,
    DbDep,
    IdempotencyKey,
    Limit,
    Offset,
    ScenarioId,
    SessionId,
    valid_session,
)
from app.api.status_stream import status_stream
from app.core import constants as c
from app.crud import admin as admin_crud
from app.domain.remediation import plans
from app.domain.scenario import runs
from app.domain.scenario.session import build_status_board
from app.realtime.publisher import remediation_channel, session_channel
from app.schemas import scenarios as views

router = APIRouter(tags=[c.ApiTag.RUNS])
review_router = APIRouter(tags=[c.ApiTag.REVIEW])
events_router = APIRouter(tags=[c.ApiTag.LIVE_UPDATES])


@router.post("/v1/sessions", status_code=202, response_model=views.RunBoard, summary="1. Start a run")
def start_run(
    body: views.StartRunRequest, response: Response, principal: Caller, idempotency_key: IdempotencyKey
) -> views.RunBoard:
    """Send `asset_id` and `supporting_system_id` (one id or a list; `service_id`, `sector_id`,
    `subsector_id` optional). 202 with the run's status; keep `session_id`. With an `Idempotency-Key`
    header a retry is safe (the same key and body: 200, the same run); without one, the same request again
    within a minute is 409 `duplicate_request`. 409 `intel_no_data`: external intelligence is on but
    nothing is imported yet (group 4)."""
    board, created = runs.create_threat_scenario_session(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200  # a replay of the caller's Idempotency-Key: the run it started
    return board


@router.post(
    "/v1/create_session",
    status_code=202,
    response_model=views.RunBoard,
    summary="1b. Start a run the AI writes from MITRE ATT&CK",
)
def create_session(
    body: views.StartRunRequest, response: Response, principal: Caller, idempotency_key: IdempotencyKey
) -> views.RunBoard:
    """The same body, answer and `Idempotency-Key` rules as `POST /v1/sessions`. The AI writes the scenarios
    from its MITRE ATT&CK knowledge (Enterprise for an IT asset, ICS for an OT one), each with its group,
    techniques and mitigations; the ATT&CK data imported in group 4 confirms them, and what it does not
    confirm is not shown. Follow, review and extend the run with the same calls as any other run. 409
    `intel_no_data`: MITRE ATT&CK is not imported yet (group 4)."""
    board, created = runs.create_attack_scenario_session(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200  # a replay of the caller's Idempotency-Key: the run it started
    return board


@router.get("/v1/sessions/{session_id}", response_model=views.RunBoard, summary="2. A run's progress")
def get_run_status(run: CallersRun) -> views.RunBoard:
    """Poll until `progress.overall` says what to do: `awaiting_review` (group 6), `awaiting_next_set`,
    `complete`, `error` or `cancelled`. Each stage (threats, scenarios, controls) reads PENDING,
    RUNNING, COMPLETE or ERROR."""
    return build_status_board(run)


@router.get("/v1/sessions/{session_id}/results", response_model=views.RunResults, summary="3. A run's scenarios")
def list_run_scenarios(
    run: CallersRun, include_replaced: bool = True, offset: Offset = 0, limit: Limit = c.Limits.PAGE_SIZE_DEFAULT
) -> views.RunResults:
    """The written scenarios: threat, actors, systems, evidence and controls, each with the versions a
    regenerate replaced (`include_replaced=false` leaves them out). Paged with `offset` and `limit`."""
    return runs.list_threat_scenarios_of_session(run, include_replaced, offset, limit)


@router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}", response_model=views.ScenarioView, summary="4. One scenario"
)
def get_scenario(run: CallersRun, scenario_id: ScenarioId) -> views.ScenarioView:
    """One scenario of the run, in full."""
    return runs.get_threat_scenario(run.session_id, scenario_id)


@router.get(
    "/v1/entities/{listed_entity_id}/scenarios", response_model=views.ScenarioList, summary="5. An entity's scenarios"
)
def list_entity_scenarios(
    listed_entity_id: int,
    principal: Caller,
    decision: c.Decision | None = None,
    offset: Offset = 0,
    limit: Limit = c.Limits.PAGE_SIZE_DEFAULT,
) -> views.ScenarioList:
    """Every run's current scenarios of the entity, newest first; `decision` filters (pending, accepted,
    rejected). The entity must be the caller's (`X-Entity-Id`), else 403."""
    return runs.list_threat_scenarios_of_entity(principal, listed_entity_id, decision, offset, limit)


@router.get(
    "/v1/sessions/{session_id}/plan-trace", response_model=views.PlanTraceView, summary="6. How a run's plan was made"
)
def get_plan_trace(run: CallersRun) -> views.PlanTraceView:
    """Why the run has as many scenarios as it has: how many candidates each planning stage took in and let
    out (`counts`; a slot is one threat as one kind of attack), each candidate left out with its stage,
    reason and detail (`drops`, the most telling first), and what became of the planned paths (`writing`:
    written, still to write, given up and why). 404 before the run is planned."""
    return runs.get_plan_trace(run)


@review_router.post(
    "/v1/sessions/{session_id}/accept", response_model=views.AcceptResult, summary="1. Accept scenarios"
)
def accept_scenarios(
    body: Annotated[views.AcceptRequest, Body(openapi_examples=views.ACCEPT_REQUEST_EXAMPLES)],
    run: CallersRun,
    principal: Caller,
) -> views.AcceptResult:
    """Send `{"mode": "subset", "scenario_ids": ["..."]}`, `{"mode": "all"}` or `{"mode": "none"}` (decides
    nothing), as TSG v1 does; `replace_accepted: true` (optional, with subset) lets a newer version replace an
    accepted one. The v2 body is also accepted: `{"scenario_ids": ["..."]}` or `{"scenario_ids": "all"}`. An
    accepted scenario can get a remediation plan (group 7)."""
    return runs.accept_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/reject", response_model=views.RejectResult, summary="2. Reject scenarios"
)
def reject_scenarios(body: views.ScenarioIdsRequest, run: CallersRun, principal: Caller) -> views.RejectResult:
    """Send `{"scenario_ids": ["..."]}`. Each answer row says what was done or why not."""
    return runs.reject_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/regenerate/scenarios",
    status_code=202,
    response_model=views.RunActionStarted,
    summary="3. Rewrite scenarios",
)
def regenerate_scenarios(body: views.ScenarioIdsRequest, run: CallersRun, principal: Caller) -> views.RunActionStarted:
    """Send `{"scenario_ids": ["..."]}`: each is written again in the background (202); follow it with
    `GET /v1/sessions/{session_id}`. The earlier version stays readable in the results, under the new one. A
    card that failed because the AI did not answer is written again in its place."""
    return runs.regenerate_threat_scenarios(principal, run, body)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/next-set",
    status_code=202,
    response_model=views.RunActionStarted,
    summary="4. Write the next set",
)
def write_next_set(run: CallersRun, principal: Caller) -> views.RunActionStarted:
    """Writes more scenarios from the attack paths not written yet (202). 409 `nothing_left` when every
    path is written."""
    return runs.write_next_threat_scenario_set(principal, run)


@review_router.post(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
    response_model=views.PromotionResult,
    summary="5. Propose an AI-written threat to the library",
)
def promote_to_library(scenario_id: ScenarioId, run: CallersRun, principal: Caller) -> views.PromotionResult:
    """For an accepted scenario whose threat the AI proposed: it goes to the curators as pending
    (group 10), never straight into the library."""
    return runs.promote_threat_scenario_to_library(principal, run, scenario_id)


@events_router.get(
    "/v1/sessions/{session_id}/events",
    response_class=EventSourceResponse,
    dependencies=[Depends(valid_session)],  # before the stream: a 404, 403 or 503 is an ordinary response
    summary="1. A run's live status",
)
async def stream_session_events(session_id: SessionId, request: Request, db: DbDep) -> AsyncIterator[ServerSentEvent]:
    """Server-Sent Events: `session.updated` (the body of `GET /v1/sessions/{session_id}`) now and at
    every change; `session.deleted` once when it is deleted. Swagger cannot show a stream: use
    `curl -N` or a browser EventSource."""
    reads = partial(runs.get_threat_scenario_session_live_status, session_id)
    gone = ServerSentEvent(event=c.Event.SESSION_DELETED, data={"session_id": session_id})
    channel = session_channel(session_id)
    still_allowed = partial(admin_crud.api_key_still_active, db, request.headers.get(c.Header.API_KEY, ""))
    async for event in status_stream(request, channel, reads, c.Event.SESSION_UPDATED, still_allowed, gone):
        yield event


@events_router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/events",
    response_class=EventSourceResponse,
    summary="2. A plan's live status",
)
async def stream_remediation_events(plan: CallersPlan, request: Request, db: DbDep) -> AsyncIterator[ServerSentEvent]:
    """The plan's status now (`remediation.updated`: the body of `.../treatment-plan/status`), then every
    change, until the client closes; `remediation.deleted` once, when its run is deleted."""
    remediation_id = plan.remediation_id
    reads = partial(plans.read_live_status, remediation_id)
    channel = remediation_channel(remediation_id)
    gone = ServerSentEvent(event=c.Event.REMEDIATION_DELETED, data={"remediation_id": remediation_id})
    still_allowed = partial(admin_crud.api_key_still_active, db, request.headers.get(c.Header.API_KEY, ""))
    async for event in status_stream(request, channel, reads, c.Event.REMEDIATION_UPDATED, still_allowed, gone):
        yield event
