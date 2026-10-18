"""The runs API: start a run, its status, its scenarios, one scenario and an entity's
list. Each route makes one service call; the run check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi import Header as HeaderParam

from app.api.dependencies import Caller, CallersRun, Limit, Offset, ScenarioId
from app.core.constants import ApiTag, Decision, Header, Limits
from app.models.scenario.views import (
    RunBoard,
    RunResults,
    ScenarioList,
    ScenarioView,
    StartRunRequest,
    build_board,
)
from app.services.scenario.runs import RunService, ScenarioQueries, get_run_service, get_scenario_queries

router = APIRouter(tags=[ApiTag.RUNS])

Runs = Annotated[RunService, Depends(get_run_service)]
Queries = Annotated[ScenarioQueries, Depends(get_scenario_queries)]


@router.post("/v1/sessions", status_code=202, response_model=RunBoard, summary="1. Start a run")
def start_run(
    body: StartRunRequest,
    response: Response,
    principal: Caller,
    runs: Runs,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> RunBoard:
    """Send `asset_id` and `supporting_system_id` (one id or a list; `service_id`, `sector_id`,
    `subsector_id` optional). 202 with the run's status; keep `session_id`. With an `Idempotency-Key`
    header a retry is safe (the same key and body: 200, the same run). 409 `active_session_exists`: the
    asset already has a run; 409 `intel_no_data`: external intelligence is on but nothing is imported
    yet (group 4)."""
    status, created = runs.start(principal, body, idempotency_key)
    if not created:
        response.status_code = 200  # a replay of the same Idempotency-Key: the run it started
    return build_board(status)


@router.get("/v1/sessions/{session_id}", response_model=RunBoard, summary="2. A run's progress")
def get_run_status(run: CallersRun) -> RunBoard:
    """Poll until `progress.overall` says what to do: `awaiting_review` (group 6), `awaiting_next_set`,
    `complete`, `error` or `cancelled`. Each stage (threats, scenarios, controls) reads PENDING,
    RUNNING, COMPLETE or ERROR."""
    return build_board(run)


@router.get("/v1/sessions/{session_id}/results", response_model=RunResults, summary="3. A run's scenarios")
def list_run_scenarios(
    run: CallersRun,
    queries: Queries,
    include_replaced: bool = False,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RunResults:
    """The written scenarios: threat, actors, systems, evidence and controls. `include_replaced=true` adds
    the versions a regenerate replaced. Paged with `offset` and `limit`."""
    return queries.run_results(run, include_replaced, offset, limit)


@router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}",
    response_model=ScenarioView,
    summary="4. One scenario",
)
def get_scenario(run: CallersRun, scenario_id: ScenarioId, queries: Queries) -> ScenarioView:
    """One scenario of the run, in full."""
    return queries.one_scenario(run.session_id, scenario_id)


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/scenarios",
    response_model=ScenarioList,
    summary="5. An entity's scenarios",
)
def list_entity_scenarios(
    listed_entity_id: int,
    principal: Caller,
    queries: Queries,
    decision: Decision | None = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> ScenarioList:
    """Every run's current scenarios of the entity, newest first; `decision` filters (pending, accepted,
    rejected). The entity must be the caller's (`X-Entity-Id`), else 403."""
    return queries.entity_scenarios(principal, listed_entity_id, decision, offset, limit)
