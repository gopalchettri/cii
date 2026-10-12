"""The runs API: start a run, its status, its scenarios, one scenario and an entity's
list. Each route makes one service call; the run check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi import Header as HeaderParam

from app.api.dependencies import Caller, CallersRun, Limit, Offset
from app.core.constants import Decision, Header, Limits
from app.models.run_board import RunBoard, build_board
from app.models.scenario_views import RunResults, ScenarioList, ScenarioView
from app.models.scenarios import StartRunRequest
from app.services.scenarios.queries import ScenarioQueries, get_scenario_queries
from app.services.scenarios.runs import RunService, get_run_service

router = APIRouter(tags=["scenarios"])

Runs = Annotated[RunService, Depends(get_run_service)]
Queries = Annotated[ScenarioQueries, Depends(get_scenario_queries)]


@router.post("/v1/sessions", status_code=202, response_model=RunBoard, summary="Start a run")
def start_run(
    body: StartRunRequest,
    response: Response,
    principal: Caller,
    runs: Runs,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> RunBoard:
    status, created = runs.start(principal, body, idempotency_key)
    if not created:
        response.status_code = 200  # a replay of the same Idempotency-Key: the run it started
    return build_board(status)


@router.get("/v1/sessions/{session_id}", response_model=RunBoard, summary="A run's status")
def get_run_status(run: CallersRun) -> RunBoard:
    return build_board(run)


@router.get("/v1/sessions/{session_id}/results", response_model=RunResults, summary="A run's scenarios")
def list_run_scenarios(
    run: CallersRun,
    queries: Queries,
    include_replaced: bool = False,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RunResults:
    return queries.run_results(run, include_replaced, offset, limit)


@router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}", response_model=ScenarioView, summary="One scenario"
)
def get_scenario(run: CallersRun, scenario_id: str, queries: Queries) -> ScenarioView:
    return queries.one_scenario(run.session_id, scenario_id)


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/scenarios",
    response_model=ScenarioList,
    summary="An entity's scenarios",
)
def list_entity_scenarios(
    listed_entity_id: int,
    principal: Caller,
    queries: Queries,
    decision: Decision | None = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> ScenarioList:
    return queries.entity_scenarios(principal, listed_entity_id, decision, offset, limit)
