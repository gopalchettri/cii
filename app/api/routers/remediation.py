"""The remediation API: request a plan (#11), accept or reject a version,
regenerate it, read its status and its result, and list the entity's plans; its live updates are in events.py.
Each route makes one service call."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from fastapi import Header as HeaderParam

from app.api.dependencies import Caller, Limit, Offset, RemediationId
from app.core.constants import Decision, Header, Limits, Remediation, Review, Status
from app.models.remediation import PlanRequested, RemediationStatus
from app.models.remediation_requests import DecisionRequest, PlanRequest, RegenerateRequest
from app.models.remediation_views import RemediationList, RemediationResult
from app.services.remediation.decisions import PlanDecisions, get_plan_decisions
from app.services.remediation.manual import ManualPlans, get_manual_plans
from app.services.remediation.queries import RemediationQueries, get_remediation_queries
from app.services.remediation.regenerate import PlanRegeneration, get_plan_regeneration
from app.services.remediation.requests import PlanRequestService, get_plan_request_service

router = APIRouter(tags=["remediation"])

Requests = Annotated[PlanRequestService, Depends(get_plan_request_service)]
Queries = Annotated[RemediationQueries, Depends(get_remediation_queries)]
Decisions = Annotated[PlanDecisions, Depends(get_plan_decisions)]
ManualRequests = Annotated[ManualPlans, Depends(get_manual_plans)]
Regenerations = Annotated[PlanRegeneration, Depends(get_plan_regeneration)]


@router.post(
    "/v1/remediation", status_code=202, response_model=PlanRequested, summary="Request a remediation plan"
)
def request_plan(  # noqa: PLR0913 — the two request paths' inputs
    body: PlanRequest,
    principal: Caller,
    requests: Requests,
    manual: ManualRequests,
    response: Response,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> PlanRequested:
    """A generated scenario's plan, or a hand-written one's (Idempotency-Key required; 200 on a replay)."""
    if body.manual_scenario is None:
        return requests.request(principal, body)
    planned, created = manual.request(principal, body, idempotency_key)
    if not created:
        response.status_code = 200
    return planned


@router.get(
    "/v1/remediation/{remediation_id}/status",
    response_model=RemediationStatus,
    summary="A remediation plan's progress",
)
def plan_status(remediation_id: RemediationId, principal: Caller, queries: Queries) -> RemediationStatus:
    return queries.status(principal, remediation_id)


@router.get(
    "/v1/remediation/{remediation_id}/result",
    response_model=RemediationResult,
    summary="A remediation plan: the shown version, the scenario and the register",
)
def plan_result(
    remediation_id: RemediationId, principal: Caller, queries: Queries, include_history: bool = False
) -> RemediationResult:
    return queries.result(principal, remediation_id, include_history)


@router.get("/v1/remediation", response_model=RemediationList, summary="The entity's remediation plans")
def list_plans(  # noqa: PLR0913 — each filter is its own query parameter
    principal: Caller,
    queries: Queries,
    session_id: Annotated[str | None, Query(max_length=Review.MAX_ID_CHARS)] = None,
    scenario_id: Annotated[str | None, Query(max_length=Review.MAX_ID_CHARS)] = None,
    status: Status | None = None,
    decision: Decision | None = None,
    risk_level: Annotated[str | None, Query(max_length=Remediation.NAME_MAX_CHARS)] = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RemediationList:
    return queries.list_plans(principal, session_id, scenario_id, status, decision, risk_level, offset, limit)


@router.post(
    "/v1/remediation/{remediation_id}/accept",
    response_model=RemediationStatus,
    summary="Accept a version of a remediation plan",
)
def accept_plan(
    remediation_id: RemediationId, body: DecisionRequest, principal: Caller, decisions: Decisions
) -> RemediationStatus:
    return decisions.accept(principal, remediation_id, body)


@router.post(
    "/v1/remediation/{remediation_id}/reject",
    response_model=RemediationStatus,
    summary="Reject a version of a remediation plan",
)
def reject_plan(
    remediation_id: RemediationId, body: DecisionRequest, principal: Caller, decisions: Decisions
) -> RemediationStatus:
    return decisions.reject(principal, remediation_id, body)


@router.post(
    "/v1/remediation/{remediation_id}/regenerate",
    status_code=202,
    response_model=PlanRequested,
    summary="Write a new version of a remediation plan",
)
def regenerate_plan(
    remediation_id: RemediationId, body: RegenerateRequest, principal: Caller, regenerations: Regenerations
) -> PlanRequested:
    return regenerations.regenerate(principal, remediation_id)
