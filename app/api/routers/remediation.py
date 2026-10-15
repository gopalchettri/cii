"""The remediation API in TSG v1's shape (owner, 2026-10-15): ONE request for a plan, for a generated or a
hand-written scenario; then every call on that plan at v1's address,
/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan..., in the order a tester uses them; then the
lists. Its live updates are in events.py. Each route makes one service call."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from fastapi import Header as HeaderParam

from app.api.dependencies import Caller, CallersPlan, CallersRun, Limit, Offset, ScenarioId, SessionId
from app.core.constants import ApiTag, Decision, Header, Limits, Remediation, Status
from app.models.jobs import PlanCancelled
from app.models.remediation import PlanRequested, PlanStarted, RemediationStatus
from app.models.remediation_requests import PlanRequest
from app.models.remediation_reviews import RegenerateRequest, ReviewRequest
from app.models.remediation_views import RemediationList, RemediationResult
from app.services.jobs import JobService, get_job_service
from app.services.remediation.decisions import PlanDecisions, get_plan_decisions
from app.services.remediation.manual import ManualPlans, get_manual_plans
from app.services.remediation.queries import RemediationQueries, get_remediation_queries
from app.services.remediation.regenerate import PlanRegeneration, get_plan_regeneration
from app.services.remediation.requests import PlanRequestService, get_plan_request_service

router = APIRouter(tags=[ApiTag.REMEDIATION])

Requests = Annotated[PlanRequestService, Depends(get_plan_request_service)]
Queries = Annotated[RemediationQueries, Depends(get_remediation_queries)]
Decisions = Annotated[PlanDecisions, Depends(get_plan_decisions)]
ManualRequests = Annotated[ManualPlans, Depends(get_manual_plans)]
Regenerations = Annotated[PlanRegeneration, Depends(get_plan_regeneration)]
Jobs = Annotated[JobService, Depends(get_job_service)]
RiskLevel = Annotated[str | None, Query(max_length=Remediation.NAME_MAX_CHARS)]

#: v1's address of one scenario's plan.
PLAN = "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan"


@router.post("/v1/remediation", status_code=202, response_model=PlanStarted, summary="1. Request a plan")
def request_plan(  # noqa: PLR0913 — the two kinds of request's inputs
    body: PlanRequest,
    principal: Caller,
    requests: Requests,
    manual: ManualRequests,
    response: Response,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> PlanStarted:
    """Start writing a remediation plan for one scenario: v1's one request for both kinds.

    - **is_manual=false**: send `session_id` and `scenario_id` of an ACCEPTED scenario of that run.
    - **is_manual=true**: send `manual_scenario` (a scenario a person wrote) and an `Idempotency-Key` header.
      TSG saves the scenario, accepts it and plans it. The same key and body again: 200, `replayed: true`.

    Every other field is the register's data; all are optional. Answers 202 at once with `remediation_id`,
    `session_id` and `scenario_id`: keep the last two, because every later call on the plan takes them in its
    address. No AI is called here: the plan job matches the scenario's controls (and a hand-written one's
    attacker) if they are missing, then writes the plan; poll `GET .../treatment-plan/status` until
    `latest_status` is `done`.

    Errors: 404 scenario unknown or not in that run; 403 another entity's; 409 `scenario_not_accepted`,
    `plan_already_exists` (regenerate it instead), `idempotency_key_conflict`, `control_library_empty`; 422 a
    field, or the two kinds mixed."""
    if not body.is_manual:
        return requests.request(principal, body)
    planned, created = manual.request(principal, body, idempotency_key)
    if not created:
        response.status_code = 200
    return planned


@router.get(f"{PLAN}/status", response_model=RemediationStatus, summary="2. A plan's progress")
def plan_status(plan: CallersPlan) -> RemediationStatus:
    """The cheap poll: `latest_status` queued → running → done (or failed / cancelled), the review `decision`
    (pending, accepted, rejected) and `progress.overall`, which says what to do next (generating,
    awaiting_review, accepted, rejected, failed, cancelled). 404 when the scenario has no plan."""
    return plan


@router.get(PLAN, response_model=RemediationResult, summary="3. Read a plan (the result)")
def plan_result(
    session_id: SessionId,
    scenario_id: ScenarioId,
    principal: Caller,
    queries: Queries,
    include_history: bool = False,
) -> RemediationResult:
    """The result: the plan shown (the accepted version, else the newest finished one), its warnings, the
    scenario it treats and the register's data (v2's old `.../result`, at v1's address).
    `include_history=true` adds every version with its own decision."""
    return queries.result(principal, session_id, scenario_id, include_history)


@router.post(f"{PLAN}/review", response_model=RemediationStatus, summary="4. Accept or reject a plan")
def review_plan(
    plan: CallersPlan, body: ReviewRequest, principal: Caller, decisions: Decisions
) -> RemediationStatus:
    """v1's review call: `{"decision": "accepted"}` or `"rejected"`, for `version` (leave it out for the
    newest finished one), with an optional `comment`. Accepting a version makes it THE plan; repeating a
    decision changes nothing. 409 `not_complete` while the version is still being written."""
    decide = decisions.accept if body.decision == Decision.ACCEPTED else decisions.reject
    return decide(principal, plan.remediation_id, body)


@router.post(
    f"{PLAN}/regenerate",
    status_code=202,
    response_model=PlanRequested,
    summary="5. Regenerate: write a new version (v2, v3...)",
)
def regenerate_plan(
    plan: CallersPlan, body: RegenerateRequest, principal: Caller, regenerations: Regenerations
) -> PlanRequested:
    """Send `{}`: the next version (2, 3, ...) is written from the same register data and the scenario's
    current controls; the earlier versions stay. Follow it with `.../status`, then accept the one you want:
    `.../review {"decision": "accepted", "version": 2}`. Allowed once the latest version is done, failed or
    cancelled; 409 `generation_in_progress` before that."""
    return regenerations.regenerate(principal, plan.remediation_id)


@router.post(f"{PLAN}/cancel", response_model=PlanCancelled, summary="6. Cancel a plan being written")
def cancel_plan(plan: CallersPlan, principal: Caller, jobs: Jobs) -> PlanCancelled:
    """Stops the version being written (409 `nothing_to_cancel` when none is). Regenerate writes it again."""
    return jobs.cancel_plan(principal, plan.remediation_id)


@router.get(
    "/v1/sessions/{session_id}/treatment-plans", response_model=RemediationList, summary="7. A run's plans"
)
def list_run_plans(  # noqa: PLR0913 — each filter is its own query parameter
    run: CallersRun,
    queries: Queries,
    status: Status | None = None,
    decision: Decision | None = None,
    risk_level: RiskLevel = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RemediationList:
    """Every plan of the run's scenarios, newest first, filtered by `status`, `decision` or `risk_level`."""
    return queries.run_plans(run.entity_id, run.session_id, status, decision, risk_level, offset, limit)


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/treatment-plans",
    response_model=RemediationList,
    summary="8. An entity's plans (the register)",
)
def list_entity_plans(  # noqa: PLR0913 — each filter is its own query parameter
    listed_entity_id: int,
    principal: Caller,
    queries: Queries,
    status: Status | None = None,
    decision: Decision | None = None,
    risk_level: RiskLevel = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RemediationList:
    """Every plan of the entity, newest first, filtered as a run's list. The entity must be the caller's
    (X-Entity-Id), else 403."""
    return queries.entity_plans(principal, listed_entity_id, status, decision, risk_level, offset, limit)
