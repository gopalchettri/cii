"""The remediation API in TSG v1's shape (owner, 2026-10-15): ONE request for a plan, for a generated or a
hand-written scenario; then every call on that plan at v1's address,
/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan..., in the order a tester uses them; then the
lists. Its live updates are in scenario.py. Each route makes one service call."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response

from app.api.dependencies import (
    Caller,
    CallersPlan,
    CallersRun,
    IdempotencyKey,
    Limit,
    Offset,
    ScenarioId,
    SessionId,
)
from app.container import get_job_service, get_remediation_plan_service
from app.core.constants import ApiTag, Decision, Limits, Remediation, Status
from app.models.jobs.views import PlanCancelled
from app.models.remediation.plan import (
    PlanRequested,
    PlanStarted,
    RemediationList,
    RemediationResult,
    RemediationStatus,
)
from app.models.remediation.requests import PlanRequest, RegenerateRequest, ReviewRequest
from app.services.jobs.job_service import JobService
from app.services.remediation.remediation_plan_service import RemediationPlanService

router = APIRouter(tags=[ApiTag.REMEDIATION])

Plans = Annotated[RemediationPlanService, Depends(get_remediation_plan_service)]
Jobs = Annotated[JobService, Depends(get_job_service)]
RiskLevel = Annotated[str | None, Query(max_length=Remediation.NAME_MAX_CHARS)]

#: v1's address of one scenario's plan.
PLAN = "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan"


@router.post("/v1/remediation", status_code=202, response_model=PlanStarted, summary="1. Request a plan")
def request_plan(
    body: PlanRequest,
    principal: Caller,
    plans: Plans,
    response: Response,
    idempotency_key: IdempotencyKey,
) -> PlanStarted:
    """Start writing a remediation plan for one scenario: v1's one request for both kinds.

    - **is_manual=false**: send `session_id` and `scenario_id` of an ACCEPTED scenario of that run.
    - **is_manual=true**: send `manual_scenario` (a scenario a person wrote). TSG saves the scenario, accepts
      it and plans it. With an `Idempotency-Key` header, the same key and body again: 200, `replayed: true`;
      if that plan failed for an outage (`error.code` `unavailable`), its version is written again: 202.
      Without one, the same body again within a minute is 409 `duplicate_request`.

    Every other field is the register's data; all are optional. `supporting_systems_applicable_to_risk` names
    the asset's systems the risk applies to (none: the asset itself), and
    `supporting_systems_applicable_to_existing_controls` those the existing controls are on (none: no
    system). Answers 202 at once with `remediation_id`, `session_id` and `scenario_id`: keep the last two,
    because every later call on the plan takes them in its address. No AI is called here: the plan job
    matches the scenario's controls (and a hand-written one's attacker) if they are missing, then writes the
    plan; poll `GET .../treatment-plan/status` until `latest_status` is `done`.

    Errors: 404 scenario unknown or not in that run; 403 another entity's; 409 `scenario_not_accepted`,
    `plan_already_exists` (regenerate it instead), `idempotency_key_conflict`, `duplicate_request`,
    `control_library_empty`, `run_being_deleted`; 422 a field, the two kinds mixed, or a listed system that is
    not a supporting system of the scenario's asset."""
    planned, created = plans.create_remediation_plan(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200
    return planned


@router.get(f"{PLAN}/status", response_model=RemediationStatus, summary="2. A plan's progress")
def plan_status(plan: CallersPlan) -> RemediationStatus:
    """The cheap poll: `latest_status` queued → running → done (or failed / cancelled), the review `decision`
    (pending, accepted, rejected) and `progress.overall`, which says what to do next (generating,
    awaiting_review, accepted, rejected, failed, cancelled; read_only when no version is decided and the
    scenario is no longer accepted, so it cannot be reviewed). 404 when the scenario has no plan."""
    return plan


@router.get(PLAN, response_model=RemediationResult, summary="3. Read a plan (the result)")
def plan_result(
    session_id: SessionId,
    scenario_id: ScenarioId,
    principal: Caller,
    plans: Plans,
    include_history: bool = False,
) -> RemediationResult:
    """The result: the plan shown (the accepted version, else the newest finished one), its warnings, the
    scenario it treats and the register's data (v2's old `.../result`, at v1's address).
    `include_history=true` adds every version with its own decision."""
    return plans.get_remediation_plan(principal, session_id, scenario_id, include_history)


@router.post(f"{PLAN}/review", response_model=RemediationStatus, summary="4. Accept or reject a plan")
def review_plan(plan: CallersPlan, body: ReviewRequest, principal: Caller, plans: Plans) -> RemediationStatus:
    """v1's review call: `{"decision": "accepted"}` or `"rejected"`, for `version` (leave it out for the
    newest finished one), with an optional `comment`. Accepting a version makes it THE plan; repeating a
    decision changes nothing. 409 `not_complete` while the version is still being written."""
    return plans.review_remediation_plan(principal, plan.remediation_id, body)


@router.post(
    f"{PLAN}/regenerate",
    status_code=202,
    response_model=PlanRequested,
    summary="5. Regenerate: write a new version (v2, v3...)",
)
def regenerate_plan(
    plan: CallersPlan, body: RegenerateRequest, principal: Caller, plans: Plans
) -> PlanRequested:
    """Send `{}`: the next version (2, 3, ...) is written from the same register data and the scenario's
    current controls; the earlier versions stay. Follow it with `.../status`, then accept the one you want:
    `.../review {"decision": "accepted", "version": 2}`. Allowed once the latest version is done, failed or
    cancelled; 409 `generation_in_progress` before that. A latest version that failed for an outage
    (`error.code` `unavailable`) is written again instead: the same version number, so it uses no version and
    the version limit (409 `version_limit_reached`) does not stop it."""
    return plans.regenerate_remediation_plan(principal, plan.remediation_id)


@router.post(f"{PLAN}/cancel", response_model=PlanCancelled, summary="6. Cancel a plan being written")
def cancel_plan(plan: CallersPlan, principal: Caller, jobs: Jobs) -> PlanCancelled:
    """Stops the version being written (409 `nothing_to_cancel` when none is). Regenerate writes it again."""
    return jobs.cancel_remediation_plan(principal, plan.remediation_id)


@router.get(
    "/v1/sessions/{session_id}/treatment-plans", response_model=RemediationList, summary="7. A run's plans"
)
def list_run_plans(  # noqa: PLR0913 — each filter is its own query parameter
    run: CallersRun,
    principal: Caller,
    plans: Plans,
    status: Status | None = None,
    decision: Decision | None = None,
    risk_level: RiskLevel = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RemediationList:
    """Every plan of the run's scenarios, newest first, filtered by `status`, `decision` or `risk_level`."""
    return plans.list_remediation_plans(
        principal, run.entity_id, run.session_id, status, decision, risk_level, offset, limit
    )


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/treatment-plans",
    response_model=RemediationList,
    summary="8. An entity's plans (the register)",
)
def list_entity_plans(  # noqa: PLR0913 — each filter is its own query parameter
    listed_entity_id: int,
    principal: Caller,
    plans: Plans,
    status: Status | None = None,
    decision: Decision | None = None,
    risk_level: RiskLevel = None,
    offset: Offset = 0,
    limit: Limit = Limits.PAGE_SIZE_DEFAULT,
) -> RemediationList:
    """Every plan of the entity, newest first, filtered as a run's list. The entity must be the caller's
    (X-Entity-Id), else 403."""
    return plans.list_remediation_plans(
        principal, listed_entity_id, None, status, decision, risk_level, offset, limit
    )
