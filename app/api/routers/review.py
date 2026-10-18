"""The review API: accept and reject scenarios, regenerate them, write the run's next set of
scenarios and promote an accepted AI-proposed threat to the library. Each route makes one service call;
the run check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import Caller, CallersRun, ScenarioId
from app.core.constants import ApiTag
from app.models.scenario.views import (
    AcceptRequest,
    AcceptResult,
    PromotionResult,
    RejectResult,
    RunActionStarted,
    ScenarioIdsRequest,
)
from app.services.library_curation import LibraryPromotion, get_library_promotion
from app.services.scenario.review import ReviewService, get_review_service
from app.services.scenario.runs import RunActions, get_run_actions

router = APIRouter(tags=[ApiTag.REVIEW])

Reviews = Annotated[ReviewService, Depends(get_review_service)]
Actions = Annotated[RunActions, Depends(get_run_actions)]
Promotions = Annotated[LibraryPromotion, Depends(get_library_promotion)]


@router.post("/v1/sessions/{session_id}/accept", response_model=AcceptResult, summary="1. Accept scenarios")
def accept_scenarios(
    body: AcceptRequest, run: CallersRun, principal: Caller, review: Reviews
) -> AcceptResult:
    """Send `{"scenario_ids": ["..."]}` or `{"scenario_ids": "all"}`. An accepted scenario can get a
    remediation plan (group 7). `replace_accepted: true` lets a newer version replace an accepted one."""
    return review.accept(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/scenarios/reject", response_model=RejectResult, summary="2. Reject scenarios"
)
def reject_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, review: Reviews
) -> RejectResult:
    """Send `{"scenario_ids": ["..."]}`. Each answer row says what was done or why not."""
    return review.reject(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/regenerate/scenarios",
    status_code=202,
    response_model=RunActionStarted,
    summary="3. Rewrite scenarios",
)
def regenerate_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, actions: Actions
) -> RunActionStarted:
    """Send `{"scenario_ids": ["..."]}`: each is written again in the background (202); follow it with
    `GET /v1/sessions/{session_id}`. The earlier version stays readable (`include_replaced=true`)."""
    return actions.regenerate(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/scenarios/next-set",
    status_code=202,
    response_model=RunActionStarted,
    summary="4. Write the next set",
)
def write_next_set(run: CallersRun, principal: Caller, actions: Actions) -> RunActionStarted:
    """Writes more scenarios from the attack paths not written yet (202). 409 `nothing_left` when every
    path is written."""
    return actions.next_set(principal, run)


@router.post(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
    response_model=PromotionResult,
    summary="5. Propose an AI-written threat to the library",
)
def promote_to_library(
    scenario_id: ScenarioId, run: CallersRun, principal: Caller, promotions: Promotions
) -> PromotionResult:
    """For an accepted scenario whose threat the AI proposed: it goes to the curators as pending
    (group 10), never straight into the library."""
    return promotions.promote(principal, run, scenario_id)
