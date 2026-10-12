"""The review API: accept and reject scenarios, regenerate them, write the run's next set of
scenarios and promote an accepted AI-proposed threat to the library. Each route makes one service call;
the run check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import Caller, CallersRun
from app.core.constants import Review
from app.models.review import (
    AcceptRequest,
    AcceptResult,
    PromotionResult,
    RejectResult,
    RunActionStarted,
    ScenarioIdsRequest,
)
from app.services.scenarios.promotion import LibraryPromotion, get_library_promotion
from app.services.scenarios.review import ReviewService, get_review_service
from app.services.scenarios.run_actions import RunActions, get_run_actions

router = APIRouter(tags=["review"])

Reviews = Annotated[ReviewService, Depends(get_review_service)]
Actions = Annotated[RunActions, Depends(get_run_actions)]
Promotions = Annotated[LibraryPromotion, Depends(get_library_promotion)]
ScenarioId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]


@router.post("/v1/sessions/{session_id}/accept", response_model=AcceptResult, summary="Accept scenarios")
def accept_scenarios(
    body: AcceptRequest, run: CallersRun, principal: Caller, review: Reviews
) -> AcceptResult:
    return review.accept(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/scenarios/reject", response_model=RejectResult, summary="Reject scenarios"
)
def reject_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, review: Reviews
) -> RejectResult:
    return review.reject(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/regenerate/scenarios",
    status_code=202,
    response_model=RunActionStarted,
    summary="Regenerate scenarios",
)
def regenerate_scenarios(
    body: ScenarioIdsRequest, run: CallersRun, principal: Caller, actions: Actions
) -> RunActionStarted:
    return actions.regenerate(principal, run, body)


@router.post(
    "/v1/sessions/{session_id}/scenarios/next-set",
    status_code=202,
    response_model=RunActionStarted,
    summary="Write the next set of scenarios",
)
def write_next_set(run: CallersRun, principal: Caller, actions: Actions) -> RunActionStarted:
    return actions.next_set(principal, run)


@router.post(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
    response_model=PromotionResult,
    summary="Promote an accepted AI-proposed threat to the library (pending a curator)",
)
def promote_to_library(
    scenario_id: ScenarioId, run: CallersRun, principal: Caller, promotions: Promotions
) -> PromotionResult:
    return promotions.promote(principal, run, scenario_id)
