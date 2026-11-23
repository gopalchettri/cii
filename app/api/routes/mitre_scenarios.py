"""The MITRE run's API (ADR-010), group 5b: start a run grounded in the stored MITRE data, follow it, review its
scenarios, write its next set and propose its threat to the library. Each answer is the same model as its group
5 or group 6 twin's; a run another pipeline made is 404 here."""

from typing import Annotated

from fastapi import APIRouter, Body, Response

from app.api.deps import Caller, CallersRun, IdempotencyKey, Limit, Offset, ScenarioId, SessionId
from app.core import constants as c
from app.domain.scenario import runs
from app.domain.scenario.mitre_scenario import mitre_session
from app.schemas import scenarios as views
from app.schemas.mitre.mitre_scenarios import MitreNextSetStarted, MitreSessionStatus

router = APIRouter(tags=[c.ApiTag.MITRE])


@router.post(
    "/v1/mitre_create_session",
    status_code=202,
    response_model=MitreSessionStatus,
    summary="1. Start a run from the MITRE data",
)
def mitre_create_session(
    body: views.StartRunRequest, response: Response, principal: Caller, idempotency_key: IdempotencyKey
) -> MitreSessionStatus:
    """The same body and `Idempotency-Key` rules as `POST /v1/sessions`. The AI selects the MITRE actors that fit
    the asset, plans attack paths over every MITRE Enterprise and ICS technique and writes the first set; code
    checks every quote, technique and group against MITRE. 202 with the same board as `POST /v1/sessions`, plus
    `mitre` (its `status_url`: poll it). 409 `intel_no_data`:
    MITRE ATT&CK is not imported yet (group 4)."""
    started, created = mitre_session.create_mitre_scenario_session(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200  # a replay of the caller's Idempotency-Key: the run it started
    return started


@router.get("/v1/mitre_sessions/{session_id}", response_model=MitreSessionStatus, summary="2. A MITRE run's progress")
def get_mitre_session(session_id: SessionId, principal: Caller) -> MitreSessionStatus:
    """The same board as `GET /v1/sessions/{session_id}`, plus `mitre`: its stage, its scenarios so far
    (`partial_scenarios`), and once complete `result` (`scenarios` with their CII library controls, `metadata`)."""
    return mitre_session.read_mitre_session_status(session_id, principal.entity_id)


@router.get(
    "/v1/mitre_sessions/{session_id}/results", response_model=views.RunResults, summary="2b. A MITRE run's scenarios"
)
def list_mitre_run_scenarios(
    run: CallersRun, include_replaced: bool = True, offset: Offset = 0, limit: Limit = c.Limits.PAGE_SIZE_DEFAULT
) -> views.RunResults:
    """The same page as `GET /v1/sessions/{session_id}/results` (each card's `actors` are its MITRE groups and
    `attack_techniques` its techniques, each with its attack.mitre.org `url`); 404 for a run that is not a MITRE
    run."""
    return mitre_session.list_mitre_run_results(run, include_replaced, offset, limit)


@router.post("/v1/mitre_sessions/{session_id}/accept", response_model=views.AcceptResult, summary="3. Accept scenarios")
def accept_mitre_scenarios(
    body: Annotated[views.AcceptRequest, Body(openapi_examples=views.ACCEPT_REQUEST_EXAMPLES)],
    run: CallersRun,
    principal: Caller,
) -> views.AcceptResult:
    """The same body and answer as `POST /v1/sessions/{session_id}/accept`."""
    mitre_session.refuse_other_pipelines(run.pipeline, run.session_id)
    return runs.accept_threat_scenarios(principal, run, body)


@router.post(
    "/v1/mitre_sessions/{session_id}/scenarios/reject", response_model=views.RejectResult, summary="4. Reject scenarios"
)
def reject_mitre_scenarios(body: views.ScenarioIdsRequest, run: CallersRun, principal: Caller) -> views.RejectResult:
    """The same body and answer as `POST /v1/sessions/{session_id}/scenarios/reject`."""
    mitre_session.refuse_other_pipelines(run.pipeline, run.session_id)
    return runs.reject_threat_scenarios(principal, run, body)


@router.post(
    "/v1/mitre_sessions/{session_id}/regenerate/scenarios",
    status_code=202,
    response_model=views.RunActionStarted,
    summary="5. Rewrite scenarios",
)
def regenerate_mitre_scenarios(
    body: views.ScenarioIdsRequest, run: CallersRun, principal: Caller
) -> views.RunActionStarted:
    """Send `{"scenario_ids": ["..."]}`: each is written again from its MITRE attack path in the background (202);
    follow it with `GET /v1/mitre_sessions/{session_id}`. The earlier version stays readable under the new one; a
    rewrite that fails the MITRE checks keeps the earlier version and shows `regenerate_error`."""
    return mitre_session.regenerate_mitre_scenarios(principal, run, body)


@router.post(
    "/v1/mitre_sessions/{session_id}/scenarios/next-set",
    status_code=202,
    response_model=MitreNextSetStarted,
    responses={200: {"model": MitreNextSetStarted, "description": "Nothing left to write: remaining 0."}},
    summary="6. Write the next set",
)
def write_mitre_next_set(run: CallersRun, principal: Caller, response: Response) -> MitreNextSetStarted:
    """Writes the next scenarios from the planned paths not written yet (202 `generating`). With nothing left,
    nothing starts: 200 with `status` `nothing_left` (every path written or dropped by the MITRE checks) or
    `target_reached` (TOTAL_SCENARIO_COUNT left the rest out) and `remaining` 0. Either answer carries
    `remaining`, `written`, `dropped` and `message`."""
    answer = mitre_session.write_next_mitre_scenario_set(principal, run)
    if answer.status != c.ActionStatus.GENERATING:  # nothing started
        response.status_code = 200
    return answer


@router.post(
    "/v1/mitre_sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
    response_model=views.PromotionResult,
    summary="7. Propose a MITRE scenario's threat to the library",
)
def promote_mitre_scenario_to_library(
    scenario_id: ScenarioId, run: CallersRun, principal: Caller
) -> views.PromotionResult:
    """For an accepted scenario: its threat (the risk title, of the library type the writer picked) goes to the
    curators as pending (group 10), never straight into the library."""
    mitre_session.refuse_other_pipelines(run.pipeline, run.session_id)
    return runs.promote_threat_scenario_to_library(principal, run, scenario_id)
