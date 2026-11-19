"""The MITRE run's API (ADR-010): start a run grounded in the stored MITRE data, follow it, write its next set.
Its scenarios are read, reviewed and cancelled with the same calls as any other run."""

from fastapi import APIRouter, Response

from app.api.deps import Caller, CallersRun, IdempotencyKey, SessionId
from app.core import constants as c
from app.domain.scenario.mitre_scenario import mitre_session
from app.schemas.mitre.mitre_scenarios import MitreSessionStarted, MitreSessionStatus
from app.schemas.scenarios import StartRunRequest

router = APIRouter(tags=[c.ApiTag.RUNS])


@router.post(
    "/v1/mitre_create_session",
    status_code=202,
    response_model=MitreSessionStarted,
    summary="1c. Start a run from the MITRE data",
)
def mitre_create_session(
    body: StartRunRequest, response: Response, principal: Caller, idempotency_key: IdempotencyKey
) -> MitreSessionStarted:
    """The same body and `Idempotency-Key` rules as `POST /v1/sessions`. The AI selects the MITRE actors that fit
    the asset, plans attack paths over every MITRE Enterprise and ICS technique and writes the first set; code
    checks every quote, technique and group against MITRE. 202 with `status_url`: poll it. 409 `intel_no_data`:
    MITRE ATT&CK is not imported yet (group 4)."""
    started, created = mitre_session.create_mitre_scenario_session(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200  # a replay of the caller's Idempotency-Key: the run it started
    return started


@router.get("/v1/mitre_sessions/{session_id}", response_model=MitreSessionStatus, summary="2c. A MITRE run's progress")
def get_mitre_session(session_id: SessionId, principal: Caller) -> MitreSessionStatus:
    """The run's `status` and `stage`, its scenarios so far (`partial_scenarios`), and once complete `result`
    (`scenarios` with their CII library controls, and `metadata`). 404 for a run not started as a MITRE run."""
    return mitre_session.read_mitre_session_status(session_id, principal.entity_id)


@router.post(
    "/v1/mitre_sessions/{session_id}/next-set",
    status_code=202,
    response_model=MitreSessionStarted,
    summary="3c. Write a MITRE run's next set",
)
def write_mitre_next_set(run: CallersRun, principal: Caller) -> MitreSessionStarted:
    """Writes the next scenarios from the planned paths not written yet (202). 409 `nothing_left` when every
    path is written or failed its checks."""
    return mitre_session.write_next_mitre_scenario_set(principal, run)
