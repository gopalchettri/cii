"""The job controls (G214): what of mine is queued or running, cancel a run or a remediation plan, delete a
run for good. The caller's own API key and entity; the run check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import Caller, CallersRun, RemediationId
from app.models.jobs import JobList, PlanCancelled, SessionDeleted
from app.models.run_board import RunBoard
from app.services.jobs import JobService, get_job_service

router = APIRouter(tags=["jobs"])

Jobs = Annotated[JobService, Depends(get_job_service)]


@router.get("/v1/jobs", response_model=JobList, summary="My runs and plans queued or running")
def list_jobs(principal: Caller, jobs: Jobs) -> JobList:
    return jobs.list_jobs(principal)


@router.post("/v1/sessions/{session_id}/cancel", response_model=RunBoard, summary="Cancel a run")
def cancel_run(run: CallersRun, principal: Caller, jobs: Jobs) -> RunBoard:
    return jobs.cancel_run(principal, run)


@router.delete("/v1/sessions/{session_id}", response_model=SessionDeleted, summary="Delete a run for good")
def delete_run(run: CallersRun, principal: Caller, jobs: Jobs) -> SessionDeleted:
    return jobs.delete_run(principal, run)


@router.post(
    "/v1/remediation/{remediation_id}/cancel",
    response_model=PlanCancelled,
    summary="Cancel a remediation plan being written",
)
def cancel_plan(remediation_id: RemediationId, principal: Caller, jobs: Jobs) -> PlanCancelled:
    return jobs.cancel_plan(principal, remediation_id)
