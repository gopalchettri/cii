"""The job controls (G214): what of mine is queued or running, cancel a run, delete a run for good (a plan's
cancel is with the other plan calls: routers/remediation.py). The caller's own API key and entity; the run
check (404/403) is the valid_session dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import Caller, CallersRun
from app.core.constants import ApiTag
from app.models.jobs import JobList, SessionDeleted
from app.models.run_board import RunBoard
from app.services.jobs import JobService, get_job_service

router = APIRouter(tags=[ApiTag.JOBS])

Jobs = Annotated[JobService, Depends(get_job_service)]


@router.get("/v1/jobs", response_model=JobList, summary="My queued or running work")
def list_jobs(principal: Caller, jobs: Jobs) -> JobList:
    """My entity's runs and plans that are queued or running, oldest first."""
    return jobs.list_jobs(principal)


@router.post("/v1/sessions/{session_id}/cancel", response_model=RunBoard, summary="Cancel a run")
def cancel_run(run: CallersRun, principal: Caller, jobs: Jobs) -> RunBoard:
    """Stops the run's work; what is already written stays readable. 409 `nothing_to_cancel` when
    nothing runs."""
    return jobs.cancel_run(principal, run)


@router.delete("/v1/sessions/{session_id}", response_model=SessionDeleted, summary="Delete a run for good")
def delete_run(run: CallersRun, principal: Caller, jobs: Jobs) -> SessionDeleted:
    """Deletes the run, its scenarios and their plans; it cannot be undone. 409 `cancel_first` while its
    work runs."""
    return jobs.delete_run(principal, run)
