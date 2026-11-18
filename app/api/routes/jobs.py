"""The job controls: my queued or running work, cancel a run, delete a run (a plan's cancel: remediation)."""

from fastapi import APIRouter

from app.api.deps import Caller, CallersRun
from app.core.constants import ApiTag
from app.domain import jobs
from app.schemas.jobs import JobList, SessionDeleted
from app.schemas.scenarios import RunBoard

router = APIRouter(tags=[ApiTag.JOBS])


@router.get("/v1/jobs", response_model=JobList, summary="My queued or running work")
def list_jobs(principal: Caller) -> JobList:
    """My entity's runs, plans and service mappings that are queued or running, oldest first."""
    return jobs.list_my_jobs(principal)


@router.post("/v1/sessions/{session_id}/cancel", response_model=RunBoard, summary="Cancel a run")
def cancel_run(run: CallersRun, principal: Caller) -> RunBoard:
    """Stops the run's work; what is already written stays readable. 409 `nothing_to_cancel` when
    nothing runs."""
    return jobs.cancel_run(principal, run)


@router.delete("/v1/sessions/{session_id}", response_model=SessionDeleted, summary="Delete a run for good")
def delete_run(run: CallersRun, principal: Caller) -> SessionDeleted:
    """Deletes the run, its scenarios and their plans; it cannot be undone. 409 `cancel_first` while its
    work runs."""
    return jobs.delete_run(principal, run)
