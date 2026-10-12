"""The bodies of the job controls (G214): the list of an organisation's work in progress, and what a delete
removed or a plan cancel stopped. A run's cancel answers with its status body (models/run_board.py)."""

from datetime import datetime

from pydantic import BaseModel

from app.core.constants import JobKind, Status


class JobProgress(BaseModel):
    """How far a run is: scenarios planned, written, still to write, and controls still being matched."""

    planned: int = 0
    written: int = 0
    remaining: int = 0
    controls_waiting: int = 0


class JobView(BaseModel):
    """One piece of work queued or running."""

    kind: JobKind
    session_id: str | None
    remediation_id: str | None = None
    asset_id: int | None
    asset_name: str | None = None
    status: Status  # queued or running
    queued_at: datetime | None  # when its job was queued (or last handed on)
    created_at: datetime | None
    attempts: int = 0
    user_id: str | None = None
    progress: JobProgress | None = None  # a run's; None for a remediation plan


class JobList(BaseModel):
    jobs: list[JobView]  # oldest first; at most JobControl.LIST_MAX runs and as many plans
    total: int  # all of them, though the list was cut


class SessionDeleted(BaseModel):
    session_id: str
    scenarios: int  # removed with it
    remediation_plans: int


class PlanCancelled(BaseModel):
    remediation_id: str
    status: Status
