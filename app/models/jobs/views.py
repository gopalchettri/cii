"""The bodies of the job controls (G214): the list of an organisation's work in progress, and what a delete
removed or a plan cancel stopped; and the retry notice a run's and a plan's status show. A run's cancel
answers with its status body (models/scenario/views.py)."""

from datetime import datetime

from pydantic import BaseModel

from app.core.constants import AiOutage, JobKind, Status


class RetryNotice(BaseModel):
    """A stage waiting to try again after an outage; null once the stage succeeds, ends or fails."""

    stage: str | None = None  # threats or scenarios on a run; None on a remediation plan
    reason: AiOutage | None  # ai_down, ai_unreachable, ai_busy, ai_timed_out; None: a store outage
    message: str  # what to tell the user
    attempt: int  # the try that failed
    max_attempts: int  # the job fails after this many
    retry_at: datetime  # when the next try starts


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
