"""The job controls' bodies and the retry notice a run's and a plan's status show."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.constants import AdminJobKind, AiOutage, IntelSource, JobKind, Status, Step
from app.schemas.intel_records import RefreshResult


class RetryNotice(BaseModel):
    """A stage waiting to try again after an outage; null once the next try starts or the stage ends."""

    stage: str | None = None  # threats, scenarios or controls on a run; None on a remediation plan
    reason: AiOutage | None  # ai_down, ai_unreachable, ai_busy, ai_timed_out; None: a store outage
    message: str  # what to tell the user
    attempt: int  # the try that failed (controls: the delivery message's try)
    max_attempts: int  # the job fails after this many (controls: after the last the sweep re-sends)
    retry_at: datetime  # when the next try starts


def retry_notice_of(status: str, retry: dict[str, Any] | None, stage: str | None = None) -> RetryNotice | None:
    """The stored notice (job.retry) as a status shows it: only while its job is queued or running."""
    if not retry or status not in (Status.QUEUED, Status.RUNNING):
        return None
    return RetryNotice(stage=stage, **retry)


def controls_retry_notice_of(counts: dict[str, Any], retry: dict[str, Any] | None) -> RetryNotice | None:
    """The controls delivery's notice (controls_delivery.retry), shown only while controls wait."""
    return retry_notice_of(Status.QUEUED, retry, Step.CONTROLS) if counts.get("controls_waiting") else None


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
    mapping_id: str | None = None  # a service mapping's
    asset_id: int | None
    asset_name: str | None = None
    status: Status  # queued or running
    queued_at: datetime | None  # when its job was queued (or last handed on)
    created_at: datetime | None
    attempts: int = 0
    user_id: str | None = None
    progress: JobProgress | None = None  # a run's; None for a remediation plan or a service mapping
    retrying: RetryNotice | None = None  # waiting out an AI or store outage: why, which try comes when


class JobList(BaseModel):
    jobs: list[JobView]  # oldest first; at most JobControl.LIST_MAX of each kind (runs, plans, mappings)
    total: int  # all of them, though the list was cut


class SessionDeleted(BaseModel):
    session_id: str
    scenarios: int  # removed with it
    remediation_plans: int


class PlanCancelled(BaseModel):
    remediation_id: str
    status: Status


class MonitoredJob(BaseModel):
    """One job of any kind as GET /v1/admin/jobs lists it: what it is, where it is, why it failed or waits,
    and which worker runs it."""

    id: str
    module: str  # threat_scenarios, remediation, service_mapper, external_intelligence, library_embeddings
    kind: str  # the task (tsg_map_services, tsg_write_scenarios, ...) or the admin job kind
    collection: str  # where its record lives
    entity_id: int | str | None = None
    status: str  # queued, running, done, failed, cancelled
    retrying: RetryNotice | None = None  # queued again after an outage: which try comes when
    attempts: int | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: dict[str, Any] | None = None  # {code, message, reason?} of a failed job
    task_id: str | None = None
    worker: str | None = None
    request_id: str | None = None  # the API request that queued it: its log lines carry the same id
    lease_until: datetime | None = None  # a running job past this has lost its worker; None for admin jobs
    resends: int | None = None  # times the reaper re-sent its lost message


class QueueState(BaseModel):
    waiting: int | None  # messages not yet taken by a worker; None when the broker could not be read
    workers_online: int | None  # None when the worker heartbeats could not be read


class JobMonitor(BaseModel):
    """Every job of every kind, newest first, and each queue's backlog and workers."""

    jobs: list[MonitoredJob]
    queues: dict[str, QueueState]


class AdminJobStarted(BaseModel):
    job_id: str
    status: Status


class EmbeddingsBuildResult(BaseModel):
    counts: dict[str, int] = Field(description="Rows each library holds now, each with its vector.")
    newly_embedded: dict[str, int] = Field(description="Vectors made while the build ran, per library.")


class IntelSourceOutcome(BaseModel):
    """What one import did to one source."""

    source: IntelSource
    outcome: RefreshResult = Field(description="refreshed, unchanged, failed, skipped or claim_lost")
    new_data: bool = Field(description="The stored data changed; false = MITRE had nothing new (a check only).")
    new_versions: int = Field(description="Records stored as new or changed.")
    retired: int = Field(description="Records MITRE no longer lists, taken out of use.")


class IntelRefreshResult(BaseModel):
    source: IntelSource | None = Field(default=None, description="The source refreshed; none = every source due.")
    sources: list[IntelSourceOutcome] = Field(default=[], description="Each source's outcome, in import order.")
    index_error: dict[str, str] | None = Field(
        default=None,
        description=(
            "Why the evidence index could not be rebuilt after the refresh: {code, message} and, when the AI "
            "was down, unreachable, busy or timed out, its reason. The refreshed data is kept."
        ),
    )


class AdminJobOut(BaseModel):
    job_id: str
    kind: AdminJobKind
    status: Status
    requested_by: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: EmbeddingsBuildResult | IntelRefreshResult | None = None
    error: dict[str, str] | None = None


class ControlLinksResult(BaseModel):
    judged: int = Field(default=0, description="Mitigations the AI judged in this run; their links were saved.")
    unchanged: int = Field(default=0, description="Mitigations the same as stored: no AI call.")
    failed: int = Field(default=0, description="Mitigations that could not be judged; their earlier links stay.")


class ControlLinksJobOut(BaseModel):
    """A control-links preparation as its own routes show it (AdminJobOut's shape stays as the UI reads it)."""

    job_id: str
    kind: str
    status: Status
    requested_by: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: ControlLinksResult | None = None
    error: dict[str, str] | None = None
