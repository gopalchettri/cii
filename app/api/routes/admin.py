"""Admin endpoints (admin key only): API-client keys, the library's embeddings build, every job, curation."""

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response

from app.api.deps import AdminUser, DbDep, Limit, Offset, require_admin_api_key
from app.core import constants as c
from app.core.clock import utc_now
from app.core.exceptions import NotFound
from app.crud import admin as admin_crud
from app.crud.admin_jobs import AdminJobRepository, get_admin_job_repository
from app.crud.audit import get_audit_repository
from app.crud.library import ThreatRepository, get_threat_repository
from app.domain import jobs
from app.domain.shared.audit import admin_actor, audit_target
from app.schemas.admin import ApiClientList, ApiClientOut, MintedApiClient, MintRequest
from app.schemas.curation import LibraryDecisionResult, LibraryDecisions, PendingThreatList
from app.schemas.jobs import AdminJobOut, AdminJobStarted, JobMonitor, MonitoredJob

router = APIRouter(dependencies=[Depends(require_admin_api_key)])
keys = APIRouter(prefix="/v1/tsg/api-clients", tags=[c.ApiTag.API_KEYS])
embeddings = APIRouter(prefix="/v1/embeddings", tags=[c.ApiTag.EMBEDDINGS])
monitor = APIRouter(prefix="/v1/admin/jobs", tags=[c.ApiTag.JOBS])
curation = APIRouter(prefix="/v1/tsg/library", tags=[c.ApiTag.CURATION])

Threats = Annotated[ThreatRepository, Depends(get_threat_repository)]
AdminJobs = Annotated[AdminJobRepository, Depends(get_admin_job_repository)]
_JOB_ID = Annotated[str, Path(max_length=64)]


@keys.post("", status_code=201, response_model=MintedApiClient, summary="1. Mint an API key (shown once)")
def mint_api_client(body: MintRequest, response: Response, db: DbDep, actor: AdminUser) -> dict:
    """Send `{"name": "shield-frontend", "description": "..."}` with `X-Admin-Key`. The answer holds
    `api_key` ONCE: keep it; every caller sends it as `X-API-Key`. 201."""
    client, api_key = admin_crud.create_api_client(db, body.name, body.description, actor)
    get_audit_repository().create_audit_record(
        c.AuditAction.KEY_MINTED,
        admin_actor(actor),
        audit_target(c.AuditTarget.API_CLIENT, client["client_id"]),
        after={"name": body.name, "key_prefix": client["key_prefix"], "active": True},
    )
    response.headers["Cache-Control"] = "no-store"
    return {**client, "api_key": api_key}


@keys.get("", response_model=ApiClientList, summary="2. List API keys")
def list_api_clients(db: DbDep, active: bool | None = None) -> dict:
    """Every client's id, name and state (`?active=true` or `false`); never a key."""
    items = admin_crud.list_api_clients(db, active)
    return {"items": items, "total": len(items)}


@keys.post("/{client_id}/revoke", response_model=ApiClientOut, summary="3. Revoke an API key")
def revoke_api_client(client_id: str, db: DbDep, actor: AdminUser) -> dict:
    """The key stops working at once; the client stays listed as revoked."""
    client, revoked_now = admin_crud.revoke_api_client(db, client_id, actor)
    if revoked_now:
        get_audit_repository().create_audit_record(
            c.AuditAction.KEY_REVOKED,
            admin_actor(actor),
            audit_target(c.AuditTarget.API_CLIENT, client_id),
            before={"active": True},
            after={"active": False},
        )
    return client


@embeddings.post(
    "", status_code=202, response_model=AdminJobStarted, summary="1. Build the library's search vectors now"
)
def start_embeddings_build(actor: AdminUser, admin_jobs: AdminJobs) -> dict:
    """A background build: 202 `{job_id}`. One at a time (409 `job_in_progress`, `details.job_id`). Needed
    once after the library is loaded; later builds run by themselves."""
    job_id, kind = uuid.uuid4().hex, c.AdminJobKind.EMBEDDINGS_BUILD
    job = {"_id": job_id, "kind": kind, "status": c.Status.QUEUED, "requested_by": actor}
    admin_crud.queue_admin_job(
        admin_jobs,
        jobs.send_admin_job,
        c.TaskName.BUILD_LIBRARY_INDEXES,
        job,
        c.AdminJobMessage.IN_PROGRESS,
        c.AdminJobMessage.NOT_SENT,
    )
    target = audit_target(c.AuditTarget.ADMIN_JOB, job_id)
    get_audit_repository().create_audit_record(
        c.AuditAction.ADMIN_JOB_STARTED, admin_actor(actor), target, after={"kind": kind}
    )
    return {"job_id": job_id, "status": c.Status.QUEUED}


@embeddings.get("/{job_id}", response_model=AdminJobOut, summary="2. Read a build")
def read_embeddings_build(job_id: Annotated[str, Path(max_length=64)], admin_jobs: AdminJobs) -> dict:
    """Its `status`: queued, running, then done or failed (with `error`)."""
    record = admin_jobs.get_admin_job(job_id, c.AdminJobKind.EMBEDDINGS_BUILD)
    if record is None:
        raise NotFound(c.AdminJobMessage.NOT_FOUND.format(job_id=job_id))
    return {"job_id": record.pop("_id"), **record}


@monitor.get("", response_model=JobMonitor, summary="Every job, queue and worker")
def list_all_jobs(
    status: Annotated[list[c.Status] | None, Query()] = None,
    module: Annotated[c.Module | None, Query()] = None,
    kind: Annotated[str | None, Query(max_length=64)] = None,
    hours: Annotated[int, Query(ge=1, le=24 * 90)] = 24,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    request_id: Annotated[str | None, Query(max_length=64)] = None,
) -> JobMonitor:
    """Every job of every kind (runs, plans, service mappings, intelligence refreshes, embeddings builds)
    active in the last `hours`, newest first: status (queued, running, done, failed, cancelled), the retry it
    waits for, its error, the worker running it. `queues`: each queue's waiting messages and workers online.
    Filter by `module` (threat_scenarios, remediation, service_mapper, external_intelligence,
    library_embeddings, maintenance), `status` (repeatable), `kind` (a task name such as tsg_map_services,
    or an admin job kind) and `request_id` (the X-Request-Id of the call that queued it)."""
    since = utc_now() - timedelta(hours=hours)
    return jobs.list_all_jobs(since, list(status or []), kind, limit, module, request_id)


@monitor.get("/{job_id}", response_model=MonitoredJob, summary="One job")
def read_any_job(job_id: _JOB_ID) -> MonitoredJob:
    """Any job by its id (an import's or build's job_id, or a run's, plan's or mapping's id): its module,
    status, error, retry and worker. 404 for an unknown id."""
    return jobs.get_any_job(job_id)


@monitor.post(
    "/{job_id}/cancel", response_model=MonitoredJob, summary="Cancel an intelligence import or embeddings build"
)
def cancel_admin_job(job_id: _JOB_ID, actor: AdminUser) -> MonitoredJob:
    """Queued: it never starts. Running: an import stops before its next source, keeping what it
    read (the next import continues from there); a build finishes but its outcome is dropped. The job reads
    `cancelled`, a new one of its kind can start at once, and the cancel is audited. 409 `nothing_to_cancel`
    for a job already ended or another module's job (a run or plan has its own cancel)."""
    return jobs.cancel_admin_job(job_id, actor)


@curation.get("/pending", response_model=PendingThreatList, summary="1. Threats waiting for a curator")
def list_pending_threats(threats: Threats, offset: Offset = 0, limit: Limit = c.Limits.PAGE_SIZE_DEFAULT) -> dict:
    """Threat types and threats proposed by hand-written scenarios or promoted from AI ones, oldest
    first; paged."""
    items, total = threats.list_pending_threats(offset, limit)
    return {"items": items, "total": total}


@curation.post("/decisions", response_model=LibraryDecisionResult, summary="2. Approve or reject them")
def decide_pending_threats(body: LibraryDecisions, threats: Threats, actor: AdminUser) -> dict:
    """Send `{"approve": [512], "reject": [513]}` (pending ids). An approved row joins the live library;
    a rejected one is never proposed again."""
    key = decision_operation_key(body.approve, body.reject, actor)
    results, applied_now = threats.decide_pending_threats(key, body.approve, body.reject, actor)
    if applied_now:  # a replay from its operation record was audited when it was applied
        get_audit_repository().create_audit_record(
            c.AuditAction.LIBRARY_DECIDED,
            admin_actor(actor),
            audit_target(c.AuditTarget.LIBRARY_THREAT, [str(row["catalogue_id"]) for row in results]),
            details={"approve": body.approve, "reject": body.reject, "results": results},
        )
    return {"results": results}


def decision_operation_key(approve: list[int], reject: list[int], decided_by: str) -> str:
    """The operation key of one set of curator decisions: the same decisions sent again share it."""
    payload = {"approve": approve, "reject": reject, "decided_by": decided_by}
    return f"decide:{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}"


for _part in (keys, embeddings, monitor, curation):
    router.include_router(_part)
