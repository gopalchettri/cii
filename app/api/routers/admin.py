"""Admin endpoints (admin key only): mint, list and revoke API-client keys; build the library's embeddings now
(#18) and read the build (#19); every job of every kind with its queue and worker (GET /v1/admin/jobs). The
embeddings are also built every 30 minutes and after every library change, without these."""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response

from app.api.dependencies import AdminUser, require_admin_api_key
from app.container import get_admin_service, get_job_monitor_service
from app.core.clock import utc_now
from app.core.constants import ApiTag, Module, Status
from app.models.admin.admin_jobs import AdminJobOut, AdminJobStarted
from app.models.admin.api_clients import ApiClientList, ApiClientOut, MintedApiClient, MintRequest
from app.models.jobs.views import JobMonitor, MonitoredJob
from app.services.admin.admin_service import AdminService
from app.services.job_monitor.job_monitor_service import JobMonitorService

router = APIRouter(dependencies=[Depends(require_admin_api_key)])

Service = Annotated[AdminService, Depends(get_admin_service)]
Monitor = Annotated[JobMonitorService, Depends(get_job_monitor_service)]
_JOB_ID = Annotated[str, Path(max_length=64)]

_API_CLIENTS, _EMBEDDINGS = "/v1/tsg/api-clients", "/v1/embeddings"


@router.post(
    _API_CLIENTS,
    tags=[ApiTag.API_KEYS],
    status_code=201,
    response_model=MintedApiClient,
    summary="1. Mint an API key (shown once)",
)
def mint_api_client(body: MintRequest, response: Response, service: Service, actor: AdminUser) -> dict:
    """Send `{"name": "shield-frontend", "description": "..."}` with `X-Admin-Key`. The answer holds
    `api_key` ONCE: keep it; every caller sends it as `X-API-Key`. 201."""
    client, api_key = service.create_api_client(body.name, body.description, actor)
    response.headers["Cache-Control"] = "no-store"
    return {**client, "api_key": api_key}


@router.get(_API_CLIENTS, tags=[ApiTag.API_KEYS], response_model=ApiClientList, summary="2. List API keys")
def list_api_clients(service: Service, active: bool | None = None) -> dict:
    """Every client's id, name and state (`?active=true` or `false`); never a key."""
    items = service.list_api_clients(active)
    return {"items": items, "total": len(items)}


@router.post(
    f"{_API_CLIENTS}/{{client_id}}/revoke",
    tags=[ApiTag.API_KEYS],
    response_model=ApiClientOut,
    summary="3. Revoke an API key",
)
def revoke_api_client(client_id: str, service: Service, actor: AdminUser) -> dict:
    """The key stops working at once; the client stays listed as revoked."""
    return service.revoke_api_client(client_id, actor)


@router.post(
    _EMBEDDINGS,
    tags=[ApiTag.EMBEDDINGS],
    status_code=202,
    response_model=AdminJobStarted,
    summary="1. Build the library's search vectors now",
)
def start_embeddings_build(service: Service, actor: AdminUser) -> dict:
    """A background build: 202 `{job_id}`. One at a time (409 `job_in_progress`, `details.job_id`). Needed
    once after the library is loaded; later builds run by themselves."""
    return service.create_embeddings_build(actor)


@router.get(
    f"{_EMBEDDINGS}/{{job_id}}",
    tags=[ApiTag.EMBEDDINGS],
    response_model=AdminJobOut,
    summary="2. Read a build",
)
def read_embeddings_build(job_id: Annotated[str, Path(max_length=64)], service: Service) -> dict:
    """Its `status`: queued, running, then done or failed (with `error`)."""
    return service.get_embeddings_build(job_id)


@router.get(
    "/v1/admin/jobs", tags=[ApiTag.JOBS], response_model=JobMonitor, summary="Every job, queue and worker"
)
def list_all_jobs(
    monitor: Monitor,
    status: Annotated[list[Status] | None, Query()] = None,
    module: Annotated[Module | None, Query()] = None,
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
    return monitor.list_jobs(since, list(status or []), kind, limit, module, request_id)


@router.get("/v1/admin/jobs/{job_id}", tags=[ApiTag.JOBS], response_model=MonitoredJob, summary="One job")
def read_any_job(job_id: _JOB_ID, monitor: Monitor) -> MonitoredJob:
    """Any job by its id (an import's or build's job_id, or a run's, plan's or mapping's id): its module,
    status, error, retry and worker. 404 for an unknown id."""
    return monitor.get_job(job_id)


@router.post(
    "/v1/admin/jobs/{job_id}/cancel",
    tags=[ApiTag.JOBS],
    response_model=MonitoredJob,
    summary="Cancel an intelligence import or embeddings build",
)
def cancel_admin_job(job_id: _JOB_ID, monitor: Monitor, actor: AdminUser) -> MonitoredJob:
    """Queued: it never starts. Running: an import stops at its next NVD request or source, keeping what it
    read (the next import continues from there); a build finishes but its outcome is dropped. The job reads
    `cancelled`, a new one of its kind can start at once, and the cancel is audited. 409 `nothing_to_cancel`
    for a job already ended or another module's job (a run or plan has its own cancel)."""
    return monitor.cancel_job(job_id, actor)
