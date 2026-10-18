"""Admin endpoints (admin key only): mint, list and revoke API-client keys; build the library's embeddings now
(#18) and read the build (#19). The embeddings are also built every 30 minutes and after every library change,
without these."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response

from app.api.dependencies import AdminUser, require_admin_api_key
from app.container import get_admin_service
from app.core.constants import ApiTag
from app.models.admin.admin_jobs import AdminJobOut, AdminJobStarted
from app.models.admin.api_clients import ApiClientList, ApiClientOut, MintedApiClient, MintRequest
from app.services.admin.admin_service import AdminService

router = APIRouter(dependencies=[Depends(require_admin_api_key)])

Service = Annotated[AdminService, Depends(get_admin_service)]

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
