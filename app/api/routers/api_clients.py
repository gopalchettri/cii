"""Admin endpoints to mint, list and revoke API-client keys (admin key only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.api.dependencies import AdminUser, require_admin_api_key
from app.core.constants import ApiTag
from app.models.api_clients import ApiClientList, ApiClientOut, MintedApiClient, MintRequest
from app.services.api_clients import ApiClientService, get_api_client_service

router = APIRouter(
    prefix="/v1/tsg/api-clients", tags=[ApiTag.API_KEYS], dependencies=[Depends(require_admin_api_key)]
)


Service = Annotated[ApiClientService, Depends(get_api_client_service)]


@router.post("", status_code=201, response_model=MintedApiClient, summary="1. Mint an API key (shown once)")
def mint_api_client(body: MintRequest, response: Response, service: Service, actor: AdminUser) -> dict:
    """Send `{"name": "shield-frontend", "description": "..."}` with `X-Admin-Key`. The answer holds
    `api_key` ONCE: keep it; every caller sends it as `X-API-Key`. 201."""
    client, api_key = service.mint_api_client(body.name, body.description, actor)
    response.headers["Cache-Control"] = "no-store"
    return {**client, "api_key": api_key}


@router.get("", response_model=ApiClientList, summary="2. List API keys")
def list_api_clients(service: Service, active: bool | None = None) -> dict:
    """Every client's id, name and state (`?active=true` or `false`); never a key."""
    items = service.list_api_clients(active)
    return {"items": items, "total": len(items)}


@router.post("/{client_id}/revoke", response_model=ApiClientOut, summary="3. Revoke an API key")
def revoke_api_client(client_id: str, service: Service, actor: AdminUser) -> dict:
    """The key stops working at once; the client stays listed as revoked."""
    return service.revoke_api_client(client_id, actor)
