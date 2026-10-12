"""Admin endpoints to mint, list and revoke API-client keys (admin key only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.api.dependencies import AdminUser, require_admin_api_key
from app.models.api_clients import ApiClientList, ApiClientOut, MintedApiClient, MintRequest
from app.services.api_clients import ApiClientService, get_api_client_service

router = APIRouter(
    prefix="/v1/tsg/api-clients", tags=["api-clients"], dependencies=[Depends(require_admin_api_key)]
)


Service = Annotated[ApiClientService, Depends(get_api_client_service)]


@router.post("", status_code=201, response_model=MintedApiClient, summary="Mint an API key (shown once)")
def mint_api_client(body: MintRequest, response: Response, service: Service, actor: AdminUser) -> dict:
    client, api_key = service.mint_api_client(body.name, body.description, actor)
    response.headers["Cache-Control"] = "no-store"
    return {**client, "api_key": api_key}


@router.get("", response_model=ApiClientList, summary="List API clients (never secrets)")
def list_api_clients(service: Service, active: bool | None = None) -> dict:
    items = service.list_api_clients(active)
    return {"items": items, "total": len(items)}


@router.post("/{client_id}/revoke", response_model=ApiClientOut, summary="Revoke an API key")
def revoke_api_client(client_id: str, service: Service, actor: AdminUser) -> dict:
    return service.revoke_api_client(client_id, actor)
