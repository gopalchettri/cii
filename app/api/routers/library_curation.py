"""Admin endpoints for the curator (admin key only): list the threats waiting for a decision (#23), approve or
reject them (#24)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import AdminUser, Limit, Offset, require_admin_api_key
from app.core.constants import Limits
from app.models.library_curation import LibraryDecisionResult, LibraryDecisions, PendingThreatList
from app.services.library_curation import LibraryCuration, get_library_curation

router = APIRouter(prefix="/v1/tsg/library", tags=["library"], dependencies=[Depends(require_admin_api_key)])

Service = Annotated[LibraryCuration, Depends(get_library_curation)]


@router.get("/pending", response_model=PendingThreatList, summary="List the threats waiting for a curator")
def list_pending_threats(
    service: Service, offset: Offset = 0, limit: Limit = Limits.PAGE_SIZE_DEFAULT
) -> dict:
    return service.list_pending(offset, limit)


@router.post("/decisions", response_model=LibraryDecisionResult, summary="Approve or reject pending threats")
def decide_pending_threats(body: LibraryDecisions, service: Service, actor: AdminUser) -> dict:
    return service.decide(body, actor)
