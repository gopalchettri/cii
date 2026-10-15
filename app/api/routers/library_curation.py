"""Admin endpoints for the curator (admin key only): list the threats waiting for a decision (#23), approve or
reject them (#24)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import AdminUser, Limit, Offset, require_admin_api_key
from app.core.constants import ApiTag, Limits
from app.models.library_curation import LibraryDecisionResult, LibraryDecisions, PendingThreatList
from app.services.library_curation import LibraryCuration, get_library_curation

router = APIRouter(
    prefix="/v1/tsg/library", tags=[ApiTag.CURATION], dependencies=[Depends(require_admin_api_key)]
)

Service = Annotated[LibraryCuration, Depends(get_library_curation)]


@router.get("/pending", response_model=PendingThreatList, summary="1. Threats waiting for a curator")
def list_pending_threats(
    service: Service, offset: Offset = 0, limit: Limit = Limits.PAGE_SIZE_DEFAULT
) -> dict:
    """Threat types and threats proposed by hand-written scenarios or promoted from AI ones, oldest
    first; paged."""
    return service.list_pending(offset, limit)


@router.post("/decisions", response_model=LibraryDecisionResult, summary="2. Approve or reject them")
def decide_pending_threats(body: LibraryDecisions, service: Service, actor: AdminUser) -> dict:
    """Send `{"approve": [512], "reject": [513]}` (pending ids). An approved row joins the live library;
    a rejected one is never proposed again."""
    return service.decide(body, actor)
