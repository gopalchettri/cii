"""Admin endpoints for the library's embeddings (admin key only): build them now (#18), read the build (#19).
They are also built every 30 minutes and after every library change, without these."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import AdminUser, require_admin_api_key
from app.core.constants import ApiTag
from app.models.admin_jobs import AdminJobOut, AdminJobStarted
from app.services.embeddings_builds import EmbeddingsBuilds, get_embeddings_builds

router = APIRouter(
    prefix="/v1/embeddings", tags=[ApiTag.EMBEDDINGS], dependencies=[Depends(require_admin_api_key)]
)

Service = Annotated[EmbeddingsBuilds, Depends(get_embeddings_builds)]


@router.post(
    "", status_code=202, response_model=AdminJobStarted, summary="1. Build the library's search vectors now"
)
def start_embeddings_build(service: Service, actor: AdminUser) -> dict:
    """A background build: 202 `{job_id}`. One at a time (409 `job_in_progress`, `details.job_id`). Needed
    once after the library is loaded; later builds run by themselves."""
    return service.start(actor)


@router.get("/{job_id}", response_model=AdminJobOut, summary="2. Read a build")
def read_embeddings_build(job_id: Annotated[str, Path(max_length=64)], service: Service) -> dict:
    """Its `status`: queued, running, then done or failed (with `error`)."""
    return service.read(job_id)
