"""Endpoints for external intelligence, in the order an operator uses them: the on/off switch, an import of
the sources now and reading it, the health report, then the withdrawal and re-approval of a source. No
admin key and no API key on any of them (owner, 2026-10-15); every change is audited as X-User-Id, else
"admin". The sources are also imported every hour while the switch is on, without these."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import AdminUser
from app.container import get_external_intelligence_service
from app.core.constants import ApiTag, IntelSource
from app.models.admin.admin_jobs import AdminJobOut, AdminJobStarted
from app.models.external_intelligence.intel_admin import (
    IntelHealthOut,
    IntelRefreshBody,
    IntelSourceApproved,
    IntelSourceRevoked,
    IntelSwitchBody,
    IntelSwitchOut,
)
from app.services.external_intelligence.external_intelligence_service import ExternalIntelligenceService

router = APIRouter(prefix="/v1/tsg/intel", tags=[ApiTag.INTELLIGENCE])

Intelligence = Annotated[ExternalIntelligenceService, Depends(get_external_intelligence_service)]


@router.get("/switch", response_model=IntelSwitchOut, summary="1. Is external intelligence on?")
def read_intel_switch(service: Intelligence) -> dict:
    """`env_enabled`: the env file's EXTERNAL_INTELLIGENCE_ENABLED; `runtime_enabled`: this switch;
    `effective`: both on, so the feeds are imported and new scenarios cite them."""
    return service.get_intelligence_switch_state()


@router.put("/switch", response_model=IntelSwitchOut, summary="2. Turn external intelligence on or off")
def change_intel_switch(body: IntelSwitchBody, service: Intelligence, actor: AdminUser) -> dict:
    """`{"enabled": false}`: no more hourly imports, imports by hand are refused, new scenarios are written
    without the feeds; nothing is deleted. `{"enabled": true}`: back on, and an import starts. Audited.
    409 while the env file says EXTERNAL_INTELLIGENCE_ENABLED=false (only the env file and a restart change
    that)."""
    return service.update_intelligence_switch_state(body.enabled, actor)


@router.post("/refresh", status_code=202, response_model=AdminJobStarted, summary="3. Import the feeds now")
def start_intel_refresh(
    service: Intelligence, actor: AdminUser, body: IntelRefreshBody | None = None
) -> dict:
    """A background import, 202 `{job_id}`: every source that is due (all 6 the first time), or one with
    `{"source": "cisa_kev"}`. Needed by hand only the first time; then it runs every hour by itself. 409 while
    the switch is off, or while an import runs (`details.job_id` names it); 422 an unknown or withdrawn
    source."""
    return service.create_intelligence_refresh(actor, body.source if body else None)


@router.get("/refresh/{job_id}", response_model=AdminJobOut, summary="4. Read an import")
def read_intel_refresh(job_id: Annotated[str, Path(max_length=64)], service: Intelligence) -> dict:
    """Poll until `status` is `done` (or `failed`, with `error`); then check the health (5)."""
    return service.get_intelligence_refresh(job_id)


@router.get("/health", response_model=IntelHealthOut, summary="5. Feeds and data health")
def read_intel_health(service: Intelligence) -> dict:
    """Each source's state, the active `snapshot_id` (set once data is imported and indexed: runs need it),
    `stale`, `pending_sources`, `no_data`, and the evidence settings (reranker, threshold)."""
    return service.get_intelligence_health()


@router.post(
    "/sources/{source}/revoke",
    response_model=IntelSourceRevoked,
    summary="6. Withdraw a source and delete its data",
)
def revoke_intel_source(source: IntelSource, service: Intelligence, actor: AdminUser) -> dict:
    """Audited first; then the source's records and vectors are deleted and it is no longer imported.
    Scenarios already written keep what they cite."""
    return service.revoke_intelligence_source(source, actor)


@router.post(
    "/sources/{source}/approve",
    response_model=IntelSourceApproved,
    summary="7. Approve a withdrawn source again",
)
def approve_intel_source(source: IntelSource, service: Intelligence, actor: AdminUser) -> dict:
    """It starts empty and an import of it is queued (`refresh_job_id`; null when one already runs or the
    switch is off). 409 while the env file switches the feature off."""
    return service.approve_intelligence_source(source, actor)
