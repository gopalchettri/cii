"""Endpoints for external intelligence, in the order an operator uses them: the on/off switch, an import of
the sources now and reading it, the health report, then the withdrawal and re-approval of a source. No
admin key and no API key on any of them (owner, 2026-10-15); every change is audited as X-User-Id, else
"admin". The sources are also imported every hour while the switch is on, without these."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import AdminUser
from app.core.constants import ApiTag, IntelSource
from app.models.admin_jobs import AdminJobOut, AdminJobStarted
from app.models.external_intelligence.intel_admin import (
    IntelHealthOut,
    IntelRefreshBody,
    IntelSourceApproved,
    IntelSourceRevoked,
    IntelSwitchBody,
    IntelSwitchOut,
)
from app.services.external_intelligence.intel_admin import IntelAdmin, get_intel_admin
from app.services.external_intelligence.intel_refreshes import IntelRefreshes, get_intel_refreshes

router = APIRouter(prefix="/v1/tsg/intel", tags=[ApiTag.INTELLIGENCE])

Admin = Annotated[IntelAdmin, Depends(get_intel_admin)]
Refreshes = Annotated[IntelRefreshes, Depends(get_intel_refreshes)]


@router.get("/switch", response_model=IntelSwitchOut, summary="1. Is external intelligence on?")
def read_intel_switch(admin: Admin) -> dict:
    """`env_enabled`: the env file's EXTERNAL_INTELLIGENCE_ENABLED; `runtime_enabled`: this switch;
    `effective`: both on, so the feeds are imported and new scenarios cite them."""
    return admin.read_switch()


@router.put("/switch", response_model=IntelSwitchOut, summary="2. Turn external intelligence on or off")
def change_intel_switch(body: IntelSwitchBody, admin: Admin, actor: AdminUser) -> dict:
    """`{"enabled": false}`: no more hourly imports, imports by hand are refused, new scenarios are written
    without the feeds; nothing is deleted. `{"enabled": true}`: back on, and an import starts. Audited.
    409 while the env file says EXTERNAL_INTELLIGENCE_ENABLED=false (only the env file and a restart change
    that)."""
    return admin.change_switch(body.enabled, actor)


@router.post("/refresh", status_code=202, response_model=AdminJobStarted, summary="3. Import the feeds now")
def start_intel_refresh(refreshes: Refreshes, actor: AdminUser, body: IntelRefreshBody | None = None) -> dict:
    """A background import, 202 `{job_id}`: every source that is due (all 6 the first time), or one with
    `{"source": "cisa_kev"}`. Needed by hand only the first time; then it runs every hour by itself. 409 while
    the switch is off, or while an import runs (`details.job_id` names it); 422 an unknown or withdrawn
    source."""
    return refreshes.start(actor, body.source if body else None)


@router.get("/refresh/{job_id}", response_model=AdminJobOut, summary="4. Read an import")
def read_intel_refresh(job_id: Annotated[str, Path(max_length=64)], refreshes: Refreshes) -> dict:
    """Poll until `status` is `done` (or `failed`, with `error`); then check the health (5)."""
    return refreshes.read(job_id)


@router.get("/health", response_model=IntelHealthOut, summary="5. Feeds and data health")
def read_intel_health(admin: Admin) -> dict:
    """Each source's state, the active `snapshot_id` (set once data is imported and indexed: runs need it),
    `stale`, `pending_sources`, `no_data`, and the evidence settings (reranker, threshold)."""
    return admin.describe_health()


@router.post(
    "/sources/{source}/revoke",
    response_model=IntelSourceRevoked,
    summary="6. Withdraw a source and delete its data",
)
def revoke_intel_source(source: IntelSource, admin: Admin, actor: AdminUser) -> dict:
    """Audited first; then the source's records and vectors are deleted and it is no longer imported.
    Scenarios already written keep what they cite."""
    return admin.revoke_source(source, actor)


@router.post(
    "/sources/{source}/approve",
    response_model=IntelSourceApproved,
    summary="7. Approve a withdrawn source again",
)
def approve_intel_source(source: IntelSource, admin: Admin, actor: AdminUser) -> dict:
    """It starts empty and an import of it is queued (`refresh_job_id`; null when one already runs or the
    switch is off). 409 while the env file switches the feature off."""
    return admin.approve_source(source, actor)
