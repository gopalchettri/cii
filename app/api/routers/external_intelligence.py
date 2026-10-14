"""Admin endpoints for external intelligence (admin key only): the on/off switch, the health report, and a
refresh of the sources now, and the revoke and re-approval of a source. They are also refreshed every hour
while the switch is on, without these."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import AdminUser, require_admin_api_key
from app.core.constants import IntelSource
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

router = APIRouter(
    prefix="/v1/tsg/intel", tags=["external-intelligence"], dependencies=[Depends(require_admin_api_key)]
)

Admin = Annotated[IntelAdmin, Depends(get_intel_admin)]
Refreshes = Annotated[IntelRefreshes, Depends(get_intel_refreshes)]


@router.get("/switch", response_model=IntelSwitchOut, summary="Read the external intelligence switch")
def read_intel_switch(admin: Admin) -> dict:
    return admin.read_switch()


@router.put("/switch", response_model=IntelSwitchOut, summary="Turn external intelligence on or off")
def change_intel_switch(body: IntelSwitchBody, admin: Admin, actor: AdminUser) -> dict:
    return admin.change_switch(body.enabled, actor)


@router.get("/health", response_model=IntelHealthOut, summary="Sources, snapshot and evidence settings")
def read_intel_health(admin: Admin) -> dict:
    return admin.describe_health()


@router.post("/refresh", status_code=202, response_model=AdminJobStarted, summary="Refresh the sources now")
def start_intel_refresh(refreshes: Refreshes, actor: AdminUser, body: IntelRefreshBody | None = None) -> dict:
    return refreshes.start(actor, body.source if body else None)


@router.post(
    "/sources/{source}/revoke",
    response_model=IntelSourceRevoked,
    summary="Revoke a source and purge its data",
)
def revoke_intel_source(source: IntelSource, admin: Admin, actor: AdminUser) -> dict:
    return admin.revoke_source(source, actor)


@router.post(
    "/sources/{source}/approve",
    response_model=IntelSourceApproved,
    summary="Approve a revoked source again and refresh it (409 while the master switch is off)",
)
def approve_intel_source(source: IntelSource, admin: Admin, actor: AdminUser) -> dict:
    return admin.approve_source(source, actor)


@router.get("/refresh/{job_id}", response_model=AdminJobOut, summary="Read an intelligence refresh")
def read_intel_refresh(job_id: Annotated[str, Path(max_length=64)], refreshes: Refreshes) -> dict:
    return refreshes.read(job_id)
