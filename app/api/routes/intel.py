"""Endpoints for external intelligence, in the order an operator uses them: the on/off switch, an import of
the sources now and reading it, the health report, the schedule, then the control links. No admin key and
no API key on any of them (owner, 2026-10-15); every change is audited as X-User-Id, else "admin". The
sources are also imported on the saved schedule while the switch is on, without these."""

from typing import Annotated

from fastapi import APIRouter, Path

from app.api.deps import AdminUser
from app.core.constants import ApiTag
from app.domain.intel import admin
from app.domain.intel import schedule as intel_schedule
from app.schemas.intel import (
    ControlLinksSummary,
    IntelHealthOut,
    IntelRefreshBody,
    IntelScheduleBody,
    IntelScheduleOut,
    IntelSwitchBody,
    IntelSwitchOut,
)
from app.schemas.jobs import AdminJobOut, AdminJobStarted, ControlLinksJobOut

router = APIRouter(prefix="/v1/tsg/intel", tags=[ApiTag.INTELLIGENCE])


@router.get("/switch", response_model=IntelSwitchOut, summary="1. Is external intelligence on?")
def read_intel_switch() -> dict:
    """`env_enabled`: the env file's EXTERNAL_INTELLIGENCE_ENABLED; `runtime_enabled`: this switch;
    `effective`: both on, so the feeds are imported and new scenarios cite them."""
    return admin.get_intelligence_switch_state()


@router.put("/switch", response_model=IntelSwitchOut, summary="2. Turn external intelligence on or off")
def change_intel_switch(body: IntelSwitchBody, actor: AdminUser) -> dict:
    """`{"enabled": false}`: no more scheduled imports, imports by hand are refused, new scenarios are written
    without the feeds; nothing is deleted. `{"enabled": true}`: back on, and an import starts. Audited.
    409 while the env file says EXTERNAL_INTELLIGENCE_ENABLED=false (only the env file and a restart change
    that)."""
    return admin.update_intelligence_switch_state(body.enabled, actor)


@router.post("/refresh", status_code=202, response_model=AdminJobStarted, summary="3. Import the feeds now")
def start_intel_refresh(actor: AdminUser, body: IntelRefreshBody | None = None) -> dict:
    """A background import, 202 `{job_id}`: every source, or one with
    `{"source": "mitre_attack_enterprise"}`. The import also runs by itself on the saved schedule (6); this
    starts one now. 409 while the switch is off, or while an import runs (`details.job_id` names it); 422 an
    unknown source."""
    return admin.create_intelligence_refresh(actor, body.source if body else None)


@router.get("/refresh/{job_id}", response_model=AdminJobOut, summary="4. Read an import")
def read_intel_refresh(job_id: Annotated[str, Path(max_length=64)]) -> dict:
    """Poll until `status` is `done` (or `failed`, with `error`); then check the health (5)."""
    return admin.get_intelligence_refresh(job_id)


@router.get("/health", response_model=IntelHealthOut, summary="5. Feeds and data health")
def read_intel_health() -> dict:
    """Each source's state, the active `snapshot_id` (set once data is imported and indexed: runs need it),
    `pending_sources`, `no_data`, and the evidence settings (reranker, threshold)."""
    return admin.get_intelligence_health()


@router.get("/schedule", response_model=IntelScheduleOut, summary="6. When is the import run by itself?")
def read_intel_schedule() -> dict:
    """The saved schedule with `next_run_at` and `last_run_at` (UTC). None saved yet: weekly, Sunday 02:00
    UTC, enabled, with one first import at the next check (the schedule is checked every minute). An import
    that failed is tried again within the hour."""
    return intel_schedule.read_schedule()


@router.put("/schedule", response_model=IntelScheduleOut, summary="7. Change when the import is run by itself")
def change_intel_schedule(body: IntelScheduleBody, actor: AdminUser) -> dict:
    """`{"enabled": true, "frequency": "weekly", "day_of_week": 6, "time": "02:00", "timezone": "Asia/Dubai"}`:
    `frequency` daily or weekly; `day_of_week` 0 (Monday) to 6 (Sunday), needed when weekly; `time` HH:MM in
    `timezone`, an IANA name. `{"enabled": false, ...}`: nothing is imported by itself; an import by hand (3)
    still runs. Audited. 422 an unknown time zone, a bad time or weekly without a day; 409 while the env file
    says EXTERNAL_INTELLIGENCE_ENABLED=false."""
    return intel_schedule.save_schedule(body, actor)


@router.get("/control-links", response_model=ControlLinksSummary, summary="8. How far are the controls linked?")
def read_control_links() -> dict:
    """The MITRE ATT&CK mitigations prepared so far, of those the stored data lists: `linked` have at least
    one library control, `without_links` have none; `not_prepared` are listed but not judged yet (or their
    judging failed); `prepared_at` is the newest preparation (null: nothing prepared yet)."""
    return admin.get_control_links_summary()


@router.post(
    "/control-links/prepare",
    status_code=202,
    response_model=AdminJobStarted,
    summary="9. Link the ATT&CK mitigations to library controls now",
)
def start_control_links(actor: AdminUser) -> dict:
    """A background preparation, 202 `{job_id}`: the AI judges which library controls do what each mitigation
    says; a mitigation that did not change costs no AI call. It also runs by itself after every import, as a
    job requested by `import`. Audited. 409 while the switch is off, or while one is queued or running
    (`details.job_id` names it)."""
    return admin.create_control_links_job(actor)


@router.get("/control-links/{job_id}", response_model=ControlLinksJobOut, summary="10. Read a preparation")
def read_control_links_job(job_id: Annotated[str, Path(max_length=64)]) -> dict:
    """Poll until `status` is `done` (or `failed`, with `error`); `result` counts the mitigations `judged`,
    `unchanged` and `failed` (a failed one keeps its earlier links)."""
    return admin.get_control_links_job(job_id)
