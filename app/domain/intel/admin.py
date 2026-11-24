"""The admin API's external intelligence actions."""

import uuid
from typing import Any

import structlog

from app.core.config import get_settings
from app.core.constants import (
    CONTROL_LINKS_JOB_KIND,
    EVIDENCE_THRESHOLD_CALIBRATED_ON,
    AdminJobKind,
    AdminJobMessage,
    AuditAction,
    AuditTarget,
    ControlLinkMessage,
    IntelDocId,
    IntelRefreshMessage,
    IntelSource,
    LogEvent,
    Status,
    TaskName,
)
from app.core.exceptions import Conflict, NotFound, Unavailable
from app.crud.admin import queue_admin_job
from app.crud.admin_jobs import get_admin_job_repository
from app.crud.attack import get_attack_repository, get_control_link_repository
from app.crud.audit import get_audit_repository
from app.crud.intel import get_intel_feed_repository, get_intel_snapshot_repository
from app.domain.intel.index import get_evidence_index_keeper
from app.domain.intel.switch import get_intelligence_switch
from app.domain.jobs import send_admin_job
from app.domain.shared.audit import admin_actor, audit_target
from app.schemas.intel_records import SwitchState, source_health_in_registry_order


def evidence_settings(rerank_model: str, threshold: float) -> dict[str, Any]:
    """The reranker's name (never its path)."""
    model = rerank_model.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    calibration = EVIDENCE_THRESHOLD_CALIBRATED_ON.get(model)
    calibrated_on = calibration[0] if calibration and calibration[1] == threshold else None
    return {
        "rerank_model": model,
        "threshold": threshold,
        "threshold_calibrated": calibrated_on is not None,
        "threshold_calibrated_on": calibrated_on,
    }


log = structlog.get_logger(__name__)
_KIND = AdminJobKind.INTEL_REFRESH


def get_intelligence_switch_state() -> dict[str, Any]:
    """The switch state; with the env master off it answers from the environment alone."""
    return get_intelligence_switch().state().as_doc()


def update_intelligence_switch_state(enabled: bool, changed_by: str) -> dict[str, Any]:
    """Set, audit and log the run-time switch (409 while the env master switch is off)."""
    if not get_settings().external_intelligence_enabled:  # nothing of the feature is written while off
        raise Conflict(IntelRefreshMessage.SWITCH_OFF)
    switch = get_intelligence_switch()
    before = switch.state()
    after = switch.save(enabled, changed_by)
    target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, IntelDocId.SWITCH)
    get_audit_repository().create_audit_record(
        AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED,
        admin_actor(changed_by),
        target,
        before=_flags(before),
        after=_flags(after),
    )
    log.info(LogEvent.EXTERNAL_INTELLIGENCE_SWITCH_CHANGED, enabled=enabled, changed_by=changed_by)
    if not (enabled and after.effective):
        return after.as_doc()
    try:
        refresh = {"refresh_job_id": create_intelligence_refresh(changed_by)["job_id"]}
    except Conflict:
        refresh = {"refresh_job_id": None}  # one is already queued or running
    except Unavailable:
        refresh = {"refresh_job_id": None, "refresh_not_queued": IntelRefreshMessage.NOT_SENT.value}
    return after.as_doc() | refresh


def create_intelligence_refresh(requested_by: str, source: IntelSource | None = None) -> dict[str, Any]:
    """Queue a refresh and return its id (with the switch off too: the MITRE run reads the import, ADR-010)."""
    job_id = uuid.uuid4().hex
    job: dict[str, Any] = {
        "_id": job_id,
        "kind": _KIND,
        "status": Status.QUEUED,
        "requested_by": requested_by,
        "source": source,
    }
    queue_admin_job(
        get_admin_job_repository(),
        send_admin_job,
        TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
        job,
        IntelRefreshMessage.IN_PROGRESS,
        IntelRefreshMessage.NOT_SENT,
    )
    target = audit_target(AuditTarget.ADMIN_JOB, job_id)
    after = {"kind": _KIND, "source": source}
    get_audit_repository().create_audit_record(
        AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after=after
    )
    return {"job_id": job_id, "status": Status.QUEUED}


def get_intelligence_refresh(job_id: str) -> dict[str, Any]:
    """One refresh job as the API shows it; 404 for any other job."""
    record = get_admin_job_repository().get_admin_job(job_id, _KIND)
    if record is None:
        raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
    return {"job_id": record.pop("_id"), **record}


def create_control_links_job(requested_by: str) -> dict[str, Any]:
    """Queue a control-links preparation and return its id (with the switch off too: the MITRE run's controls
    start from these links, ADR-010)."""
    job_id = uuid.uuid4().hex
    kind = {"kind": CONTROL_LINKS_JOB_KIND}
    queue_admin_job(
        get_admin_job_repository(),
        send_admin_job,
        TaskName.LINK_MITIGATIONS,
        kind | {"_id": job_id, "status": Status.QUEUED, "requested_by": requested_by},
        ControlLinkMessage.IN_PROGRESS,
        ControlLinkMessage.NOT_SENT,
    )
    target = audit_target(AuditTarget.ADMIN_JOB, job_id)
    get_audit_repository().create_audit_record(
        AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after=kind
    )
    return {"job_id": job_id, "status": Status.QUEUED}


def get_control_links_job(job_id: str) -> dict[str, Any]:
    """One control-links preparation as the API shows it; 404 for any other job."""
    record = get_admin_job_repository().get_admin_job(job_id, CONTROL_LINKS_JOB_KIND)
    if record is None:
        raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
    return {"job_id": record.pop("_id"), **record}


def get_control_links_summary() -> dict[str, Any]:
    """Of the mitigations the stored graph lists: how many are prepared, with and without a control, or not yet."""
    listed = {row["attack_id"] for row in get_attack_repository().list_mitigations()}
    return get_control_link_repository().summarise_links(listed)


def get_intelligence_health() -> dict[str, Any]:
    """The health report with the evidence settings. The sources are shown with the switch off too: the MITRE
    import runs whatever the switch says (ADR-010); only the evidence part stays unread while off."""
    settings = get_settings()
    evidence = evidence_settings(settings.rerank_model, settings.evidence_similarity_threshold)
    sources = source_health_in_registry_order(get_intel_feed_repository().list(sources=True))
    pending = [health.source for health in sources if health.is_pending]  # first data awaited
    if settings.external_intelligence_enabled:
        switch = get_intelligence_switch().state().as_doc()
        active = get_intel_snapshot_repository().get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
        snapshot_id = active.get("snapshot_id") if active else get_evidence_index_keeper().peek_index().snapshot_id
    else:
        switch, snapshot_id = SwitchState(env_enabled=False).as_doc(), None
    return {
        "switch": switch,
        "snapshot_id": snapshot_id,
        "pending_sources": pending,
        "no_data": len(pending) == len(sources),
        "sources": [health.as_doc() for health in sources],
        "evidence": evidence,
    }


def _flags(state: SwitchState) -> dict[str, bool]:
    return {"env_enabled": state.env_enabled, "runtime_enabled": state.runtime_enabled}
