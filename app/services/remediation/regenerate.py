"""A new version of a remediation plan: only while its scenario is still accepted, its run is not being
deleted (409 run_being_deleted, nothing written), its latest version is done, failed or cancelled, and the
plan has fewer than REGENERATIONS_MAX_VERSION_COUNT versions. The new version's register is read against the
current library with no AI call, and its plan job completes the snapshot. One conditional append; a delete
landing meanwhile stops the new version (409 run_being_deleted), else the plan job is sent."""

from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.constants import AuditAction, AuditTarget, Status, TaskName
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.jobs.repository import new_job
from app.data_access.remediation.repository import (
    PLANNED_SCENARIO_FIELDS,
    is_plan_run_being_deleted,
    remediation_plans,
    stop_remediation_plan_version,
)
from app.data_access.scenario.repository import scenarios
from app.domain.remediation.plan_rules import (
    check_plan_changeable,
    check_plan_owner,
    check_regenerable,
    new_version,
    run_being_deleted,
    version_in_progress,
)
from app.models.api_clients import Principal
from app.models.remediation import PlanRequested
from app.models.remediation_requests import RegisterData
from app.realtime.publisher import publish_remediation_status
from app.services.audit import audit_target, caller_actor
from app.services.remediation.snapshots import SnapshotMaker, get_snapshot_maker
from app.worker.celery_app import send_job


class PlanRegeneration:
    def __init__(self, snapshots: SnapshotMaker) -> None:
        self._snapshots = snapshots

    def regenerate(self, principal: Principal, remediation_id: str) -> PlanRequested:
        read = read_owned(principal, remediation_id)
        scenario = scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=read["scenario_id"])
        check_plan_changeable(scenario, read)
        latest, version = (
            read["job"]["epoch"],
            check_regenerable(read, remediation_id, get_settings().regenerations_max_version_count),
        )
        assert scenario is not None  # check_plan_changeable refused a missing one
        if is_plan_run_being_deleted(read["session_id"]):
            raise run_being_deleted(read["session_id"])
        register = RegisterData.model_validate(read["register"])
        snapshot = self._snapshots.make(register, scenario, stored=True)
        now = datetime.now(UTC)
        job = new_job(TaskName.WRITE_PLAN, version, now)
        item = new_version(version, principal, snapshot, now)
        if not remediation_plans.create_remediation_plan_version(remediation_id, latest, item, job, now):
            raise version_in_progress(remediation_id, latest)  # another regenerate made it first
        # Checked again after the append: either this sees the delete's mark or the delete's check for work
        # sees the new version.
        if is_plan_run_being_deleted(read["session_id"]):
            stop_remediation_plan_version(remediation_id, version)
            publish_remediation_status(remediation_id)
            raise run_being_deleted(read["session_id"])
        send_job(TaskName.WRITE_PLAN, remediation_id, version)
        target = audit_target(AuditTarget.REMEDIATION, remediation_id)
        audit_records.create_audit_record(
            AuditAction.PLAN_REGENERATED, caller_actor(principal), target, after={"version": version}
        )
        publish_remediation_status(remediation_id)
        return PlanRequested(
            remediation_id=remediation_id,
            session_id=read["session_id"],
            scenario_id=read["scenario_id"],
            version=version,
            status=Status.QUEUED,
        )


def read_owned(principal: Principal, remediation_id: str) -> dict[str, Any]:
    """What a regenerate or a decision reads first of tsg_remediations (id-only gate read); 404 unknown, 403
    another entity's."""
    read = remediation_plans.get(fields="change", _id=remediation_id)
    return check_plan_owner(read, principal.entity_id, remediation_id)


@singleton
def get_plan_regeneration() -> PlanRegeneration:
    return PlanRegeneration(get_snapshot_maker())
