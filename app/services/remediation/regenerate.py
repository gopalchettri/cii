"""A new version of a remediation plan: only while its scenario is
still accepted and its latest version is done, failed or cancelled. The new version's snapshot is made now
with no AI call (the register from the record, read against the current library; the scenario and its
controls as they are now), with a warning for each control the previous version had that is no longer
mapped; or pending, completed by its plan job (G262). One conditional append, then the plan job is sent."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    RemediationMessage,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.job_records import new_job
from app.data_access.remediation_versions import RemediationVersions
from app.data_access.remediations import RemediationRepository
from app.domain.remediation.snapshot import is_pending, no_longer_mapped
from app.models.api_clients import Principal
from app.models.remediation import PlanRequested
from app.models.remediation_requests import RegisterData
from app.realtime.publisher import publish_remediation_status
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.remediation.requests import new_version, still_accepted
from app.services.remediation.snapshots import SnapshotMaker, get_snapshot_maker
from app.worker.celery_app import send_job


class PlanRegeneration:
    def __init__(
        self, plans: RemediationRepository, versions: RemediationVersions, snapshots: SnapshotMaker
    ) -> None:
        self._plans, self._versions, self._snapshots = plans, versions, snapshots

    @traced("remediation.regenerate")
    def regenerate(self, principal: Principal, remediation_id: str) -> PlanRequested:
        read = read_owned(self._versions, principal, remediation_id)
        scenario = self._plans.find_scenario(read["scenario_id"])
        refuse_read_only(scenario, read)
        latest = read["job"]["epoch"]
        if read["status"] not in (Status.DONE, Status.FAILED, Status.CANCELLED):  # G214: resumed on purpose
            raise _in_progress(remediation_id, latest)
        assert scenario is not None  # refuse_read_only refused a missing one
        register = RegisterData.model_validate(read["register"])
        snapshot = self._snapshots.make(register, scenario, stored=True)
        if not is_pending(snapshot):  # a pending one gets its warnings from its plan job
            previous = self._plans.find_snapshot(remediation_id, latest) or {}
            snapshot["warnings"] += no_longer_mapped(previous, snapshot, latest)
        now, version = datetime.now(UTC), latest + 1
        job = new_job(TaskName.WRITE_PLAN, version, now)
        item = new_version(version, principal, snapshot, now)
        if not self._versions.append_version(remediation_id, latest, item, job, now):
            raise _in_progress(remediation_id, latest)  # another regenerate made it first
        send_job(TaskName.WRITE_PLAN, remediation_id, version)
        target = audit_target(AuditTarget.REMEDIATION, remediation_id)
        record_audit(
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


def read_owned(versions: RemediationVersions, principal: Principal, remediation_id: str) -> dict[str, Any]:
    """What a regenerate or a decision reads first; 404 unknown, 403 another entity's."""
    read = versions.find_for_change(remediation_id)
    if read is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    if read["entity_id"] != principal.entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=remediation_id))
    return read


def refuse_read_only(scenario: dict[str, Any] | None, read: dict[str, Any]) -> None:
    """A plan whose scenario is no longer accepted stays readable but takes no change (G-J)."""
    if not still_accepted(scenario):
        message = RemediationMessage.PLAN_READ_ONLY.format(scenario_id=read["scenario_id"])
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)


def _in_progress(remediation_id: str, version: int) -> Conflict:
    message = RemediationMessage.VERSION_IN_PROGRESS.format(version=version, remediation_id=remediation_id)
    return Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)


@singleton
def get_plan_regeneration() -> PlanRegeneration:
    db = get_mongodb()
    return PlanRegeneration(RemediationRepository(db), RemediationVersions(db), get_snapshot_maker())
