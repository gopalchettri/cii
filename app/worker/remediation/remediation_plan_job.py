"""The plan job (tsg_write_plan): one plan version written from its frozen snapshot; a pending one is
completed first (plan_inputs.py: a hand-written scenario's attackers, the scenario's missing controls).
Leased on its tsg_remediations record with the version as the epoch, so a duplicate or stale message does
nothing; one AI call, then code's checks and dates (app/domain/remediation/planner.py), then one fenced
write: the version's plan, warnings and prompt, and the record done; then the audit (`plan.completed`). An
outage gives the job back and retries it; an unusable answer or a plan without action fails the version
with its code."""

from datetime import UTC, datetime

from app.ai import ChatModel
from app.core import metrics
from app.core.constants import AuditAction, AuditTarget, ErrorCode, RemediationMessage, Status, TaskName
from app.core.exceptions import JobFailed
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import JobLease
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.domain.remediation.planner import RemediationPlanner
from app.domain.remediation.snapshot import is_pending
from app.domain.shared.audit import audit_target
from app.worker.remediation.plan_inputs import PlanInputs


class RemediationPlanJob:
    """Writes remediation plan versions; long-lived, one per worker."""

    def __init__(
        self, remediations: RemediationRepository, chat: ChatModel, inputs: PlanInputs, audit: AuditRepository
    ) -> None:
        self._remediations, self._chat, self._inputs, self._audit = remediations, chat, inputs, audit

    def write_remediation_plan_version(self, lease: JobLease) -> None:
        """Writes the leased version's plan from its snapshot, completing a pending snapshot first."""
        snapshot = self._remediations.get_remediation_plan_version_snapshot(lease.record_id, lease.epoch)
        if snapshot is None:  # a version is never removed: only a damaged record lands here
            message = RemediationMessage.VERSION_GONE.format(
                version=lease.epoch, remediation_id=lease.record_id
            )
            raise JobFailed(ErrorCode.INTERNAL_ERROR, message)
        if is_pending(snapshot):
            snapshot = self._inputs.complete(lease, snapshot)
        try:
            finished = RemediationPlanner(self._chat).plan(snapshot)
        except JobFailed:
            metrics.PLANS.labels(Status.FAILED).inc()
            raise
        written = {
            "status": Status.DONE,
            "plan": finished.plan,
            "warnings": list(finished.warnings),
            "prompt_version": finished.prompt_version,
            "completed_at": datetime.now(UTC),
        }
        self._remediations.update_remediation_plan_version_written(lease, written)
        metrics.PLANS.labels(Status.DONE).inc()
        target = audit_target(AuditTarget.REMEDIATION, lease.record_id)
        after = {"version": lease.epoch, "warnings": len(finished.warnings)}
        self._audit.create_audit_record(
            AuditAction.PLAN_COMPLETED, {"system": TaskName.WRITE_PLAN}, target, after=after
        )
