"""The plan job (tsg_write_plan; BLUEPRINT M11 R3; BUILD_PLAN S52): one plan version written from its
frozen snapshot. Leased on its tsg_remediations record with the version as the epoch, so a duplicate or
stale message does nothing; one AI call, then code's checks and dates (app/engine/remediation/planner.py),
then one fenced write: the version's plan, warnings and prompt, and the record done; then the audit
(`plan.completed`). An outage gives the job back and retries it; an unusable answer or a plan without
action fails the version with its code."""

from datetime import UTC, datetime

from celery import Task

from app.ai import get_chat_model
from app.core import metrics
from app.core.constants import (
    AuditAction,
    AuditTarget,
    Collection,
    ErrorCode,
    RemediationMessage,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed
from app.core.tracing import traced
from app.data_access.audit import record_audit
from app.data_access.job_records import JobLease
from app.data_access.remediations import RemediationRepository
from app.engine.remediation.planner import RemediationPlanner
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job


@celery_app.task(name=TaskName.WRITE_PLAN, bind=True)
def write_plan(self: Task, record_id: str, epoch: int) -> None:
    run_leased_job(self, Collection.REMEDIATIONS, record_id, epoch, write_version)


@traced("worker.write_plan")
def write_version(lease: JobLease) -> None:
    snapshot = RemediationRepository(get_mongodb()).find_snapshot(lease.record_id, lease.epoch)
    if snapshot is None:  # a version is never removed: only a damaged record lands here
        message = RemediationMessage.VERSION_GONE.format(version=lease.epoch, remediation_id=lease.record_id)
        raise JobFailed(ErrorCode.INTERNAL_ERROR, message)
    try:
        finished = RemediationPlanner(get_chat_model()).plan(snapshot)
    except JobFailed:
        metrics.PLANS.labels(Status.FAILED).inc()
        raise
    version = {
        "status": Status.DONE,
        "plan": finished.plan,
        "warnings": list(finished.warnings),
        "prompt_version": finished.prompt_version,
        "completed_at": datetime.now(UTC),
    }
    changes = {f"versions.$[v].{field}": value for field, value in version.items()}
    lease.finish(changes, [{"v.version": lease.epoch}])
    metrics.PLANS.labels(Status.DONE).inc()
    target = {"type": AuditTarget.REMEDIATION, "id": lease.record_id}
    after = {"version": lease.epoch, "warnings": len(finished.warnings)}
    record_audit(AuditAction.PLAN_COMPLETED, {"system": TaskName.WRITE_PLAN}, target, after=after)
