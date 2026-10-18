"""An organisation's control over its own work: list what is queued or running, cancel a run or a plan (what
is done stays), delete a run for good. Each change is announced to live watchers and audited."""

from typing import Any

from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    JobControlMessage,
    JobKind,
    Status,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.scenario.repository import JobControlRepository
from app.domain.jobs import check_run_cancel_stopped_something, run_job_kind_and_status
from app.models.api_clients import Principal
from app.models.jobs import JobList, JobProgress, JobView, PlanCancelled, SessionDeleted
from app.models.scenario.views import RunBoard, SessionStatus
from app.realtime.publisher import publish_remediation_status, publish_session_status
from app.services.audit import audit_target, caller_actor
from app.services.scenario.results import build_board
from app.services.scenario.runs import find_status_for_caller


class JobService:
    def __init__(self, records: JobControlRepository) -> None:
        self._records = records

    def list_jobs(self, principal: Principal) -> JobList:
        """The caller's runs and remediation plans queued or running (a run also while its controls are being
        matched), oldest first; `total` counts them all, though the list shows at most JobControl.LIST_MAX
        runs and as many plans."""
        runs, run_total = self._records.list_working_scenario_sessions(principal.entity_id)
        plans, plan_total = self._records.list_working_remediation_plans(principal.entity_id)
        jobs = [_run_job(record) for record in runs] + [_plan_job(record) for record in plans]
        jobs.sort(key=lambda job: (job.created_at is None, job.created_at))
        return JobList(jobs=jobs, total=run_total + plan_total)

    def cancel_run(self, principal: Principal, run: SessionStatus) -> RunBoard:
        """Stop the run now: its job, and the controls still being matched for its scenarios. What is written
        stays readable and decidable; a next set or regenerate resumes it on purpose. 409 when nothing of it
        is queued or running."""
        stopped, controls = self._records.cancel_scenario_session(
            run.session_id, principal.entity_id, _who(principal)
        )
        check_run_cancel_stopped_something(run.session_id, stopped, controls)
        publish_session_status(run.session_id)
        after = {"job_stopped": stopped, "controls_cancelled": controls}
        target = audit_target(AuditTarget.SESSION, run.session_id)
        audit_records.create_audit_record(
            AuditAction.RUN_CANCELLED, caller_actor(principal), target, after=after
        )
        return build_board(find_status_for_caller(run.session_id, principal.entity_id))

    def delete_run(self, principal: Principal, run: SessionStatus) -> SessionDeleted:
        """Remove the run for good, with its scenarios, their SQL operation records and its remediation plans.
        409 cancel_first while anything of it is queued or running: nothing is ever deleted under a worker."""
        deleted = self._records.delete_scenario_session(run.session_id, principal.entity_id)
        if deleted is None:  # still working, or a next set started first
            message = JobControlMessage.CANCEL_FIRST.format(session_id=run.session_id)
            raise Conflict(message, reason=ConflictReason.CANCEL_FIRST)
        removed, plan_ids = deleted
        publish_session_status(run.session_id)  # a watcher's stream reads it gone: session.deleted, then ends
        for plan_id in plan_ids:  # and each plan's: remediation.deleted
            publish_remediation_status(plan_id)
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"asset_id": run.asset_id, **removed}
        audit_records.create_audit_record(
            AuditAction.SESSION_DELETED, caller_actor(principal), target, after=after
        )
        return SessionDeleted(session_id=run.session_id, **removed)

    def cancel_plan(self, principal: Principal, remediation_id: str) -> PlanCancelled:
        """Stop a plan being written (409 when it is not); 404/403 come from the route's CallersPlan."""
        if not self._records.cancel_remediation_plan(remediation_id, principal.entity_id, _who(principal)):
            message = JobControlMessage.PLAN_NOTHING_TO_CANCEL.format(remediation_id=remediation_id)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
        publish_remediation_status(remediation_id)
        target = audit_target(AuditTarget.REMEDIATION, remediation_id)
        audit_records.create_audit_record(AuditAction.PLAN_CANCELLED, caller_actor(principal), target)
        return PlanCancelled(remediation_id=remediation_id, status=Status.CANCELLED)


def _who(principal: Principal) -> dict[str, Any]:
    """Who cancelled: the user and the calling system."""
    return {"user_id": principal.user_id, "client_id": principal.client_id}


def _run_job(record: dict[str, Any]) -> JobView:
    """A run as the list shows it: finding threats or writing scenarios while its job is queued or running,
    else matching its scenarios' controls."""
    job, counts = record.get("job") or {}, record.get("counts") or {}
    kind, status = run_job_kind_and_status(record["status"], job.get("task"))
    return JobView(
        kind=kind,
        session_id=record["_id"],
        asset_id=record.get("asset_id"),
        asset_name=((record.get("context") or {}).get("asset") or {}).get("name"),
        status=status,
        queued_at=job.get("due_at"),
        created_at=record.get("created_at"),
        attempts=job.get("attempts") or 0,
        user_id=record.get("user_id"),
        progress=JobProgress(**{key: counts.get(key, 0) for key in JobProgress.model_fields}),
    )


def _plan_job(record: dict[str, Any]) -> JobView:
    """A remediation plan as the list shows it."""
    job = record.get("job") or {}
    return JobView(
        kind=JobKind.REMEDIATION,
        session_id=record.get("session_id"),
        remediation_id=record["_id"],
        asset_id=record.get("asset_id"),
        status=record["status"],
        queued_at=job.get("due_at"),
        created_at=record.get("created_at"),
        attempts=job.get("attempts") or 0,
        user_id=record.get("user_id"),
    )


@singleton
def get_job_service() -> JobService:
    """The process's job-control service."""
    return JobService(JobControlRepository(get_mongodb()))
