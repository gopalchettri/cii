"""An organisation's control over its own work: list what is queued or running (runs, plans and service
mappings), cancel a run or a plan (what is done stays), delete a run for good. Each change is announced to
live watchers and audited."""

from typing import Any

from app.core.callables import Publish
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    JobControlMessage,
    JobKind,
    Status,
)
from app.core.exceptions import Conflict
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.jobs import cancel_first, check_run_cancel_stopped_something, run_job_kind_and_status
from app.domain.scenario.results import build_board
from app.domain.scenario.review import check_session_of_caller
from app.domain.shared.audit import audit_target, caller_actor
from app.models.admin.api_clients import Principal
from app.models.jobs.views import (
    JobList,
    JobProgress,
    JobView,
    PlanCancelled,
    SessionDeleted,
    controls_retry_notice_of,
    retry_notice_of,
)
from app.models.scenario.views import RunBoard, SessionStatus, session_status_from_record


class JobService:
    """The job controls: list, cancel and delete an organisation's runs, and cancel its plans."""

    def __init__(
        self,
        work_control: WorkControlRepository,
        sessions: ThreatScenarioSessionRepository,
        audit: AuditRepository,
        publish_session_status: Publish,
        publish_remediation_status: Publish,
    ) -> None:
        self._work_control, self._sessions, self._audit = work_control, sessions, audit
        self._publish_session_status = publish_session_status
        self._publish_remediation_status = publish_remediation_status

    def list_jobs(self, principal: Principal) -> JobList:
        """The caller's runs, remediation plans and service mappings queued or running (a run also while its
        controls are being matched), oldest first; `total` counts them all, though the list shows at most
        JobControl.LIST_MAX of each kind."""
        work = self._work_control
        runs, run_total = work.list_working_scenario_sessions(principal.entity_id)
        plans, plan_total = work.list_working_remediation_plans(principal.entity_id)
        mappings, mapping_total = work.list_working_service_mappings(principal.tenant_id, principal.entity_id)
        jobs = [_run_job(record) for record in runs] + [_plan_job(record) for record in plans]
        jobs += [_mapping_job(record) for record in mappings]
        jobs.sort(key=lambda job: (job.created_at is None, job.created_at))
        return JobList(jobs=jobs, total=run_total + plan_total + mapping_total)

    def cancel_threat_scenario_session(self, principal: Principal, run: SessionStatus) -> RunBoard:
        """Stop the run now: its job, and the controls still being matched for its scenarios (never a plan's:
        a hand-written scenario's, or those a plan job maps now). What is written stays readable and
        decidable; a next set or regenerate resumes it on purpose. 409 when nothing of it is queued or
        running."""
        stopped, controls = self._work_control.cancel_scenario_session(
            run.session_id, principal.entity_id, _who(principal)
        )
        check_run_cancel_stopped_something(run.session_id, stopped, controls)
        self._publish_session_status(run.session_id)
        after = {"job_stopped": stopped, "controls_cancelled": controls}
        target = audit_target(AuditTarget.SESSION, run.session_id)
        self._audit.create_audit_record(
            AuditAction.RUN_CANCELLED, caller_actor(principal), target, after=after
        )
        record = self._sessions.get(fields="status", _id=run.session_id)
        record = check_session_of_caller(record, run.session_id, principal.entity_id)
        return build_board(session_status_from_record(record))

    def delete_threat_scenario_session(self, principal: Principal, run: SessionStatus) -> SessionDeleted:
        """Remove the run for good, with its scenarios, their SQL operation records and its remediation plans.
        409 cancel_first while anything of it is queued or running (naming the plans being written): nothing
        is ever deleted under a worker."""
        deleted = self._work_control.delete_scenario_session(run.session_id, principal.entity_id)
        if deleted is None:  # still working, or a next set started first
            plans = self._work_control.list_working_plans(run.session_id, principal.entity_id)
            raise cancel_first(run.session_id, plans)
        removed, plan_ids = deleted
        self._publish_session_status(run.session_id)  # a watcher's stream reads it gone: session.deleted
        for plan_id in plan_ids:  # and each plan's: remediation.deleted
            self._publish_remediation_status(plan_id)
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"asset_id": run.asset_id, **removed}
        self._audit.create_audit_record(
            AuditAction.SESSION_DELETED, caller_actor(principal), target, after=after
        )
        return SessionDeleted(session_id=run.session_id, **removed)

    def cancel_remediation_plan(self, principal: Principal, remediation_id: str) -> PlanCancelled:
        """Stop a plan being written, with its hand-written scenario's controls (409 when it is not); 404/403
        come from the route's CallersPlan. The plan's watchers and its run's are told."""
        plan = self._work_control.cancel_remediation_plan(
            remediation_id, principal.entity_id, _who(principal)
        )
        if plan is None:
            message = JobControlMessage.PLAN_NOTHING_TO_CANCEL.format(remediation_id=remediation_id)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
        self._publish_remediation_status(remediation_id)
        if plan.get("session_id"):  # its controls may have stopped: the run's counts changed
            self._publish_session_status(plan["session_id"])
        target = audit_target(AuditTarget.REMEDIATION, remediation_id)
        self._audit.create_audit_record(AuditAction.PLAN_CANCELLED, caller_actor(principal), target)
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
        retrying=retry_notice_of(record["status"], job.get("retry"), record.get("step"))
        or controls_retry_notice_of(counts, (record.get("controls_delivery") or {}).get("retry")),
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
        retrying=retry_notice_of(record["status"], job.get("retry")),
    )


def _mapping_job(record: dict[str, Any]) -> JobView:
    """A service mapping being generated as the list shows it."""
    job = record.get("job") or {}
    return JobView(
        kind=JobKind.SERVICE_MAPPING,
        session_id=None,
        mapping_id=record["_id"],
        asset_id=None,
        status=record["status"],
        queued_at=job.get("due_at"),
        created_at=record.get("created_at"),
        attempts=job.get("attempts") or 0,
        user_id=record.get("created_by"),
        retrying=retry_notice_of(record["status"], job.get("retry")),
    )
