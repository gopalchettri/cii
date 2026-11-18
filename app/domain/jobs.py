"""Job controls: an organisation's work listed, cancelled and deleted; every job monitored by the admin."""

from datetime import datetime
from typing import Any

import structlog

from app.core import readiness
from app.core.clock import utc_now
from app.core.constants import (
    ROUTED_QUEUES,
    AuditAction,
    AuditTarget,
    Collection,
    ConflictReason,
    JobControlMessage,
    JobKind,
    JobMonitorMessage,
    LogEvent,
    Status,
    TaskName,
    module_of,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, NotFound
from app.core.security import Principal
from app.crud import scenarios as scenario_crud
from app.crud import work_control
from app.crud.admin_jobs import get_admin_job_repository
from app.crud.audit import get_audit_repository
from app.crud.jobs import JobRepository
from app.domain.scenario.session import build_status_board, get_session_owned_by_caller
from app.domain.shared.audit import admin_actor, audit_target, caller_actor
from app.realtime import publisher
from app.schemas.jobs import (
    JobList,
    JobMonitor,
    JobProgress,
    JobView,
    MonitoredJob,
    PlanCancelled,
    QueueState,
    SessionDeleted,
    controls_retry_notice_of,
    retry_notice_of,
)
from app.schemas.remediation import shown_plan_status
from app.schemas.scenarios import RunBoard, SessionStatus, session_status_from_record

log = structlog.get_logger(__name__)
_WORKING = (Status.QUEUED, Status.RUNNING)


def run_being_deleted(session_id: str) -> Conflict:
    """409 run_being_deleted."""
    message = JobControlMessage.BEING_DELETED.format(session_id=session_id)
    return Conflict(message, reason=ConflictReason.RUN_BEING_DELETED)


def list_my_jobs(principal: Principal) -> JobList:
    """The caller's queued or running runs, plans and mappings, oldest first (LIST_MAX of each)."""
    runs, plans, mappings, total = work_control.list_working_jobs(principal.tenant_id, principal.entity_id)
    jobs = [_run_job(record) for record in runs] + [_plan_job(record) for record in plans]
    jobs += [_mapping_job(record) for record in mappings]
    jobs.sort(key=lambda job: (job.created_at is None, job.created_at))
    return JobList(jobs=jobs, total=total)


def cancel_run(principal: Principal, run: SessionStatus) -> RunBoard:
    """Stop the run's job and its own controls; 409 when nothing of it is queued or running."""
    stopped, controls = work_control.cancel_scenario_session(run.session_id, principal.entity_id, _who(principal))
    if not stopped and not controls:  # neither the run's job nor any control matching
        message = JobControlMessage.NOTHING_TO_CANCEL.format(session_id=run.session_id)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
    publisher.publish_session_status(run.session_id)
    after = {"job_stopped": stopped, "controls_cancelled": controls}
    target = audit_target(AuditTarget.SESSION, run.session_id)
    audit = get_audit_repository()
    audit.create_audit_record(AuditAction.RUN_CANCELLED, caller_actor(principal), target, after=after)
    record = scenario_crud.get_threat_scenario_session_repository().get(fields="status", _id=run.session_id)
    record = get_session_owned_by_caller(record, run.session_id, principal.entity_id)
    return build_status_board(session_status_from_record(record))


def delete_run(principal: Principal, run: SessionStatus) -> SessionDeleted:
    """Remove the run, its scenarios and plans for good; 409 cancel_first (naming its plans) while it works."""
    deleted = work_control.delete_scenario_session(run.session_id, principal.entity_id)
    if deleted is None:  # still working, or a next set started first
        working = work_control.list_working_plans(run.session_id, principal.entity_id)
        to_cancel = [{"remediation_id": plan["_id"], "scenario_id": plan.get("scenario_id")} for plan in working]
        message = JobControlMessage.CANCEL_FIRST.format(session_id=run.session_id)
        if to_cancel:
            names = ", ".join(plan["remediation_id"] for plan in to_cancel)
            message = JobControlMessage.CANCEL_PLANS_FIRST.format(session_id=run.session_id, remediation_ids=names)
        raise Conflict(message, reason=ConflictReason.CANCEL_FIRST, details={"plans_to_cancel": to_cancel})
    removed, plan_ids = deleted
    publisher.publish_session_status(run.session_id)  # a watcher's stream reads it gone: session.deleted
    for plan_id in plan_ids:  # and each plan's: remediation.deleted
        publisher.publish_remediation_status(plan_id)
    target = audit_target(AuditTarget.SESSION, run.session_id)
    after = {"asset_id": run.asset_id, **removed}
    audit = get_audit_repository()
    audit.create_audit_record(AuditAction.SESSION_DELETED, caller_actor(principal), target, after=after)
    return SessionDeleted(session_id=run.session_id, **removed)


def cancel_plan(principal: Principal, remediation_id: str) -> PlanCancelled:
    """Stop a plan being written and the controls only it maps; 409 when it is not being written."""
    plan = work_control.cancel_remediation_plan(remediation_id, principal.entity_id, _who(principal))
    if plan is None:
        message = JobControlMessage.PLAN_NOTHING_TO_CANCEL.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
    publisher.publish_remediation_status(remediation_id)
    if plan.get("session_id"):  # its controls may have stopped: the run's counts changed
        publisher.publish_session_status(plan["session_id"])
    target = audit_target(AuditTarget.REMEDIATION, remediation_id)
    get_audit_repository().create_audit_record(AuditAction.PLAN_CANCELLED, caller_actor(principal), target)
    return PlanCancelled(remediation_id=remediation_id, status=Status.CANCELLED)


def get_any_job(job_id: str) -> MonitoredJob:
    """One job of any kind by its id (an admin job's job_id, or a run's, plan's or mapping's id); 404."""
    if (record := get_admin_job_repository().get_any_admin_job(job_id)) is not None:
        return _admin_job(record)
    for collection in _job_collections():
        if (leased := JobRepository(get_mongodb()[collection]).get_job_record(job_id)) is not None:
            return _leased_job(collection, leased)
    raise NotFound(JobMonitorMessage.NOT_FOUND.format(job_id=job_id))


def cancel_admin_job(job_id: str, actor: str) -> MonitoredJob:
    """Cancel a queued or running admin job, audited; 409 for another module's or an ended job."""
    job = get_any_job(job_id)
    if job.collection != Collection.ADMIN_JOBS:
        message = JobMonitorMessage.NOT_ADMIN_JOB.format(job_id=job_id, module=job.module)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
    if not get_admin_job_repository().cancel_admin_job(job_id, utc_now(), actor):
        ended = get_any_job(job_id).status  # it may have ended since it was read
        message = JobMonitorMessage.ALREADY_ENDED.format(job_id=job_id, status=ended)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
    get_audit_repository().create_audit_record(
        AuditAction.ADMIN_JOB_CANCELLED,
        admin_actor(actor),
        audit_target(AuditTarget.ADMIN_JOB, job_id),
        before={"status": job.status},
        after={"status": "cancelled", "kind": job.kind},
    )
    return get_any_job(job_id)


def list_all_jobs(  # noqa: PLR0913 — the list's filters: each one is needed
    since: datetime,
    statuses: list[str],
    kind: str | None,
    limit: int,
    module: str | None = None,
    request_id: str | None = None,
) -> JobMonitor:
    """The jobs active since `since`, newest first, narrowed by the filters, and each queue's state."""
    jobs = [
        _leased_job(collection, record)
        for collection in _job_collections()
        for record in JobRepository(get_mongodb()[collection]).list_recent_jobs(since, statuses, kind, limit)
    ]
    admin_jobs = get_admin_job_repository()
    jobs += [_admin_job(record) for record in admin_jobs.list_recent_admin_jobs(since, statuses, kind, limit)]
    if module:
        jobs = [job for job in jobs if job.module == module]
    if request_id:  # ponytail: filtered after each collection's newest `limit`: an older job is missed
        jobs = [job for job in jobs if job.request_id == request_id]
    jobs.sort(key=lambda job: job.started_at or job.created_at or since, reverse=True)
    return JobMonitor(jobs=jobs[:limit], queues=_queue_states())


def _job_collections() -> list[str]:
    from app.worker.jobs import JOB_COLLECTIONS

    return list(JOB_COLLECTIONS)


def _queue_states() -> dict[str, QueueState]:
    try:
        workers: dict[str, int] | None = readiness.count_online_workers(ROUTED_QUEUES)
    except Exception:  # noqa: BLE001 — the broker unreachable: the list still answers, the count is unknown
        log.warning(LogEvent.JOB_QUEUE_SIZE_UNKNOWN, count="workers_online", exc_info=True)
        workers = None
    return {
        queue: QueueState(
            waiting=_count_waiting(queue), workers_online=None if workers is None else workers.get(queue, 0)
        )
        for queue in ROUTED_QUEUES
    }


def _count_waiting(queue: str) -> int | None:
    from app.worker.celery_app import count_waiting_messages

    try:
        return count_waiting_messages(queue)
    except Exception:  # noqa: BLE001 — the broker unreachable: the list still answers, the count is unknown
        log.warning(LogEvent.JOB_QUEUE_SIZE_UNKNOWN, queue=queue, exc_info=True)
        return None


def _who(principal: Principal) -> dict[str, Any]:
    return {"user_id": principal.user_id, "client_id": principal.client_id}


def _run_job(record: dict[str, Any]) -> JobView:
    job, counts = record.get("job") or {}, record.get("counts") or {}
    kind, status = JobKind.CONTROLS, Status.RUNNING  # its job over: matching controls
    if record["status"] in _WORKING:
        kind = JobKind.THREATS if job.get("task") == TaskName.FIND_THREATS else JobKind.SCENARIOS
        status = Status(record["status"])
    retrying = retry_notice_of(record["status"], job.get("retry"), record.get("step"))
    return _view(
        record,
        kind,
        status,
        retrying or controls_retry_notice_of(counts, (record.get("controls_delivery") or {}).get("retry")),
        session_id=record["_id"],
        asset_name=((record.get("context") or {}).get("asset") or {}).get("name"),
        progress=JobProgress(**{key: counts.get(key, 0) for key in JobProgress.model_fields}),
    )


def _plan_job(record: dict[str, Any]) -> JobView:
    status = shown_plan_status(record)  # queued while its job waits for another job
    retrying = retry_notice_of(status, (record.get("job") or {}).get("retry"))
    fields = {"session_id": record.get("session_id"), "remediation_id": record["_id"]}
    return _view(record, JobKind.REMEDIATION, status, retrying, **fields)


def _mapping_job(record: dict[str, Any]) -> JobView:
    retrying = retry_notice_of(record["status"], (record.get("job") or {}).get("retry"))
    fields = {"mapping_id": record["_id"], "user_id": record.get("created_by")}
    return _view(record, JobKind.SERVICE_MAPPING, record["status"], retrying, session_id=None, asset_id=None, **fields)


def _view(record: dict[str, Any], kind: JobKind, status: str, retrying: Any, **fields: Any) -> JobView:
    job = record.get("job") or {}
    shown = {"asset_id": record.get("asset_id"), "user_id": record.get("user_id")} | fields
    return JobView(
        kind=kind,
        status=Status(status),
        queued_at=job.get("due_at"),
        created_at=record.get("created_at"),
        attempts=job.get("attempts") or 0,
        retrying=retrying,
        **shown,
    )


def _leased_job(collection: str, record: dict[str, Any]) -> MonitoredJob:
    job = record.get("job") or {}
    status = record.get("status", "")
    return _monitored(
        record | job,
        job.get("task", ""),
        collection,
        entity_id=record.get("entity_id"),
        retrying=retry_notice_of(status, job.get("retry")),
        attempts=job.get("attempts"),
        resends=job.get("resends"),
        status=status,
        finished_at=record.get("finished_at"),
    )


def _admin_job(record: dict[str, Any]) -> MonitoredJob:
    return _monitored(record, record.get("kind", ""), Collection.ADMIN_JOBS)  # lease_until: its heartbeat


def _monitored(fields: dict[str, Any], kind: str, collection: str, **extra: Any) -> MonitoredJob:
    shown = ("status", "created_at", "started_at", "finished_at", "error", "task_id", "worker", "request_id")
    found: dict[str, Any] = {name: fields.get(name) for name in (*shown, "lease_until")} | {
        "status": fields.get("status", "")
    }
    return MonitoredJob(
        id=str(fields["_id"]), module=module_of(kind), kind=kind, collection=collection, **(found | extra)
    )


def send_admin_job(task: TaskName, job_id: str) -> bool:
    """Sends an admin job to the worker: a route asks here, never the worker itself."""
    from app.worker.celery_app import send_admin_job as send

    return send(task, job_id)
