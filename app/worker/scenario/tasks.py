"""The scenario tasks: tsg_find_threats, tsg_write_scenarios, tsg_map_controls and tsg_retry_controls, each
asking the container for its job when it runs."""

import structlog
from celery import Task

from app.core.constants import Collection, Controls, Lease, LogEvent, TaskName, Worker
from app.core.exceptions import TEMPORARY_ERRORS
from app.data_access.jobs.job_repository import JobLease
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job
from app.worker.scenario.plan_job import PLAN_JOB_FIELDS

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.FIND_THREATS, bind=True)
def find_threats(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: plan the run; a plan refusal fails it for good, an outage retries the job."""
    from app import container

    def plan(lease: JobLease) -> None:
        container.get_plan_job().plan_threat_scenario_session(lease)

    run_leased_job(self, Collection.SESSIONS, record_id, epoch, plan, fields=PLAN_JOB_FIELDS)


@celery_app.task(name=TaskName.WRITE_SCENARIOS, bind=True)
def write_scenarios(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: write the run's current batch under the run's job lease."""
    from app import container

    def write_batch(lease: JobLease) -> None:
        container.get_scenario_write_job().write_scenario_batch(lease)

    run_leased_job(self, Collection.SESSIONS, record_id, epoch, write_batch)


@celery_app.task(name=TaskName.MAP_CONTROLS, bind=True)
def map_controls(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: take the run's delivery lease and map its waiting scenarios; an outage, noted on the
    run's status, retries the message after the back-off, Controls.MAX_MESSAGE_RETRIES times, then ends it
    (the sweep re-sends)."""
    from app import container

    structlog.contextvars.bind_contextvars(record_id=record_id)  # run_leased_job binds it; this task skips it
    try:
        container.get_controls_job().map_threat_scenario_controls(record_id, self.request.id)
    except TEMPORARY_ERRORS as exc:
        retries, backoff = self.request.retries, Lease.RETRY_DELAYS_SECONDS
        last = retries >= Controls.MAX_MESSAGE_RETRIES
        # ponytail: the sweep's re-send time, approximate; add lease end and beat interval if exact matters.
        delay = Controls.RESEND_QUEUED_AFTER_SECONDS if last else backoff[min(retries, len(backoff) - 1)]
        container.get_controls_job().note_controls_outage(record_id, self.request.id, exc, retries + 1, delay)
        if last:
            log.warning(
                LogEvent.JOB_NOT_CLAIMED, reason="outage_retries_used", attempt=retries + 1, message=str(exc)
            )
            return
        raise self.retry(countdown=delay, exc=exc, priority=Worker.NEXT_STAGE_PRIORITY) from exc


@celery_app.task(name=TaskName.RETRY_CONTROLS)
def retry_controls() -> None:
    """Beat task: requeue stalled mappings, then send one message per run they belong to that no delivery
    serves."""
    from app import container

    container.get_controls_job().retry_stalled_controls()
