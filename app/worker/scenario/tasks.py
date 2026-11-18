"""The scenario tasks: tsg_find_threats, tsg_write_scenarios, tsg_map_controls and tsg_retry_controls."""

import time
from collections.abc import Callable
from functools import partial

import structlog
from celery import Task

from app import ai
from app.core import constants as c
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.exceptions import TEMPORARY_ERRORS
from app.crud.jobs import JobLease, ended_job_fields
from app.domain.intel.switch import IntelligenceSwitch, get_intelligence_switch
from app.domain.scenario import plan
from app.domain.scenario.session import pick_next_paths_to_write
from app.schemas.scenario_internal import FrozenContext, ThreatFindings
from app.search.service import get_library_search
from app.worker.celery_app import celery_app
from app.worker.jobs import hand_over, run_leased_job
from app.worker.scenario import controls_job, write_job

log = structlog.get_logger(__name__)


@celery_app.task(name=c.TaskName.FIND_THREATS, bind=True)
def find_threats(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: plan the run; a plan refusal fails it for good, an outage retries the job."""

    def plan_it(lease: JobLease) -> None:
        models = (
            ai.chat.get_scenario_chat_model(),
            get_library_search(),
            ai.rerank.get_rerank_model(),
            ai.embeddings.get_embedding_model(),
        )
        plan_run(lease, partial(plan.find_threats, *models), get_intelligence_switch())

    run_leased_job(self, c.Collection.SESSIONS, record_id, epoch, plan_it, fields=PLAN_JOB_FIELDS)


@celery_app.task(name=c.TaskName.WRITE_SCENARIOS, bind=True)
def write_scenarios(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: write the run's current batch under the run's job lease."""

    run_leased_job(self, c.Collection.SESSIONS, record_id, epoch, write_job.write_scenario_batch)


@celery_app.task(name=c.TaskName.MAP_CONTROLS, bind=True)
def map_controls(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: map the run's waiting scenarios; an outage retries the message."""
    structlog.contextvars.bind_contextvars(record_id=record_id, session_id=record_id)
    try:
        controls_job.map_threat_scenario_controls(record_id, self.request.id)
    except TEMPORARY_ERRORS as exc:
        retries, backoff = self.request.retries, c.Lease.RETRY_DELAYS_SECONDS
        last = retries >= c.Controls.MAX_MESSAGE_RETRIES
        # ponytail: the sweep's re-send time, approximate; add lease end and beat interval if exact matters.
        delay = c.Controls.RESEND_QUEUED_AFTER_SECONDS if last else backoff[min(retries, len(backoff) - 1)]
        controls_job.note_controls_outage(record_id, self.request.id, exc, retries + 1, delay)
        if last:
            log.warning(c.LogEvent.JOB_NOT_CLAIMED, reason="outage_retries_used", attempt=retries + 1, message=str(exc))
            return
        raise self.retry(countdown=delay, exc=exc, priority=c.Worker.NEXT_STAGE_PRIORITY) from exc


@celery_app.task(name=c.TaskName.RETRY_CONTROLS)
def retry_controls() -> None:
    """Beat task: requeue stalled mappings and send one message per run no delivery holds."""
    controls_job.retry_stalled_controls()


PLAN_JOB_FIELDS = ("context",)


def plan_run(lease: JobLease, find_threats: Callable[..., ThreatFindings], switch: IntelligenceSwitch) -> None:
    """Plan the run and hand its first set to the write job in one fenced write."""
    started = time.perf_counter()
    context = FrozenContext.from_record(lease.record["context"])
    country = get_settings().context_country if switch.is_on() else ""  # a fact, ranks nothing
    is_last_attempt = lease.attempts >= c.Lease.MAX_ATTEMPTS
    findings = find_threats(context, country, is_last_attempt=is_last_attempt)
    built = plan.build_plan(findings, get_settings().total_scenario_count)  # its other sessions never block
    built["frozen_at"] = utc_now()
    selected = [path["path_id"] for path in built["paths"] if path["selected"]]
    asked, batch = pick_next_paths_to_write(built["paths"], get_settings().initial_set_size)  # [] when none
    trace = plan.build_plan_trace(findings, built, len(asked))
    changes = {
        "plan": built,
        "plan_trace": trace,
        "step": c.Step.SCENARIOS,
        "counts.planned": len(selected),
        "counts.remaining": len(selected),
        "counts.not_judged": trace["counts"]["not_judged"],
        "timings.threats_s": round(time.perf_counter() - started, 1),
    }
    if asked:
        hand_over(lease, c.TaskName.WRITE_SCENARIOS, changes | {"job.batch": batch, "job.set": asked})
    else:
        ended = {"last_action.outcome": c.RunActionOutcome.COMPLETE} | ended_job_fields(c.Status.DONE)
        lease.update_job(changes | ended)
    log.info(c.LogEvent.PLANNER_FUNNEL, **trace["counts"], landscape_cut=trace["landscape_cut"])
