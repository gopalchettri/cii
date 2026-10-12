"""The scenario run's jobs (guide §7.2-7.4). tsg_find_threats plans the run and hands its first set
(INITIAL_SET_SIZE paths), in ONE fenced write, to tsg_write_scenarios (Step 12) on the same epoch: the claim
filters on job.task, so a late copy of this message can never plan the run again."""

import time
from datetime import UTC, datetime
from typing import Any

import structlog
from celery import Task

from app.core.config import get_settings
from app.core.constants import (
    Collection,
    LogEvent,
    PlanMessage,
    RunActionOutcome,
    Step,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.tracing import traced
from app.data_access.job_records import JobLease
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.attack_paths.path_progress import set_and_first_batch
from app.engine.scenarios.attack_paths.path_selector import get_attack_path_selector
from app.engine.scenarios.finding.threat_finder import get_threat_finder
from app.models.asset_context import FrozenContext
from app.worker.celery_app import celery_app
from app.worker.jobs import hand_over, run_leased_job

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.FIND_THREATS, bind=True)
def find_threats(self: Task, record_id: str, epoch: int) -> None:
    """A plan refusal (PlanRefused, a JobFailed) fails the run with plan_refused or actor_library_empty and is
    never retried; an outage gives the job back and retries (run_leased_job)."""
    run_leased_job(self, Collection.SESSIONS, record_id, epoch, plan_run)


@traced("worker.plan_run")
def plan_run(lease: JobLease) -> None:
    """Plan the run, then hand its first set to scenario writing in ONE fenced write. A plan with no path ends
    the run in that same write: nothing is left to write, so no writer job is queued."""
    started = time.perf_counter()
    context = FrozenContext.from_record(SessionRepository(get_mongodb()).find_context(lease.record_id))
    findings = get_threat_finder().find_threats(context)
    plan = get_attack_path_selector().build_plan(findings)
    plan |= {"frozen_at": datetime.now(UTC), "made_with": made_with(findings.library_stamp)}
    selected = [path["path_id"] for path in plan["paths"] if path["selected"]]
    changes = plan_changes(plan, len(selected), time.perf_counter() - started)
    if selected:
        asked, batch = set_and_first_batch(plan["paths"], get_settings().initial_set_size)
        hand_over(lease, TaskName.WRITE_SCENARIOS, changes | {"job.batch": batch, "job.set": asked})
    else:
        lease.finish(changes | {"last_action.outcome": finished_outcome(plan)})
    log.info(
        LogEvent.PLANNER_PLAN_MADE,
        threats=len(plan["threats"]),
        paths=len(plan["paths"]),
        not_assessed=plan["not_assessed"],
    )


def finished_outcome(plan: dict[str, Any]) -> RunActionOutcome:
    """complete, or partial when a category could not be assessed: a gap the reviewer must see (G113)."""
    return RunActionOutcome.PARTIAL if plan["not_assessed"] else RunActionOutcome.COMPLETE


def plan_changes(plan: dict[str, Any], selected: int, seconds: float) -> dict[str, Any]:
    """The plan and what the run shows from it: the counts and the plan note."""
    return {
        "plan": plan,
        "plan_note": PlanMessage.PLAN_NOTE.format(planned=selected, written=0, remaining=selected),
        "step": Step.SCENARIOS,
        "counts.planned": selected,
        "counts.remaining": selected,
        "timings.threats_s": round(seconds, 1),
    }


def made_with(library_stamp: dict[str, str | None]) -> dict[str, Any]:
    """What the plan was made with, so a reviewer can tell why this plan and not another (v1 froze the same):
    the models and the library version."""
    settings = get_settings()
    chat_models = [settings.chat_model] + (
        [settings.chat_fallback_model] if settings.chat_fallback_model else []
    )
    return {
        "chat_models": chat_models,
        "embedding_model": settings.embedding_model,
        "rerank_model": settings.rerank_model,
        "library": library_stamp,
    }
