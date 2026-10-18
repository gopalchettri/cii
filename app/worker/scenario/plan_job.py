"""The plan job: plans a run and hands its first set to the write job in one fenced write, on the same epoch
(the claim filters on job.task, so a late copy of the message never plans the run again)."""

import time
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.core.constants import (
    Lease,
    LogEvent,
    PlanMessage,
    RunActionOutcome,
    Status,
    Step,
    TaskName,
)
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.data_access.jobs.job_repository import JobLease, ended_job_fields
from app.domain.scenario.plan import ThreatFinder, build_plan, set_and_first_batch
from app.models.scenario.asset_context import FrozenContext
from app.worker.jobs import hand_over

log = structlog.get_logger(__name__)


class PlanJob:
    """Plans threat scenario sessions; long-lived, one per worker."""

    def __init__(self, threat_finder: ThreatFinder, switch: IntelligenceSwitch) -> None:
        self._threat_finder, self._switch = threat_finder, switch

    def plan_threat_scenario_session(self, lease: JobLease) -> None:
        """Plan the run and hand its first set to the write job in one fenced write; a plan with no path ends
        the run in that write instead."""
        started = time.perf_counter()
        context = FrozenContext.from_record(lease.record["context"])
        country = get_settings().context_country if self._switch.is_on() else ""  # a fact, ranks nothing
        last_attempt = lease.attempts >= Lease.MAX_ATTEMPTS
        findings = self._threat_finder.find_threats(context, country, last_attempt=last_attempt)
        plan = build_plan(findings, get_settings().total_scenario_count)
        plan |= {"frozen_at": datetime.now(UTC), "made_with": _made_with(findings.library_stamp)}
        selected = [path["path_id"] for path in plan["paths"] if path["selected"]]
        changes = _plan_changes(plan, len(selected), time.perf_counter() - started)
        if selected:
            asked, batch = set_and_first_batch(plan["paths"], get_settings().initial_set_size)
            hand_over(lease, TaskName.WRITE_SCENARIOS, changes | {"job.batch": batch, "job.set": asked})
        else:
            ended = {"last_action.outcome": RunActionOutcome.COMPLETE} | ended_job_fields(Status.DONE)
            lease.update_job(changes | ended)
        log.info(LogEvent.PLANNER_PLAN_MADE, threats=len(plan["threats"]), paths=len(plan["paths"]))


def _plan_changes(plan: dict[str, Any], selected: int, seconds: float) -> dict[str, Any]:
    """The plan and what the run shows from it: the counts and the plan note."""
    return {
        "plan": plan,
        "plan_note": PlanMessage.PLAN_NOTE.format(planned=selected, written=0, remaining=selected),
        "step": Step.SCENARIOS,
        "counts.planned": selected,
        "counts.remaining": selected,
        "timings.threats_s": round(seconds, 1),
    }


def _made_with(library_stamp: dict[str, str | None]) -> dict[str, Any]:
    """The models and library version the plan was made with, frozen on the plan for the reviewer."""
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
