"""The MITRE run's task (ADR-010): tsg_write_mitre_scenarios writes one set of a MITRE run; its first set plans
the run first. Each card is saved as it is written, then the existing controls job maps CII library controls."""

import time
from functools import partial
from typing import Any

import structlog
from celery import Task

from app.ai.chat import get_scenario_chat_model
from app.core import constants as c
from app.core.config import get_settings
from app.core.exceptions import JobFailed, LeaseLost
from app.crud.jobs import JobLease, ended_job_fields
from app.crud.scenarios import get_threat_scenario_repository, get_threat_scenario_session_repository
from app.domain.scenario.mitre_scenario import mitre_engine as engine
from app.domain.scenario.mitre_scenario import mitre_session
from app.realtime.publisher import publish_session_status
from app.search.mitre.mitre_index import get_current_mitre_index
from app.worker.celery_app import celery_app, send_job
from app.worker.jobs import run_leased_job
from app.worker.scenario.write_job import save_with_unique_title

log = structlog.get_logger(__name__)


@celery_app.task(name=c.TaskName.WRITE_MITRE_SCENARIOS, bind=True)
def write_mitre_scenarios(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: write the MITRE run's current set under the run's job lease."""
    run_leased_job(
        self, c.Collection.SESSIONS, record_id, epoch, write_mitre_scenario_set, fields=mitre_session.MITRE_RUN_FIELDS
    )


def write_mitre_scenario_set(lease: JobLease) -> None:
    """Plan the run when it has no paths yet, then write the set's open paths in parallel, saving each card."""
    started, settings = time.perf_counter(), get_settings()
    chat, index, run = get_scenario_chat_model(), get_current_mitre_index(), lease.record
    mitre, timings = run["mitre"], {}  # the board's times, as the shared pipeline's plan_progress names them
    if not mitre.get("paths"):
        mitre = mitre_session.plan_and_store_mitre_paths(lease, chat, index, settings)
        timings["timings.threats_s"] = round(time.perf_counter() - started, 1)
    writing_from = time.perf_counter()
    progress = mitre_session.read_mitre_run_progress(lease.record_id, mitre, index, lease.epoch)
    open_paths = progress["open_paths"]
    goal = min(max(0, run["job"]["set_goal"] - progress["written_this_set"]), len(open_paths))  # a retry: its rest
    mitre_session.store_mitre_stage(lease, c.MitreStage.WRITING)
    outcome = engine.write_scenarios_in_parallel(
        chat,
        open_paths,
        goal,
        progress["group_usage"],
        partial(save_mitre_card, lease, run),
        asset_context=mitre["asset_context"],
        index=index,
        settings=settings,
        actor_selection=mitre["actor_selection"],
        system_mitre_assets=mitre_session.system_mitre_assets_by_name(mitre),
        run_target=progress["written"] + goal,  # the share cap is of the scenarios written by this set's end
        crossing_required=mitre["it_ot_crossing_required"] and not progress["crossing_met"],
    )
    failed_path_ids = []
    for position in outcome["failed_positions"]:
        failed_path_ids.append(open_paths[position]["path_id"])
    written = len(outcome["written"])
    seconds = round(time.perf_counter() - started, 1)
    log.info(c.LogEvent.MITRE_SET_WRITTEN, written=written, dropped=len(failed_path_ids), seconds=seconds)
    remaining = len(open_paths) - written - len(failed_path_ids)
    removed = outcome["groups_removed_over_share"]
    timings["timings.scenarios_s"] = round(time.perf_counter() - writing_from, 1)
    finish_mitre_set(
        lease, mitre, remaining, written + progress["written_this_set"], failed_path_ids, goal, removed, timings
    )


def save_mitre_card(lease: JobLease, run: dict[str, Any], path: dict[str, Any], scenario: dict[str, Any]) -> None:
    """Saves one written scenario's card while the job still owns the run (a retry finds it saved)."""
    if not lease.renew_job():  # right before the save: a cancelled or reaped run saves nothing more
        raise LeaseLost(lease.record_id)
    card = mitre_session.build_mitre_card(run, path, scenario, lease.epoch)
    save_with_unique_title(get_threat_scenario_repository(), card, card["content"]["actors"][0]["name"])
    publish_session_status(lease.record_id)


def finish_mitre_set(
    lease: JobLease,
    mitre: dict[str, Any],
    remaining: int,
    written: int,
    failed_path_ids: list[str],
    goal: int,
    groups_removed_over_share: int,
    timings: dict[str, float],
) -> None:
    """Queue the set's controls, count the run's cards and end the job; a set that wrote nothing fails the run.
    `written`: the set's cards, those an earlier try of this job saved included; the groups the share cap removed
    are added to the run's count; `timings`: the set's planning and writing seconds for the board."""
    if written:
        send_job(c.TaskName.MAP_CONTROLS, lease.record_id, lease.epoch)
    get_threat_scenario_session_repository().update_scenario_session_counts(lease.record_id)
    changes = {
        "mitre.failed_path_ids": [*(mitre.get("failed_path_ids") or []), *failed_path_ids],
        "counts.planned": mitre["run_target"],
        "counts.remaining": remaining,
        **timings,
    }
    removed = {"$inc": {"mitre.groups_removed_over_share": groups_removed_over_share}}
    if goal and not written:  # its failed paths are stored first: never written again
        lease.update_job(changes, operators=removed)
        raise JobFailed(c.ErrorCode.GENERATION_FAILED, c.MitreMessage.NO_SCENARIO)
    outcome = c.RunActionOutcome.PARTIAL if failed_path_ids else c.RunActionOutcome.COMPLETE
    ended = {"mitre.stage": c.MitreStage.COMPLETE, "last_action.outcome": outcome} | ended_job_fields(c.Status.DONE)
    lease.update_job(changes | ended, operators=removed)
