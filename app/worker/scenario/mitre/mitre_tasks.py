"""The MITRE run's task (ADR-010): tsg_write_mitre_scenarios writes one set of a MITRE run (its first set plans
the run first) or, for a regenerate, writes its chosen paths again as new versions. Each card is saved as it is
written; no controls job maps it (owner 2026-11-27: its remediation plan identifies its controls)."""

import time
from functools import partial
from typing import Any

import structlog
from celery import Task

from app.ai import ChatModel
from app.ai.chat import get_scenario_chat_model
from app.core import constants as c
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.exceptions import JobFailed, LeaseLost
from app.crud.jobs import JobLease, ended_job_fields
from app.crud.scenarios import (
    ThreatScenarioRepository,
    get_threat_scenario_repository,
    get_threat_scenario_session_repository,
)
from app.domain.scenario import write
from app.domain.scenario.attack_prompt import list_threat_choices
from app.domain.scenario.mitre_scenario import mitre_engine as engine
from app.domain.scenario.mitre_scenario import mitre_session
from app.realtime.publisher import publish_session_status
from app.search.library_cache import get_library_cache
from app.search.mitre.mitre_index import MitreIndex, get_current_mitre_index
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job
from app.worker.scenario.write_job import _note_regenerate_failure, save_with_unique_title, supersede_scenario_version

log = structlog.get_logger(__name__)


@celery_app.task(name=c.TaskName.WRITE_MITRE_SCENARIOS, bind=True)
def write_mitre_scenarios(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: run the MITRE run's queued job under the run's job lease."""
    run_leased_job(self, c.Collection.SESSIONS, record_id, epoch, run_mitre_job, fields=mitre_session.MITRE_RUN_FIELDS)


def run_mitre_job(lease: JobLease) -> None:
    """A regenerate's job (it carries a batch of scenarios to replace) or a set's."""
    if lease.record["job"].get("batch"):
        rewrite_mitre_scenarios(lease)
    else:
        write_mitre_scenario_set(lease)


def build_writer_arguments(mitre: dict[str, Any], index: MitreIndex, settings: Settings) -> dict[str, Any]:
    """The writers' run-wide inputs; the library's threat types come from its in-memory cache (no database read)."""
    _, threat_types = list_threat_choices(get_library_cache().get_threat_library())
    return {
        "asset_context": mitre["asset_context"],
        "index": index,
        "settings": settings,
        "actor_selection": mitre["actor_selection"],
        "system_mitre_assets": mitre_session.system_mitre_assets_by_name(mitre),
        "threat_types": threat_types,
    }


def write_mitre_scenario_set(lease: JobLease) -> None:
    """Plan the run when it has no paths yet, then write the set's open paths together, saving each card (a set
    short of open paths asks the further round first; one that leaves none asks it once its cards are saved)."""
    started, settings = time.perf_counter(), get_settings()
    chat, index, run = get_scenario_chat_model(), get_current_mitre_index(), lease.record
    mitre = run["mitre"]
    if not mitre.get("paths"):
        mitre = mitre_session.plan_and_store_mitre_paths(lease, chat, index, settings)
    mitre, progress = read_open_paths_planning_more_when_short(lease, chat, index, settings, mitre)
    timings = {"timings.threats_s": seconds_until_writing(run, started)}  # the board's, as plan_progress's
    writing_from, open_paths = time.perf_counter(), progress["open_paths"]
    goal = min(max(0, run["job"]["set_goal"] - progress["written_this_set"]), len(open_paths))  # a retry: its rest
    goal = min(goal, max(0, mitre["run_target"] - progress["written"]))  # never past the run's target
    mitre_session.store_mitre_stage(lease, c.MitreStage.WRITING)
    outcome = engine.write_scenario_set(
        chat,
        open_paths,
        goal,
        progress["group_usage"],
        partial(save_mitre_card, lease, run, {}),
        **build_writer_arguments(mitre, index, settings),
        run_target=progress["written"] + goal,  # the share cap is of the scenarios written by this set's end
        crossing_required=mitre["it_ot_crossing_required"] and not progress["crossing_met"],
    )
    failed_path_ids = failed_paths_of(outcome, open_paths)
    written = len(outcome["written"])
    seconds = round(time.perf_counter() - started, 1)
    log.info(c.LogEvent.MITRE_SET_WRITTEN, written=written, dropped=len(failed_path_ids), seconds=seconds)
    remaining = min(len(open_paths) - len(failed_path_ids), mitre["run_target"] - progress["written"]) - written
    timings["timings.scenarios_s"] = round(time.perf_counter() - writing_from, 1)
    written += progress["written_this_set"]  # an earlier try's saved cards count too
    run_failed = bool(goal) and not written and not progress["written"]  # no card in the whole run
    if not run_failed:  # a run left with no card fails: no round for it
        mitre, remaining = plan_more_when_none_left(lease, chat, index, settings, mitre, remaining, timings)
    finish_mitre_set(
        lease, mitre, written, failed_path_ids, run_failed, remaining, outcome["groups_removed_over_share"], timings
    )


def seconds_until_writing(run: dict[str, Any], job_started: float) -> float:
    """The board's threats time, as the shared pipeline's (owner 2026-10-28): a create's from its job's start (its
    plan); a next set's or regenerate's from the click, so its queue wait and any planning round in it count."""
    last_action = run.get("last_action") or {}
    if last_action.get("kind") in (c.RunActionKind.NEXT_SET, c.RunActionKind.REGENERATE):
        return round((utc_now() - last_action["started_at"]).total_seconds(), 1)
    return round(time.perf_counter() - job_started, 1)


def failed_paths_of(outcome: dict[str, Any], open_paths: list[dict[str, Any]]) -> list[str]:
    """The path ids the set's writing dropped."""
    failed_path_ids = []
    for position in outcome["failed_positions"]:
        failed_path_ids.append(open_paths[position]["path_id"])
    return failed_path_ids


def read_open_paths_planning_more_when_short(
    lease: JobLease, chat: ChatModel, index: MitreIndex, settings: Settings, mitre: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The run's progress (its open paths). A set of an incomplete "all paths" plan with fewer open paths than it
    writes asks the planner's further round first, so a round is asked only by the set that needs it."""
    progress = mitre_session.read_mitre_run_progress(lease.record_id, mitre, index, lease.epoch)
    set_goal = lease.record["job"]["set_goal"] - progress["written_this_set"]
    if len(progress["open_paths"]) >= set_goal or mitre.get("paths_complete", True):
        return mitre, progress
    open_count = len(progress["open_paths"])
    mitre = mitre_session.plan_further_paths_first(lease, chat, index, settings, mitre, open_count)
    return mitre, mitre_session.read_mitre_run_progress(lease.record_id, mitre, index, lease.epoch)


def plan_more_when_none_left(
    lease: JobLease,
    chat: ChatModel,
    index: MitreIndex,
    settings: Settings,
    mitre: dict[str, Any],
    remaining: int,
    timings: dict[str, float],
) -> tuple[dict[str, Any], int]:
    """An incomplete "all paths" plan that this set left with no open path asks its further round now, so the
    board never reads complete while the planner may find more: (the run's `mitre` part, the paths still open).
    The round's seconds join the set's threats time in `timings`. A plan with paths still open waits for the next
    set that runs short (read_open_paths_planning_more_when_short)."""
    if mitre.get("paths_complete", True) or remaining > 0:
        return mitre, remaining
    planned_before, round_from = len(mitre["paths"]), time.perf_counter()
    mitre = mitre_session.plan_further_paths_first(lease, chat, index, settings, mitre, remaining)
    timings["timings.threats_s"] = round(timings["timings.threats_s"] + time.perf_counter() - round_from, 1)
    return mitre, remaining + len(mitre["paths"]) - planned_before


def rewrite_mitre_scenarios(lease: JobLease) -> None:
    """A regenerate: each chosen path written again from its plan; the new version is saved and supersedes the
    path's current card, and a path that fails its checks keeps its current card, which shows regenerate_error."""
    started, settings, run = time.perf_counter(), get_settings(), lease.record
    chat, index, mitre = get_scenario_chat_model(), get_current_mitre_index(), run["mitre"]
    scenarios = get_threat_scenario_repository()
    current_cards, already_replaced = find_cards_to_rewrite(lease, scenarios)
    paths = []
    for path in mitre["paths"]:
        if path["path_id"] in current_cards:
            paths.append(path)
    progress = mitre_session.read_mitre_run_progress(
        lease.record_id, mitre, index, lease.epoch, replaced_path_ids=set(current_cards)
    )
    timings = {"timings.threats_s": seconds_until_writing(run, started)}
    writing_from = time.perf_counter()
    mitre_session.store_mitre_stage(lease, c.MitreStage.WRITING)
    outcome = engine.write_scenario_set(
        chat,
        paths,
        len(paths),  # only these paths: none is backfilled by another
        progress["group_usage"],  # the cards being replaced not counted: a version keeps its own groups
        partial(save_mitre_card, lease, run, current_cards),
        **build_writer_arguments(mitre, index, settings),
        run_target=progress["written"],  # a rewrite adds no scenario to the run
        crossing_required=False,
    )
    for position in outcome["failed_positions"]:
        failed_card = current_cards[paths[position]["path_id"]]
        _note_regenerate_failure(scenarios, failed_card["_id"], *regenerate_failure_of(paths[position], index))
    replaced = already_replaced + len(outcome["written"])
    timings["timings.scenarios_s"] = round(time.perf_counter() - writing_from, 1)
    finish_mitre_rewrite(lease, replaced, len(run["job"]["batch"]), timings)


def regenerate_failure_of(path: dict[str, Any], index: MitreIndex) -> tuple[c.ErrorCode, str]:
    """(code, message) of a path a regenerate could not write: one whose technique an ATT&CK import retired
    says so, never a retryable-looking "no scenario passed" (owner 2026-11-27)."""
    if engine.retired_techniques_of(path, index):
        return c.ErrorCode.LIBRARY_RECORD_RETIRED, c.MitreMessage.TECHNIQUE_RETIRED
    return c.ErrorCode.GENERATION_FAILED, c.MitreMessage.NO_SCENARIO


def find_cards_to_rewrite(lease: JobLease, scenarios: ThreatScenarioRepository) -> tuple[dict[str, Any], int]:
    """The batch's current cards by path, in one read, and how many an earlier try of this job already replaced
    (its new version saved: superseded now if the try stopped between the two writes, never written again)."""
    batch = lease.record["job"]["batch"]
    path_ids = []
    for item in batch:
        path_ids.append(item["path_id"])
    rows = scenarios.list(
        fields="version", session_id=lease.record_id, path_id_in=path_ids, status=c.ScenarioStatus.DONE
    )
    cards_by_id = {}
    for row in rows:
        cards_by_id[row["_id"]] = row
    current_cards, already_replaced = {}, 0
    for item in batch:
        card = cards_by_id.get(item.get("replaces"))
        if card is None:  # no current card to replace (a failure card is rewritten by the shared regenerate only)
            continue
        new_id = write.build_scenario_id(lease.record_id, item["path_id"], card["version"] + 1)
        if card["superseded_by"] or new_id in cards_by_id:
            if not card["superseded_by"]:
                supersede_scenario_version(scenarios, card["_id"], new_id)
            already_replaced += 1
            continue
        current_cards[item["path_id"]] = card
    return current_cards, already_replaced


def save_mitre_card(
    lease: JobLease, run: dict[str, Any], current_cards: dict[str, Any], path: dict[str, Any], scenario: dict[str, Any]
) -> None:
    """Saves one written scenario's card while the job still owns the run (a retry finds it saved); with a current
    card for its path (`current_cards`, a regenerate's), as its next version, which then supersedes it."""
    if not lease.renew_job():  # right before the save: a cancelled or reaped run saves nothing more
        raise LeaseLost(lease.record_id)
    replaced = current_cards.get(path["path_id"])
    card = mitre_session.build_mitre_card(run, path, scenario, lease.epoch, replaced)
    scenarios = get_threat_scenario_repository()
    save_with_unique_title(scenarios, card, card["content"]["actors"][0]["name"])
    if replaced:
        supersede_scenario_version(scenarios, replaced["_id"], card["_id"])
    publish_session_status(lease.record_id)


def finish_mitre_set(
    lease: JobLease,
    mitre: dict[str, Any],
    written: int,
    failed_path_ids: list[str],
    run_failed: bool,
    remaining: int,
    groups_removed_over_share: int,
    timings: dict[str, float],
) -> None:
    """Count the run's cards and end the job. `run_failed`: the set wrote nothing and the run has no card, so the
    run fails; a later set that writes nothing ends partial, as the shared next set does, and keeps the run's
    cards. `written`: its cards, those an earlier try saved included; `timings`: the set's planning and writing
    seconds for the board."""
    get_threat_scenario_session_repository().update_scenario_session_counts(lease.record_id)
    changes = {
        "mitre.failed_path_ids": [*(mitre.get("failed_path_ids") or []), *failed_path_ids],
        "counts.planned": mitre["run_target"],
        "counts.remaining": remaining,
        **timings,
    }
    operators: dict[str, dict[str, Any]] = {"$inc": {"mitre.groups_removed_over_share": groups_removed_over_share}}
    if run_failed:  # its failed paths are stored first: never written again
        lease.update_job(changes, operators=operators)
        raise JobFailed(c.ErrorCode.GENERATION_FAILED, c.MitreMessage.NO_SCENARIO)
    outcome = c.RunActionOutcome.PARTIAL if failed_path_ids else c.RunActionOutcome.COMPLETE
    ended = {"mitre.stage": c.MitreStage.COMPLETE, "last_action.outcome": outcome} | ended_job_fields(c.Status.DONE)
    if lease.record["last_action"]["kind"] == c.RunActionKind.NEXT_SET:  # the board's last_next_set, as shared
        ended |= {
            "last_next_set.outcome": outcome,
            "last_next_set.delivered": written,
            "last_next_set.remaining": remaining,
        }
    lease.update_job(changes | ended, operators=operators)


def finish_mitre_rewrite(lease: JobLease, replaced: int, requested: int, timings: dict[str, float]) -> None:
    """Count the run's cards and end the job with the board's last_regen and `timings` (its threats and writing
    seconds)."""
    get_threat_scenario_session_repository().update_scenario_session_counts(lease.record_id)
    outcome = c.RunActionOutcome.COMPLETE if replaced == requested else c.RunActionOutcome.PARTIAL
    ended = {
        "mitre.stage": c.MitreStage.COMPLETE,
        "last_action.outcome": outcome,
        "last_regen.outcome": outcome,
        "last_regen.replaced": replaced,
        **timings,
    }
    lease.update_job(ended | ended_job_fields(c.Status.DONE))
