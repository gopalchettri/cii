"""The owner's cancel, resume and delete of runs and plans, the list of work, and the controls sweep."""

from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Collection, JobControl, Lease, RunActionKind, RunActionOutcome, RunKind, Status
from app.crud.base import MongoRepository, Record
from app.crud.jobs import ended_job_fields
from app.crud.remediation import get_remediation_repository
from app.crud.scenarios import (
    DELETING_MARK,
    FAILED_WITH_ATTEMPTS_LEFT,
    MAPPED_VERSIONS,
    SWEPT,
    get_threat_scenario_repository,
    get_threat_scenario_session_repository,
    run_controls_to_stop,
    waiting_controls,
)

_WORKING = [Status.QUEUED, Status.RUNNING]
_LISTED_FIELDS = dict.fromkeys(
    ("asset_id", "status", "job.due_at", "job.attempts", "job.retry", "user_id", "client_id")
    + ("created_at", "updated_at"),
    1,
)
_SESSION_FIELDS = _LISTED_FIELDS | dict.fromkeys(
    ("context.asset.name", "step", "job.task", "counts", "controls_delivery.retry"), 1
)
_PLAN_FIELDS = _LISTED_FIELDS | dict.fromkeys(("session_id", "scenario_id", "job.waiting"), 1)
_MAPPING_FIELDS = _LISTED_FIELDS | {"created_by": 1}
_SUMMARY_OF: dict[str, str] = {RunActionKind.NEXT_SET: "last_next_set", RunActionKind.REGENERATE: "last_regen"}
#: A resume's first update: the session reads done again unless at work (its cancel stamp kept).
_DONE_AGAIN = [
    {"$set": {"status": {"$cond": [{"$in": ["$status", [Status.DONE, Status.CANCELLED]]}, Status.DONE, "$status"]}}}
]
_CANCEL_CONTROLS = {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}}
#: What the sweep calls once per session whose controls it changed.
Recount = Callable[[str], object]


def list_working_jobs(tenant_id: str, entity_id: int) -> tuple[list[Record], list[Record], list[Record], int]:
    """The entity's runs at work (and finished runs still matching controls), plans being written and the
    tenant entity's mappings being generated, oldest first (at most JobControl.LIST_MAX per query); the total."""
    working = {"entity_id": entity_id, "status": {"$in": _WORKING}}
    matching = {"entity_id": entity_id, "status": {"$nin": _WORKING}, "kind": {"$ne": RunKind.MANUAL}}
    matching["counts.controls_waiting"] = {"$gt": 0}  # the partial index holds only these
    sessions = get_threat_scenario_session_repository().collection
    runs, run_total = _oldest_first(sessions, _SESSION_FIELDS, (working, matching))
    plans, plan_total = _oldest_first(get_remediation_repository().collection, _PLAN_FIELDS, (working,))
    query = {"tenant_id": tenant_id, "entity_id": entity_id, "status": {"$in": _WORKING}}
    mappings_collection = MongoRepository(Collection.SERVICE_MAPPINGS).collection
    mappings, mapping_total = _oldest_first(mappings_collection, _MAPPING_FIELDS, (query,))
    return runs, plans, mappings, run_total + plan_total + mapping_total


def cancel_scenario_session(session_id: str, entity_id: int, who: dict[str, Any]) -> tuple[bool, int]:
    """(whether the run's job was stopped, how many scenarios' controls were); a done run is stamped."""
    runs = get_threat_scenario_session_repository()
    sessions, now = runs.collection, utc_now()
    session, cancelled = {"_id": session_id, "entity_id": entity_id}, {**who, "at": now}
    stop_session = {
        "$set": _cancelled_job(cancelled, now) | {"last_action.outcome": RunActionOutcome.CANCELLED},
        "$unset": {"controls_delivery": ""},
    }
    before = sessions.find_one_and_update(
        {**session, "status": {"$in": _WORKING}}, stop_session, {"last_action.kind": 1, "job.epoch": 1}
    )
    # The stopped next set's or regenerate's summary ends cancelled, only at the stopped job's epoch.
    if before is not None and (summary := _SUMMARY_OF.get(str((before.get("last_action") or {}).get("kind")))):
        at_epoch = {"_id": session_id, "job.epoch": (before.get("job") or {}).get("epoch")}
        sessions.update_one(
            at_epoch | {f"{summary}.outcome": RunActionOutcome.RUNNING},
            {"$set": {f"{summary}.outcome": RunActionOutcome.CANCELLED}},
        )
    controls = (
        get_threat_scenario_repository()
        .collection.update_many(
            {"session_id": session_id, "entity_id": entity_id, **run_controls_to_stop(now)}, _CANCEL_CONTROLS
        )
        .modified_count
    )
    if controls:
        runs.update_scenario_session_counts(session_id)
    if controls and before is None:  # a finished run whose controls were still being matched
        sessions.update_one(
            {**session, "status": {"$nin": _WORKING}},
            {"$set": {"cancelled": cancelled, "updated_at": now}, "$unset": {"controls_delivery": ""}},
        )
    return before is not None, controls


def cancel_remediation_plan(remediation_id: str, entity_id: int, who: dict[str, Any]) -> dict[str, Any] | None:
    """Stop the plan's job and the controls only it maps; its scenario_id and session_id."""
    sessions, scenarios, now = get_threat_scenario_session_repository(), get_threat_scenario_repository(), utc_now()
    plan = get_remediation_repository().collection.find_one_and_update(
        {"_id": remediation_id, "entity_id": entity_id, "status": {"$in": _WORKING}},
        {"$set": _cancelled_job({**who, "at": now}, now)},
        {"scenario_id": 1, "session_id": 1},
    )
    if plan is None:
        return None
    scenario_id = plan["scenario_id"]
    own_controls = {"_id": scenario_id, "source": RunKind.MANUAL, "controls.status": {"$in": _WORKING}}
    stopped = scenarios.collection.update_one(own_controls, _CANCEL_CONTROLS).modified_count
    # A generated scenario's controls the plan's job holds go back to the run (cancelled with it).
    handed_back = False
    if (held := scenarios.get_plans_controls_claim(scenario_id)) is not None:
        outcome = Status.CANCELLED if sessions.is_cancelled(held["session_id"]) else Status.QUEUED
        claim = held["controls"]
        handed_back = scenarios.update_scenario_controls(scenario_id, claim["task_id"], claim["attempts"], outcome)
    if (stopped or handed_back) and plan.get("session_id"):
        sessions.update_scenario_session_counts(plan["session_id"])
    return plan


def resume_scenario_controls(session_id: str, cancelled_at: datetime | None, restart_times: bool = False) -> int | None:
    """Re-queue the controls a cancel stopped; 0 when a newer cancel wins, None when deleting."""
    # The session changes first and the delete mark is checked again after the re-queue; a cancel stamp
    # other than `cancelled_at` (the one the caller saw) undoes the re-queue.
    runs = get_threat_scenario_session_repository()
    sessions, scenarios = runs.collection, get_threat_scenario_repository().collection
    stopped = {"session_id": session_id, "controls.status": Status.CANCELLED}
    if scenarios.find_one(stopped, {"_id": 1}) is None:
        return 0
    stamp_seen = {"_id": session_id, "cancelled.at": cancelled_at}
    if not sessions.update_one({**stamp_seen, DELETING_MARK: {"$exists": False}}, _DONE_AGAIN).matched_count:
        return None if runs.is_being_deleted(session_id) else 0
    requeued_at = utc_now()
    waits = {"controls.status": Status.QUEUED, "controls.queued_at": requeued_at, "controls.error": None}
    requeued = scenarios.update_many(stopped, {"$set": waits}).modified_count
    if runs.is_being_deleted(session_id):
        _stop_requeued_controls(session_id, requeued_at)
        return None
    resumed: dict[str, Any] = {"$unset": {"cancelled": ""}}
    if restart_times:  # the resume is the run's latest action: its times start again
        times = {"threats_s": 0.0, "scenarios_s": 0.0}
        resumed["$set"] = {"timings": times, "last_action.started_at": requeued_at}
    if not sessions.update_one(stamp_seen, resumed).matched_count:
        _stop_requeued_controls(session_id, requeued_at)  # cancelled meanwhile: the cancel stands
        return 0
    runs.update_scenario_session_counts(session_id)
    return requeued


def _stop_requeued_controls(session_id: str, requeued_at: datetime) -> None:
    get_threat_scenario_repository().collection.update_many(
        {"session_id": session_id, "controls.status": Status.QUEUED, "controls.queued_at": requeued_at},
        {"$set": {"controls.status": Status.CANCELLED}},
    )


def list_working_plans(session_id: str, entity_id: int) -> list[dict[str, Any]]:
    """The run's remediation plans being written, oldest first: id and scenario_id."""
    working = {"session_id": session_id, "entity_id": entity_id, "status": {"$in": _WORKING}}
    return list(get_remediation_repository().collection.find(working, {"scenario_id": 1}).sort("created_at", 1))


def delete_scenario_session(session_id: str, entity_id: int) -> tuple[dict[str, int], list[str]] | None:
    """Mark, check for work, then delete SQL operation records, scenarios, plans and the run last."""
    sessions = get_threat_scenario_session_repository().collection
    scenarios = get_threat_scenario_repository().collection
    plans, session = get_remediation_repository().collection, {"_id": session_id, "entity_id": entity_id}
    marked = sessions.update_one(
        {**session, "status": {"$nin": _WORKING}}, {"$set": {DELETING_MARK: utc_now()}}
    ).matched_count
    if not marked:
        return None
    children = {"session_id": session_id, "entity_id": entity_id}
    working = {"$in": _WORKING}
    own_controls = {**children, "controls.status": working, "source": {"$ne": RunKind.MANUAL}}
    work_left = (
        sessions.find_one({"_id": session_id, "status": working}, {"_id": 1}) is not None
        or scenarios.find_one(own_controls | MAPPED_VERSIONS, {"_id": 1}) is not None
        or bool(list_working_plans(session_id, entity_id))
    )
    if work_left:  # final: nothing new can start on a marked session
        sessions.update_one(session, {"$unset": {DELETING_MARK: ""}})
        return None
    operation_ids = [  # a reused key must never replay a deleted scenario's answer
        f"{write}:{scenario_id}"
        for scenario_id in scenarios.distinct("_id", children)
        for write in ("promote", "propose")
    ]
    if operation_ids:
        sessions.database[Collection.SQL_OPERATIONS].delete_many({"_id": {"$in": operation_ids}})
    plan_ids: list[str] = plans.distinct("_id", children)
    removed = {
        "scenarios": scenarios.delete_many(children).deleted_count,
        "remediation_plans": plans.delete_many(children).deleted_count,
    }
    sessions.delete_one(session)
    return removed, plan_ids


def settle_stopped_scenario_sessions(recount: Recount | None = None) -> None:
    """Stop controls waiting on a cancelled run; delete a deleted run's scenarios."""
    runs, scenarios = get_threat_scenario_session_repository(), get_threat_scenario_repository().collection
    stoppable = {"$or": [*waiting_controls(utc_now()), FAILED_WITH_ATTEMPTS_LEFT]}
    waiting = {**SWEPT, "$and": [MAPPED_VERSIONS, stoppable]}
    waiting_cards = list(scenarios.find(waiting, {"session_id": 1}))
    waiting_ids = {card.get("session_id") for card in waiting_cards}
    # How far back the sweep looks for scenarios whose session is gone: a write racing a delete.
    recent = {"created_at": {"$gte": utc_now() - timedelta(seconds=Lease.MAX_JOB_SECONDS)}}
    session_ids = [found for found in waiting_ids | set(scenarios.distinct("session_id", recent)) if found]
    if not session_ids:
        return
    states = {record["_id"]: record.get("status") for record in runs.list(fields=["status"], _id={"$in": session_ids})}
    if cancelled := {session_id for session_id in waiting_ids if states.get(session_id) == Status.CANCELLED}:
        stopped_cards = [card["_id"] for card in waiting_cards if card.get("session_id") in cancelled]
        scenarios.update_many({**waiting, "_id": {"$in": stopped_cards}}, _CANCEL_CONTROLS)
        for session_id in sorted(cancelled):
            (recount or runs.update_scenario_session_counts)(session_id)
    if deleted := [session_id for session_id in session_ids if session_id not in states]:
        scenarios.delete_many({"session_id": {"$in": deleted}})


def sweep_stalled_controls(recount: Recount | None = None) -> list[str]:
    """Settle stopped runs, fail or re-queue stalled controls; the runs that need a send."""
    runs, scenarios = get_threat_scenario_session_repository(), get_threat_scenario_repository()
    recount = recount or runs.update_scenario_session_counts
    settle_stopped_scenario_sessions(recount)
    now = utc_now()
    abandoned = scenarios.fail_abandoned_controls(now)
    session_ids = scenarios.requeue_stalled_controls(now)
    for session_id in sorted({*abandoned, *session_ids}):
        recount(session_id)
    live = runs.list_scenario_sessions_with_live_delivery(session_ids)
    return sorted(set(session_ids) - live)


def _cancelled_job(cancelled: dict[str, Any], now: datetime) -> dict[str, Any]:
    return ended_job_fields(Status.CANCELLED, now) | {"cancelled": cancelled, "updated_at": now}


def _oldest_first(
    records: MongoCollection, fields: dict[str, int], queries: Iterable[dict[str, Any]]
) -> tuple[list[Record], int]:
    found: list[Record] = []
    total = 0
    for query in queries:
        page = list(records.find(query, fields).sort("created_at", 1).limit(JobControl.LIST_MAX))
        found += page
        total += records.count_documents(query) if len(page) == JobControl.LIST_MAX else len(page)
    return found, total
