"""The MITRE run's use cases (ADR-010): start it, plan it once, turn each written scenario into a card, queue
its next set and read its status. The engine (mitre_engine.py) does the AI work; this module stores it.

A MITRE run is a tsg_sessions record with pipeline "mitre" at step scenarios; its own part is `mitre`: stage,
asset_context (the engine's shape), and once planned: paths, actor_selection, system_mitre_assets,
it_ot_crossing_required, it_ot_crossing_reason, invalid_paths, planner_calls, run_target, relevant_actors,
failed_path_ids and groups_removed_over_share.
Its cards are tsg_scenarios records: content.mitre is the POC scenario, content.attack the shape the controls
job picks CII library controls from (attack_controls.pick_set_controls)."""

import uuid
from datetime import datetime
from typing import Any, Final

import structlog

from app.ai import ChatModel
from app.core import constants as c
from app.core import metrics
from app.core.asset_types import compatible_asset_types
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.constants import AiApi
from app.core.exceptions import Conflict, NotFound
from app.core.logging import current_job_origin, current_request_id
from app.core.security import Principal
from app.crud import work_control
from app.crud.audit import get_audit_repository
from app.crud.jobs import JobLease, new_job
from app.crud.mitre.mitre_stix import get_mitre_enterprise_stix_repository, get_mitre_ics_stix_repository
from app.crud.scenarios import (
    DELETING_MARK,
    get_asset_context,
    get_threat_scenario_repository,
    get_threat_scenario_session_repository,
    running_action,
)
from app.domain import jobs as job_rules
from app.domain.scenario import runs, write
from app.domain.scenario.mitre_scenario import mitre_engine as engine
from app.domain.scenario.session import build_run_context, check_session_ready_for_review, get_session_owned_by_caller
from app.domain.shared.audit import audit_target, caller_actor, origin_of_its_jobs
from app.domain.shared.prompt_redaction import facts_safe_for_prompt
from app.realtime.publisher import publish_session_status
from app.schemas.mitre.mitre_scenarios import MitreRunStatus, MitreSessionStarted, MitreSessionStatus
from app.schemas.scenario_internal import FrozenContext, control_view
from app.schemas.scenarios import SessionStatus, StartRunRequest
from app.search.mitre.mitre_index import MitreIndex, get_mitre_id
from app.worker.celery_app import send_job

log = structlog.get_logger(__name__)

#: A run's status as the MITRE routes show it (the POC's words).
SHOWN_STATUS: Final[dict[c.Status, MitreRunStatus]] = {
    c.Status.QUEUED: "queued",
    c.Status.RUNNING: "running",
    c.Status.DONE: "complete",
    c.Status.FAILED: "failed",
    c.Status.CANCELLED: "cancelled",
}
#: What the worker's claim reads of a MITRE run: everything a set needs, in the claim's one read.
MITRE_RUN_FIELDS: Final = ("entity_id", "asset_id", "context", "mitre", "job.set_goal")
#: A system column the engine never gets: ids, the alias and the category the engine's own type replaces.
SYSTEM_COLUMNS_NOT_SENT: Final = (*c.ContextProperties.ALWAYS_USED, "category_name")
#: The status read's fields: the run without its frozen context or plan paths.
MITRE_STATUS_FIELDS: Final = (
    "entity_id",
    "pipeline",
    "status",
    "counts",
    "job.error",
    "last_action.started_at",
    "finished_at",
    "mitre.stage",
    "mitre.asset_context",
    "mitre.actor_selection",
    "mitre.relevant_actors",
    "mitre.groups_removed_over_share",
    "mitre.run_target",
    "mitre.failed_path_ids",
    "mitre.it_ot_crossing_required",
    "mitre.it_ot_crossing_reason",
    "mitre.invalid_paths",
    "mitre.planner_calls",
    "mitre.system_mitre_assets",
)
MITRE_CARD_FIELDS: Final = (
    "path_id",
    "path_rank",
    "content.mitre",
    "controls.status",
    "controls.items",
    "controls.technique_states",
)


def mitre_status_url(session_id: str) -> str:
    return f"/v1/mitre_sessions/{session_id}"


@origin_of_its_jobs(AiApi.MITRE_CREATE_SESSION)
def create_mitre_scenario_session(
    principal: Principal, request: StartRunRequest, idempotency_key: str, *, derived: bool = False
) -> tuple[MitreSessionStarted, bool]:
    """Start a MITRE run: where to follow it and whether it was created now (False for a replay)."""
    # ponytail: the start route's own replay and request hash, shared so one key never replays another pipeline
    replayed = runs._replay(principal, request, idempotency_key, derived, c.RunPipeline.MITRE)
    if replayed:
        return _started(replayed.session_id, replayed.status), False
    context = build_run_context(request, get_asset_context(principal.entity_id, request))
    asset_context = build_engine_asset_context(context)
    refuse_without_mitre_data(asset_context)
    record = build_new_mitre_run_record(principal, request, idempotency_key, context, asset_context)
    clash = get_threat_scenario_session_repository().create_scenario_session(record)
    if clash:
        replayed = runs._replay(principal, request, idempotency_key, derived, c.RunPipeline.MITRE)
        if replayed:
            return _started(replayed.session_id, replayed.status), False
        message = c.SessionMessage.IDEMPOTENCY_KEY_RUN_GONE  # the run that took the key was deleted since
        raise Conflict(message, reason=c.ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    send_job(c.TaskName.WRITE_MITRE_SCENARIOS, record["_id"], record["job"]["epoch"])
    metrics.RUNS.labels(c.RunKind.GENERATED).inc()
    get_audit_repository().create_audit_record(
        c.AuditAction.RUN_STARTED,
        caller_actor(principal),
        audit_target(c.AuditTarget.SESSION, record["_id"]),
        after={"asset_id": record["asset_id"], "supporting_system_ids": record["request"]["supporting_system_ids"]},
    )
    return _started(record["_id"], c.Status.QUEUED), True


def _started(session_id: str, status: c.Status) -> MitreSessionStarted:
    return MitreSessionStarted(
        session_id=session_id, status=SHOWN_STATUS[status], status_url=mitre_status_url(session_id)
    )


def refuse_without_mitre_data(asset_context: dict[str, Any]) -> None:
    """409 intel_no_data unless MITRE Enterprise (and ICS, for an asset with OT) is imported."""
    missing = []
    if get_mitre_enterprise_stix_repository().get(("_id",)) is None:
        missing.append("Enterprise")
    is_ot_in_scope = "OT" in engine.asset_and_system_types(asset_context)
    if is_ot_in_scope and get_mitre_ics_stix_repository().get(("_id",)) is None:
        missing.append("ICS")
    if missing:
        message = c.MitreMessage.NO_MITRE_DATA.format(domains=" and ".join(missing))
        raise Conflict(message, reason=c.ConflictReason.INTEL_NO_DATA)


def engine_asset_type(category_code: str | None, unknown_as: str) -> str:
    r"""The engine's IT or OT for a category code: IT only for IT, OT for OT and IT\OT, `unknown_as` else."""
    fitting = compatible_asset_types(category_code, ())
    if not fitting:
        return unknown_as
    return "OT" if c.AssetType.OT in fitting else "IT"


def build_engine_asset_context(context: FrozenContext) -> dict[str, Any]:
    """The engine's asset context from the run's frozen one: the asset's own facts and its systems', redacted
    as every prompt's are, and no contact name (the engine sends every field to the model)."""
    facts = context.asset_context
    asset_type = engine_asset_type(context.asset.get("category_code"), "IT")
    supporting_systems = []
    for system in context.systems:
        system_facts = {}
        for name, value in system.items():
            if name not in SYSTEM_COLUMNS_NOT_SENT:
                system_facts[name] = value
        system_type = engine_asset_type(system.get("category_code"), asset_type)
        supporting_systems.append({"name": system["name"], "type": system_type, **facts_safe_for_prompt(system_facts)})
    described = {
        "asset_description": facts.get("cii_asset_description"),
        "sector": facts.get("sector"),
        "subsector": facts.get("sub_sector"),
        "service_name": facts.get("critical_service"),
        "data_handled": facts.get("data_handled"),
    }
    named = {"asset_name": context.asset["name"], "asset_type": asset_type}
    return {**named, **facts_safe_for_prompt(described), "supporting_systems": supporting_systems}


def build_new_mitre_run_record(
    principal: Principal,
    request: StartRunRequest,
    idempotency_key: str,
    context: FrozenContext,
    asset_context: dict[str, Any],
) -> dict[str, Any]:
    """A new MITRE run, queued for its first set: INITIAL_SET_SIZE scenarios, planned first."""
    now = utc_now()
    return {
        "_id": uuid.uuid4().hex,
        "kind": c.RunKind.GENERATED,
        "pipeline": c.RunPipeline.MITRE,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,  # the calling system: stored, never shown, never used to refuse
        "asset_id": request.asset_id,
        "request": request.model_dump(exclude={"asset_id"}),
        "request_hash": runs._hash_request(request, c.RunPipeline.MITRE),
        "context": context.to_record(),
        "status": c.Status.QUEUED,
        "step": c.Step.SCENARIOS,
        "last_action": running_action(c.RunActionKind.START, now),
        "counts": {},
        "job": new_job(c.TaskName.WRITE_MITRE_SCENARIOS, 1, now, set_goal=get_settings().initial_set_size),
        "mitre": {"stage": c.MitreStage.QUEUED, "asset_context": asset_context, "failed_path_ids": []},
        "created_at": now,
        "updated_at": now,
        "idempotency_key": idempotency_key,
    }


def store_mitre_stage(lease: JobLease, stage: c.MitreStage) -> None:
    lease.update_job({"mitre.stage": stage})
    publish_session_status(lease.record_id)


def plan_and_store_mitre_paths(
    lease: JobLease, chat: ChatModel, index: MitreIndex, settings: Settings
) -> dict[str, Any]:
    """The run's first set only: select actors, plan the ranked paths and store them; the run's `mitre` part."""
    mitre = lease.record["mitre"]
    asset_context = mitre["asset_context"]
    store_mitre_stage(lease, c.MitreStage.SELECTING_ACTORS)
    selection = engine.select_relevant_actors_from_all_mitre_actors(chat, asset_context, index, settings)
    store_mitre_stage(lease, c.MitreStage.PLANNING)
    planned = engine.plan_attack_paths(chat, asset_context, index, settings, selection)
    paths = []
    for rank, path in enumerate(planned["paths"], start=1):
        paths.append({"path_id": f"mitre-{rank}", "path_rank": rank, **path})
    system_mitre_assets = []  # a list: a system's name may hold a "." that a MongoDB key may not
    for system_name, asset_ids in planned["system_mitre_assets"].items():
        system_mitre_assets.append({"supporting_system": system_name, "mitre_asset_ids": asset_ids})
    stored = {
        "paths": paths,
        "actor_selection": selection,
        "system_mitre_assets": system_mitre_assets,
        "it_ot_crossing_required": planned["it_ot_crossing_required"],
        "it_ot_crossing_reason": planned["it_ot_crossing_reason"],
        "invalid_paths": planned["invalid_paths"],
        "planner_calls": planned["planner_calls"],
        "run_target": len(paths),
        "relevant_actors": report_selected_actors(selection, index),
    }
    changes = {f"mitre.{key}": value for key, value in stored.items()}
    lease.update_job(changes | {"counts.planned": len(paths), "counts.remaining": len(paths)})
    log.info(
        c.LogEvent.MITRE_RUN_PLANNED, paths=len(paths), actors=len(selection["actors"]), status=selection["status"]
    )
    return mitre | stored


def report_selected_actors(selection: dict[str, Any], index: MitreIndex) -> list[dict[str, Any]]:
    """The selected actors in rank order, each with the MITRE quote it was kept for (the POC's audit list)."""
    report = []
    for actor_id in selection["ranked_actor_ids"]:
        actor = index["objects"][actor_id]
        report.append({"mitre_id": get_mitre_id(actor), "name": actor["name"], **selection["actors"][actor_id]})
    return report


def system_mitre_assets_by_name(mitre: dict[str, Any]) -> dict[str, list[str]]:
    """The planner's MITRE ICS asset types of each supporting system, as the engine takes them."""
    by_name = {}
    for mapping in mitre.get("system_mitre_assets") or []:
        by_name[mapping["supporting_system"]] = mapping["mitre_asset_ids"]
    return by_name


def read_mitre_run_progress(run_id: str, mitre: dict[str, Any], index: MitreIndex, epoch: int) -> dict[str, Any]:
    """One read of the run's cards: the paths still open (neither written nor failed), the cards naming each
    group, how many are written (in all and by this set's epoch) and whether one crosses IT and OT."""
    cards = get_threat_scenario_repository().list(
        fields=("path_id", "generation.epoch", "content.mitre.relevant_groups", "content.mitre.attack_techniques"),
        session_id=run_id,
        status=c.ScenarioStatus.DONE,
        newest=True,
    )
    group_usage: dict[str, int] = {}
    written_path_ids, written_this_set, crossing_met = set(), 0, False
    for card in cards:
        written_path_ids.add(card["path_id"])
        if (card.get("generation") or {}).get("epoch") == epoch:
            written_this_set += 1
        scenario = card["content"]["mitre"]
        for group in scenario["relevant_groups"]:
            group_usage[group["mitre_id"]] = group_usage.get(group["mitre_id"], 0) + 1
        technique_ids = []
        for technique in scenario["attack_techniques"]:
            technique_ids.append(technique["stix_id"])
        crossing_met = crossing_met or engine.path_has_both_it_and_ot_techniques(technique_ids, index)
    failed = set(mitre.get("failed_path_ids") or [])
    open_paths = []
    for path in mitre.get("paths") or []:
        if path["path_id"] not in written_path_ids and path["path_id"] not in failed:
            open_paths.append(path)
    return {
        "open_paths": open_paths,
        "group_usage": group_usage,
        "written": len(cards),
        "written_this_set": written_this_set,
        "crossing_met": crossing_met,
    }


def build_mitre_attack_block(scenario: dict[str, Any]) -> dict[str, Any]:
    """content.attack as the controls job reads it: the lead group, each technique with the MITRE mitigations
    recorded for it, and those mitigations once each (the ones that are no defence left out)."""
    recorded = {}
    for technique_mitigations in scenario["mitigations"]:
        recorded[technique_mitigations["technique"]] = technique_mitigations["mitigations"]
    techniques, mitigations = [], dict[str, dict[str, str]]()
    for technique in scenario["attack_techniques"]:
        source = c.IntelSource.ATTACK_ICS if technique["domain"] == "ics" else c.IntelSource.ATTACK_ENTERPRISE
        mitigation_ids = []
        for mitigation in recorded.get(technique["mitre_id"], []):
            mitigation_ids.append(mitigation["mitre_id"])
            if mitigation["mitre_id"] not in c.ControlLinks.NOT_MITIGATIONS:
                mitigations.setdefault(
                    mitigation["mitre_id"], {"id": mitigation["mitre_id"], "name": mitigation["name"]}
                )
        techniques.append(
            {"id": technique["mitre_id"], "name": technique["name"], "source": source, "mitigations": mitigation_ids}
        )
    lead_group = scenario["relevant_groups"][0]
    group = {"id": lead_group["mitre_id"], "name": lead_group["name"]}
    return {"group": group, "techniques": techniques, "mitigations": list(mitigations.values())}


def build_mitre_card_content(run: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    """The card's content: the CII fields every shared route reads, content.mitre (the whole MITRE scenario) and
    content.attack (what the controls are picked from)."""
    system_ids = {}
    for system in run["context"]["systems"]:
        system_ids[system["name"]] = system["id"]
    systems = []
    for system_name in scenario["supporting_systems"]:
        systems.append({"id": system_ids[system_name], "name": system_name, "entry_point": False})
    lead_group = scenario["relevant_groups"][0]
    return {
        "title": scenario["scenario_title"],
        "statement": scenario["threat_scenario"],
        "risk_statement": scenario["risk_statement"],
        "assumptions": list(scenario["assumptions"]),
        "category": scenario["category"],
        "systems": systems,
        "actors": [{"id": None, "name": lead_group["name"], "role": c.ActorRole.ACTING, "closest": False}],
        "prompt_version": c.PromptVersion.MITRE_WRITER,
        "mitre": scenario,
        "attack": build_mitre_attack_block(scenario),
    }


def build_mitre_card(run: dict[str, Any], path: dict[str, Any], scenario: dict[str, Any], epoch: int) -> dict[str, Any]:
    """A written scenario's card, done with its controls queued as every written card's are."""
    now = utc_now()
    origin = {"request_id": current_request_id(), "origin": current_job_origin()}
    return {
        "_id": write.build_scenario_id(run["_id"], path["path_id"], write.FIRST_VERSION),
        "session_id": run["_id"],
        "entity_id": run["entity_id"],
        "asset_id": run["asset_id"],
        "path_id": path["path_id"],
        "path_rank": path["path_rank"],
        "version": write.FIRST_VERSION,
        "source": c.RunKind.GENERATED,
        "status": c.ScenarioStatus.DONE,
        "decision": c.Decision.PENDING,
        "decided_by": None,
        "decided_at": None,
        "replaces": None,
        "superseded_by": None,
        "content": build_mitre_card_content(run, scenario),
        "findings": [],
        "rewritten": False,
        "generation": {"epoch": epoch, "started_at": None, "finished_at": now},
        "controls": {"status": c.Status.QUEUED, "attempts": 0, "queued_at": now, **origin},
        "created_at": now,
        "updated_at": now,
    }


def refuse_other_pipelines(pipeline: str | None, session_id: str) -> None:
    """404 for a run another pipeline made: the MITRE routes never read or write one."""
    if pipeline != c.RunPipeline.MITRE:
        raise NotFound(c.SessionMessage.NOT_FOUND.format(session_id=session_id))


@origin_of_its_jobs(AiApi.MITRE_NEXT_SET)
def write_next_mitre_scenario_set(principal: Principal, run: SessionStatus) -> MitreSessionStarted:
    """Queues the run's next NEXT_SET_SIZE open paths (a run never planned plans first); 409 when none is left."""
    refuse_other_pipelines(run.pipeline, run.session_id)
    check_session_ready_for_review(run)
    if run.counts.get("planned") and not run.counts.get("remaining"):
        message = c.ReviewMessage.NOTHING_LEFT.format(session_id=run.session_id)
        raise Conflict(message, reason=c.ConflictReason.NOTHING_LEFT)
    epoch = queue_next_mitre_set(run, utc_now())
    was_cancelled = run.status == c.Status.CANCELLED or run.cancelled is not None
    if (was_cancelled or run.counts.get("controls_cancelled", 0)) and work_control.resume_scenario_controls(
        run.session_id, None
    ):  # a cancelled run is resumed whole
        send_job(c.TaskName.MAP_CONTROLS, run.session_id, 0)  # the epoch is never checked for controls
    send_job(c.TaskName.WRITE_MITRE_SCENARIOS, run.session_id, epoch)
    publish_session_status(run.session_id)
    target = audit_target(c.AuditTarget.SESSION, run.session_id)
    get_audit_repository().create_audit_record(
        c.AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after={"epoch": epoch}
    )
    return _started(run.session_id, c.Status.QUEUED)


def queue_next_mitre_set(run: SessionStatus, now: datetime) -> int:
    """The next set's job (epoch + 1), written only while the run is as read (the shared next set's fence)."""
    still_as_read = {
        "entity_id": run.entity_id,
        "pipeline": c.RunPipeline.MITRE,
        "job.epoch": run.epoch,
        "status": {"$in": [c.Status.DONE, c.Status.FAILED, c.Status.CANCELLED]},
        "step": c.Step.SCENARIOS,
        "cancelled.at": (run.cancelled or {}).get("at"),  # None also matches no stamp
        DELETING_MARK: {"$exists": False},
    }
    epoch = run.epoch + 1
    queued = {
        "status": c.Status.QUEUED,
        "job": new_job(c.TaskName.WRITE_MITRE_SCENARIOS, epoch, now, set_goal=get_settings().next_set_size),
        "last_action": running_action(c.RunActionKind.NEXT_SET, now),
        "mitre.stage": c.MitreStage.QUEUED,
        "finished_at": None,
        "cancelled": None,
        "timings": {},  # this action's times only, as the shared next set; {} so the controls' $inc still works
        "updated_at": now,
    }
    sessions = get_threat_scenario_session_repository()
    if sessions.update(queued, only_if=still_as_read, _id=run.session_id):
        return epoch
    if sessions.is_being_deleted(run.session_id):
        raise job_rules.run_being_deleted(run.session_id)
    message = c.ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
    raise Conflict(message, reason=c.ConflictReason.GENERATION_IN_PROGRESS)


def read_mitre_session_status(session_id: str, entity_id: int) -> MitreSessionStatus:
    """The run's stage and scenarios in two reads: 404 unknown or another pipeline's, 403 another entity's."""
    found = get_threat_scenario_session_repository().get(fields=MITRE_STATUS_FIELDS, _id=session_id)
    record = get_session_owned_by_caller(found, session_id, entity_id)
    refuse_other_pipelines(record.get("pipeline"), session_id)
    scenarios = list_mitre_scenarios_with_controls(session_id)
    mitre, status = record.get("mitre") or {}, SHOWN_STATUS[c.Status(record["status"])]
    run_target = mitre.get("run_target") or 0
    ended = record.get("finished_at") if status not in ("queued", "running") else None
    started = (record.get("last_action") or {}).get("started_at") or utc_now()
    partial_scenarios: list[dict[str, Any]] | None = scenarios
    result: dict[str, Any] | None = None
    if status == "complete":
        partial_scenarios, result = (
            None,
            {"scenarios": scenarios, "metadata": build_mitre_result_metadata(mitre, scenarios)},
        )
    return MitreSessionStatus(
        session_id=session_id,
        status=status,
        stage=mitre.get("stage"),
        elapsed_seconds=round(((ended or utc_now()) - started).total_seconds(), 1),
        written=len(scenarios),
        run_target=run_target,
        scenarios_left=max(0, run_target - len(scenarios) - len(mitre.get("failed_path_ids") or [])),
        partial_scenarios=partial_scenarios,
        result=result,
        error=(record.get("job") or {}).get("error"),
        status_url=mitre_status_url(session_id),
        next_set_url=f"{mitre_status_url(session_id)}/next-set",
    )


def list_mitre_scenarios_with_controls(session_id: str) -> list[dict[str, Any]]:
    """The run's written scenarios in path order, each the MITRE scenario with the CII library controls mapped."""
    cards = get_threat_scenario_repository().list(
        fields=MITRE_CARD_FIELDS, sort="path_rank", session_id=session_id, status=c.ScenarioStatus.DONE, newest=True
    )
    scenarios = []
    for card in cards:
        controls = card.get("controls") or {}
        shown_controls = []
        for item in controls.get("items") or []:
            shown_controls.append(control_view(item).model_dump(mode="json"))
        mapped = {"controls_status": controls.get("status"), "controls": shown_controls}
        mapped["technique_control_states"] = controls.get("technique_states") or []
        scenarios.append({"scenario_id": card["_id"], **card["content"]["mitre"], **mapped})
    return scenarios


def build_mitre_result_metadata(mitre: dict[str, Any], scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """The POC result's metadata a stored run still knows: how it was planned and what it selected."""
    distinct_groups, crossing_met = set(), False
    for scenario in scenarios:
        for group in scenario["relevant_groups"]:
            distinct_groups.add(group["mitre_id"])
        domains = set()
        for technique in scenario["attack_techniques"]:
            domains.add(technique["domain"])
        crossing_met = crossing_met or domains == {"enterprise", "ics"}
    selection = mitre.get("actor_selection") or {}
    return {
        "asset_context": mitre.get("asset_context"),
        "prompt_version": c.PromptVersion.MITRE_WRITER,
        "valid_paths_found": mitre.get("run_target") or 0,
        "invalid_paths": mitre.get("invalid_paths") or {},
        "planner_calls": mitre.get("planner_calls") or 0,
        "written": len(scenarios),
        "failed_scenarios": len(mitre.get("failed_path_ids") or []),
        "supporting_system_mitre_assets": system_mitre_assets_by_name(mitre),
        "relevant_actor_selection": selection.get("status"),
        "relevant_actor_rows_rejected": selection.get("rejected_rows") or {},
        "relevant_actors_selected": len(selection.get("actors") or {}),
        "relevant_actors": mitre.get("relevant_actors") or [],
        "distinct_relevant_groups": len(distinct_groups),
        "groups_removed_over_share": mitre.get("groups_removed_over_share") or 0,
        "it_ot_crossing_required": mitre.get("it_ot_crossing_required"),
        "it_ot_crossing_reason": mitre.get("it_ot_crossing_reason"),
        "it_ot_crossing_met": crossing_met if mitre.get("it_ot_crossing_required") else None,
    }
