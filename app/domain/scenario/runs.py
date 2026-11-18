"""The scenario module's use cases: start, read, review, regenerate and promote."""

import uuid
from datetime import datetime
from typing import Any, Final

from app.core import constants as c
from app.core import metrics
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import AiApi
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.core.security import Principal
from app.crud import work_control
from app.crud.attack import get_attack_repository
from app.crud.audit import get_audit_repository
from app.crud.intel import get_intel_snapshot_repository
from app.crud.jobs import new_job
from app.crud.library import get_threat_repository
from app.crud.scenarios import (
    get_asset_context,
    get_threat_scenario_repository,
    get_threat_scenario_session_repository,
    running_action,
)
from app.domain import jobs as job_rules
from app.domain.intel.switch import get_intelligence_switch
from app.domain.scenario import attack
from app.domain.scenario import session as rules
from app.domain.scenario.attack_prompt import find_attack_sources_of_asset
from app.domain.scenario.session import build_run_context, check_session_ready_for_review
from app.domain.shared.audit import audit_target, caller_actor, origin_of_its_jobs
from app.domain.shared.idempotency import duplicate_request
from app.realtime.publisher import publish_session_status
from app.schemas import scenarios as api_views
from app.schemas.library import ThreatProposal
from app.schemas.scenario_internal import FrozenContext
from app.schemas.scenarios import session_status_from_record
from app.search.library_cache import get_library_cache
from app.worker.celery_app import send_job

_NO_PATH_LEFT_MESSAGES: Final = {
    c.ConflictReason.NOTHING_LEFT: c.ReviewMessage.NOTHING_LEFT,
    c.ConflictReason.TARGET_REACHED: c.ReviewMessage.TARGET_REACHED,
    c.ConflictReason.SCENARIOS_ABANDONED: c.ReviewMessage.SCENARIOS_ABANDONED,
}


@origin_of_its_jobs(AiApi.CREATE_SCENARIO)
def create_threat_scenario_session(
    principal: Principal, request: api_views.StartRunRequest, idempotency_key: str, *, derived: bool = False
) -> tuple[api_views.RunBoard, bool]:
    """Start a run: its status board and whether it was created now (False for a replay)."""
    return _start_run(principal, request, idempotency_key, derived)


@origin_of_its_jobs(AiApi.CREATE_SESSION)
def create_attack_scenario_session(
    principal: Principal, request: api_views.StartRunRequest, idempotency_key: str, *, derived: bool = False
) -> tuple[api_views.RunBoard, bool]:
    """Start a run the AI writes from its MITRE ATT&CK knowledge: its board and whether it was created now."""
    return _start_run(principal, request, idempotency_key, derived, c.RunPipeline.ATTACK)


def _start_run(
    principal: Principal,
    request: api_views.StartRunRequest,
    idempotency_key: str,
    derived: bool,
    pipeline: c.RunPipeline | None = None,
) -> tuple[api_views.RunBoard, bool]:
    if replayed := _replay(principal, request, idempotency_key, derived, pipeline):
        return rules.build_status_board(replayed), False
    _refuse_without_data(pipeline)
    asset_context = get_asset_context(principal.entity_id, request)
    context = build_run_context(request, asset_context)
    if pipeline is not None:
        _refuse_without_data(pipeline, context)
    record = _new_run_record(principal, request, idempotency_key, context, pipeline)
    clash = get_threat_scenario_session_repository().create_scenario_session(record)
    if clash and (replayed := _replay(principal, request, idempotency_key, derived, pipeline)):
        return rules.build_status_board(replayed), False
    if clash is c.RunClash.IDEMPOTENCY_KEY:  # the run that took the key was deleted since
        message = c.SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
        raise Conflict(message, reason=c.ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    send_job(record["job"]["task"], record["_id"], record["job"]["epoch"])
    metrics.RUNS.labels(c.RunKind.GENERATED).inc()
    get_audit_repository().create_audit_record(
        c.AuditAction.RUN_STARTED,
        caller_actor(principal),
        audit_target(c.AuditTarget.SESSION, record["_id"]),
        after={"asset_id": record["asset_id"], "supporting_system_ids": record["request"]["supporting_system_ids"]},
    )
    return rules.build_status_board(session_status_from_record(record)), True


def _refuse_without_data(pipeline: c.RunPipeline | None, context: FrozenContext | None = None) -> None:
    """`context`: an attack run's asset once it is read, so each ATT&CK source it needs must hold data."""
    if pipeline is None:
        _refuse_without_intel_data()  # never a job that can only fail its evidence searches
        return
    needed = find_attack_sources_of_asset(context) if context else ()
    if not get_attack_repository().has_data(needed):  # never a job whose scenarios nothing can confirm
        raise Conflict(c.AttackMessage.NO_DATA, reason=c.ConflictReason.INTEL_NO_DATA)


def _refuse_without_intel_data() -> None:
    if not get_intelligence_switch().is_on():
        return
    snapshot = get_intel_snapshot_repository().get("description", _id=c.IntelDocId.ACTIVE_SNAPSHOT) or {}
    if not (snapshot.get("counts") or {}).get("indexed"):
        raise Conflict(c.IntelMessage.NO_DATA_YET, reason=c.ConflictReason.INTEL_NO_DATA)


def _hash_request(request: api_views.StartRunRequest, pipeline: c.RunPipeline | None) -> str:
    fingerprint = request.fingerprint()  # one key never replays the other start route's run
    return f"{pipeline}:{fingerprint}" if pipeline else fingerprint


def _replay(
    principal: Principal,
    request: api_views.StartRunRequest,
    key: str,
    derived: bool,
    pipeline: c.RunPipeline | None = None,
) -> api_views.SessionStatus | None:
    earlier = get_threat_scenario_session_repository().get(
        fields="replay", entity_id=principal.entity_id, idempotency_key=key
    )
    if earlier is None:
        return None
    if (
        earlier.get("kind") == c.RunKind.MANUAL
        or earlier["asset_id"] != request.asset_id
        or earlier.get("request_hash") != _hash_request(request, pipeline)
    ):
        message = c.SessionMessage.IDEMPOTENCY_KEY_CONFLICT
        raise Conflict(message, reason=c.ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    if derived:
        raise duplicate_request(earlier["created_at"], session_id=earlier["_id"])
    return session_status_from_record(earlier)


def get_threat_scenario_session_status(session_id: str, entity_id: int) -> api_views.SessionStatus:
    """The status of a run the caller's entity owns: 404 unknown, 403 another entity's."""
    record = get_threat_scenario_session_repository().get(fields="status", _id=session_id)
    return session_status_from_record(rules.get_session_owned_by_caller(record, session_id, entity_id))


def get_threat_scenario_session_live_status(session_id: str) -> dict[str, Any]:
    """The run's status body read now; NotFound once the run is deleted."""
    record = get_threat_scenario_session_repository().get(fields="status", _id=session_id)
    if record is None:
        raise NotFound(c.SessionMessage.NOT_FOUND.format(session_id=session_id))
    return rules.build_status_board(session_status_from_record(record)).model_dump(mode="json")


def list_threat_scenarios_of_session(
    run: api_views.SessionStatus, include_replaced: bool, offset: int, limit: int
) -> api_views.RunResults:
    """The run, its progress and a page of its current versions in the plan's order."""
    in_turns = ["content.threat.rank", "created_at"]
    records, total = _scenario_page(in_turns, offset, limit, session_id=run.session_id)
    scenarios = _scenario_views(records, include_replaced)
    board = rules.build_status_board(run)
    header = board.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id"})
    return api_views.RunResults(**header, progress=board.progress, error=board.error, scenarios=scenarios, total=total)


def get_plan_trace(run: api_views.SessionStatus) -> api_views.PlanTraceView:
    """How the run's plan was made."""
    record = get_threat_scenario_session_repository().get(fields="plan_trace", _id=run.session_id)
    if record is None or not record.get("plan_trace"):
        raise NotFound(c.PlanTraceMessage.NOT_PLANNED.format(session_id=run.session_id))
    paths = (record.get("plan") or {}).get("paths") or []
    return rules.build_plan_trace_view(run.session_id, record["plan_trace"], paths)


def get_threat_scenario(session_id: str, scenario_id: str) -> api_views.ScenarioView:
    """One scenario of the run in full, with every version it replaced; 404 when it is not in the run."""
    record = get_threat_scenario_repository().get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
    if record is None:
        raise NotFound(c.SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id))
    return _scenario_views([record], include_replaced=True)[0]


def list_threat_scenarios_of_entity(
    principal: Principal, entity_id: int, decision: c.Decision | None, offset: int, limit: int
) -> api_views.ScenarioList:
    """Every run's current versions of the caller's entity, newest first; another entity's -> 403."""
    if entity_id != principal.entity_id:
        raise Forbidden(c.SessionMessage.ENTITY_MISMATCH)
    chosen = {} if decision is None else {"decision": decision}
    records, total = _scenario_page("-created_at", offset, limit, entity_id=entity_id, **chosen)
    return api_views.ScenarioList(scenarios=_scenario_views(records, False), total=total)


def _scenario_views(records: list[dict[str, Any]], include_replaced: bool) -> list[api_views.ScenarioView]:
    others = _other_versions(records, include_replaced)
    accepted = {
        (doc["session_id"], doc["path_id"]): doc["_id"] for doc in others if doc.get("decision") == c.Decision.ACCEPTED
    }
    replaced = sorted((doc for doc in others if doc.get("superseded_by")), key=lambda doc: -doc["version"])
    views = []
    for record in records:
        path = (record["session_id"], record.get("path_id"))
        elsewhere = accepted.get(path) if record.get("decision") != c.Decision.ACCEPTED else None
        older = [doc for doc in replaced if (doc["session_id"], doc["path_id"]) == path]
        older = [doc for doc in older if doc["version"] < record["version"]] if include_replaced else []
        views.append(rules.build_scenario_view(record, elsewhere, older))
    return views


def _scenario_page(sort: str | list[str], offset: int, limit: int, **where: Any) -> tuple[list[dict[str, Any]], int]:
    scenarios = get_threat_scenario_repository()
    shown = {"served": True, "current": True, **where}
    records = scenarios.list(fields="shown", sort=sort, skip=offset, limit=limit, **shown)
    if (records or offset == 0) and len(records) < limit:
        return records, offset + len(records)
    return records, scenarios.count_current_scenarios(**where)


def _other_versions(records: list[dict[str, Any]], with_replaced: bool) -> list[dict[str, Any]]:
    paths = {(record["session_id"], record["path_id"]) for record in records if record.get("path_id")}
    if not paths:
        return []
    wanted: dict[str, Any] = {"accepted_or_replaced": True} if with_replaced else {"decision": c.Decision.ACCEPTED}
    found = get_threat_scenario_repository().list(
        fields="shown" if with_replaced else "lookup",
        session_id_in=sorted({session for session, _ in paths}),
        path_id_in=sorted({path for _, path in paths}),
        served=True,
        **wanted,
    )
    return [doc for doc in found if (doc["session_id"], doc["path_id"]) in paths]


def accept_threat_scenarios(
    principal: Principal, run: api_views.SessionStatus, request: api_views.AcceptRequest
) -> api_views.AcceptResult:
    """Accepts the chosen scenarios, or every acceptable one ("all")."""
    check_session_ready_for_review(run)
    if request.scenario_ids is None:  # v1's mode "none": decides nothing, writes nothing
        return api_views.AcceptResult(accepted=[], replaced=[], skipped=[], controls_pending=[])
    replaced: list[str] = []
    if request.scenario_ids == "all":
        targets, skipped = _everything_acceptable(run.session_id)
    else:
        targets, skipped = _chosen(run.session_id, request.scenario_ids, c.Decision.ACCEPTED), []
        replaced = _make_room(run.session_id, targets, request.replace_accepted, principal)
    accepted, newly, raced = _decide(run.session_id, targets, c.Decision.ACCEPTED, principal)
    skipped += raced
    changes = {"accepted": newly, "replaced": replaced}
    _announce_decisions(principal, run.session_id, c.AuditAction.SCENARIOS_ACCEPTED, changes, skipped)
    unmapped = {target["_id"] for target in targets if (target.get("controls") or {}).get("status") != c.Status.DONE}
    pending = [scenario_id for scenario_id in accepted if scenario_id in unmapped]
    return api_views.AcceptResult(accepted=accepted, replaced=replaced, skipped=skipped, controls_pending=pending)


def reject_threat_scenarios(
    principal: Principal, run: api_views.SessionStatus, request: api_views.ScenarioIdsRequest
) -> api_views.RejectResult:
    """Rejects the chosen scenarios."""
    check_session_ready_for_review(run)
    targets = _chosen(run.session_id, request.scenario_ids, c.Decision.REJECTED)
    rejected, newly, skipped = _decide(run.session_id, targets, c.Decision.REJECTED, principal)
    _announce_decisions(principal, run.session_id, c.AuditAction.SCENARIOS_REJECTED, {"rejected": newly}, skipped)
    return api_views.RejectResult(rejected=rejected, skipped=skipped)


def _list_review_targets(session_id: str, scenario_ids: list[str]) -> dict[str, dict[str, Any]]:
    found = get_threat_scenario_repository().list(
        fields="target", scenario_id_in=scenario_ids, session_id=session_id, served=True
    )
    return {row["_id"]: row for row in found}


def _accepted_version_of_attack_paths(session_id: str, path_ids: list[str]) -> dict[str, str]:
    found = get_threat_scenario_repository().list(
        fields="path_id", session_id=session_id, path_id_in=path_ids, decision=c.Decision.ACCEPTED
    )
    return {row["path_id"]: row["_id"] for row in found}


def _chosen(session_id: str, scenario_ids: list[str], decision: c.Decision) -> rules.ScenarioTargets:
    found = _list_review_targets(session_id, scenario_ids)
    held = (
        rules.list_active_or_pending_threat_ids(get_library_cache().get_threat_library())
        if decision == c.Decision.ACCEPTED
        else frozenset()
    )
    return rules.get_scenarios_to_decide(scenario_ids, found, decision, held)


def _everything_acceptable(session_id: str) -> tuple[rules.ScenarioTargets, list[api_views.TargetSkipped]]:
    rows = get_threat_scenario_repository().list(
        fields="target",
        sort="created_at",
        session_id=session_id,
        status=c.ScenarioStatus.DONE,
        newest=True,
        not_rejected=True,
    )
    if not rows:
        message = c.ReviewMessage.NOTHING_TO_ACCEPT.format(session_id=session_id)
        raise Conflict(message, reason=c.ConflictReason.NOTHING_TO_ACCEPT)
    path_ids = sorted({row["path_id"] for row in rows})
    accepted = _accepted_version_of_attack_paths(session_id, path_ids)
    held = rules.list_active_or_pending_threat_ids(get_library_cache().get_threat_library())
    return rules.pick_scenarios_for_accept_all(rows, accepted, held)


def _make_room(session_id: str, targets: rules.ScenarioTargets, replace: bool, principal: Principal) -> list[str]:
    path_ids = list(dict.fromkeys(target["path_id"] for target in targets))
    accepted = _accepted_version_of_attack_paths(session_id, path_ids)
    others = rules.find_versions_to_replace(targets, accepted, replace)
    if others:
        stamp = _new_decided_stamp(principal)
        get_threat_scenario_repository().update_scenario_decisions(
            others, c.Decision.ACCEPTED, c.Decision.PENDING, stamp
        )
    return others


def _decide(
    session_id: str, targets: rules.ScenarioTargets, decision: c.Decision, principal: Principal
) -> tuple[list[str], list[str], list[api_views.TargetSkipped]]:
    ids = [target["_id"] for target in targets]
    pending = [target["_id"] for target in targets if target["decision"] == c.Decision.PENDING]
    stamp = _new_decided_stamp(principal)
    scenarios = get_threat_scenario_repository()
    changed = scenarios.update_scenario_decisions(pending, c.Decision.PENDING, decision, stamp) if pending else 0
    if changed == len(pending):
        return ids, pending, []
    now = _list_review_targets(session_id, ids)
    return rules.read_decision_results(ids, pending, now, decision, stamp["decision_id"])


def _announce_decisions(
    principal: Principal,
    session_id: str,
    action: c.AuditAction,
    changes: dict[str, list[str]],
    skipped: list[api_views.TargetSkipped],
) -> None:
    decided = changes.get("accepted", changes.get("rejected", []))
    if decided or changes.get("replaced"):
        decision = c.Decision.ACCEPTED if action == c.AuditAction.SCENARIOS_ACCEPTED else c.Decision.REJECTED
        metrics.DECISIONS.labels(decision).inc(len(decided))
        get_audit_repository().create_audit_record(
            action,
            caller_actor(principal),
            audit_target(c.AuditTarget.SESSION, session_id),
            after=changes,
            details={"skipped": [skip.model_dump(mode="json") for skip in skipped]},
        )
    get_threat_scenario_session_repository().update_scenario_session_counts(session_id)
    publish_session_status(session_id)


@origin_of_its_jobs(AiApi.NEXT_SET)
def write_next_threat_scenario_set(principal: Principal, run: api_views.SessionStatus) -> api_views.RunActionStarted:
    """Queues the next NEXT_SET_SIZE open paths, best rank first."""
    check_session_ready_for_review(run)
    record = get_threat_scenario_session_repository().get(fields="attack_paths", _id=run.session_id)
    if record is None:  # deleted since the status read
        raise NotFound(c.SessionMessage.NOT_FOUND.format(session_id=run.session_id))
    paths = (record.get("plan") or {}).get("paths") or []
    asked, batch = rules.pick_next_paths_to_write(paths, get_settings().next_set_size)
    if asked:
        epoch = _queue_write_job(principal, run, c.RunActionKind.NEXT_SET, batch, asked)
        return _started(run, c.ActionStatus.GENERATING, epoch)
    cancelled_at = (run.cancelled or {}).get("at")  # the cancel the caller saw
    resumed = _resume_controls(run.session_id, cancelled_at, restart_times=True)
    if resumed is None:
        raise job_rules.run_being_deleted(run.session_id)
    if not resumed:
        reason = rules.find_why_no_path_left(paths)
        raise Conflict(_NO_PATH_LEFT_MESSAGES[reason].format(session_id=run.session_id), reason=reason)
    publish_session_status(run.session_id)
    target = audit_target(c.AuditTarget.SESSION, run.session_id)
    after = {"controls_resumed": resumed}
    get_audit_repository().create_audit_record(c.AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after=after)
    return _started(run, c.ActionStatus.MAPPING_CONTROLS, run.epoch)


@origin_of_its_jobs(AiApi.REGENERATE)
def regenerate_threat_scenarios(
    principal: Principal, run: api_views.SessionStatus, request: api_views.ScenarioIdsRequest
) -> api_views.RunActionStarted:
    """Queues a new version of each chosen scenario."""
    check_session_ready_for_review(run)
    targets = _list_review_targets(run.session_id, request.scenario_ids)
    batch = rules.build_regenerate_batch(request.scenario_ids, targets)
    epoch = _queue_write_job(principal, run, c.RunActionKind.REGENERATE, batch)
    return _started(run, c.ActionStatus.REGENERATING, epoch)


def _queue_write_job(
    principal: Principal,
    run: api_views.SessionStatus,
    kind: c.RunActionKind,
    batch: list[dict[str, Any]],
    asked: list[str] | None = None,
) -> int:
    sessions = get_threat_scenario_session_repository()
    stored = sessions.get(fields="context", _id=run.session_id) if run.pipeline else None
    _refuse_without_data(run.pipeline, FrozenContext.from_record(stored["context"]) if stored else None)
    clash = sessions.update_scenario_session_job(run, kind, batch, asked)
    if clash is c.RunClash.DELETING:
        raise job_rules.run_being_deleted(run.session_id)
    if clash is c.RunClash.CHANGED:
        message = c.ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
        raise Conflict(message, reason=c.ConflictReason.GENERATION_IN_PROGRESS)
    epoch = run.epoch + 1
    cancelled = run.status == c.Status.CANCELLED or run.cancelled is not None
    if cancelled or run.counts.get("controls_cancelled", 0) > 0:  # a cancelled run is resumed whole
        _resume_controls(run.session_id, None)  # the new job cleared the cancel stamp it saw
    send_job(c.TaskName.WRITE_SCENARIOS, run.session_id, epoch)
    publish_session_status(run.session_id)
    action = c.AuditAction.RUN_NEXT_SET if kind == c.RunActionKind.NEXT_SET else c.AuditAction.RUN_REGENERATED
    target = audit_target(c.AuditTarget.SESSION, run.session_id)
    after = {"epoch": epoch, "batch": batch} | ({"set": asked} if asked else {})
    get_audit_repository().create_audit_record(action, caller_actor(principal), target, after=after)
    return epoch


def _resume_controls(session_id: str, cancelled_at: datetime | None, restart_times: bool = False) -> int | None:
    resumed = work_control.resume_scenario_controls(session_id, cancelled_at, restart_times)
    if resumed:
        send_job(c.TaskName.MAP_CONTROLS, session_id, 0)  # the epoch is never checked for controls
    return resumed


def promote_threat_scenario_to_library(
    principal: Principal, run: api_views.SessionStatus, scenario_id: str
) -> api_views.PromotionResult:
    """Proposes the accepted scenario's AI threat to the curators."""
    scenario, threat = _accepted_ai_threat(run.session_id, scenario_id)
    actors = (scenario.get("content") or {}).get("actors") or []
    actor_ids = tuple(actor["id"] for actor in actors if actor.get("id"))
    result = _propose_threat(scenario_id, threat, actor_ids, principal)
    promotion = {
        "by": principal.user_id,
        "by_client": principal.client_id,
        "at": utc_now(),
        "results": [result.model_dump(mode="json")],
    }
    changes = {"library_promotion": promotion, "updated_at": promotion["at"]}
    if get_threat_scenario_repository().update(changes, _id=scenario_id, not_promoted=True):  # a repeat is quiet
        target = audit_target(c.AuditTarget.SCENARIO, scenario_id)
        after = {"results": promotion["results"]}
        get_audit_repository().create_audit_record(
            c.AuditAction.LIBRARY_PROMOTED, caller_actor(principal), target, after=after
        )
    return api_views.PromotionResult(scenario_id=scenario_id, results=[result])


def _accepted_ai_threat(session_id: str, scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The accepted scenario and its AI-written threat: 404 unknown, 409 not accepted or nothing to promote."""
    scenario = get_threat_scenario_repository().get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
    if scenario is None:
        message = c.SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
        raise NotFound(message)
    if scenario.get("decision") != c.Decision.ACCEPTED:
        message = c.ReviewMessage.SCENARIO_NOT_ACCEPTED.format(scenario_id=scenario_id)
        raise Conflict(message, reason=c.ConflictReason.SCENARIO_NOT_ACCEPTED)
    reference = (scenario.get("content") or {}).get("threat") or {}
    threat = None
    if reference.get("ai_generated") and (key := reference.get("key")):  # a library threat has nothing to promote
        where = {"_id": session_id, "plan.threats.key": key}
        found = get_threat_scenario_session_repository().get(fields="plan_threat", **where)
        threat = (((found or {}).get("plan") or {}).get("threats") or [None])[0]
    if threat is None:
        message = c.ReviewMessage.NOTHING_TO_PROMOTE.format(scenario_id=scenario_id)
        raise Conflict(message, reason=c.ConflictReason.NOTHING_TO_PROMOTE)
    return scenario, threat


def _propose_threat(
    scenario_id: str, threat: dict[str, Any], actor_ids: tuple[int, ...], principal: Principal
) -> api_views.PromotedThreat:
    name, type_name = threat["name"], threat["type"]["name"]
    known = rules.find_library_threat_by_name(get_library_cache().get_threat_library(), name)
    if known is not None:
        outcome, type_id, catalogue_id = known
    else:
        proposal = ThreatProposal(threat["category"], type_name, name, c.LibrarySource.AI, principal.user_id, actor_ids)
        proposed, _ = get_threat_repository().propose_threat(f"promote:{scenario_id}", proposal)
        outcome = {
            c.ResolveOutcome.CREATED_PENDING: c.PromotionOutcome.INSERTED,
            c.ResolveOutcome.CURATOR_REJECTED: c.PromotionOutcome.CURATOR_REJECTED,
        }.get(proposed.outcome, c.PromotionOutcome.EXISTING)
        type_id, catalogue_id = proposed.type_id, proposed.catalogue_id
    return api_views.PromotedThreat(
        threat=name, threat_type=type_name, threat_type_id=type_id, threat_catalogue_id=catalogue_id, outcome=outcome
    )


def _new_run_record(
    principal: Principal,
    request: api_views.StartRunRequest,
    idempotency_key: str,
    context: FrozenContext,
    pipeline: c.RunPipeline | None = None,
) -> dict[str, Any]:
    now = utc_now()
    record: dict[str, Any] = {
        "_id": uuid.uuid4().hex,
        "kind": c.RunKind.GENERATED,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,  # the calling system: stored, never shown, never used to refuse
        "asset_id": request.asset_id,
        "request": request.model_dump(exclude={"asset_id"}),
        "request_hash": _hash_request(request, pipeline),
        "context": context.to_record(),
        "status": c.Status.QUEUED,
        "step": c.Step.THREATS,
        "last_action": running_action(c.RunActionKind.START, now),
        "counts": {},
        "job": new_job(c.TaskName.FIND_THREATS, 1, now),
        "created_at": now,
        "updated_at": now,
        "idempotency_key": idempotency_key,
    }
    if pipeline is None:
        return record
    starting = attack.build_starting_plan(context, now)  # no threat finding: the first write call finds the risks
    return record | {
        "pipeline": pipeline,
        "step": c.Step.SCENARIOS,
        "counts": starting["counts"],
        "job": new_job(c.TaskName.WRITE_SCENARIOS, 1, now, batch=starting["batch"], set=starting["set"]),
        "plan": starting["plan"],
        "plan_trace": starting["plan_trace"],
    }


def _started(run: api_views.SessionStatus, status: c.ActionStatus, epoch: int) -> api_views.RunActionStarted:
    return api_views.RunActionStarted(session_id=run.session_id, user_id=run.user_id, status=status, epoch=epoch)


def _new_decided_stamp(principal: Principal) -> dict[str, Any]:
    now = utc_now()
    return {
        "decided_by": principal.user_id,
        "decided_by_client": principal.client_id,
        "decided_at": now,
        "decision_id": uuid.uuid4().hex,
        "updated_at": now,
    }
