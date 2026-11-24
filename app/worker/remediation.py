"""The plan job (tsg_write_plan): one plan version written from the scenario now and the stored register."""

import time
from functools import partial
from typing import Any

import structlog
from celery import Task

from app import ai
from app.ai import ChatModel, RerankModel
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    ActorRole,
    AuditAction,
    AuditTarget,
    Collection,
    LibrarySource,
    LibraryStatus,
    LogEvent,
    PromptVersion,
    Remediation,
    ResolveOutcome,
    RunKind,
    Status,
    TaskName,
)
from app.core.exceptions import (
    TEMPORARY_ERRORS,
    ControlsNotMapped,
    JobFailed,
    LeaseLost,
    WaitingForAnotherJob,
    job_error_of,
)
from app.core.redaction import redact
from app.crud import scenarios as scenario_crud
from app.crud.audit import AuditRepository, get_audit_repository
from app.crud.jobs import JobLease
from app.crud.library import ThreatRepository, get_threat_repository
from app.crud.remediation import PLANNED_SCENARIO_FIELDS, get_remediation_repository
from app.crud.scenarios import ThreatScenarioRepository
from app.domain.remediation.write import (
    active_mapped_controls,
    assess_controls,
    build_snapshot,
    existing_controls_not_for_this_risk,
    list_affected_systems,
    write_plan,
)
from app.domain.scenario.attack_controls import is_attack_scenario, pick_set_controls
from app.domain.scenario.session import scenario_asset_type
from app.domain.scenario.write import find_alternative_controls, map_controls
from app.domain.shared.audit import audit_target
from app.realtime.publisher import publish_session_status
from app.schemas.library import LibraryControl, ThreatProposal
from app.schemas.remediation import Doc
from app.schemas.scenario_internal import FrozenContext
from app.search.service import LibrarySearch, get_library_search
from app.search.snapshot import LibrarySnapshot, linked_actors_by_type
from app.worker.celery_app import celery_app
from app.worker.jobs import keep_lease_alive, outage_error, run_leased_job

_CONTROLS_BEING_MAPPED = "The scenario's controls are being matched by another job; the plan job tries again."

log = structlog.get_logger(__name__)

_LIBRARY_STATUS = {
    ResolveOutcome.EXISTING_ACTIVE: LibraryStatus.ACTIVE,
    ResolveOutcome.CURATOR_REJECTED: LibraryStatus.CURATOR_REJECTED,
}


JOB_FIELDS = ("scenario_id", "register")


def write_plan_version(
    lease: JobLease, *, chat: ChatModel, search: LibrarySearch, rerank: RerankModel, threats: ThreatRepository
) -> None:
    """Writes the leased version: its snapshot rebuilt and saved, the checked plan, then the audit."""

    try:
        snapshot = _save_snapshot(lease, search, rerank, threats)
        started = time.perf_counter()
        plan, warnings = write_plan(chat, snapshot)
    except JobFailed:
        metrics.PLANS.labels(Status.FAILED).inc()
        raise
    written = {
        "status": Status.DONE,
        "plan": plan,
        "warnings": warnings,
        "prompt_version": PromptVersion.REMEDIATION,
        "completed_at": utc_now(),
    }
    plan_seconds = {"plan_s": time.perf_counter() - started}
    get_remediation_repository().update_remediation_plan_version(lease, written, done=True, timings=plan_seconds)
    metrics.PLANS.labels(Status.DONE).inc()
    target = audit_target(AuditTarget.REMEDIATION, lease.record_id)
    after = {"version": lease.epoch, "warnings": len(warnings)}
    get_audit_repository().create_audit_record(
        AuditAction.PLAN_COMPLETED, {"system": TaskName.WRITE_PLAN}, target, after=after
    )


def _save_snapshot(lease: JobLease, search: LibrarySearch, rerank: RerankModel, threats: ThreatRepository) -> Doc:

    started, scenarios = time.perf_counter(), scenario_crud.get_threat_scenario_repository()
    scenario = scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=lease.record["scenario_id"])
    if scenario is None:  # deleted with its run (and its plan with it)
        raise LeaseLost(lease.record_id)
    stored_context = scenario_crud.get_threat_scenario_session_repository().get_scenario_session_context(
        scenario["session_id"]
    )
    context, library = FrozenContext.from_record(stored_context), search.snapshot()
    pending = scenario.get("pending") or {}
    if pending.get("actors"):  # hand-written: its attackers saved (and a new wording's library ids)
        actors = pick_manual_attacker(library, scenario)
        changes: Doc = {"content.actors": actors}
        if pending.get("proposal"):
            asset_type = scenario_asset_type(scenario["content"], context)
            changes |= _propose_while_held(threats, lease, scenario, tuple(actor["id"] for actor in actors), asset_type)
        scenario = scenarios.update_manual_scenario_findings(scenario["_id"], changes, PLANNED_SCENARIO_FIELDS)
        if scenario is None:  # deleted with its run meanwhile
            raise LeaseLost(lease.record_id)
    controls = library.library.control_library
    by_id = {row.control_id: row for row in controls}
    mapped = _mapped_controls(lease, scenario, context, library, by_id, rerank)
    items, register = mapped["items"], lease.record["register"]
    affected = list_affected_systems(context, register)
    categories = context.system_categories()
    library_mapped, warnings = assess_controls(items, register, controls, affected, categories)
    found = find_alternative_controls(rerank, scenario, context, library, [i["control_id"] for i in items], 5, mapped)
    offered = [{"control_id": c.control_id, "code": c.code, "score": s, "match": "alternative"} for c, s in found]
    alternatives = assess_controls(offered, register, controls, affected, categories)[0]
    considered = [row["control_id"] for row in library_mapped + alternatives]
    warnings = warnings + existing_controls_not_for_this_risk(register, controls, considered)
    snapshot = build_snapshot(scenario, context, register, library_mapped, warnings, affected, alternatives)
    seconds = {"controls_s": time.perf_counter() - started}
    get_remediation_repository().update_remediation_plan_version(lease, {"snapshot": snapshot}, timings=seconds)
    return snapshot


def pick_manual_attacker(search_snapshot: LibrarySnapshot, scenario: Doc) -> list[Doc]:
    """The stored acting attacker: best of the threat's actors, else its type's, else the library's."""
    content, library = scenario["content"], search_snapshot.library.threat_library
    threat = content.get("threat") or {}
    by_threat = {row.catalogue_id: row.linked_actors for row in library.threats}
    active = threat.get("library_status") == LibraryStatus.ACTIVE
    own = by_threat.get(threat.get("library_id") or 0, ()) if active else ()
    linked = own or linked_actors_by_type(library).get(threat.get("type_id") or 0, ())  # 0: a new type
    candidates = linked or library.actors
    if not candidates:
        return []
    type_name, name = redact(threat.get("type") or ""), redact(threat.get("name") or "")
    query = f"{type_name}: {name}. {redact(content.get('statement') or '')}".strip()
    allowed = {actor.actor_id for actor in candidates}
    (found,) = search_snapshot.find_actors([query], top_k=len(library.actors), allowed_ids=[allowed])
    acting = found[0][0] if found else candidates[0]
    return [{"id": acting.actor_id, "name": acting.name, "role": ActorRole.ACTING, "closest": not linked}]


def _mapped_controls(
    lease: JobLease,
    scenario: Doc,
    context: FrozenContext,
    library: LibrarySnapshot,
    by_id: dict[int, LibraryControl],
    rerank: RerankModel,
) -> Doc:

    if active_mapped_controls(scenario, by_id):
        return scenario["controls"]
    scenario_id, task_id = scenario["_id"], f"{lease.task_id}{Remediation.CONTROLS_CLAIM_SUFFIX}"
    remap = (scenario.get("controls") or {}).get("status") == Status.DONE  # mapped, but nothing active
    scenarios = scenario_crud.get_threat_scenario_repository()
    claimed = scenarios.claim_scenario_controls_by_id(scenario_id, task_id, remap)
    if claimed is not None:
        return _map(claimed, task_id, context, library, rerank)
    mapped = scenarios.get(["controls"], _id=scenario_id, controls_mapped=True)
    if mapped is None or not active_mapped_controls(mapped, by_id):  # given back: no attempt used
        raise WaitingForAnotherJob(_CONTROLS_BEING_MAPPED)
    return mapped["controls"]


def _map(claimed: Doc, task_id: str, context: FrozenContext, library: LibrarySnapshot, rerank: RerankModel) -> Doc:

    scenario_id, attempts, started = claimed["_id"], claimed["controls"]["attempts"], time.perf_counter()
    scenarios = scenario_crud.get_threat_scenario_repository()
    try:
        with keep_lease_alive(scenario_id, _ControlsLease(scenarios, scenario_id, task_id, attempts).renew):
            if is_attack_scenario(claimed) and library.library.control_library:  # picked, as its controls job does
                record = pick_set_controls(rerank, [claimed], context, library)[scenario_id]
            else:
                record = map_controls(rerank, claimed, context, library)
    except ControlsNotMapped as exc:  # an empty library: no retry changes it
        error = {"code": exc.code, "message": exc.message}
        scenarios.update_scenario_controls(scenario_id, task_id, attempts, Status.FAILED, error=error)
        _settle(claimed)
        raise JobFailed(exc.code, exc.message) from exc
    except Exception as exc:  # an outage (retried), a lost lease, a fault: the controls are freed at once
        run_cancelled = scenario_crud.get_threat_scenario_session_repository().is_cancelled(claimed["session_id"])
        outcome, freed_error = _freed_controls(claimed, exc, run_cancelled)
        scenarios.update_scenario_controls(scenario_id, task_id, attempts, outcome, error=freed_error)
        _settle(claimed)
        if isinstance(exc, LeaseLost) and str(exc) == scenario_id:  # its control lease, not the job's
            raise WaitingForAnotherJob(_CONTROLS_BEING_MAPPED) from exc
        raise
    if not scenarios.update_scenario_controls(
        scenario_id, task_id, attempts, Status.DONE, mapping=record
    ):  # its claim was taken over meanwhile
        raise WaitingForAnotherJob(_CONTROLS_BEING_MAPPED)
    _settle(claimed, time.perf_counter() - started)
    log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(record["items"]), saved=True)
    return record


def _settle(claimed: Doc, seconds: float = 0.0) -> None:

    manual = claimed.get("source") == RunKind.MANUAL
    scenario_crud.get_threat_scenario_session_repository().update_scenario_session_counts(
        claimed["session_id"], seconds if manual else 0.0
    )
    publish_session_status(claimed["session_id"])


class _ControlsLease:
    def __init__(self, scenarios: ThreatScenarioRepository, scenario_id: str, task_id: str, attempts: int) -> None:
        self._scenarios = scenarios
        self.record_id, self._task_id, self._attempts = scenario_id, task_id, attempts

    def renew(self) -> bool:
        """Renews this scenario's control lease; True while it holds."""
        return self._scenarios.update_scenario_controls(self.record_id, self._task_id, self._attempts, Status.RUNNING)


def _freed_controls(claimed: Doc, exc: Exception, run_cancelled: bool) -> tuple[Status, dict[str, str] | None]:
    manual = claimed.get("source") == RunKind.MANUAL
    if (run_cancelled and not manual) or (manual and isinstance(exc, LeaseLost)):
        return Status.CANCELLED, None
    if isinstance(exc, LeaseLost):
        return Status.QUEUED, None
    error = outage_error(exc) if isinstance(exc, TEMPORARY_ERRORS) else job_error_of(exc)
    return (Status.FAILED if manual else Status.QUEUED), error


def _propose_while_held(
    threats: ThreatRepository, lease: JobLease, scenario: Doc, actor_ids: tuple[int, ...], asset_type: str | None
) -> Doc:
    # ponytail: a cancel and delete landing between this renewal and the proposal still propose; closing that
    # needs one transaction across MongoDB and SQL Server.
    if not lease.renew_job():
        raise LeaseLost(lease.record_id)
    content, by = scenario["content"], scenario["pending"]["by"]
    audit = get_audit_repository()
    return _propose_manual_threat(threats, audit, scenario["_id"], content, actor_ids, by, asset_type)


def _propose_manual_threat(
    threats: ThreatRepository,
    audit: AuditRepository,
    scenario_id: str,
    content: Doc,
    actor_ids: tuple[int, ...],
    by: Doc,
    asset_type: str | None = None,
) -> Doc:
    """The hand-written threat proposed, linked to the attackers when its type is new and typed IT or OT by where
    the scenario attacks (owner 2026-11-24)."""
    threat = content["threat"]
    proposal = ThreatProposal(
        content.get("category"),
        threat["type"],
        threat["name"],
        LibrarySource.MANUAL,
        by["user_id"],
        actor_ids if threat.get("type_id") is None else (),  # a new type is linked to the attackers
        asset_type,
    )
    proposed, applied_now = threats.propose_threat(f"propose:{scenario_id}", proposal)
    if applied_now:  # audited once, as the person who asked, by the attempt that applied it
        target = audit_target(AuditTarget.LIBRARY_THREAT, str(proposed.catalogue_id))
        after = {"threat": threat["name"], "type": threat["type"], "outcome": proposed.outcome}
        audit.create_audit_record(AuditAction.LIBRARY_PROPOSED, by, target, after=after)
    return {
        "content.threat.type_id": proposed.type_id,
        "content.threat.library_id": proposed.catalogue_id,
        "content.threat.library_status": _LIBRARY_STATUS.get(proposed.outcome, LibraryStatus.PENDING),
    }


def plan_job_parts() -> dict[str, Any]:
    """The plan job's AI and library parts: the process singletons."""

    return {
        "chat": ai.chat.get_remediation_chat_model(),
        "search": get_library_search(),
        "rerank": ai.rerank.get_rerank_model(),
        "threats": get_threat_repository(),
    }


@celery_app.task(name=TaskName.WRITE_PLAN, bind=True)
def tsg_write_plan(self: Task, record_id: str, epoch: int) -> None:
    """Writes one remediation plan version under its job lease."""
    write = partial(write_plan_version, **plan_job_parts())
    run_leased_job(self, Collection.REMEDIATIONS, record_id, epoch, write, fields=JOB_FIELDS)
