"""Remediation plans: a plan for a generated or hand-written scenario, its versions, review and reads."""

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AiApi,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ControlMatch,
    Decision,
    Dependency,
    ErrorCode,
    ErrorMessage,
    LibraryRowKind,
    LibraryStatus,
    LogEvent,
    PlanMessage,
    Route,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    StrideCategory,
    TaskName,
    Worker,
)
from app.core.exceptions import (
    MONGO_UNAVAILABLE_ERRORS,
    Conflict,
    DuplicateRecord,
    Forbidden,
    Invalid,
    NotFound,
    Unavailable,
)
from app.core.redaction import REDACTED
from app.core.security import Principal
from app.crud.audit import get_audit_repository
from app.crud.jobs import new_job
from app.crud.remediation import PLANNED_SCENARIO_FIELDS, get_remediation_repository
from app.crud.scenarios import get_asset_context, get_threat_scenario_repository, get_threat_scenario_session_repository
from app.domain import jobs as job_rules
from app.domain.remediation.write import describe_ref, resolve_control_refs
from app.domain.scenario.session import build_run_context
from app.domain.shared.audit import audit_target, caller_actor, origin_of_its_jobs
from app.domain.shared.idempotency import duplicate_request
from app.domain.shared.names import name_match_key, threat_name_without_code
from app.realtime.publisher import publish_remediation_status
from app.schemas import remediation as schemas
from app.schemas.library import LibraryControl, ThreatLibrary
from app.schemas.remediation import SYSTEM_LISTS, Doc, ManualScenario, PlanRequest, RemediationStatus, version_status
from app.schemas.scenario_internal import FrozenContext
from app.search.library_cache import LibraryCache
from app.worker.celery_app import send_job

log = structlog.get_logger(__name__)

_SCENARIO_NOT_FOUND = "Scenario '{scenario_id}' does not exist."
_PLAN_NOT_FOUND = "Remediation plan '{remediation_id}' does not exist."
_PLAN_OTHER_ENTITY = "Remediation plan '{remediation_id}' belongs to another entity."
_ID_NAME_DISAGREE = "Id {id} is the library's '{library_name}', not '{name}'."
Errors = list[dict[str, str]]
_SCENARIO_SUMMARY_FIELDS = ("content", "controls.items", "status", "decision")
_SCENARIO_DECISION_FIELDS = ("status", "decision")
_AUDITED = {Decision.ACCEPTED: AuditAction.PLAN_ACCEPTED, Decision.REJECTED: AuditAction.PLAN_REJECTED}


@origin_of_its_jobs(AiApi.CREATE_PLAN)
def create_plan(
    library: LibraryCache, principal: Principal, body: schemas.PlanRequest, key: str, *, derived: bool = False
) -> tuple[schemas.PlanStarted, bool]:
    """Starts a plan for an accepted scenario: (the plan, True when work started now)."""
    if body.is_manual:
        return _create_manual_plan(library, principal, body, key, derived)
    assert body.session_id is not None and body.scenario_id is not None  # PlanRequest: is_manual=false
    scenario = get_threat_scenario_repository().get(fields=PLANNED_SCENARIO_FIELDS, _id=body.scenario_id)
    checked = _check_plannable_scenario(scenario, body.session_id, body.scenario_id, principal.entity_id)
    if any(getattr(body, listed) for listed in schemas.SYSTEM_LISTS):
        stored = get_threat_scenario_session_repository().get_scenario_session_context(checked["session_id"])
        check_register_systems(body, [system["id"] for system in FrozenContext.from_record(stored).linked_systems()])
    return _plan_scenario(library, principal, body.register(), checked), True


@origin_of_its_jobs(AiApi.REGENERATE)
def regenerate_plan(library: LibraryCache, principal: Principal, remediation_id: str) -> schemas.PlanRequested:
    """Starts the plan's next version, or writes an outage-failed latest one again in place."""
    read = _read_changeable(principal, remediation_id)
    latest, in_place = read["job"]["epoch"], _outage_failed(read)
    max_versions = get_settings().regenerations_max_version_count
    version = latest if in_place else check_regenerable(read, remediation_id, max_versions)
    if (requested := _start_version(library, principal, read, version, in_place)) is None:
        raise _version_still_generating_error(remediation_id, latest)  # another regenerate made it first
    return requested


def review_plan(principal: Principal, remediation_id: str, body: schemas.ReviewRequest) -> schemas.RemediationStatus:
    """Accepts or rejects a done version, fenced on decision_seq; a race reads again once, then 409."""
    decided_by = {"decided_by": principal.user_id, "decided_by_client": principal.client_id}
    for _read_again in range(2):
        read = _read_changeable(principal, remediation_id)
        version = decidable_version(read, body.version, remediation_id)
        change = decision_change(read, version, body.decision, decided_by, body.comment, utc_now())
        if change is None:  # a repeat
            return _status_now(remediation_id)
        if get_remediation_repository().update_remediation_plan_decision(remediation_id, read["decision_seq"], change):
            before = {"accepted_version": read.get("accepted_version")}
            after = {"version": version, "decision": body.decision}
            target = audit_target(AuditTarget.REMEDIATION, remediation_id)
            get_audit_repository().create_audit_record(
                _AUDITED[body.decision], caller_actor(principal), target, before=before, after=after
            )
            publish_remediation_status(remediation_id)
            return _status_now(remediation_id)
    message = f"Remediation plan '{remediation_id}' changed while this decision was made: read it again."
    raise Conflict(message, reason=ConflictReason.CHANGED_CONCURRENTLY)


def read_plan(
    principal: Principal, session_id: str, scenario_id: str, include_history: bool
) -> schemas.RemediationResult:
    """The scenario's plan as shown, with the scenario it treats; 404/403 as every plan route."""
    record = get_remediation_repository().get(fields="result", scenario_id=scenario_id)
    scenario = get_threat_scenario_repository().get(fields=_SCENARIO_SUMMARY_FIELDS, _id=scenario_id)
    accepted = _still_accepted(scenario)
    status = None if record is None else schemas.RemediationStatus.from_record(record, accepted)
    _check_plan_of_scenario(status, principal.entity_id, session_id, scenario_id)
    assert record is not None  # _check_plan_of_scenario refused a missing plan
    return schemas.RemediationResult.from_records(record, scenario, accepted, include_history)


def list_plans(
    principal: Principal, entity_id: int, offset: int, limit: int, **filters: Any
) -> schemas.RemediationList:
    """The entity's plans (of one run when `session_id` is given), newest first, filtered."""
    if entity_id != principal.entity_id:
        raise Forbidden(SessionMessage.ENTITY_MISMATCH)
    where: Doc = {key: value for key, value in filters.items() if value is not None}
    where["entity_id"] = entity_id  # each filter with the newest-first sort is one index scan
    plans = get_remediation_repository()
    records = plans.list(fields="summary", sort="-created_at", skip=offset, limit=limit, **where)
    items = [schemas.RemediationSummary.from_record(record) for record in records]
    return schemas.RemediationList(items=items, total=plans.count(**where))


def read_plan_status(session_id: str, scenario_id: str, entity_id: int) -> schemas.RemediationStatus:
    """The plan of a scenario in a run: 404 when none or not in this run, 403 another entity's."""
    return _check_plan_of_scenario(_status(scenario_id=scenario_id), entity_id, session_id, scenario_id)


def read_live_status(remediation_id: str) -> Doc | None:
    """The plan's status body read now; None when MongoDB cannot say; NotFound once the plan is gone."""
    try:
        status = _status_now(remediation_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    return status.model_dump(mode="json")


def _create_manual_plan(
    library: LibraryCache, principal: Principal, body: schemas.PlanRequest, key: str, derived: bool
) -> tuple[schemas.PlanStarted, bool]:
    given = body.manual_scenario
    assert given is not None  # PlanRequest: is_manual=true
    if given.entity_id != principal.entity_id:
        raise Forbidden(SessionMessage.ENTITY_MISMATCH_BODY)
    fingerprint = manual_request_fingerprint(body)
    ids = session_id, scenario_id = manual_ids(principal.entity_id, key)
    scenario: Doc | None = None
    earlier = get_threat_scenario_session_repository().get(
        fields="replay", entity_id=principal.entity_id, idempotency_key=key
    )
    if earlier is not None:  # the key was used before: the same request again, else 409
        if earlier.get("kind") != RunKind.MANUAL or earlier.get("request_hash") != fingerprint:
            raise Conflict(SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        if derived:
            raise duplicate_request(earlier["created_at"], session_id=session_id, scenario_id=scenario_id)
        scenario = get_threat_scenario_repository().get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
    if scenario is not None and (replayed := _replayed(library, principal, scenario)) is not None:
        return replayed
    saved_before = scenario is not None  # an earlier call saved it, then stopped
    if scenario is None:  # its lists checked against SQL as it is saved (a retry sends the same body)
        scenario = _save_manual_scenario(library, principal, given, body, key, fingerprint, ids)
    try:
        started = _plan_scenario(library, principal, body.register(), scenario)
        return started.model_copy(update={"replayed": saved_before}), True
    except Conflict as clash:  # the same request made at the same moment won: its answer, replayed
        if clash.reason != ConflictReason.PLAN_ALREADY_EXISTS:
            raise
        if derived:  # a derived key's twin is refused, never replayed
            raise duplicate_request(utc_now(), session_id=session_id, scenario_id=scenario_id) from None
        if (replayed := _replayed(library, principal, scenario)) is None:
            raise
        return replayed


def _plan_scenario(library: LibraryCache, principal: Principal, register: Doc, scenario: Doc) -> schemas.PlanStarted:
    _check_control_library(library.get_loaded_libraries().control_library)
    now = utc_now()
    record = _new_plan_record(principal, register, scenario, new_job(TaskName.WRITE_PLAN, 1, now), now)
    plans = get_remediation_repository()
    try:
        plans.create(record)
    except DuplicateRecord:  # a plan exists, or a request made at the same moment won
        winner = _status(scenario_id=scenario["_id"])
        raise _plan_already_exists_error(scenario["_id"], winner.remediation_id if winner else None) from None
    if not get_threat_scenario_repository().count(_id=scenario["_id"]):
        plans.delete(_id=record["_id"])
        raise NotFound(_SCENARIO_NOT_FOUND.format(scenario_id=scenario["_id"]))
    # Checked after the insert: either this sees the delete's mark or the delete's check for work sees it.
    if get_threat_scenario_session_repository().is_being_deleted(record["session_id"]):
        plans.delete(_id=record["_id"])
        raise job_rules.run_being_deleted(record["session_id"])
    _send_plan_job(principal.entity_id, record["_id"], record["job"]["epoch"])
    register = dict(record["register"])  # audited with the risk owner masked
    if register.get("risk_owner"):
        register["risk_owner"] = REDACTED
    after = {"scenario_id": record["scenario_id"], "version": 1, "register": register}
    target = audit_target(AuditTarget.REMEDIATION, record["_id"])
    get_audit_repository().create_audit_record(AuditAction.PLAN_REQUESTED, caller_actor(principal), target, after=after)
    publish_remediation_status(record["_id"])
    is_manual = record["source"] == RunKind.MANUAL
    return schemas.PlanStarted(**_requested(record, 1).model_dump(), is_manual=is_manual)


def _save_manual_scenario(
    library: LibraryCache,
    principal: Principal,
    given: schemas.ManualScenario,
    body: schemas.PlanRequest,
    key: str,
    request_hash: str,
    ids: tuple[str, str],
) -> Doc:
    context = build_run_context(given, get_asset_context(principal.entity_id, given))
    check_register_systems(body, [system["id"] for system in context.linked_systems()])
    library.check_library_once()  # a row a curator added in the last minute is seen
    loaded = library.get_loaded_libraries()
    if not loaded.threat_library.actors:  # the plan job names an attacker
        raise Unavailable(PlanMessage.ACTOR_LIBRARY_EMPTY, reason=ErrorCode.ACTOR_LIBRARY_EMPTY)
    _check_control_library(loaded.control_library)
    threat = resolve_threat(loaded.threat_library, given)
    now = utc_now()
    controls = _given_controls(_resolve_mapped_controls(given, loaded.control_library), now)
    run = _manual_run_record(principal, given, ids[0], key, request_hash, context, now)
    actor = caller_actor(principal)
    scenario = _manual_scenario_record(principal, given, ids, threat, context, controls, actor, now)
    sessions = get_threat_scenario_session_repository()
    if sessions.create_scenario_session(run) is not None:  # the key was taken meanwhile
        raise Conflict(SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    try:  # inserted once: a retry after a crash finds it stored and changes nothing
        get_threat_scenario_repository().create(scenario)
    except DuplicateRecord as clash:
        if clash.index_name != "_id_":
            raise
    sessions.update_scenario_session_counts(ids[0])
    return scenario


def _start_version(
    library: LibraryCache, principal: Principal, read: Doc, version: int, in_place: bool
) -> schemas.PlanRequested | None:
    remediation_id, latest, sessions = (read["_id"], read["job"]["epoch"], get_threat_scenario_session_repository())
    if sessions.is_being_deleted(read["session_id"]):
        raise job_rules.run_being_deleted(read["session_id"])
    _check_control_library(library.get_loaded_libraries().control_library)
    now = utc_now()
    job, plans = new_job(TaskName.WRITE_PLAN, version, now), get_remediation_repository()
    if in_place:
        started = plans.retry_remediation_plan_version(remediation_id, version, job, now)
    else:
        item = _new_version(version, principal, now)
        started = plans.create_remediation_plan_version(remediation_id, latest, item, job, now)
    if not started:
        return None
    # Checked again after the write: either this sees the delete's mark or the delete sees the version.
    if sessions.is_being_deleted(read["session_id"]):
        if in_place:
            plans.stop_remediation_plan_version(read["_id"], version, read["job"]["error"])
        else:
            plans.undo_remediation_plan_version(read, version)
        publish_remediation_status(read["_id"])
        raise job_rules.run_being_deleted(read["session_id"])
    _send_plan_job(principal.entity_id, remediation_id, version)
    target = audit_target(AuditTarget.REMEDIATION, remediation_id)
    get_audit_repository().create_audit_record(
        AuditAction.PLAN_REGENERATED, caller_actor(principal), target, after={"version": version}
    )
    publish_remediation_status(remediation_id)
    return _requested(read, version)


def _send_plan_job(entity_id: int, remediation_id: str, version: int) -> None:
    working = {"$in": [Status.QUEUED, Status.RUNNING]}
    others = get_remediation_repository().count(entity_id=entity_id, status=working) - 1  # this one is queued
    busy = others >= Worker.BUSY_ENTITY_WAITING
    priority = Worker.BUSY_ENTITY_PRIORITY if busy else Worker.NEW_WORK_PRIORITY
    send_job(TaskName.WRITE_PLAN, remediation_id, version, priority)  # a lost send is re-sent


def _replayed(library: LibraryCache, principal: Principal, scenario: Doc) -> tuple[schemas.PlanStarted, bool] | None:
    plans = get_remediation_repository()
    record = plans.get(fields="status", scenario_id=scenario["_id"])
    if record is not None and _outage_failed(record) and _still_accepted(scenario):
        retried = _start_version(library, principal, record, record["job"]["epoch"], in_place=True)
        if retried is not None:
            return schemas.PlanStarted(**retried.model_dump(), is_manual=True, replayed=True), True
        record = plans.get(fields="status", _id=record["_id"])  # another repeat retried it
    if record is None:
        return None
    status = schemas.RemediationStatus.from_record(record, _still_accepted(scenario))
    ids = status.model_dump(include={"remediation_id", "session_id", "scenario_id"})
    version, latest = status.latest_version, status.latest_status
    return schemas.PlanStarted(**ids, version=version, status=latest, is_manual=True, replayed=True), False


def _read_changeable(principal: Principal, remediation_id: str) -> Doc:
    read = get_remediation_repository().get(fields="change", _id=remediation_id)
    scenario = None
    if read is not None:
        scenario = get_threat_scenario_repository().get(fields=_SCENARIO_DECISION_FIELDS, _id=read["scenario_id"])
    return _check_plan_changeable(scenario, read, principal.entity_id, remediation_id)


def _status(**where: Any) -> schemas.RemediationStatus | None:
    record = get_remediation_repository().get(fields="status", **where)
    if record is None:
        return None
    scenario = get_threat_scenario_repository().get(fields=_SCENARIO_DECISION_FIELDS, _id=record["scenario_id"])
    return schemas.RemediationStatus.from_record(record, _still_accepted(scenario))


def _status_now(remediation_id: str) -> schemas.RemediationStatus:
    if (status := _status(_id=remediation_id)) is None:
        raise NotFound(_PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    return status


def _requested(record: Doc, version: int) -> schemas.PlanRequested:
    ids = {"session_id": record["session_id"], "scenario_id": record["scenario_id"]}
    return schemas.PlanRequested(remediation_id=record["_id"], **ids, version=version, status=Status.QUEUED)


def _still_accepted(scenario: Doc | None) -> bool:
    return (
        scenario is not None and scenario["status"] == ScenarioStatus.DONE and scenario["decision"] == Decision.ACCEPTED
    )


def _check_plannable_scenario(scenario: Doc | None, session_id: str, scenario_id: str, entity_id: int) -> Doc:
    if scenario is None:
        raise NotFound(_SCENARIO_NOT_FOUND.format(scenario_id=scenario_id))
    if scenario["session_id"] != session_id:
        raise NotFound(f"Scenario '{scenario_id}' is not in session '{session_id}'.")
    if scenario["entity_id"] != entity_id:
        raise Forbidden(f"Scenario '{scenario_id}' belongs to another entity.")
    if not _still_accepted(scenario):
        message = f"Scenario '{scenario_id}' is not accepted: only an accepted scenario gets a plan."
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
    return scenario


def _check_plan_changeable(scenario: Doc | None, read: Doc | None, entity_id: int, remediation_id: str) -> Doc:
    if read is None:
        raise NotFound(_PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    if read["entity_id"] != entity_id:
        raise Forbidden(_PLAN_OTHER_ENTITY.format(remediation_id=remediation_id))
    if not _still_accepted(scenario):
        message = (
            "Scenario '{scenario_id}' is no longer accepted, so its remediation plan is "
            "read-only: request a plan for the accepted version instead."
        ).format(scenario_id=read["scenario_id"])
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
    return read


def check_regenerable(read: Doc, remediation_id: str, max_version_count: int) -> int:
    """The new version's number: 409 while the latest is being written or the version limit is reached."""
    latest = read["job"]["epoch"]
    if read["status"] not in (Status.DONE, Status.FAILED, Status.CANCELLED):
        raise _version_still_generating_error(remediation_id, latest)
    if latest >= max_version_count:
        message = (
            f"Remediation plan '{remediation_id}' already has {max_version_count} versions, the "
            "most one plan keeps (REGENERATIONS_MAX_VERSION_COUNT): accept or reject one of "
            "them instead of regenerating."
        )
        raise Conflict(message, reason=ConflictReason.VERSION_LIMIT_REACHED)
    return latest + 1


def _outage_failed(read: Doc) -> bool:
    error = read["job"].get("error") or {}
    return read["status"] == Status.FAILED and error.get("code") == ErrorCode.UNAVAILABLE


def _version_still_generating_error(remediation_id: str, version: int) -> Conflict:
    message = (
        f"Version {version} of remediation plan '{remediation_id}' is still being written:"
        " regenerate it once it is done or failed."
    )
    return Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)


def _plan_already_exists_error(scenario_id: str, remediation_id: str | None) -> Conflict:
    message = f"Scenario '{scenario_id}' already has a plan ({remediation_id}): regenerate it instead."
    return Conflict(message, reason=ConflictReason.PLAN_ALREADY_EXISTS, details={"remediation_id": remediation_id})


def _check_plan_of_scenario(
    status: RemediationStatus | None, entity_id: int, session_id: str, scenario_id: str
) -> RemediationStatus:
    if status is None or status.session_id != session_id:
        message = f"No remediation plan has been requested for scenario '{scenario_id}' in session '{session_id}'."
        raise NotFound(message)
    if status.entity_id != entity_id:
        raise Forbidden(_PLAN_OTHER_ENTITY.format(remediation_id=status.remediation_id))
    return status


def _check_control_library(library: Sequence[LibraryControl]) -> None:
    if not library:
        raise Conflict(ErrorMessage.CONTROL_LIBRARY_EMPTY, reason=ErrorCode.CONTROL_LIBRARY_EMPTY)


def check_register_systems(body: PlanRequest, system_ids: Sequence[int]) -> None:
    """422 naming each entry of the two system lists, at its place as sent, not a system of the asset."""
    known = set(system_ids)
    errors = [
        {
            "field": f"body.{listed}[{position}]",
            "message": (
                "{system_id} is not a supporting system of this scenario's asset (its systems "
                "when its run started: {known})."
            ).format(system_id=system_id, known=", ".join(map(str, system_ids))),
        }
        for listed in SYSTEM_LISTS
        for position, system_id in enumerate(getattr(body, listed))
        if system_id not in known
    ]
    if errors:
        raise Invalid(("A supporting system list names a system the scenario's asset does not have."), errors=errors)


def _new_plan_record(principal: Principal, register: Doc, scenario: Doc, job: Doc, now: datetime) -> Doc:
    content = scenario.get("content") or {}
    return {
        "_id": uuid.uuid4().hex,
        "scenario_id": scenario["_id"],
        "session_id": scenario["session_id"],
        "entity_id": principal.entity_id,
        "asset_id": scenario["asset_id"],
        "source": scenario["source"],
        "title": content.get("title") or (content.get("threat") or {}).get("name"),
        "register": register,
        "versions": [_new_version(1, principal, now)],
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "risk_level": register["risk_level"],
        "status": Status.QUEUED,
        "job": job,
        "created_at": now,
        "updated_at": now,
    }


def _new_version(number: int, principal: Principal, now: datetime) -> Doc:
    return {
        "version": number,
        "status": Status.QUEUED,
        "snapshot": None,
        "plan": None,
        "warnings": [],
        "prompt_version": None,
        "error": None,
        "decision": Decision.PENDING,
        "decided_by": None,
        "decided_by_client": None,
        "decided_at": None,
        "review_comment": None,
        "requested_by": principal.user_id,
        "requested_by_client": principal.client_id,
        "requested_at": now,
        "completed_at": None,
    }


def decidable_version(read: Doc, asked: int | None, remediation_id: str) -> int:
    """The version to decide (asked, else the newest done): 409 none done, 404 unknown, 409 not done."""
    done = [item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE]
    version = asked if asked is not None else max(done, default=None)
    if version is None:
        message = f"Remediation plan '{remediation_id}' has no finished version to decide yet."
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    item = next((item for item in read["versions"] if item["version"] == version), None)
    if item is None:
        message = f"Remediation plan '{remediation_id}' has no version {version}."
        raise NotFound(message, reason=ConflictReason.VERSION_NOT_FOUND)
    if (status := version_status(read, item)) != Status.DONE:
        message = (
            f"Version {version} of remediation plan '{remediation_id}' is {status}: only a done version is decided."
        )
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    return version


def decision_change(
    read: Doc, version: int, decision: Decision, decided_by: dict[str, str], comment: str | None, now: datetime
) -> Doc | None:
    """The one change a decision makes as plain values, or None for a repeat; at most one version accepted."""
    decisions = {item["version"]: item["decision"] for item in read["versions"]}
    accepted = read.get("accepted_version")
    repeat = accepted == version if decision == Decision.ACCEPTED else decisions[version] == Decision.REJECTED
    if repeat:
        return None
    decisions[version] = decision
    back_to_pending = None
    if decision == Decision.ACCEPTED:
        if accepted is not None:
            back_to_pending = accepted
            decisions[accepted] = Decision.PENDING
        accepted = version
    elif accepted == version:
        accepted = None
    done = {item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE}
    if accepted is not None:
        record_decision = Decision.ACCEPTED
    elif any(decisions[v] == Decision.PENDING for v in done | {read["job"]["epoch"]}):
        record_decision = Decision.PENDING  # the latest or a done version still waits
    else:
        record_decision = Decision.REJECTED
    return {
        "version": version,
        "decision": decision,
        "stamp": {**decided_by, "decided_at": now, "review_comment": comment},
        "back_to_pending": back_to_pending,
        "accepted_version": accepted,
        "record_decision": record_decision,
    }


def manual_request_fingerprint(body: PlanRequest) -> str:
    """SHA-256 of the whole request, so a key replays only the request it first named."""
    return hashlib.sha256(json.dumps(body.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def manual_ids(entity_id: int, idempotency_key: str) -> tuple[str, str]:
    """(the run's id, the scenario's id), the same for every retry with this key."""
    base = f"{entity_id}:{idempotency_key}"
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{base}:run").hex, uuid.uuid5(uuid.NAMESPACE_URL, f"{base}:scenario").hex


def _manual_run_record(
    principal: Principal,
    scenario: ManualScenario,
    run_id: str,
    idempotency_key: str,
    request_hash: str,
    context: FrozenContext,
    now: datetime,
) -> Doc:
    return {
        "_id": run_id,
        "kind": RunKind.MANUAL,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,
        "asset_id": scenario.asset_id,
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "context": context.to_record(),
        "status": Status.DONE,
        "step": Step.SCENARIOS,
        "last_action": None,
        "counts": {},  # counted from its scenario once saved (scenarios.update_scenario_session_counts)
        "created_at": now,
        "updated_at": now,
        "finished_at": now,
    }


def _manual_scenario_record(
    principal: Principal,
    scenario: ManualScenario,
    ids: tuple[str, str],
    threat: Doc,
    context: FrozenContext,
    controls: Doc,
    by: Doc,
    now: datetime,
) -> Doc:
    run_id, scenario_id = ids
    return {
        "_id": scenario_id,
        "session_id": run_id,
        "entity_id": principal.entity_id,
        "asset_id": scenario.asset_id,
        "path_id": "manual",
        "version": 1,
        "source": RunKind.MANUAL,
        "status": ScenarioStatus.DONE,
        "decision": Decision.ACCEPTED,  # the person who wrote it
        "decided_by": principal.user_id,
        "decided_by_client": principal.client_id,
        "decided_at": now,
        "replaces": None,
        "superseded_by": None,
        "content": _content(scenario, threat, context),
        "pending": {"actors": True, "proposal": threat["status"] is None, "by": by},
        "findings": [],  # the code checks are for AI text only
        "controls": controls,
        "created_at": now,
        "updated_at": now,
    }


def _content(scenario: ManualScenario, threat: Doc, context: FrozenContext) -> Doc:
    names = {system["id"]: system["name"] for system in context.systems}
    return {
        "title": None,
        "statement": scenario.threat_scenario,
        "risk_statement": scenario.risk_statement,
        "assumptions": [],
        "category": threat["category"],
        "category_id": threat["category_id"],
        "contributing_categories": [],
        "threat": {
            "type": threat["type_name"],
            "type_id": threat["type_id"],
            "name": threat["threat_name"],
            "library_id": threat["catalogue_id"],
            "library_status": threat["status"],
            "ai_generated": False,
        },
        "actors": [],
        "systems": [
            {"id": system_id, "name": names[system_id], "entry_point": i == 0}
            for i, system_id in enumerate(scenario.supporting_system_ids)
        ],
        "route": {"status": Route.STANDALONE if len(names) == 1 else Route.UNKNOWN, "note": None},
        "prompt_version": None,
    }


def _resolve_mapped_controls(manual: ManualScenario, controls: Sequence[LibraryControl]) -> list[LibraryControl]:
    rows, unresolved = resolve_control_refs(manual.mapped_controls or [], controls)
    if unresolved:
        errors = [
            {
                "field": f"{ManualScenario.FIELD_PREFIX}.mapped_controls[{position}]",
                "message": f"No active library control matches {describe_ref(ref)}.",
            }
            for position, ref in unresolved
        ]
        raise Invalid("Some control references cannot be resolved.", errors=errors)
    return rows


def _given_controls(controls: Sequence[LibraryControl], now: datetime) -> Doc:
    if not controls:
        return {"status": Status.QUEUED, "attempts": 0, "queued_at": now}
    items = [
        {
            "control_id": control.control_id,
            "code": control.code,
            "name": control.name,
            "domain": control.domain,
            "asset_type": control.asset_type,
            "description": control.description,
            "rank": rank,
            "score": None,
            "match": ControlMatch.GIVEN,
        }
        for rank, control in enumerate(controls, start=1)
    ]
    return {"status": Status.DONE, "items": items, "mapped_at": now}


@dataclass(frozen=True)
class _LibraryEntry:
    row_id: int
    name: str
    status: LibraryStatus
    type_id: int | None = None  # a threat's type
    categories: tuple[StrideCategory, ...] = ()  # a live threat's, in STRIDE order
    category: StrideCategory | None = None  # a live type's own


def resolve_threat(library: ThreatLibrary, scenario: ManualScenario) -> Doc:
    """The scenario's category, type and threat as the library knows them; every fault in one 422."""
    errors: Errors = []
    types, threats = _library_rows(library)
    threat_type = _find_by_id_or_name(types, scenario.threat_type_id, scenario.threat_type_name, "threat_type", errors)
    threat = _find_by_id_or_name(threats, scenario.threat_id, scenario.threat_name, "threat", errors)
    in_library = threat is not None and threat.status != LibraryStatus.CURATOR_REJECTED
    reason: ConflictReason | None = None
    if threat is not None and in_library:  # threat names are unique across the library: its type decides
        type_id = threat.type_id
        library_type = next((row for row in types if row.row_id == type_id), None)
        if threat_type is None or threat_type.row_id != type_id:
            shown = library_type.name if library_type else str(type_id)
            message = f"The library files '{threat.name}' under the type '{shown}'."
            part = "threat_type_id" if scenario.threat_type_id is not None else "threat_type_name"
            errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}", "message": message})
            reason = ConflictReason.TYPE_MISMATCH
        threat_type = library_type
    named_category = (scenario.threat_category_id, scenario.threat_category_name)
    category = _choose_stride_category(library, named_category, threat, threat_type, errors)
    if errors:
        raise Invalid("The threat, its type or its category does not match the library.", errors=errors, reason=reason)
    folded = category.casefold() if category is not None else None
    return {
        "category": category,
        "category_id": next((row_id for row_id, name in library.category_ids if name.casefold() == folded), None),
        "type_name": threat_type.name if threat_type else str(scenario.threat_type_name),
        "type_id": threat_type.row_id if threat_type else None,
        "threat_name": threat.name if threat is not None else str(scenario.threat_name),
        "catalogue_id": threat.row_id if threat is not None and in_library else None,
        "status": threat.status if threat is not None else None,
    }


def _library_rows(library: ThreatLibrary) -> tuple[list[_LibraryEntry], list[_LibraryEntry]]:
    types = [_LibraryEntry(t.type_id, t.name, LibraryStatus.ACTIVE, category=t.category) for t in library.types]
    threats = [
        _LibraryEntry(t.catalogue_id, t.name, LibraryStatus.ACTIVE, t.type_id, t.categories) for t in library.threats
    ]
    for row in library.pending:
        if row.kind == LibraryRowKind.TYPE:
            types.append(_LibraryEntry(row.row_id, row.name, LibraryStatus.PENDING))
        elif row.kind == LibraryRowKind.THREAT:
            threats.append(_LibraryEntry(row.row_id, row.name, LibraryStatus.PENDING, row.type_id))
    threats += [
        _LibraryEntry(row.catalogue_id, row.name, LibraryStatus.CURATOR_REJECTED, row.type_id)
        for row in library.curator_rejected
    ]
    return types, threats


def _find_by_id_or_name(
    rows: Sequence[_LibraryEntry], row_id: int | None, name: str | None, part: str, errors: Errors
) -> _LibraryEntry | None:
    named: _LibraryEntry | None = None
    if name:  # names compared normalised, any library code left out
        wanted = name_match_key(threat_name_without_code(name))
        named = next((row for row in rows if name_match_key(threat_name_without_code(row.name)) == wanted), None)
    if row_id is None:
        return named
    by_id = next((row for row in rows if row.row_id == row_id), None)
    if by_id is None:
        message = f"No live or pending library row has id {row_id}."
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}_id", "message": message})
        return None
    if name and named is not by_id:
        message = _ID_NAME_DISAGREE.format(id=row_id, library_name=by_id.name, name=name)
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}_name", "message": message})
    return by_id


def _choose_stride_category(
    library: ThreatLibrary,
    given: tuple[int | None, str | None],
    threat: _LibraryEntry | None,
    threat_type: _LibraryEntry | None,
    errors: Errors,
) -> StrideCategory | None:
    filed = threat.categories if threat is not None else ()
    given_id, given_name = given
    if given_id is None and not given_name:
        return filed[0] if filed else (threat_type.category if threat_type else None)
    name = dict(library.category_ids).get(given_id, "") if given_id is not None else str(given_name)
    category = next((c for c in StrideCategory if c.value.casefold() == name.casefold()), None)
    part = "threat_category_id" if given_id is not None else "threat_category_name"
    field = f"{ManualScenario.FIELD_PREFIX}.{part}"
    if given_id is not None and given_name and name and given_name.casefold() != name.casefold():  # disagree
        message = _ID_NAME_DISAGREE.format(id=given_id, library_name=name, name=given_name)
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.threat_category_name", "message": message})
    elif category is None:
        message = f"'{name or given_id}' is not a STRIDE category."
        errors.append({"field": field, "message": message})
    elif threat is not None and filed and category not in filed:
        message = "The library files '{threat}' under {categories}, not '{category}'.".format(
            threat=threat.name, categories=", ".join(filed), category=category
        )
        errors.append({"field": field, "message": message})
    return category
