"""A run's use cases: start it from the asset's frozen facts, give it more work (next set, regenerate), and
read runs and their scenarios."""

import hashlib
import json
import uuid
from collections import Counter
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Final

import structlog

from app.core import metrics
from app.core.config import get_settings
from app.core.constants import (
    ActionStatus,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ContextProperties,
    Decision,
    Dependency,
    IntelMessage,
    JobControlMessage,
    LogEvent,
    PropertyMessage,
    ReviewMessage,
    RunActionKind,
    RunClash,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    TargetProblem,
    TaskName,
    ThreatFinding,
)
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Conflict, Forbidden, Invalid, NotFound, SetupError
from app.core.singletons import singleton
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.data_access.job_control import JobControlRecords
from app.data_access.job_records import new_job
from app.data_access.scenario.runs import (
    AssetContextRepository,
    RunActionRecords,
    SessionRepository,
    find_run_coverage,
    find_session_status,
)
from app.data_access.scenario.scenarios import Page, ScenarioRepository, ScenarioReview, ScenarioVersions
from app.domain.scenario.plan import set_and_first_batch, why_no_path_left
from app.domain.shared.prompt_redaction import DATABASE_KEYS, facts_safe_for_prompt
from app.models.api_clients import Principal
from app.models.asset_context import AssetContextRows, FrozenContext, Row
from app.models.scenario.views import (
    RunActionStarted,
    RunResults,
    ScenarioIdsRequest,
    ScenarioList,
    ScenarioView,
    SessionStatus,
    StartRunRequest,
    build_board,
    explain_given_up,
    running_action,
)
from app.realtime.publisher import publish_session_status
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.external_intelligence.switch import get_external_intelligence_switch
from app.services.scenario.review import check_review_open
from app.worker.celery_app import send_job

log = structlog.get_logger(__name__)

#: Coded columns holding one saved option value, and the option code that names it.
SINGLE_SELECT_CODES: Final = {
    "accessability_channel": "acc-channel",
    "hosting_location": "hosting-location",
    "network_connectivity_primary_dr": "network-connectivity",
    "dr_drill_frequency": "dr-drill",
    "managed_by": "managed-by",
}
#: Coded columns holding a JSON array of saved option values, or the names the procedure already joined.
MULTI_SELECT_CODES: Final = {
    "technology_used": "technology-used",
    "database_platforms": "database-platforms",
    "targeted_users": "targeted-users",
    "saas_platform_list": "saas-platforms",
    "public_cloud_platforms": "pub-c-platforms",
}
_SINGLE_CODES: Final = {**SINGLE_SELECT_CODES, "asset_priority": "priority"}
_NAME_FACTS: Final = ("critical_service", "sector", "sub_sector")
_NEVER_TESTED_YEAR: Final = 1900  # SQL Server's minimum date: "never", not a real date
#: Names a fact column may not have: the app's own (alias) and the keys every prompt drops.
_RESERVED_NAMES: Final = (frozenset(ContextProperties.ALWAYS_USED) | DATABASE_KEYS) - set(
    ContextProperties.HEAD
)
_ASSET_SETTING, _SYSTEM_SETTING = "ASSET_PROPERTIES_REQUIRED", "SYSTEM_PROPERTIES_REQUIRED"
_ALWAYS_REQUIRED: Final = frozenset({"name"})  # every prompt, card and search names the asset and its systems
_RUN_COUNTS: Final = (
    "planned",
    "written",
    "remaining",
    "failed",
    "abandoned",
    "accepted",
    "rejected",
    "pending",
    "controls_waiting",
    "controls_failed",
)
_NONE_LEFT: Final = {
    ConflictReason.NOTHING_LEFT: ReviewMessage.NOTHING_LEFT,
    ConflictReason.TARGET_REACHED: ReviewMessage.TARGET_REACHED,
    ConflictReason.SCENARIOS_ABANDONED: ReviewMessage.SCENARIOS_ABANDONED,
}


def freeze_context(request: StartRunRequest, rows: AssetContextRows) -> FrozenContext:
    """The run's frozen context from the procedure's rows: 403/404/422 for the request, 500 for a procedure
    set up wrong."""
    _check_procedure_columns(rows)
    _check_ownership(request, rows)
    assert rows.asset is not None
    _check_sector(request, rows.sector)
    _warn_unlinked_service(request, rows.services)
    options = _option_names_by_code(rows.options)
    systems_by_id = {row["id"]: row for row in rows.systems}
    asset_facts = _facts_of_row(rows.asset, options)
    systems = [
        _frozen_system(systems_by_id[system_id], f"{ThreatFinding.SYSTEM_ALIAS}{position}", options)
        for position, system_id in enumerate(request.supporting_system_ids, start=1)
    ]
    asset = _head_columns(rows.asset)
    check_required(request, {"name": asset["name"], **asset_facts}, systems)
    return FrozenContext(asset, asset_facts, systems, _missing_facts(systems))


def _display_name(value: Any) -> Any:
    """A name as prompts and cards show it: runs of whitespace collapsed to one space."""
    return " ".join(value.split()) if isinstance(value, str) else value


def _check_procedure_columns(rows: AssetContextRows) -> None:
    """500 setup_error when a row lacks a head column, a fact has a reserved name, or the dropdown names
    lack code, name and value (or id)."""
    for kind, found in (("asset", [rows.asset] if rows.asset else []), ("supporting system", rows.systems)):
        if not found:
            continue
        if any(column not in row for row in found for column in ContextProperties.HEAD):
            columns = ", ".join(ContextProperties.HEAD)
            raise SetupError(PropertyMessage.HEAD_MISSING.format(columns=columns, rows=kind))
        facts = set(found[0]) - set(ContextProperties.HEAD)  # one result set: every row has its columns
        # A reserved name would replace SYS1..n, or count as recorded while the AI never saw it.
        if reserved := sorted(facts & _RESERVED_NAMES):
            raise SetupError(PropertyMessage.RESERVED.format(columns=", ".join(reserved), rows=kind))
    if rows.options and not _option_key(rows.options[0]):
        raise SetupError(PropertyMessage.OPTIONS_OUT_OF_DATE.format(found=", ".join(rows.options[0])))


def _check_ownership(request: StartRunRequest, rows: AssetContextRows) -> None:
    """403 an asset the entity does not own or a system not linked; 404 an unknown service or sector."""
    if rows.asset is None:
        raise Forbidden(
            SessionMessage.ASSET_NOT_OWNED.format(asset_id=request.asset_id),
            reason=ConflictReason.ASSET_NOT_OWNED,
        )
    linked = {row["id"] for row in rows.systems}
    unlinked = [system_id for system_id in request.supporting_system_ids if system_id not in linked]
    if unlinked:
        message = SessionMessage.SYSTEMS_NOT_LINKED.format(system_ids=unlinked, asset_id=request.asset_id)
        raise Forbidden(message, reason=ConflictReason.SYSTEM_NOT_LINKED, details={"system_ids": unlinked})
    if request.service_id is not None and not any(row["id"] == request.service_id for row in rows.services):
        raise NotFound(SessionMessage.SERVICE_NOT_FOUND.format(service_id=request.service_id))
    asked_sector = request.subsector_id or request.sector_id
    if asked_sector is not None and rows.sector is None:
        raise NotFound(SessionMessage.SECTOR_NOT_FOUND.format(sector_id=asked_sector))


def _check_sector(request: StartRunRequest, row: Row | None) -> None:
    """422 when a sector_id sent with a sub-sector is not its parent."""
    if row is None or request.subsector_id is None or request.sector_id is None:
        return
    top_id = row["parent_id"] if row["parent_id"] is not None else row["id"]
    if top_id != request.sector_id:
        message = SessionMessage.SECTOR_NOT_PARENT.format(
            sector_id=request.sector_id, subsector_id=request.subsector_id, parent_id=top_id
        )
        raise Invalid(message, errors=[{"field": f"{request.FIELD_PREFIX}.sector_id", "message": message}])


def _warn_unlinked_service(request: StartRunRequest, rows: list[Row]) -> None:
    """Logs an asked service the asset is not linked to; it is used anyway."""
    if request.service_id is not None and not any(row["linked"] for row in rows):
        log.warning(
            LogEvent.CONTEXT_SERVICE_NOT_LINKED, asset_id=request.asset_id, service_id=request.service_id
        )


def _option_names_by_code(rows: list[Row]) -> dict[str, dict[int, str]]:
    """{option code in lower case (SQL compares codes case-insensitively): {saved number: name}}."""
    names: dict[str, dict[int, str]] = {}
    key = _option_key(rows[0]) if rows else None
    for row in rows:
        if key and (row["name"] or "").strip():  # a blank option name names nothing: reads as unanswered
            names.setdefault(str(row["code"]).strip().lower(), {})[row[key]] = row["name"]
    return names


def _option_key(row: Row) -> str | None:
    """The column a dropdown-names row holds its number in (value or id), when it has code and name."""
    if any(column not in row for column in ContextProperties.OPTION_COLUMNS):
        return None
    return next((key for key in ContextProperties.OPTION_KEYS if key in row), None)


def _single_select_name(raw: int | str | None, code: str, options: dict[str, dict[int, str]]) -> str | None:
    """The saved option's name, or the name the procedure already gave; None when unanswered (NULL or the
    form's 0) or unknown (logged)."""
    if isinstance(raw, str):
        number = _whole_number(raw)
        if number is None:
            return _display_name(raw) or None
        raw = number
    if not raw:
        return None
    name = options.get(code, {}).get(raw)
    if name is None:
        log.warning(LogEvent.CONTEXT_OPTION_VALUE_NOT_FOUND, code=code, value=raw)
    return name


def _multi_select_names(raw: str | None, code: str, options: dict[str, dict[int, str]]) -> list[str] | None:
    """Names of a JSON array of saved values (an unknown item dropped alone, as SQL's TRY_CAST); a broken
    array is none; a text that is no array is the names the procedure already joined."""
    text = (raw or "").strip()
    try:
        items = json.loads(text) if text else []
    except ValueError:
        if text.startswith("["):
            return None
        return [name for name in (part.strip() for part in text.split(",")) if name] or None
    known = options.get(code, {})
    values = map(_whole_number, items if isinstance(items, list) else [])
    return [known[value] for value in values if value in known] or None


def _whole_number(item: Any) -> int | None:
    """6 or "6" -> 6; null, true, 6.5 or "x" -> None (as SQL's TRY_CAST(... AS INT))."""
    try:
        return int(str(item))
    except ValueError:
        return None


def _stored_value(value: Any) -> Any:
    """A column's value as MongoDB stores it and a prompt reads it: a DECIMAL as a number, a date as ISO text
    (SQL Server's minimum date as None), binary as None, any other type as text."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, date):  # a datetime too
        return None if value.year <= _NEVER_TESTED_YEAR else value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return None
    return str(value)


def _fact_value(column: str, value: Any, options: dict[str, dict[int, str]]) -> Any:
    """One column's fact: option names for a coded column, collapsed spaces for a name, else its value."""
    if column in _SINGLE_CODES:
        return _single_select_name(value, _SINGLE_CODES[column], options)
    if column in MULTI_SELECT_CODES:
        return _multi_select_names(value, MULTI_SELECT_CODES[column], options)
    if column in _NAME_FACTS:
        return _display_name(value)
    return _stored_value(value)


def _facts_of_row(row: Row, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    """Every column of a procedure row but its head, in the procedure's order."""
    return {
        column: _fact_value(column, value, options)
        for column, value in row.items()
        if column not in ContextProperties.HEAD
    }


def _head_columns(row: Row) -> dict[str, Any]:
    """A row's id, display name and category code."""
    return {"id": row["id"], "name": _display_name(row["name"]), "category_code": row["category_code"]}


def _frozen_system(row: Row, alias: str, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    """A supporting system as the run freezes it: id, alias, head and facts."""
    return {"id": row["id"], "alias": alias, **_head_columns(row), **_facts_of_row(row, options)}


def _missing_facts(systems: list[dict[str, Any]]) -> list[str]:
    """The system facts not one system in scope records: shown to the reviewer, never a reason to refuse."""
    first = systems[0] if systems else {}  # one result set: every system has the same columns
    columns = [column for column in first if column not in ContextProperties.ALWAYS_USED]
    return sorted(
        column
        for column in columns
        if not any(facts_safe_for_prompt({"fact": system.get(column)}) for system in systems)
    )


def check_required(
    request: StartRunRequest, asset_facts: dict[str, Any], systems: list[dict[str, Any]]
) -> None:
    """500 when a required name is no column of the procedure; else 422 naming every required fact not
    recorded (as the AI would be shown it), the asset's first, then each system's in request order."""
    settings = get_settings()
    required_asset = settings.required_asset_properties | _ALWAYS_REQUIRED
    required_system = settings.required_system_properties | _ALWAYS_REQUIRED
    _check_returned(_ASSET_SETTING, required_asset, asset_facts)
    for system in systems[:1]:  # every system row has the procedure's same columns
        _check_returned(_SYSTEM_SETTING, required_system, system)
    gaps: list[tuple[str, str, list[str]]] = []  # (field, owner, names)
    by_field: dict[str, list[str]] = {}
    for name in _not_recorded(asset_facts, required_asset):  # sector & co come from the request's own fields
        field = ContextProperties.REQUEST_FIELDS.get(name, "asset_id")
        by_field.setdefault(f"{request.FIELD_PREFIX}.{field}", []).append(name)
    gaps += [(field, f"asset {request.asset_id}", names) for field, names in by_field.items()]
    for index, system in enumerate(systems):
        if names := _not_recorded(system, required_system):
            gaps.append(
                (f"{request.FIELD_PREFIX}.supporting_system_id.{index}", f"system {system['id']}", names)
            )
    if gaps:
        _refuse_missing_facts(gaps)


def _check_returned(setting: str, required: frozenset[str], facts: dict[str, Any]) -> None:
    """500 setup_error naming the required names the procedure does not return."""
    if absent := sorted(required - facts.keys()):
        raise SetupError(PropertyMessage.NOT_RETURNED.format(setting=setting, names=", ".join(absent)))


def _not_recorded(facts: dict[str, Any], required: frozenset[str]) -> list[str]:
    """The required names, in the facts' order, whose value the AI would not be shown."""
    return [name for name in facts if name in required and not facts_safe_for_prompt({"fact": facts[name]})]


def _refuse_missing_facts(gaps: list[tuple[str, str, list[str]]]) -> None:
    """422 required_facts_missing with one error per field: names and ids, never a value."""
    errors = [
        {"field": field, "message": PropertyMessage.NOT_RECORDED.format(owner=owner, names=", ".join(names))}
        for field, owner, names in gaps
    ]
    detail = PropertyMessage.REQUIRED_MISSING.format(
        gaps="; ".join(f"{owner}: {', '.join(names)}" for _, owner, names in gaps)
    )
    raise Invalid(detail, reason=ConflictReason.REQUIRED_FACTS_MISSING, errors=errors)


def refuse_without_intel_data() -> None:
    """409 intel_no_data while external intelligence is on and its active snapshot indexes nothing."""
    if not get_external_intelligence_switch().is_enabled():
        return
    active = SnapshotPointerStore(get_mongodb()).read_active_snapshot() or {}
    if not (active.get("counts") or {}).get("indexed"):
        raise Conflict(IntelMessage.NO_DATA_YET, reason=ConflictReason.INTEL_NO_DATA)


class RunService:
    def __init__(self, asset_contexts: AssetContextRepository, sessions: SessionRepository) -> None:
        self._asset_contexts, self._sessions = asset_contexts, sessions

    def start(
        self, principal: Principal, request: StartRunRequest, idempotency_key: str | None
    ) -> tuple[SessionStatus, bool]:
        """Starts a run: (its status, True when created now, False for a replay of an Idempotency-Key)."""
        if idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
            return replayed, False
        refuse_without_intel_data()  # never a run that can only fail its evidence searches
        context = freeze_context(request, self._asset_contexts.read(principal.entity_id, request))
        record = _new_run_record(principal, request, idempotency_key, context)
        clash = self._sessions.insert_run(record)
        if clash is RunClash.ACTIVE_RUN:
            active_id = self._sessions.find_active_run_id(principal.entity_id, request.asset_id)
            message = SessionMessage.ACTIVE_SESSION_EXISTS.format(asset_id=request.asset_id)
            raise Conflict(
                message, reason=ConflictReason.ACTIVE_SESSION_EXISTS, details={"active_session_id": active_id}
            )
        if clash is RunClash.IDEMPOTENCY_KEY:  # a parallel start with the same key won: this is its replay
            assert idempotency_key is not None
            replayed = self._replay(principal, request, idempotency_key)
            if replayed is None:  # the run that took the key was deleted since
                message = SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
                raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
            return replayed, False
        _announce_start(principal, record, context)
        return SessionStatus.from_record(record), True

    def _replay(self, principal: Principal, request: StartRunRequest, key: str) -> SessionStatus | None:
        """The run that took this key, when it is the same request; 409 when the key named another request or
        a hand-written run."""
        earlier = self._sessions.find_by_idempotency_key(principal.entity_id, key)
        if earlier is None:
            return None
        fingerprint = _request_fingerprint(request)
        if (
            earlier.get("kind") == RunKind.MANUAL
            or earlier["asset_id"] != request.asset_id
            or earlier.get("request_hash", fingerprint) != fingerprint
        ):
            raise Conflict(
                SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT
            )
        return SessionStatus.from_record(earlier)


def _announce_start(principal: Principal, record: dict[str, Any], context: FrozenContext) -> None:
    """Sends the new run's job (a failed send is re-sent by the reaper), counts and audits it."""
    send_job(TaskName.FIND_THREATS, record["_id"], record["job"]["epoch"])
    metrics.RUNS.labels(RunKind.GENERATED).inc()
    record_audit(
        AuditAction.RUN_STARTED,
        caller_actor(principal),
        audit_target(AuditTarget.SESSION, record["_id"]),
        after={
            "asset_id": record["asset_id"],
            "supporting_system_ids": record["request"]["supporting_system_ids"],
        },
        details={"missing_facts": context.missing_facts},
    )


def _request_fingerprint(request: StartRunRequest) -> str:
    """SHA-256 of the request's canonical JSON (systems as a set): what a replayed key must match."""
    canonical = request.model_dump(mode="json") | {
        "supporting_system_ids": sorted(request.supporting_system_ids)
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def _new_run_record(
    principal: Principal, request: StartRunRequest, idempotency_key: str | None, context: FrozenContext
) -> dict[str, Any]:
    """A queued run with its threat-finding job."""
    now = datetime.now(UTC)
    record: dict[str, Any] = {
        "_id": uuid.uuid4().hex,
        "kind": RunKind.GENERATED,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,  # the calling system: stored, never shown, never used to refuse
        "asset_id": request.asset_id,
        "request": request.model_dump(exclude={"asset_id"}),
        "request_hash": _request_fingerprint(request),
        "context": context.to_record(),
        "status": Status.QUEUED,
        "step": Step.THREATS,
        "active": True,
        "plan_note": None,
        "last_action": running_action(RunActionKind.START, now),
        "counts": dict.fromkeys(_RUN_COUNTS, 0),
        "job": new_job(TaskName.FIND_THREATS, 1, now),
        "created_at": now,
        "updated_at": now,
    }
    if idempotency_key:
        record["idempotency_key"] = idempotency_key
    return record


class RunActions:
    def __init__(
        self,
        records: RunActionRecords,
        review: ScenarioReview,
        sessions: SessionRepository,
        controls: JobControlRecords,
    ) -> None:
        self._records, self._review, self._sessions, self._controls = records, review, sessions, controls

    def next_set(self, principal: Principal, run: SessionStatus) -> RunActionStarted:
        """Queues the next NEXT_SET_SIZE open paths, best rank first; none left, resumes the controls a cancel
        stopped, else 409 naming why."""
        check_review_open(run)
        record = self._records.find_for_action(run.session_id, with_paths=True)
        paths = (record.get("plan") or {}).get("paths") or []
        asked, batch = set_and_first_batch(paths, get_settings().next_set_size)
        if asked:
            epoch = self._queue_again(principal, run, record, RunActionKind.NEXT_SET, batch, asked)
            return _started(run, ActionStatus.GENERATING, epoch)
        resumed = self._resume_controls(record["_id"])
        if resumed is None:
            raise _being_deleted(record["_id"])
        if not resumed:
            reason = why_no_path_left(paths)
            raise Conflict(_NONE_LEFT[reason].format(session_id=run.session_id), reason=reason)
        publish_session_status(record["_id"])
        target = audit_target(AuditTarget.SESSION, record["_id"])
        after = {"controls_resumed": resumed}
        record_audit(AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after=after)
        return _started(run, ActionStatus.MAPPING_CONTROLS, record["job"]["epoch"])

    def regenerate(
        self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest
    ) -> RunActionStarted:
        """Queues a new version of each chosen scenario; 409 scenarios_not_regenerable names each bad id."""
        check_review_open(run)
        targets = self._review.find_targets(run.session_id, request.scenario_ids)
        errors = why_ids_cannot_be_regenerated(request.scenario_ids, targets)
        if errors:
            message = ReviewMessage.NOT_REGENERABLE
            raise Conflict(message, reason=ConflictReason.SCENARIOS_NOT_REGENERABLE, errors=errors)
        batch = [{"path_id": targets[sid]["path_id"], "replaces": sid} for sid in request.scenario_ids]
        # ponytail: a second read for job.epoch, which the guarded update keys on and the status read
        # (SessionStatus.RECORD_FIELDS) lacks; adding it there would let this read go.
        record = self._records.find_for_action(run.session_id, with_paths=False)
        epoch = self._queue_again(principal, run, record, RunActionKind.REGENERATE, batch)
        return _started(run, ActionStatus.REGENERATING, epoch)

    def _queue_again(
        self,
        principal: Principal,
        run: SessionStatus,
        record: dict[str, Any],
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> int:
        """The run's new write job in one conditional update, then sent, announced and audited; its epoch."""
        clash = self._records.queue_again(record, kind, batch, asked)
        if clash is RunClash.ACTIVE_RUN:
            active_id = self._sessions.find_active_run_id(record["entity_id"], record["asset_id"])
            message = ReviewMessage.ASSET_BUSY.format(asset_id=record["asset_id"])
            raise Conflict(
                message, reason=ConflictReason.ASSET_BUSY, details={"active_session_id": active_id}
            )
        if clash is RunClash.DELETING:
            raise _being_deleted(record["_id"])
        if clash is RunClash.CHANGED:
            message = ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=record["_id"])
            raise Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)
        epoch = record["job"]["epoch"] + 1
        if _controls_were_cancelled(run):  # a cancelled run is resumed whole
            self._resume_controls(record["_id"])
        send_job(TaskName.WRITE_SCENARIOS, record["_id"], epoch)  # a lost send is re-sent by the reaper
        publish_session_status(record["_id"])
        action = AuditAction.RUN_NEXT_SET if kind == RunActionKind.NEXT_SET else AuditAction.RUN_REGENERATED
        target = audit_target(AuditTarget.SESSION, record["_id"])
        after = {"epoch": epoch, "batch": batch} | ({"set": asked} if asked else {})
        record_audit(action, caller_actor(principal), target, after=after)
        return epoch

    def _resume_controls(self, session_id: str) -> int | None:
        """Queues again and sends the controls a cancel stopped; None when the run is being deleted."""
        resumed = self._controls.resume_controls(session_id)
        if resumed:
            send_job(TaskName.MAP_CONTROLS, session_id, 0)  # the epoch is never checked for controls
        return resumed


def why_ids_cannot_be_regenerated(
    scenario_ids: list[str], targets: dict[str, dict[str, Any]]
) -> list[dict[str, str]]:
    """Why each id cannot be regenerated: only the current written version of a path, one per path (a failure
    card is retried by the write job itself, so two jobs never write one path)."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        if target is None:
            reason: TargetProblem | None = TargetProblem.UNKNOWN
        elif target["status"] != ScenarioStatus.DONE:
            reason = TargetProblem.FAILURE_SCENARIO
        elif target.get("source") == RunKind.MANUAL:
            reason = TargetProblem.HAND_WRITTEN
        elif target.get("superseded_by"):
            reason = TargetProblem.VERSION_NOT_CURRENT
        elif versions_per_path[target["path_id"]] > 1:
            reason = TargetProblem.DUPLICATE_VERSION
        else:
            reason = None
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    return errors


def _controls_were_cancelled(run: SessionStatus) -> bool:
    """True when the run shows a cancel: cancelled, stamped by one, or holding cancelled controls."""
    return (
        run.status == Status.CANCELLED
        or run.cancelled is not None
        or run.counts.get("controls_cancelled", 0) > 0
    )


def _started(run: SessionStatus, status: ActionStatus, epoch: int) -> RunActionStarted:
    """The 202 body: the run, its owner, what started and the job's epoch."""
    return RunActionStarted(session_id=run.session_id, user_id=run.user_id, status=status, epoch=epoch)


def _being_deleted(session_id: str) -> Conflict:
    """409 run_being_deleted, for a click that lost the race with its run's delete."""
    message = JobControlMessage.BEING_DELETED.format(session_id=session_id)
    return Conflict(message, reason=ConflictReason.RUN_BEING_DELETED)


def find_status_for_caller(session_id: str, entity_id: int) -> SessionStatus:
    """The status of a run the caller's entity owns: 404 unknown, 403 another entity's."""
    status = find_session_status(session_id)
    if status is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    if status.entity_id != entity_id:
        raise Forbidden(SessionMessage.OTHER_ENTITY.format(session_id=session_id))
    return status


def read_current_status(session_id: str) -> dict[str, Any] | None:
    """The run's status body read now; None while MongoDB cannot say; NotFound once the run is deleted."""
    try:
        status = find_session_status(session_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    if status is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    return build_board(status).model_dump(mode="json")


class ScenarioQueries:
    def __init__(self, scenarios: ScenarioRepository, versions: ScenarioVersions) -> None:
        self._scenarios, self._versions = scenarios, versions

    def run_results(self, run: SessionStatus, include_replaced: bool, offset: int, limit: int) -> RunResults:
        """The run, its progress and coverage, and a page of its current versions, oldest first."""
        page = self._scenario_list(
            self._scenarios.list_for_run(run.session_id, offset, limit), include_replaced
        )
        board = build_board(run)
        header = board.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id"})
        return RunResults(
            **header,
            progress=board.progress,
            coverage=self._run_coverage(run.session_id),
            scenarios=page.scenarios,
            total=page.total,
        )

    def _run_coverage(self, session_id: str) -> dict[str, Any] | None:
        """The run's coverage, each given-up path named by its threat and its card's reason."""
        coverage = find_run_coverage(session_id)
        if coverage and coverage["given_up"]:
            path_ids = [entry["path_id"] for entry in coverage["given_up"]]
            cards = self._versions.newest_cards(session_id, path_ids)
            coverage["given_up"] = explain_given_up(coverage["given_up"], cards)
        return coverage

    def one_scenario(self, session_id: str, scenario_id: str) -> ScenarioView:
        """One scenario of the run; 404 when it is not in the run."""
        record = self._scenarios.find_in_run(session_id, scenario_id)
        if record is None:
            raise NotFound(
                SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            )
        return self._scenario_views([record], include_replaced=False)[0]

    def entity_scenarios(
        self, principal: Principal, entity_id: int, decision: Decision | None, offset: int, limit: int
    ) -> ScenarioList:
        """Every run's current versions of the caller's entity, newest first; another entity's -> 403."""
        if entity_id != principal.entity_id:
            raise Forbidden(SessionMessage.ENTITY_MISMATCH)
        return self._scenario_list(self._scenarios.list_for_entity(entity_id, decision, offset, limit))

    def _scenario_list(self, page: Page, include_replaced: bool = False) -> ScenarioList:
        """A page of records as their views, with the total."""
        records, total = page
        return ScenarioList(scenarios=self._scenario_views(records, include_replaced), total=total)

    def _scenario_views(self, records: list[dict[str, Any]], include_replaced: bool) -> list[ScenarioView]:
        """Each record's view with its path's other versions, read once for the whole page."""
        others = self._versions.find_other_versions(records, include_replaced)
        accepted = {
            (doc["session_id"], doc["path_id"]): doc["_id"]
            for doc in others
            if doc.get("decision") == Decision.ACCEPTED
        }
        replaced = sorted(
            (doc for doc in others if doc.get("superseded_by")), key=lambda doc: -doc["version"]
        )
        views = []
        for record in records:
            path = (record["session_id"], record.get("path_id"))
            elsewhere = accepted.get(path) if record.get("decision") != Decision.ACCEPTED else None
            older = [doc for doc in replaced if (doc["session_id"], doc["path_id"]) == path]
            older = [doc for doc in older if doc["version"] < record["version"]] if include_replaced else []
            views.append(ScenarioView.from_record(record, elsewhere, older))
        return views


@singleton
def get_run_service() -> RunService:
    """The process's run service."""
    return RunService(AssetContextRepository(get_stored_procedure_client()), SessionRepository(get_mongodb()))


@singleton
def get_run_actions() -> RunActions:
    """The process's next-set and regenerate service."""
    db = get_mongodb()
    return RunActions(RunActionRecords(db), ScenarioReview(db), SessionRepository(db), JobControlRecords(db))


@singleton
def get_scenario_queries() -> ScenarioQueries:
    """The process's run and scenario reads."""
    db = get_mongodb()
    return ScenarioQueries(ScenarioRepository(db), ScenarioVersions(db))
