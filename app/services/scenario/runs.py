"""A run's use cases: start it from the asset's frozen facts, give it more work (next set, regenerate), and
read runs and their scenarios."""

import uuid
from datetime import UTC, datetime
from typing import Any, Final

import structlog

from app.core import metrics
from app.core.config import get_settings
from app.core.constants import (
    ActionStatus,
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    Dependency,
    IntelDocId,
    JobControlMessage,
    LogEvent,
    ReviewMessage,
    RunActionKind,
    RunClash,
    RunKind,
    SessionMessage,
    Status,
    Step,
    TaskName,
)
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Conflict, Forbidden, NotFound
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.external_intelligence.repository import intel_snapshots
from app.data_access.jobs.repository import new_job
from app.data_access.library.repository import SqlServerRepository
from app.data_access.scenario.repository import (
    JobControlRepository,
    ScenarioSessionRepository,
    running_action,
    scenario_sessions,
    scenarios,
    session_status_from_record,
)
from app.domain.scenario.plan import (
    check_intel_has_data,
    check_same_start_request,
    freeze_context,
    nothing_left_to_write,
    request_fingerprint,
    set_and_first_batch,
)
from app.domain.scenario.review import (
    cancel_stamp_seen,
    check_review_open,
    controls_were_cancelled,
    regenerate_batch,
)
from app.models.api_clients import Principal
from app.models.asset_context import FrozenContext
from app.models.scenario.views import (
    RunActionStarted,
    RunResults,
    ScenarioIdsRequest,
    ScenarioList,
    ScenarioView,
    SessionStatus,
    StartRunRequest,
)
from app.realtime.publisher import publish_session_status
from app.services.audit import audit_target, caller_actor
from app.services.external_intelligence.switch import get_external_intelligence_switch
from app.services.scenario.results import build_board, build_scenario_view
from app.services.scenario.review import list_review_targets
from app.worker.celery_app import send_job

log = structlog.get_logger(__name__)

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


def refuse_without_intel_data() -> None:
    """409 intel_no_data while external intelligence is on and its active snapshot indexes nothing."""
    if not get_external_intelligence_switch().is_enabled():
        return
    check_intel_has_data(intel_snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT) or {})


class RunService:
    def __init__(self, asset_contexts: SqlServerRepository, sessions: ScenarioSessionRepository) -> None:
        self._asset_contexts, self._sessions = asset_contexts, sessions

    def start(
        self, principal: Principal, request: StartRunRequest, idempotency_key: str | None
    ) -> tuple[SessionStatus, bool]:
        """Starts a run: (its status, True when created now, False for a replay of an Idempotency-Key)."""
        if idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
            return replayed, False
        refuse_without_intel_data()  # never a run that can only fail its evidence searches
        asset_context = self._asset_contexts.get_asset_context(principal.entity_id, request)
        context = freeze_context(request, asset_context)
        record = _new_run_record(principal, request, idempotency_key, context)
        clash = self._sessions.create_scenario_session(record)
        # A parallel start with the same key won, whichever unique rule refused this insert: its replay.
        if clash and idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
            return replayed, False
        if clash is RunClash.ACTIVE_RUN:
            active_id = _active_session_id(self._sessions, principal.entity_id, request.asset_id)
            message = SessionMessage.ACTIVE_SESSION_EXISTS.format(asset_id=request.asset_id)
            raise Conflict(
                message, reason=ConflictReason.ACTIVE_SESSION_EXISTS, details={"active_session_id": active_id}
            )
        if clash is RunClash.IDEMPOTENCY_KEY:  # the run that took the key was deleted since
            message = SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        _announce_start(principal, record, context)
        return session_status_from_record(record), True

    def _replay(self, principal: Principal, request: StartRunRequest, key: str) -> SessionStatus | None:
        """The run that took this key, when it is the same request; 409 when the key named another request or
        a hand-written run."""
        earlier = self._sessions.get(fields="replay", entity_id=principal.entity_id, idempotency_key=key)
        if earlier is None:
            return None
        check_same_start_request(earlier, request)
        return session_status_from_record(earlier)


def _active_session_id(sessions: ScenarioSessionRepository, entity_id: int, asset_id: int) -> str | None:
    """The id of the asset's active scenario session in tsg_sessions, if any."""
    found = sessions.get(fields=["_id"], entity_id=entity_id, asset_id=asset_id, active=True)
    return None if found is None else found["_id"]


def _announce_start(principal: Principal, record: dict[str, Any], context: FrozenContext) -> None:
    """Sends the new run's job (a failed send is re-sent by the reaper), counts and audits it."""
    send_job(TaskName.FIND_THREATS, record["_id"], record["job"]["epoch"])
    metrics.RUNS.labels(RunKind.GENERATED).inc()
    audit_records.create_audit_record(
        AuditAction.RUN_STARTED,
        caller_actor(principal),
        audit_target(AuditTarget.SESSION, record["_id"]),
        after={
            "asset_id": record["asset_id"],
            "supporting_system_ids": record["request"]["supporting_system_ids"],
        },
        details={"missing_facts": context.missing_facts},
    )


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
        "request_hash": request_fingerprint(request),
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
        sessions: ScenarioSessionRepository,
        controls: JobControlRepository,
    ) -> None:
        self._sessions, self._controls = sessions, controls

    def next_set(self, principal: Principal, run: SessionStatus) -> RunActionStarted:
        """Queues the next NEXT_SET_SIZE open paths, best rank first; none left, resumes the controls a cancel
        stopped, else 409 naming why."""
        check_review_open(run)
        record = self._sessions.get(fields="attack_paths", _id=run.session_id)
        if record is None:  # deleted since the status read
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=run.session_id))
        paths = (record.get("plan") or {}).get("paths") or []
        asked, batch = set_and_first_batch(paths, get_settings().next_set_size)
        if asked:
            epoch = self._queue_write_job(principal, run, RunActionKind.NEXT_SET, batch, asked)
            return _started(run, ActionStatus.GENERATING, epoch)
        resumed = self._resume_controls(run.session_id, cancel_stamp_seen(run))
        if resumed is None:
            raise _being_deleted(run.session_id)
        if not resumed:
            raise nothing_left_to_write(run.session_id, paths)
        publish_session_status(run.session_id)
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"controls_resumed": resumed}
        audit_records.create_audit_record(
            AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after=after
        )
        return _started(run, ActionStatus.MAPPING_CONTROLS, run.epoch)

    def regenerate(
        self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest
    ) -> RunActionStarted:
        """Queues a new version of each chosen scenario; 409 scenarios_not_regenerable names each bad id."""
        check_review_open(run)
        targets = list_review_targets(run.session_id, request.scenario_ids)
        batch = regenerate_batch(request.scenario_ids, targets)
        epoch = self._queue_write_job(principal, run, RunActionKind.REGENERATE, batch)
        return _started(run, ActionStatus.REGENERATING, epoch)

    def _queue_write_job(
        self,
        principal: Principal,
        run: SessionStatus,
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> int:
        """The scenario session's new write job in one guarded update, then sent, announced and audited; its
        epoch."""
        refuse_without_intel_data()  # never a write job that can only fail its evidence searches
        clash = self._sessions.update_scenario_session_job(run, kind, batch, asked)
        if clash is RunClash.ACTIVE_RUN:
            active_id = _active_session_id(self._sessions, run.entity_id, run.asset_id)
            message = ReviewMessage.ASSET_BUSY.format(asset_id=run.asset_id)
            raise Conflict(
                message, reason=ConflictReason.ASSET_BUSY, details={"active_session_id": active_id}
            )
        if clash is RunClash.DELETING:
            raise _being_deleted(run.session_id)
        if clash is RunClash.CHANGED:
            message = ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
            raise Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)
        epoch = run.epoch + 1
        if controls_were_cancelled(run):  # a cancelled run is resumed whole
            self._resume_controls(run.session_id, None)  # the new job cleared the cancel stamp it saw
        send_job(TaskName.WRITE_SCENARIOS, run.session_id, epoch)  # a lost send is re-sent by the reaper
        publish_session_status(run.session_id)
        action = AuditAction.RUN_NEXT_SET if kind == RunActionKind.NEXT_SET else AuditAction.RUN_REGENERATED
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"epoch": epoch, "batch": batch} | ({"set": asked} if asked else {})
        audit_records.create_audit_record(action, caller_actor(principal), target, after=after)
        return epoch

    def _resume_controls(self, session_id: str, cancelled_at: datetime | None) -> int | None:
        """Queues again and sends the controls a cancel stopped, unless a cancel other than the one stamped
        `cancelled_at` (the one the caller saw) landed since; None when the run is being deleted."""
        resumed = self._controls.resume_scenario_controls(session_id, cancelled_at)
        if resumed:
            send_job(TaskName.MAP_CONTROLS, session_id, 0)  # the epoch is never checked for controls
        return resumed


def _started(run: SessionStatus, status: ActionStatus, epoch: int) -> RunActionStarted:
    """The 202 body: the run, its owner, what started and the job's epoch."""
    return RunActionStarted(session_id=run.session_id, user_id=run.user_id, status=status, epoch=epoch)


def _being_deleted(session_id: str) -> Conflict:
    """409 run_being_deleted, for a click that lost the race with its run's delete."""
    message = JobControlMessage.BEING_DELETED.format(session_id=session_id)
    return Conflict(message, reason=ConflictReason.RUN_BEING_DELETED)


def find_status_for_caller(session_id: str, entity_id: int) -> SessionStatus:
    """The status of a run the caller's entity owns, read by id only: 404 unknown, 403 another entity's."""
    record = scenario_sessions.get(fields="status", _id=session_id)
    if record is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    if record["entity_id"] != entity_id:
        raise Forbidden(SessionMessage.OTHER_ENTITY.format(session_id=session_id))
    return session_status_from_record(record)


def read_current_status(session_id: str) -> dict[str, Any] | None:
    """The run's status body read now; None while MongoDB cannot say; NotFound once the run is deleted."""
    try:
        record = scenario_sessions.get(fields="status", _id=session_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    if record is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    return build_board(session_status_from_record(record)).model_dump(mode="json")


#: A page of tsg_scenarios records and the total of the read.
ScenarioPage = tuple[list[dict[str, Any]], int]


class ScenarioQueries:
    def run_results(self, run: SessionStatus, include_replaced: bool, offset: int, limit: int) -> RunResults:
        """The run, its progress and a page of its current versions, oldest first."""
        page = self._scenario_list(
            _scenario_page("created_at", offset, limit, session_id=run.session_id), include_replaced
        )
        board = build_board(run)
        header = board.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id"})
        return RunResults(
            **header,
            progress=board.progress,
            scenarios=page.scenarios,
            total=page.total,
        )

    def one_scenario(self, session_id: str, scenario_id: str) -> ScenarioView:
        """One scenario of the run; 404 when it is not in the run."""
        record = scenarios.get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
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
        chosen = {} if decision is None else {"decision": decision}
        return self._scenario_list(
            _scenario_page("-created_at", offset, limit, entity_id=entity_id, **chosen)
        )

    def _scenario_list(self, page: ScenarioPage, include_replaced: bool = False) -> ScenarioList:
        """A page of records as their views, with the total."""
        records, total = page
        return ScenarioList(scenarios=self._scenario_views(records, include_replaced), total=total)

    def _scenario_views(self, records: list[dict[str, Any]], include_replaced: bool) -> list[ScenarioView]:
        """Each record's view with its path's other versions, read once for the whole page."""
        others = _other_versions(records, include_replaced)
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
            views.append(build_scenario_view(record, elsewhere, older))
        return views


def _scenario_page(sort: str, offset: int, limit: int, **where: Any) -> ScenarioPage:
    """A page of served current tsg_scenarios versions and their total; a short last page needs no count."""
    shown = {"served": True, "current": True, **where}
    records = scenarios.list(fields="shown", sort=sort, skip=offset, limit=limit, **shown)
    if (records or offset == 0) and len(records) < limit:
        return records, offset + len(records)
    return records, scenarios.count(**shown)


def _other_versions(records: list[dict[str, Any]], with_replaced: bool) -> list[dict[str, Any]]:
    """In one tsg_scenarios read for a page: the accepted versions of its attack paths and, `with_replaced`,
    every replaced version of them (whole records only when they are nested)."""
    paths = {(record["session_id"], record["path_id"]) for record in records if record.get("path_id")}
    if not paths:
        return []
    wanted: dict[str, Any] = (
        {"accepted_or_replaced": True} if with_replaced else {"decision": Decision.ACCEPTED}
    )
    found = scenarios.list(
        fields="shown" if with_replaced else "lookup",
        session_id_in=sorted({session for session, _ in paths}),
        path_id_in=sorted({path for _, path in paths}),
        served=True,
        **wanted,
    )
    return [doc for doc in found if (doc["session_id"], doc["path_id"]) in paths]


@singleton
def get_run_service() -> RunService:
    """The process's run service."""
    return RunService(SqlServerRepository(get_stored_procedure_client()), scenario_sessions)


@singleton
def get_run_actions() -> RunActions:
    """The process's next-set and regenerate service."""
    db = get_mongodb()
    return RunActions(scenario_sessions, JobControlRepository(db))


@singleton
def get_scenario_queries() -> ScenarioQueries:
    """The process's run and scenario reads."""
    return ScenarioQueries()
