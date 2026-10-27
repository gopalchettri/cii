"""Remediation plans: a plan requested for a generated or a hand-written scenario, a new version, a review,
and the reads. No request calls the AI: the plan job builds each version's input and writes it."""

from typing import Any

import structlog

from app.core.callables import Publish, SendJob
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    Dependency,
    LogEvent,
    RemediationMessage,
    RunKind,
    SessionMessage,
    Status,
    TaskName,
)
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Conflict, DuplicateRecord, NotFound
from app.core.redaction import REDACTED
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import new_job
from app.data_access.remediation.remediation_repository import PLANNED_SCENARIO_FIELDS, RemediationRepository
from app.data_access.scenario.asset_repository import AssetRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.jobs import run_being_deleted
from app.domain.remediation.manual import (
    check_actor_library,
    check_manual_request,
    check_same_manual_request,
    given_controls,
    manual_ids,
    manual_request_fingerprint,
    manual_run_record,
    manual_scenario_record,
    resolve_mapped_controls,
    resolve_threat,
)
from app.domain.remediation.rules import (
    check_control_library,
    check_own_entity,
    check_plan_changeable,
    check_plan_of_scenario,
    check_plannable_scenario,
    check_regenerable,
    check_register_systems,
    decidable_version,
    decision_change,
    new_plan_record,
    new_version,
    outage_failed,
    plan_exists,
    still_accepted,
    version_in_progress,
)
from app.domain.scenario.plan import freeze_context
from app.domain.shared.audit import audit_target, caller_actor
from app.domain.shared.idempotency import duplicate_request
from app.models.admin.api_clients import Principal
from app.models.remediation.plan import (
    PlanRequested,
    PlanStarted,
    RemediationList,
    RemediationResult,
    RemediationStatus,
    RemediationSummary,
)
from app.models.remediation.requests import SYSTEM_LISTS, ManualScenario, PlanRequest, ReviewRequest
from app.models.scenario.asset_context import FrozenContext
from app.search.library_cache import LibraryCache

log = structlog.get_logger(__name__)

#: What a result shows of the planned scenario, and whether it is still accepted.
_SCENARIO_SUMMARY_FIELDS = ("content", "controls.items", "status", "decision")
#: What a status, a regenerate or a review reads of the planned scenario: whether it is still accepted.
_SCENARIO_DECISION_FIELDS = ("status", "decision")
_AUDITED = {Decision.ACCEPTED: AuditAction.PLAN_ACCEPTED, Decision.REJECTED: AuditAction.PLAN_REJECTED}


class RemediationPlanService:
    """Remediation plans: one method per use case."""

    def __init__(
        self,
        *,
        remediations: RemediationRepository,
        scenarios: ThreatScenarioRepository,
        sessions: ThreatScenarioSessionRepository,
        assets: AssetRepository,
        library: LibraryCache,
        audit: AuditRepository,
        send_job: SendJob,
        publish_remediation_status: Publish,
    ) -> None:
        self._remediations, self._scenarios, self._sessions = remediations, scenarios, sessions
        self._assets, self._library, self._audit = assets, library, audit
        self._send_job, self._publish_remediation_status = send_job, publish_remediation_status

    def create_remediation_plan(
        self, principal: Principal, body: PlanRequest, idempotency_key: str, *, derived: bool = False
    ) -> tuple[PlanStarted, bool]:
        """Starts a plan for an accepted scenario: (the plan, True when work started now, False for a plain
        replay)."""
        if body.is_manual:
            return self._create_manual_remediation_plan(principal, body, idempotency_key, derived)
        assert body.session_id is not None and body.scenario_id is not None  # PlanRequest: is_manual=false
        scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=body.scenario_id)
        checked = check_plannable_scenario(scenario, body.session_id, body.scenario_id, principal.entity_id)
        self._check_register_systems(body, checked["session_id"])
        return self._plan_scenario(principal, body.register(), checked), True

    def regenerate_remediation_plan(self, principal: Principal, remediation_id: str) -> PlanRequested:
        """Starts the plan's next version, or writes a latest one that failed for an outage again in place
        (no version used), unless its run is being deleted or its latest one still runs."""
        read = self._read_changeable(principal, remediation_id)
        latest, in_place = read["job"]["epoch"], outage_failed(read)
        max_versions = get_settings().regenerations_max_version_count
        version = latest if in_place else check_regenerable(read, remediation_id, max_versions)
        if (requested := self._start_version(principal, read, version, in_place)) is None:
            raise version_in_progress(remediation_id, latest)  # another regenerate made it first
        return requested

    def review_remediation_plan(
        self, principal: Principal, remediation_id: str, body: ReviewRequest
    ) -> RemediationStatus:
        """Accepts or rejects a done version (by default the newest done one), one update fenced on
        decision_seq; a decision landing in between reads again once, then 409. A repeat changes nothing."""
        decided_by = {"decided_by": principal.user_id, "decided_by_client": principal.client_id}
        for _read_again in range(2):
            read = self._read_changeable(principal, remediation_id)
            version = decidable_version(read, body.version, remediation_id)
            now = utc_now()
            change = decision_change(read, version, body.decision, decided_by, body.comment, now)
            if change is None:  # a repeat
                return self._status_now(remediation_id)
            if self._remediations.update_remediation_plan_decision(
                remediation_id, read["decision_seq"], change
            ):
                before = {"accepted_version": read.get("accepted_version")}
                after = {"version": version, "decision": body.decision}
                target = audit_target(AuditTarget.REMEDIATION, remediation_id)
                self._audit.create_audit_record(
                    _AUDITED[body.decision], caller_actor(principal), target, before=before, after=after
                )
                self._publish_remediation_status(remediation_id)
                return self._status_now(remediation_id)
        message = RemediationMessage.CHANGED_CONCURRENTLY.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.CHANGED_CONCURRENTLY)

    def get_remediation_plan(
        self, principal: Principal, session_id: str, scenario_id: str, include_history: bool
    ) -> RemediationResult:
        """The scenario's plan as shown, with the scenario it treats; 404/403 as every plan route."""
        record = self._remediations.get(fields="result", scenario_id=scenario_id)
        scenario = self._scenarios.get(fields=_SCENARIO_SUMMARY_FIELDS, _id=scenario_id)
        accepted = still_accepted(scenario)
        status = None if record is None else RemediationStatus.from_record(record, accepted)
        check_plan_of_scenario(status, principal.entity_id, session_id, scenario_id)
        assert record is not None  # check_plan_of_scenario refused a missing plan
        return RemediationResult.from_records(record, scenario, accepted, include_history)

    def list_remediation_plans(
        self,
        principal: Principal,
        entity_id: int,
        session_id: str | None,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The entity's plans (of one run when `session_id` is given), newest first, filtered by every filter
        given; 403 unless the entity is the caller's."""
        check_own_entity(entity_id, principal.entity_id)
        given = {"session_id": session_id, "status": status, "decision": decision, "risk_level": risk_level}
        where: dict[str, Any] = {key: value for key, value in given.items() if value is not None}
        where["entity_id"] = entity_id  # each filter with the newest-first sort is one index scan
        records = self._remediations.list(
            fields="summary", sort="-created_at", skip=offset, limit=limit, **where
        )
        total = self._remediations.count(**where)
        return RemediationList(
            items=[RemediationSummary.from_record(record) for record in records], total=total
        )

    def get_remediation_plan_status(
        self, session_id: str, scenario_id: str, entity_id: int
    ) -> RemediationStatus:
        """The plan of a scenario in a run, as every `.../treatment-plan` route reads it first: 404 when the
        scenario has no plan or is not in this run, 403 another entity's."""
        return check_plan_of_scenario(
            self._status(scenario_id=scenario_id), entity_id, session_id, scenario_id
        )

    def get_remediation_plan_live_status(self, remediation_id: str) -> dict[str, Any] | None:
        """The plan's status body read now; None when MongoDB cannot say (the next published change follows
        anyway); NotFound once the plan is gone (deleted with its run)."""
        try:
            status = self._status_now(remediation_id)
        except MONGO_UNAVAILABLE_ERRORS:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
            return None
        return status.model_dump(mode="json")

    def _create_manual_remediation_plan(
        self, principal: Principal, body: PlanRequest, key: str, derived: bool
    ) -> tuple[PlanStarted, bool]:
        """A hand-written scenario's plan: the caller's key and the same body replay the first answer (a plan
        that failed for an outage is written again), a derived key's repeat is 409 duplicate_request; the key
        of another request is 409; a first request saves the scenario, then plans it as a generated one."""
        manual = check_manual_request(principal, body)
        fingerprint = manual_request_fingerprint(body)
        session_id, scenario_id = manual_ids(principal.entity_id, key)
        scenario: dict[str, Any] | None = None
        earlier = self._sessions.get(fields="replay", entity_id=principal.entity_id, idempotency_key=key)
        if earlier is not None:  # the key was used before: the same request again, else 409
            check_same_manual_request(earlier, fingerprint)
            if derived:
                raise duplicate_request(earlier["created_at"], session_id=session_id, scenario_id=scenario_id)
            scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
        if scenario is not None and (replayed := self._replayed(principal, scenario)) is not None:
            return replayed
        saved_before = scenario is not None  # an earlier call saved it, then stopped
        if scenario is None:  # its lists checked against SQL as it is saved (a retry sends the same body)
            scenario = self._save_manual_scenario(principal, manual, body, key, fingerprint)
        try:
            started = self._plan_scenario(principal, body.register(), scenario)
            return started.model_copy(update={"replayed": saved_before}), True
        except Conflict as clash:  # the same request made at the same moment won: its answer, replayed
            if clash.reason != ConflictReason.PLAN_ALREADY_EXISTS:
                raise
            if derived:  # a derived key's twin is refused, never replayed
                raise duplicate_request(utc_now(), session_id=session_id, scenario_id=scenario_id) from None
            if (replayed := self._replayed(principal, scenario)) is None:
                raise
            return replayed

    def _plan_scenario(
        self, principal: Principal, register: dict[str, Any], scenario: dict[str, Any]
    ) -> PlanStarted:
        """One plan per scenario (the unique index decides): version 1 queued, its job sent and audited."""
        check_control_library(self._library.get_loaded_libraries().control_library)
        now = utc_now()
        record = new_plan_record(principal, register, scenario, new_job(TaskName.WRITE_PLAN, 1, now), now)
        try:
            self._remediations.create(record)
        except DuplicateRecord:  # a plan exists, or a request made at the same moment won
            winner = self._status(scenario_id=scenario["_id"])
            raise plan_exists(scenario["_id"], winner.remediation_id if winner else None) from None
        # Its run was deleted meanwhile: no plan outlives it.
        if not self._scenarios.count(_id=scenario["_id"]):
            self._remediations.delete(_id=record["_id"])
            raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario["_id"]))
        # Checked after the insert: either this sees the delete's mark or the delete's check for work sees it.
        if self._sessions.is_being_deleted(record["session_id"]):
            self._remediations.delete(_id=record["_id"])
            raise run_being_deleted(record["session_id"])
        self._send_job(TaskName.WRITE_PLAN, record["_id"], record["job"]["epoch"])  # a lost send is re-sent
        register = dict(record["register"])  # audited with the risk owner masked
        if register.get("risk_owner"):
            register["risk_owner"] = REDACTED
        after = {"scenario_id": record["scenario_id"], "version": 1, "register": register}
        target = audit_target(AuditTarget.REMEDIATION, record["_id"])
        self._audit.create_audit_record(
            AuditAction.PLAN_REQUESTED, caller_actor(principal), target, after=after
        )
        self._publish_remediation_status(record["_id"])
        return PlanStarted(
            remediation_id=record["_id"],
            session_id=record["session_id"],
            scenario_id=record["scenario_id"],
            version=1,
            status=Status.QUEUED,
            is_manual=record["source"] == RunKind.MANUAL,
        )

    def _check_register_systems(self, body: PlanRequest, session_id: str) -> None:
        """422 for a listed supporting system the run's asset does not have; the run is read only when a
        list names one."""
        if any(getattr(body, listed) for listed in SYSTEM_LISTS):
            context = FrozenContext.from_record(self._sessions.get_scenario_session_context(session_id))
            check_register_systems(body, [system["id"] for system in context.linked_systems()])

    def _save_manual_scenario(
        self,
        principal: Principal,
        manual: ManualScenario,
        body: PlanRequest,
        key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        """Saves the scenario (accepted by its writer) and its run; everything a 422 or 409 could refuse is
        checked before the first write, and no AI is called."""
        context = freeze_context(manual, self._assets.get_asset_context(principal.entity_id, manual))
        check_register_systems(body, [system["id"] for system in context.linked_systems()])
        self._library.check_library_once()  # a row a curator added in the last minute is seen
        loaded = self._library.get_loaded_libraries()
        check_actor_library(loaded.threat_library.actors)
        check_control_library(loaded.control_library)
        threat = resolve_threat(loaded.threat_library, manual)
        controls = resolve_mapped_controls(manual, loaded.control_library)
        now, ids = utc_now(), manual_ids(principal.entity_id, key)
        run = manual_run_record(principal, manual, ids[0], key, request_hash, context, now)
        scenario = manual_scenario_record(
            principal,
            manual,
            ids,
            threat,
            context,
            given_controls(controls, now),
            caller_actor(principal),
            now,
        )
        if self._sessions.create_manual_scenario_session(run) is not None:  # the key was taken meanwhile
            message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        try:  # inserted once: a retry after a crash finds it stored and changes nothing
            self._scenarios.create(scenario)
        except DuplicateRecord as clash:
            if clash.index_name != "_id_":
                raise
        self._sessions.update_scenario_session_counts(ids[0])
        return scenario

    def _start_version(
        self, principal: Principal, read: dict[str, Any], version: int, in_place: bool
    ) -> PlanRequested | None:
        """Queues `version`, the failed latest one again `in_place` or else appended, then sends, audits and
        publishes it; None when another request made it first, 409 while its run is being deleted."""
        remediation_id, latest = read["_id"], read["job"]["epoch"]
        if self._sessions.is_being_deleted(read["session_id"]):
            raise run_being_deleted(read["session_id"])
        check_control_library(self._library.get_loaded_libraries().control_library)
        now = utc_now()
        job = new_job(TaskName.WRITE_PLAN, version, now)
        if in_place:
            started = self._remediations.retry_remediation_plan_version(remediation_id, version, job, now)
        else:
            item = new_version(version, principal, now)
            started = self._remediations.create_remediation_plan_version(
                remediation_id, latest, item, job, now
            )
        if not started:
            return None
        # Checked again after the write: either this sees the delete's mark or the delete sees the version.
        if self._sessions.is_being_deleted(read["session_id"]):
            self._undo_version(read, version, in_place)
            raise run_being_deleted(read["session_id"])
        self._send_job(TaskName.WRITE_PLAN, remediation_id, version)
        target = audit_target(AuditTarget.REMEDIATION, remediation_id)
        self._audit.create_audit_record(
            AuditAction.PLAN_REGENERATED, caller_actor(principal), target, after={"version": version}
        )
        self._publish_remediation_status(remediation_id)
        return PlanRequested(
            remediation_id=remediation_id,
            session_id=read["session_id"],
            scenario_id=read["scenario_id"],
            version=version,
            status=Status.QUEUED,
        )

    def _undo_version(self, read: dict[str, Any], version: int, in_place: bool) -> None:
        """The plan put back as `read` before `version` was queued: one queued again in place fails for its
        outage again (still retryable), an appended one is removed (no version used, no decision changed)."""
        if in_place:
            self._remediations.stop_remediation_plan_version(read["_id"], version, read["job"]["error"])
        else:
            self._remediations.undo_remediation_plan_version(read, version)
        self._publish_remediation_status(read["_id"])

    def _replayed(self, principal: Principal, scenario: dict[str, Any]) -> tuple[PlanStarted, bool] | None:
        """A hand-written request's plan for a repeat of it: written again in place as a regenerate does when
        it failed for an outage (True), else its first call's answer read back (False); None without one."""
        record = self._remediations.get(fields="status", scenario_id=scenario["_id"])
        if record is not None and outage_failed(record) and still_accepted(scenario):
            retried = self._start_version(principal, record, record["job"]["epoch"], in_place=True)
            if retried is not None:
                return PlanStarted(**retried.model_dump(), is_manual=True, replayed=True), True
            record = self._remediations.get(fields="status", _id=record["_id"])  # another repeat retried it
        if record is None:
            return None
        status = RemediationStatus.from_record(record, still_accepted(scenario))
        replayed = PlanStarted(
            remediation_id=status.remediation_id,
            session_id=status.session_id,
            scenario_id=status.scenario_id,
            version=status.latest_version,
            status=status.latest_status,
            is_manual=True,
            replayed=True,
        )
        return replayed, False

    def _read_changeable(self, principal: Principal, remediation_id: str) -> dict[str, Any]:
        """The plan a regenerate or a review changes: 404 unknown, 403 another entity's, 409 read-only."""
        read = self._remediations.get(fields="change", _id=remediation_id)
        scenario = None
        if read is not None:
            scenario = self._scenarios.get(fields=_SCENARIO_DECISION_FIELDS, _id=read["scenario_id"])
        return check_plan_changeable(scenario, read, principal.entity_id, remediation_id)

    def _status(self, **where: Any) -> RemediationStatus | None:
        """The status of the plan matching `where` (never a snapshot or a plan) as its scenario stands now, or
        None."""
        record = self._remediations.get(fields="status", **where)
        if record is None:
            return None
        scenario = self._scenarios.get(fields=_SCENARIO_DECISION_FIELDS, _id=record["scenario_id"])
        return RemediationStatus.from_record(record, still_accepted(scenario))

    def _status_now(self, remediation_id: str) -> RemediationStatus:
        """The plan's status read now; 404 once it is gone (deleted with its run)."""
        status = self._status(_id=remediation_id)
        if status is None:
            raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
        return status
