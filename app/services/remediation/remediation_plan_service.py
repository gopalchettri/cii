"""Remediation plans: a plan requested for a generated or a hand-written scenario, a new version, a decision,
and the reads (a plan, a run's or an entity's plans, the status a route or a live-update stream reads). No
request calls the AI: the plan job completes each version's input and writes it."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.callables import Publish, SendJob
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
from app.domain.remediation.decisions import decidable_version, work_out_decision_change
from app.domain.remediation.manual_records import (
    check_actor_library,
    check_manual_request,
    check_same_manual_request,
    given_controls,
    manual_ids,
    manual_request_fingerprint,
    manual_run_record,
    manual_scenario_record,
)
from app.domain.remediation.plan_rules import (
    check_own_entity,
    check_plan_changeable,
    check_plan_of_scenario,
    check_plan_owner,
    check_plannable_scenario,
    check_regenerable,
    new_plan_record,
    new_version,
    plan_exists,
    run_being_deleted,
    version_in_progress,
)
from app.domain.remediation.references import resolve_controls
from app.domain.remediation.register import register_half
from app.domain.remediation.snapshot import check_control_library, pending_snapshot
from app.domain.remediation.threat_identity import resolve_threat
from app.domain.scenario.plan import freeze_context
from app.domain.shared.audit import audit_target, caller_actor
from app.models.admin.api_clients import Principal
from app.models.remediation.plan import PlanRequested, PlanStarted, RemediationStatus
from app.models.remediation.requests import ManualScenario, PlanRequest, RegisterData
from app.models.remediation.reviews import DecisionRequest
from app.models.remediation.views import RemediationList, RemediationResult, RemediationSummary
from app.search.library_cache import LibraryCache

log = structlog.get_logger(__name__)

#: What a result shows of the planned scenario.
_SCENARIO_SUMMARY_FIELDS = ("content", "controls.items")
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
        self, principal: Principal, body: PlanRequest, idempotency_key: str | None
    ) -> tuple[PlanStarted, bool]:
        """Starts a plan for an accepted scenario: (the plan, True when it was created now; False for a replay
        of the same key and body)."""
        if body.is_manual:
            return self._create_manual_remediation_plan(principal, body, idempotency_key)
        assert body.session_id is not None and body.scenario_id is not None  # PlanRequest: is_manual=false
        scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=body.scenario_id)
        checked = check_plannable_scenario(scenario, body.session_id, body.scenario_id, principal.entity_id)
        return self._plan_scenario(principal, body, checked), True

    def regenerate_remediation_plan(self, principal: Principal, remediation_id: str) -> PlanRequested:
        """Starts the plan's next version, unless its run is being deleted or its latest one still runs."""
        read = self._read_owned(principal, remediation_id)
        scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=read["scenario_id"])
        check_plan_changeable(scenario, read)
        latest, version = (
            read["job"]["epoch"],
            check_regenerable(read, remediation_id, get_settings().regenerations_max_version_count),
        )
        assert scenario is not None  # check_plan_changeable refused a missing one
        if self._sessions.is_being_deleted(read["session_id"]):
            raise run_being_deleted(read["session_id"])
        register = RegisterData.model_validate(read["register"])
        snapshot = self._make_snapshot(register, scenario, stored=True)
        now = datetime.now(UTC)
        job = new_job(TaskName.WRITE_PLAN, version, now)
        item = new_version(version, principal, snapshot, now)
        if not self._remediations.create_remediation_plan_version(remediation_id, latest, item, job, now):
            raise version_in_progress(remediation_id, latest)  # another regenerate made it first
        # Checked again after the append: either this sees the delete's mark or the delete's check for work
        # sees the new version.
        if self._sessions.is_being_deleted(read["session_id"]):
            self._remediations.stop_remediation_plan_version(remediation_id, version)
            self._publish_remediation_status(remediation_id)
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

    def accept_remediation_plan(
        self, principal: Principal, remediation_id: str, body: DecisionRequest
    ) -> RemediationStatus:
        """Accepts a done version of the plan (by default the newest done one)."""
        return self._decide(principal, remediation_id, body, Decision.ACCEPTED)

    def reject_remediation_plan(
        self, principal: Principal, remediation_id: str, body: DecisionRequest
    ) -> RemediationStatus:
        """Rejects a done version of the plan (by default the newest done one)."""
        return self._decide(principal, remediation_id, body, Decision.REJECTED)

    def get_remediation_plan(
        self, principal: Principal, session_id: str, scenario_id: str, include_history: bool
    ) -> RemediationResult:
        """The scenario's plan as shown, with the scenario it treats; 404/403 as every plan route."""
        record = self._remediations.get(fields="result", scenario_id=scenario_id)
        status = None if record is None else RemediationStatus.from_record(record)
        check_plan_of_scenario(status, principal.entity_id, session_id, scenario_id)
        assert record is not None  # check_plan_of_scenario refused a missing plan
        scenario = self._scenarios.get(fields=_SCENARIO_SUMMARY_FIELDS, _id=scenario_id)
        return RemediationResult.from_records(record, scenario, include_history)

    def list_remediation_plans_of_entity(  # noqa: PLR0913 — the list's filters, each its own query parameter
        self,
        principal: Principal,
        entity_id: int,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The entity's plans (the entity in the path must be the caller's, else 403), newest first."""
        check_own_entity(entity_id, principal.entity_id)
        return self.list_remediation_plans_of_session(
            entity_id, None, status, decision, risk_level, offset, limit
        )

    def list_remediation_plans_of_session(  # noqa: PLR0913 — the list's filters, each its own query parameter
        self,
        entity_id: int,
        session_id: str | None,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The entity's plans (of one run when `session_id` is given), newest first, filtered by every filter
        given. The caller's run is checked by the route (valid_session)."""
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
        status = self._remediations.get_remediation_plan_status_of_scenario(scenario_id)
        return check_plan_of_scenario(status, entity_id, session_id, scenario_id)

    def get_remediation_plan_live_status(self, remediation_id: str) -> dict[str, Any] | None:
        """The plan's status body read now; None when MongoDB cannot say (the next published change follows
        anyway); NotFound once the plan is gone (deleted with its run)."""
        try:
            status = self._remediations.get_remediation_plan_status(remediation_id)
        except MONGO_UNAVAILABLE_ERRORS:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
            return None
        if status is None:
            raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
        return status.model_dump(mode="json")

    def _create_manual_remediation_plan(
        self, principal: Principal, body: PlanRequest, key: str | None
    ) -> tuple[PlanStarted, bool]:
        """A hand-written scenario's plan: the same key and body replay the first answer; the key of a
        generated run, of another asset or of another body is 409; a first request saves the scenario, then
        plans it as a generated one."""
        manual = check_manual_request(principal, body, key)
        assert key is not None  # check_manual_request refused a missing one
        fingerprint = manual_request_fingerprint(body)
        scenario = self._earlier_scenario(principal, manual, key, fingerprint)
        if scenario is not None and (replayed := self._replayed(scenario["_id"])) is not None:
            return replayed, False
        saved_before = scenario is not None  # an earlier call saved it, then stopped (v1: replayed)
        if scenario is None:  # the stored one: a parallel request with this key and body may have saved first
            saved = self._save_manual_scenario(principal, body, key, fingerprint)
            scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=saved["_id"]) or saved
        try:
            started = self._plan_scenario(principal, body, scenario)
            return started.model_copy(update={"replayed": saved_before}), True
        except Conflict as clash:  # the same request made at the same moment won: its answer, replayed
            replayed = self._replayed(scenario["_id"])
            if clash.reason != ConflictReason.PLAN_ALREADY_EXISTS or replayed is None:
                raise
            return replayed, False

    def _plan_scenario(
        self, principal: Principal, register: RegisterData, scenario: dict[str, Any]
    ) -> PlanStarted:
        """R1 steps 3-8 for an accepted scenario, generated or hand-written: one plan per scenario, the
        pending snapshot, one insert, the job sent."""
        existing = self._remediations.get_remediation_plan_status_of_scenario(scenario["_id"])
        if existing is not None:
            raise plan_exists(scenario["_id"], existing.remediation_id)
        snapshot, now = self._make_snapshot(register, scenario), datetime.now(UTC)
        job = new_job(TaskName.WRITE_PLAN, 1, now)
        record = new_plan_record(principal, register, scenario, snapshot, job, now)
        try:
            self._remediations.create(record)
        except DuplicateRecord:  # a request made at the same moment won
            winner = self._remediations.get_remediation_plan_status_of_scenario(scenario["_id"])
            raise plan_exists(scenario["_id"], winner.remediation_id if winner else None) from None
        # its run was deleted meanwhile: no plan outlives it
        if not self._scenarios.count(_id=scenario["_id"]):
            self._remediations.delete(_id=record["_id"])
            raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario["_id"]))
        # Checked after the insert: either this sees the delete's mark or the delete's check for work sees it.
        if self._sessions.is_being_deleted(record["session_id"]):
            self._remediations.delete(_id=record["_id"])
            raise run_being_deleted(record["session_id"])
        self._announce(principal, record)
        return PlanStarted(
            remediation_id=record["_id"],
            session_id=record["session_id"],
            scenario_id=record["scenario_id"],
            version=1,
            status=Status.QUEUED,
            is_manual=record["source"] == RunKind.MANUAL,
        )

    def _announce(self, principal: Principal, record: dict[str, Any]) -> None:
        """After the insert: the job is sent (a failed send is re-sent by the reaper), audited with the risk
        owner masked (a person), and watchers told."""
        self._send_job(TaskName.WRITE_PLAN, record["_id"], record["job"]["epoch"])
        register = dict(record["register"])
        if register.get("risk_owner"):
            register["risk_owner"] = REDACTED
        self._audit.create_audit_record(
            AuditAction.PLAN_REQUESTED,
            caller_actor(principal),
            audit_target(AuditTarget.REMEDIATION, record["_id"]),
            after={"scenario_id": record["scenario_id"], "version": 1, "register": register},
        )
        self._publish_remediation_status(record["_id"])

    def _make_snapshot(
        self, register: RegisterData, scenario: dict[str, Any], stored: bool = False
    ) -> dict[str, Any]:
        """The version's pending snapshot; `stored`: the register a regenerate rebuilds from (a library change
        since is a warning). The register is resolved first: one it refuses (422) saves nothing; an empty
        control library is refused at once."""
        loaded = self._library.get_loaded_libraries()  # one library copy for every check below
        controls, today = loaded.control_library, datetime.now(UTC).date()
        check_control_library(controls)
        register_part = register_half(register, controls, today, stored, loaded.retired_controls)
        return pending_snapshot(scenario["_id"], register_part)

    def _save_manual_scenario(
        self, principal: Principal, body: PlanRequest, key: str, request_hash: str
    ) -> dict[str, Any]:
        """The scenario as saved (accepted by its writer), its run beside it. Everything a 422 could refuse is
        checked before the first write; no AI is called."""
        manual = body.manual_scenario
        assert manual is not None
        rows = self._assets.get_asset_context(principal.entity_id, manual)
        context = freeze_context(manual, rows)
        self._library.check_library_once()  # a row a curator added in the last minute is seen
        loaded = self._library.get_loaded_libraries()
        check_actor_library(loaded.threat_library.actors)  # in memory
        check_control_library(loaded.control_library)
        identity = resolve_threat(loaded.threat_library, manual)
        # The register too: a refused one (an id and a code naming two rows) must save nothing, or a corrected
        # retry under the same key would meet its orphaned scenario (409).
        resolve_controls(
            body.existing_controls or [], loaded.control_library, "existing_controls", strict=False
        )
        refs = manual.mapped_controls or []
        controls = resolve_controls(
            refs, loaded.control_library, "manual_scenario.mapped_controls", strict=True
        )
        now, ids = datetime.now(UTC), manual_ids(principal.entity_id, key)
        run = manual_run_record(principal, manual, ids[0], key, request_hash, context, now)
        saved = given_controls(controls.controls, now)
        scenario = manual_scenario_record(
            principal, manual, ids, identity, context, saved, caller_actor(principal), now
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

    def _earlier_scenario(
        self, principal: Principal, manual: ManualScenario, key: str, fingerprint: str
    ) -> dict[str, Any] | None:
        """The scenario an earlier request with this key saved; 409 when the key named another request."""
        earlier = self._sessions.get(fields="replay", entity_id=principal.entity_id, idempotency_key=key)
        if earlier is None:
            return None
        check_same_manual_request(earlier, manual, fingerprint)
        scenario_id = manual_ids(principal.entity_id, key)[1]
        return self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)

    def _replayed(self, scenario_id: str) -> PlanStarted | None:
        """The answer a hand-written request's first call gave, read back from its plan; None without one."""
        status = self._remediations.get_remediation_plan_status_of_scenario(scenario_id)
        if status is None:
            return None
        return PlanStarted(
            remediation_id=status.remediation_id,
            session_id=status.session_id,
            scenario_id=status.scenario_id,
            version=status.latest_version,
            status=status.latest_status,
            is_manual=True,
            replayed=True,
        )

    def _read_owned(self, principal: Principal, remediation_id: str) -> dict[str, Any]:
        """What a regenerate or a decision reads first of tsg_remediations (id-only gate read); 404 unknown,
        403 another entity's."""
        read = self._remediations.get(fields="change", _id=remediation_id)
        return check_plan_owner(read, principal.entity_id, remediation_id)

    def _decide(
        self, principal: Principal, remediation_id: str, body: DecisionRequest, decision: Decision
    ) -> RemediationStatus:
        """One update fenced on `decision_seq`, at most one version accepted, while the plan's scenario is
        still accepted; another decision landing in between reads again once, then 409
        changed_concurrently. A repeat changes nothing and audits nothing."""
        decided_by = {"decided_by": principal.user_id, "decided_by_client": principal.client_id}
        for _read_again in range(2):
            read = self._read_owned(principal, remediation_id)
            scenario = self._scenarios.get(fields=("status", "decision"), _id=read["scenario_id"])
            check_plan_changeable(scenario, read)
            version = decidable_version(read, body.version, remediation_id)
            now = datetime.now(UTC)
            change = work_out_decision_change(read, version, decision, decided_by, body.comment, now)
            if change is None:  # a repeat
                return self._status_now(remediation_id)
            if self._remediations.update_remediation_plan_decision(
                remediation_id, read["decision_seq"], change
            ):
                before = {"accepted_version": read.get("accepted_version")}
                after = {"version": version, "decision": decision}
                target = audit_target(AuditTarget.REMEDIATION, remediation_id)
                self._audit.create_audit_record(
                    _AUDITED[decision], caller_actor(principal), target, before=before, after=after
                )
                self._publish_remediation_status(remediation_id)
                return self._status_now(remediation_id)
        message = RemediationMessage.CHANGED_CONCURRENTLY.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.CHANGED_CONCURRENTLY)

    def _status_now(self, remediation_id: str) -> RemediationStatus:
        """The plan's status read after a decision; 404 when it was deleted with its run just now."""
        status = self._remediations.get_remediation_plan_status(remediation_id)
        if status is None:
            raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
        return status
