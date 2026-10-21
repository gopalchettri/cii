"""The plan job (tsg_write_plan): one plan version written from the scenario now and the stored register."""

import time
from datetime import UTC, datetime
from typing import Any

import structlog

from app.ai import ChatModel
from app.core import metrics
from app.core.constants import (
    AuditAction,
    AuditTarget,
    LibrarySource,
    LibraryStatus,
    LogEvent,
    Remediation,
    RemediationMessage,
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
)
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import JobLease
from app.data_access.library.threat_repository import ThreatRepository
from app.data_access.remediation.remediation_repository import PLANNED_SCENARIO_FIELDS, RemediationRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.remediation.manual import pick_manual_attacker
from app.domain.remediation.plan import (
    active_mapped_controls,
    assess_alternatives,
    assess_controls,
    build_snapshot,
    risk_scope,
    write_plan,
)
from app.domain.scenario.controls import ControlMapper, controls_record
from app.domain.shared.audit import audit_target
from app.models.library.library import LibraryControl, ThreatProposal
from app.models.scenario.asset_context import FrozenContext
from app.realtime.publisher import publish_session_status
from app.search.service import LibrarySearch
from app.search.snapshot import LibrarySnapshot
from app.worker.jobs import job_error_of, keep_lease_alive, outage_error

log = structlog.get_logger(__name__)

#: tsg_ResolveThreat's answer as a hand-written threat's library status; any other answer: pending.
_LIBRARY_STATUS = {
    ResolveOutcome.EXISTING_ACTIVE: LibraryStatus.ACTIVE,
    ResolveOutcome.CURATOR_REJECTED: LibraryStatus.CURATOR_REJECTED,
}


class RemediationPlanJob:
    """Writes remediation plan versions; long-lived, one per worker."""

    #: The plan record's fields the job lease reads.
    RECORD_FIELDS = ("scenario_id", "register")

    def __init__(
        self,
        remediations: RemediationRepository,
        scenarios: ThreatScenarioRepository,
        sessions: ThreatScenarioSessionRepository,
        threats: ThreatRepository,
        audit: AuditRepository,
        search: LibrarySearch,
        mapper: ControlMapper,
        chat: ChatModel,
    ) -> None:
        self._remediations, self._scenarios, self._sessions = remediations, scenarios, sessions
        self._threats, self._audit, self._search = threats, audit, search
        self._mapper, self._chat = mapper, chat

    def write_remediation_plan_version(self, lease: JobLease) -> None:
        """Writes the leased version: its snapshot rebuilt and saved, the checked plan, then the audit."""
        try:
            snapshot = self._save_snapshot(lease)
            plan, warnings = write_plan(self._chat, snapshot)
        except JobFailed:
            metrics.PLANS.labels(Status.FAILED).inc()
            raise
        written = {
            "status": Status.DONE,
            "plan": plan,
            "warnings": warnings,
            "prompt_version": Remediation.PROMPT_VERSION,
            "completed_at": datetime.now(UTC),
        }
        self._remediations.update_remediation_plan_version(lease, written, done=True)
        metrics.PLANS.labels(Status.DONE).inc()
        target = audit_target(AuditTarget.REMEDIATION, lease.record_id)
        after = {"version": lease.epoch, "warnings": len(warnings)}
        self._audit.create_audit_record(
            AuditAction.PLAN_COMPLETED, {"system": TaskName.WRITE_PLAN}, target, after=after
        )

    def _save_snapshot(self, lease: JobLease) -> dict[str, Any]:
        """The version's input from the scenario now and the stored register, saved on the version."""
        scenario = self._scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=lease.record["scenario_id"])
        if scenario is None:  # deleted with its run (and its plan with it)
            raise LeaseLost(lease.record_id)
        stored_context = self._sessions.get_scenario_session_context(scenario["session_id"])
        context, library = FrozenContext.from_record(stored_context), self._search.snapshot()
        pending = scenario.get("pending") or {}
        if pending.get("actors"):  # hand-written: its attackers saved (and a new wording's library ids)
            actors = pick_manual_attacker(library, scenario)
            changes: dict[str, Any] = {"content.actors": actors}
            if pending.get("proposal"):
                actor_ids = tuple(actor["id"] for actor in actors)
                changes |= _propose_manual_threat(
                    self._threats, self._audit, scenario["_id"], scenario["content"], actor_ids, pending["by"]
                )
            scenario = self._scenarios.update_manual_scenario_findings(
                scenario["_id"], changes, PLANNED_SCENARIO_FIELDS
            )
            if scenario is None:  # deleted with its run meanwhile
                raise LeaseLost(lease.record_id)
        controls = library.library.control_library
        by_id = {row.control_id: row for row in controls}
        items = self._mapped_items(lease, scenario, context, library, by_id)
        register = lease.record["register"]
        systems, affected = risk_scope(scenario, context, register)
        library_mapped, warnings = assess_controls(items, register, controls, systems, affected)
        identified = [item["control_id"] for item in items]
        found = self._mapper.find_alternatives(
            scenario, context, library, identified, Remediation.ALTERNATIVES
        )
        alternatives = assess_alternatives(found, register, controls, systems, affected)
        snapshot = build_snapshot(
            scenario, context, register, library_mapped, warnings, affected, alternatives
        )
        self._remediations.update_remediation_plan_version(lease, {"snapshot": snapshot})
        return snapshot

    def _mapped_items(
        self,
        lease: JobLease,
        scenario: dict[str, Any],
        context: FrozenContext,
        library: LibrarySnapshot,
        by_id: dict[int, LibraryControl],
    ) -> list[dict[str, Any]]:
        """The scenario's mapped control items: as stored, mapped here, or mapped by another job."""
        if active_mapped_controls(scenario, by_id):
            return scenario["controls"]["items"]
        scenario_id, task_id = scenario["_id"], f"{lease.task_id}:plan"
        remap = (scenario.get("controls") or {}).get("status") == Status.DONE  # mapped, but nothing active
        claimed = self._scenarios.claim_scenario_controls_by_id(scenario_id, task_id, remap)
        if claimed is not None:
            return self._map(claimed, task_id, context, library)
        mapped = self._scenarios.get(
            ["controls.status", "controls.items"], _id=scenario_id, controls_mapped=True
        )
        if mapped is None or not active_mapped_controls(mapped, by_id):  # given back: no attempt used
            raise WaitingForAnotherJob(RemediationMessage.CONTROLS_BEING_MAPPED)
        return mapped["controls"]["items"]

    def _map(
        self, claimed: dict[str, Any], task_id: str, context: FrozenContext, library: LibrarySnapshot
    ) -> list[dict[str, Any]]:
        """Maps and saves the claimed scenario's controls under its lease; gives them back on a failure."""
        scenario_id, attempts, started = claimed["_id"], claimed["controls"]["attempts"], time.perf_counter()
        try:
            with keep_lease_alive(_ControlsLease(self._scenarios, scenario_id, task_id, attempts)):
                mapping = self._mapper.map_controls(claimed, context, library)
        except ControlsNotMapped as exc:  # an empty library: no retry changes it
            error = {"code": exc.code, "message": exc.message}
            self._scenarios.update_scenario_controls(
                scenario_id, task_id, attempts, Status.FAILED, error=error
            )
            self._settle(claimed)
            raise JobFailed(exc.code, exc.message) from exc
        except Exception as exc:  # an outage (retried), a lost lease, a fault: the controls are freed at once
            # A generated scenario's queued again, a hand-written one's failed; a stopped job keeps no error.
            outcome = Status.FAILED if claimed.get("source") == RunKind.MANUAL else Status.QUEUED
            freed_error: dict[str, str] | None = None
            if isinstance(exc, TEMPORARY_ERRORS):
                freed_error = outage_error(exc)
            elif not isinstance(exc, LeaseLost):
                freed_error = job_error_of(exc)
            self._scenarios.update_scenario_controls(
                scenario_id, task_id, attempts, outcome, error=freed_error
            )
            self._settle(claimed)
            if isinstance(exc, LeaseLost) and str(exc) == scenario_id:  # its control lease, not the job's
                raise WaitingForAnotherJob(RemediationMessage.CONTROLS_BEING_MAPPED) from exc
            raise
        record = controls_record(mapping, library)
        if not self._scenarios.update_scenario_controls(
            scenario_id, task_id, attempts, Status.DONE, mapping=record
        ):  # its claim was taken over meanwhile
            raise WaitingForAnotherJob(RemediationMessage.CONTROLS_BEING_MAPPED)
        self._settle(claimed, time.perf_counter() - started)
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=True)
        return record["items"]

    def _settle(self, claimed: dict[str, Any], seconds: float = 0.0) -> None:
        """Updates the run's counts and tells its watchers after a scenario's controls changed state."""
        self._sessions.update_scenario_session_counts(claimed["session_id"], seconds)
        publish_session_status(claimed["session_id"])


class _ControlsLease:
    """One scenario's control lease as keep_lease_alive renews it."""

    def __init__(
        self, scenarios: ThreatScenarioRepository, scenario_id: str, task_id: str, attempts: int
    ) -> None:
        self._scenarios = scenarios
        self.record_id, self._task_id, self._attempts = scenario_id, task_id, attempts

    def renew(self) -> bool:
        """Renews this scenario's control lease; True while it holds."""
        return self._scenarios.update_scenario_controls(
            self.record_id, self._task_id, self._attempts, Status.RUNNING
        )


def _propose_manual_threat(
    threats: ThreatRepository,
    audit: AuditRepository,
    scenario_id: str,
    content: dict[str, Any],
    actor_ids: tuple[int, ...],
    by: dict[str, Any],
) -> dict[str, Any]:
    """Proposes a new wording once through operation propose:{scenario_id}; its library ids as changes."""
    threat = content["threat"]
    proposal = ThreatProposal(
        content.get("category"),
        threat["type"],
        threat["name"],
        LibrarySource.MANUAL,
        by["user_id"],
        actor_ids if threat.get("type_id") is None else (),  # a new type is linked to the attackers
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
