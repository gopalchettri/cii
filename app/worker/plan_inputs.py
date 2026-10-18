"""A pending plan version's input, completed by its plan job (G262, owner 2026-10-15: a plan request makes no
AI call, since with many users at once an AI step inside the request answered 503). In order:
1. a hand-written scenario's attackers, ranked as a generated threat's, and its new wording proposed to the
   library (a new type linked to those attackers), audited as the person who asked;
2. the scenario's controls, when none is mapped (or every one was retired since), under the scenario's own
   control lease, so the run's controls job never maps it at the same time; one that job maps now is
   waited for (its result is used);
3. the snapshot, built from the register frozen at the request, saved on the version (a retried job never
   does this twice), with the controls a regenerate no longer maps as warnings.
A busy or unreachable AI only means waiting: a worker waits up to AiLimits.WORKER_SLOT_WAIT_SECONDS for a
place, and an outage gives the job back for its back-off (Lease.RETRY_DELAYS_SECONDS)."""

import time
from typing import Any

import structlog

from app.ai import RerankModel, get_rerank_model
from app.core.constants import (
    AuditAction,
    AuditTarget,
    Controls,
    ErrorCode,
    LibrarySource,
    LibraryStatus,
    LogEvent,
    RemediationMessage,
    ResolveOutcome,
    RunKind,
    Status,
)
from app.core.database import get_stored_procedure_client
from app.core.exceptions import ControlsNotMapped, JobFailed, LeaseLost, Unavailable
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.jobs.repository import JobLease
from app.data_access.library.repository import SqlServerRepository
from app.data_access.remediation.repository import PLANNED_SCENARIO_FIELDS, remediation_plans
from app.data_access.scenario.repository import scenario_controls, scenario_sessions, scenarios
from app.domain.remediation.manual_actors import manual_planned_threat
from app.domain.remediation.manual_records import actor_records
from app.domain.remediation.snapshot import build_snapshot, inputs_ready, no_longer_mapped
from app.domain.scenario.controls import ControlMapper, controls_record
from app.domain.scenario.plan import assign_attackers
from app.models.asset_context import FrozenContext
from app.models.library import ThreatProposal
from app.models.scenario.plan import PlannedActor
from app.realtime.publisher import publish_session_status
from app.search.service import LibrarySearch, get_library_search
from app.search.snapshot import LibrarySnapshot
from app.worker.jobs import describe_outage, keep_lease_alive

log = structlog.get_logger(__name__)

#: tsg_ResolveThreat's answer as a hand-written threat's library status; any other answer: pending.
_LIBRARY_STATUS = {
    ResolveOutcome.EXISTING_ACTIVE: LibraryStatus.ACTIVE,
    ResolveOutcome.CURATOR_REJECTED: LibraryStatus.CURATOR_REJECTED,
}


class PlanInputs:
    def __init__(
        self,
        search: LibrarySearch,
        rerank: RerankModel,
        proposals: SqlServerRepository,
    ) -> None:
        self._search, self._rerank, self._proposals = search, rerank, proposals
        self._mapper = ControlMapper(rerank)

    def complete(self, lease: JobLease, pending: dict[str, Any]) -> dict[str, Any]:
        """The version's whole snapshot, saved on it (fenced on the job's lease)."""
        scenario = self._scenario(lease, pending["scenario_id"])
        context = FrozenContext.from_record(
            scenario_sessions.get_scenario_session_context(scenario["session_id"])
        )
        snapshot = self._search.snapshot()
        if (scenario.get("pending") or {}).get("actors"):
            scenario = self._attackers(lease, scenario, snapshot)
        by_id = {row.control_id: row for row in snapshot.library.control_library}  # as the mapping sees it
        if not inputs_ready(scenario, by_id):
            items = self._controls(lease, scenario, context, snapshot, by_id)
            scenario = scenario | {"controls": {"status": Status.DONE, "items": items}}
        full = build_snapshot(scenario, context, pending["register_part"], by_id)
        if lease.epoch > 1:  # a regenerate: the controls its previous version had and this one lost
            previous = remediation_plans.get_remediation_plan_version_snapshot(
                lease.record_id, lease.epoch - 1
            )
            full["warnings"] += no_longer_mapped(previous or {}, full, lease.epoch - 1)
        remediation_plans.update_remediation_plan_version_snapshot(lease, full)
        return full

    def _scenario(self, lease: JobLease, scenario_id: str) -> dict[str, Any]:
        scenario = scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
        if scenario is None:  # deleted with its run, and its plan with it (G214): nothing to write
            raise LeaseLost(lease.record_id)
        return scenario

    def _attackers(
        self, lease: JobLease, scenario: dict[str, Any], snapshot: LibrarySnapshot
    ) -> dict[str, Any]:
        """A hand-written scenario's attackers (and a new wording's library ids) saved; then re-read."""
        content, pending = scenario["content"], scenario["pending"]
        (assigned,) = assign_attackers(snapshot, [manual_planned_threat(content)], sector="")
        changes: dict[str, Any] = {
            "content.actors": actor_records(assigned.actors, assigned.closest_attacker)
        }
        if pending.get("proposal"):
            changes |= self._propose(scenario["_id"], content, assigned.actors, pending["by"])
        scenarios.update_manual_scenario_findings(scenario["_id"], changes)
        return self._scenario(lease, scenario["_id"])

    def _propose(
        self, scenario_id: str, content: dict[str, Any], actors: tuple[PlannedActor, ...], by: dict[str, Any]
    ) -> dict[str, Any]:
        """A new wording proposed pending a curator (a new type linked to the attackers just chosen) through
        its operation record propose:{scenario_id}; audited once, as the person who asked, by the attempt that
        applied it. A retried job gets the stored answer, or replays a lost one: nothing is proposed twice."""
        threat = content["threat"]
        actor_ids = tuple(actor.actor_id for actor in actors) if threat.get("type_id") is None else ()
        proposal = ThreatProposal(
            content.get("category"),
            threat["type"],
            threat["name"],
            LibrarySource.MANUAL,
            by["user_id"],
            actor_ids,
        )
        proposed, applied_now = self._proposals.propose_threat(f"propose:{scenario_id}", proposal)
        if applied_now:
            target = {"type": AuditTarget.LIBRARY_THREAT, "id": str(proposed.catalogue_id)}
            after = {"threat": threat["name"], "type": threat["type"], "outcome": proposed.outcome}
            audit_records.create_audit_record(AuditAction.LIBRARY_PROPOSED, by, target, after=after)
        return {
            "content.threat.type_id": proposed.type_id,
            "content.threat.library_id": proposed.catalogue_id,
            "content.threat.library_status": _LIBRARY_STATUS.get(proposed.outcome, LibraryStatus.PENDING),
        }

    def _controls(
        self,
        lease: JobLease,
        scenario: dict[str, Any],
        context: FrozenContext,
        snapshot: LibrarySnapshot,
        by_id: dict[int, Any],
    ) -> list[dict[str, Any]]:
        """The scenario's mapped controls: mapped here under its own lease, or by the job that holds it now,
        waited for (at most Controls.LEASE_SECONDS, then this job is given back for a later try)."""
        scenario_id, task_id = scenario["_id"], f"{lease.task_id}:plan"
        remap = (scenario.get("controls") or {}).get("status") == Status.DONE  # mapped, but nothing active
        until = time.monotonic() + Controls.LEASE_SECONDS
        while True:
            claimed = scenario_controls.claim_scenario_controls_by_id(scenario_id, task_id, remap)
            if claimed is not None:
                return self._map(claimed, task_id, context, snapshot)
            mapped = scenario_controls.get(
                ["controls.status", "controls.items"], _id=scenario_id, controls_mapped=True
            )
            if mapped is not None and inputs_ready(mapped, by_id):
                return mapped["controls"]["items"]
            if time.monotonic() >= until:
                raise Unavailable(
                    RemediationMessage.CONTROLS_BEING_MAPPED.format(seconds=Controls.LEASE_SECONDS)
                )
            time.sleep(Controls.PLAN_WAIT_POLL_SECONDS)

    def _map(
        self, claimed: dict[str, Any], task_id: str, context: FrozenContext, snapshot: LibrarySnapshot
    ) -> list[dict[str, Any]]:
        scenario_id, attempts, started = claimed["_id"], claimed["controls"]["attempts"], time.perf_counter()
        try:
            with keep_lease_alive(_ControlsLease(scenario_id, task_id, attempts)):
                mapping = self._mapper.map_controls(claimed, context, snapshot)
        except ControlsNotMapped as exc:  # an empty library: no retry changes it
            error = {"code": exc.code, "message": exc.message}
            scenario_controls.update_scenario_controls(
                scenario_id, task_id, attempts, Status.FAILED, error=error
            )
            self._settle(claimed)
            raise JobFailed(exc.code, exc.message) from exc
        except Exception as exc:  # an outage (retried), a lost lease, a fault: the controls are freed at once
            self._give_back(claimed, task_id, describe_outage(exc))
            raise
        record = controls_record(mapping, snapshot)
        if not scenario_controls.update_scenario_controls(
            scenario_id, task_id, attempts, Status.DONE, mapping=record
        ):  # its claim was taken over meanwhile
            raise Unavailable(RemediationMessage.CONTROLS_BEING_MAPPED.format(seconds=Controls.LEASE_SECONDS))
        self._settle(claimed, time.perf_counter() - started)
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=True)
        return record["items"]

    def _give_back(self, claimed: dict[str, Any], task_id: str, reason: str) -> None:
        """A generated scenario's controls queued again (its run's controls job may map them first); a
        hand-written one's failed, as nothing in the background maps it: this job's retry claims it again."""
        error = {"code": ErrorCode.UNAVAILABLE, "message": reason}
        outcome = Status.FAILED if claimed.get("source") == RunKind.MANUAL else Status.QUEUED
        scenario_controls.update_scenario_controls(
            claimed["_id"], task_id, claimed["controls"]["attempts"], outcome, error=error
        )
        self._settle(claimed)

    def _settle(self, claimed: dict[str, Any], seconds: float = 0.0) -> None:
        """The run's counts and its watchers after one of its scenarios' controls changed state."""
        scenarios.update_scenario_session_counts(claimed["session_id"], seconds)
        publish_session_status(claimed["session_id"])


class _ControlsLease:
    """One scenario's control lease as keep_lease_alive renews it."""

    def __init__(self, scenario_id: str, task_id: str, attempts: int) -> None:
        self.record_id, self._task_id, self._attempts = scenario_id, task_id, attempts

    def renew(self) -> bool:
        """Renew this scenario's control lease; True while it holds."""
        return scenario_controls.update_scenario_controls(
            self.record_id, self._task_id, self._attempts, Status.RUNNING
        )


@singleton
def get_plan_inputs() -> PlanInputs:
    return PlanInputs(
        get_library_search(),
        get_rerank_model(),
        SqlServerRepository(get_stored_procedure_client()),
    )
