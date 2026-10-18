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
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import ControlsNotMapped, JobFailed, LeaseLost, Unavailable
from app.core.singletons import singleton
from app.data_access.audit import record_audit
from app.data_access.job_records import JobLease
from app.data_access.library import LibraryRepository
from app.data_access.manual_scenarios import ManualRecords
from app.data_access.remediations import RemediationRepository
from app.data_access.scenario.runs import SessionRepository
from app.data_access.scenario.scenarios import ControlLeases, RunCounts
from app.domain.remediation.manual_actors import manual_planned_threat
from app.domain.remediation.manual_records import actor_records
from app.domain.remediation.snapshot import build_snapshot, inputs_ready, no_longer_mapped
from app.domain.scenario.controls import ControlMapper, controls_record
from app.domain.scenario.plan import assign_attackers
from app.models.asset_context import FrozenContext
from app.models.library import ThreatProposal
from app.models.scenario.plan import PlannedActor
from app.realtime.publisher import publish_session_status
from app.search.library_cache import LibraryService, get_library_service
from app.search.service import LibrarySearch, get_library_search
from app.search.snapshot import LibrarySnapshot
from app.worker.jobs import describe_outage, keep_lease_alive

log = structlog.get_logger(__name__)


class PlanInputs:
    def __init__(
        self,
        library: LibraryService,
        search: LibrarySearch,
        rerank: RerankModel,
        proposals: LibraryRepository,
    ) -> None:
        db = get_mongodb()
        self._plans, self._sessions, self._manual = (
            RemediationRepository(db),
            SessionRepository(db),
            ManualRecords(db),
        )
        self._leases, self._counts = ControlLeases(db), RunCounts(db)
        self._library, self._search, self._rerank, self._proposals = library, search, rerank, proposals
        self._mapper = ControlMapper(rerank)

    def complete(self, lease: JobLease, pending: dict[str, Any]) -> dict[str, Any]:
        """The version's whole snapshot, saved on it (fenced on the job's lease)."""
        scenario = self._scenario(lease, pending["scenario_id"])
        context = FrozenContext.from_record(self._sessions.find_context(scenario["session_id"]))
        snapshot = self._search.snapshot()
        if (scenario.get("pending") or {}).get("actors"):
            scenario = self._attackers(lease, scenario, snapshot)
        by_id = {row.control_id: row for row in self._library.get_control_library()}
        if not inputs_ready(scenario, by_id):
            items = self._controls(lease, scenario, context, snapshot, by_id)
            scenario = scenario | {"controls": {"status": Status.DONE, "items": items}}
        full = build_snapshot(scenario, context, pending["register_part"], by_id)
        if lease.epoch > 1:  # a regenerate: the controls its previous version had and this one lost
            previous = self._plans.find_snapshot(lease.record_id, lease.epoch - 1) or {}
            full["warnings"] += no_longer_mapped(previous, full, lease.epoch - 1)
        lease.write({"versions.$[v].snapshot": full}, [{"v.version": lease.epoch}])
        return full

    def _scenario(self, lease: JobLease, scenario_id: str) -> dict[str, Any]:
        scenario = self._plans.find_scenario(scenario_id)
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
            changes |= self._propose(content, assigned.actors, pending["by"])
        self._manual.complete(scenario["_id"], changes)
        return self._scenario(lease, scenario["_id"])

    def _propose(
        self, content: dict[str, Any], actors: tuple[PlannedActor, ...], by: dict[str, Any]
    ) -> dict[str, Any]:
        """A new wording proposed pending a curator (a new type linked to the attackers just chosen); audited
        as the person who asked. The procedure answers an existing name as it is, so a retried job proposes
        nothing twice."""
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
        proposed = self._proposals.propose_threat(proposal)
        target = {"type": AuditTarget.LIBRARY_THREAT, "id": str(proposed.catalogue_id)}
        after = {"threat": threat["name"], "type": threat["type"], "outcome": proposed.outcome}
        record_audit(AuditAction.LIBRARY_PROPOSED, by, target, after=after)
        active = proposed.outcome == ResolveOutcome.EXISTING_ACTIVE
        return {
            "content.threat.type_id": proposed.type_id,
            "content.threat.library_id": proposed.catalogue_id,
            "content.threat.library_status": LibraryStatus.ACTIVE if active else LibraryStatus.PENDING,
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
            claimed = self._leases.claim_scenario(scenario_id, task_id, remap)
            if claimed is not None:
                return self._map(claimed, task_id, context, snapshot)
            items = self._leases.find_mapped(scenario_id)
            if items is not None and inputs_ready(
                {"controls": {"status": Status.DONE, "items": items}}, by_id
            ):
                return items
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
            with keep_lease_alive(_ControlsLease(self._leases, scenario_id, task_id, attempts)):
                mapping = self._mapper.map_controls(claimed, context, snapshot)
        except ControlsNotMapped as exc:  # an empty library: no retry changes it
            self._leases.fail(scenario_id, task_id, attempts, {"code": exc.code, "message": exc.message})
            self._settle(claimed)
            raise JobFailed(exc.code, exc.message) from exc
        except Exception as exc:  # an outage (retried), a lost lease, a fault: the controls are freed at once
            self._give_back(claimed, task_id, describe_outage(exc))
            raise
        record = controls_record(mapping, snapshot)
        if not self._leases.finish(
            scenario_id, task_id, attempts, record
        ):  # its claim was taken over meanwhile
            raise Unavailable(RemediationMessage.CONTROLS_BEING_MAPPED.format(seconds=Controls.LEASE_SECONDS))
        self._settle(claimed, time.perf_counter() - started)
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=True)
        return record["items"]

    def _give_back(self, claimed: dict[str, Any], task_id: str, reason: str) -> None:
        """A generated scenario's controls queued again (its run's controls job may map them first); a
        hand-written one's failed, as nothing in the background maps it: this job's retry claims it again."""
        error = {"code": ErrorCode.UNAVAILABLE, "message": reason}
        if claimed.get("source") == RunKind.MANUAL:
            self._leases.fail(claimed["_id"], task_id, claimed["controls"]["attempts"], error)
        else:
            self._leases.give_back(claimed["_id"], task_id, claimed["controls"]["attempts"], error)
        self._settle(claimed)

    def _settle(self, claimed: dict[str, Any], seconds: float = 0.0) -> None:
        """The run's counts and its watchers after one of its scenarios' controls changed state."""
        self._counts.refresh(claimed["session_id"], seconds)
        publish_session_status(claimed["session_id"])


class _ControlsLease:
    """One scenario's control lease as keep_lease_alive renews it."""

    def __init__(self, leases: ControlLeases, scenario_id: str, task_id: str, attempts: int) -> None:
        self._leases, self.record_id, self._task_id, self._attempts = leases, scenario_id, task_id, attempts

    def renew(self) -> bool:
        return self._leases.renew(self.record_id, self._task_id, self._attempts)


@singleton
def get_plan_inputs() -> PlanInputs:
    return PlanInputs(
        get_library_service(),
        get_library_search(),
        get_rerank_model(),
        LibraryRepository(get_stored_procedure_client()),
    )
