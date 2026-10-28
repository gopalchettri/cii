"""The scenario module's use cases: start a run from the asset's frozen facts, read it and its scenarios,
accept or reject them, give the run more work (next set, regenerate) and propose an accepted AI-written threat
to the library."""

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Final

import structlog

from app.core import metrics
from app.core.callables import Publish, SendJob
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    ActionStatus,
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    Dependency,
    IntelDocId,
    LibrarySource,
    LogEvent,
    PlanTraceMessage,
    ReviewMessage,
    RunActionKind,
    RunClash,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    TaskName,
)
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Conflict, Forbidden, NotFound
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.external_intelligence.intel_snapshot_repository import IntelSnapshotRepository
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.data_access.jobs.job_repository import new_job
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.data_access.scenario.asset_repository import AssetRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import (
    ThreatScenarioSessionRepository,
    running_action,
)
from app.domain.jobs import run_being_deleted
from app.domain.library.curation import (
    accepted_ai_threat_key,
    promotion_outcome,
    scenario_actor_ids,
    threat_to_promote,
)
from app.domain.scenario.library_rules import known_threat_ids
from app.domain.scenario.plan import (
    check_intel_has_data,
    check_same_start_request,
    freeze_context,
    library_threats_named,
    nothing_left_to_write,
    request_fingerprint,
    set_and_first_batch,
)
from app.domain.scenario.plan_trace import plan_trace_view
from app.domain.scenario.results import build_board, build_scenario_view
from app.domain.scenario.review import (
    Targets,
    cancel_stamp_seen,
    check_review_open,
    check_session_of_caller,
    check_something_to_accept,
    controls_pending,
    controls_were_cancelled,
    decidable_targets,
    decided_stamp,
    decision_outcome,
    regenerate_batch,
    split_accept_all,
    versions_to_replace,
)
from app.domain.shared.audit import audit_target, caller_actor
from app.domain.shared.idempotency import duplicate_request
from app.models.admin.api_clients import Principal
from app.models.library.library import ThreatLibrary, ThreatProposal
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.views import (
    AcceptRequest,
    AcceptResult,
    PlanTraceView,
    PromotedThreat,
    PromotionResult,
    RejectResult,
    RunActionStarted,
    RunBoard,
    RunResults,
    ScenarioIdsRequest,
    ScenarioList,
    ScenarioView,
    SessionStatus,
    StartRunRequest,
    TargetSkipped,
    session_status_from_record,
)

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

#: A page of tsg_scenarios records and the total of the read.
ScenarioPage = tuple[list[dict[str, Any]], int]


class ThreatScenarioService:
    """Runs and their threat scenarios: start, read, review, more work and promotion to the library."""

    def __init__(
        self,
        *,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        assets: AssetRepository,
        work_control: WorkControlRepository,
        threats: ThreatRepository,
        threat_library: Callable[[], ThreatLibrary],
        switch: IntelligenceSwitch,
        intel_snapshots: IntelSnapshotRepository,
        audit: AuditRepository,
        send_job: SendJob,
        publish_session_status: Publish,
    ) -> None:
        self._sessions, self._scenarios, self._assets = sessions, scenarios, assets
        self._work_control, self._threats, self._threat_library = work_control, threats, threat_library
        self._switch, self._intel_snapshots, self._audit = switch, intel_snapshots, audit
        self._send_job, self._publish_session_status = send_job, publish_session_status

    # Starting a run.

    def create_threat_scenario_session(
        self, principal: Principal, request: StartRunRequest, idempotency_key: str, *, derived: bool = False
    ) -> tuple[RunBoard, bool]:
        """Starts a run: (its status board, True when created now, False for a replay of the caller's
        Idempotency-Key); 409 duplicate_request for a repeat of a `derived` one."""
        if replayed := self._replay(principal, request, idempotency_key, derived):
            return build_board(replayed), False
        self._refuse_without_intel_data()  # never a run that can only fail its evidence searches
        asset_context = self._assets.get_asset_context(principal.entity_id, request)
        context = freeze_context(request, asset_context)
        record = _new_run_record(principal, request, idempotency_key, context)
        clash = self._sessions.create_scenario_session(record)
        # A parallel start with the same key won: its replay.
        if clash and (replayed := self._replay(principal, request, idempotency_key, derived)):
            return build_board(replayed), False
        if clash is RunClash.IDEMPOTENCY_KEY:  # the run that took the key was deleted since
            message = SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        self._announce_start(principal, record, context)
        return build_board(session_status_from_record(record)), True

    def _refuse_without_intel_data(self) -> None:
        """409 intel_no_data while external intelligence is on and its active snapshot indexes nothing."""
        if not self._switch.is_on():
            return
        check_intel_has_data(self._intel_snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT) or {})

    def _replay(
        self, principal: Principal, request: StartRunRequest, key: str, derived: bool
    ) -> SessionStatus | None:
        """The run that took this key, when it is the same request; 409 when the key named another request or
        a hand-written run, or was `derived` (a repeat the caller sent no key for)."""
        earlier = self._sessions.get(fields="replay", entity_id=principal.entity_id, idempotency_key=key)
        if earlier is None:
            return None
        check_same_start_request(earlier, request)
        if derived:
            raise duplicate_request(earlier["created_at"], session_id=earlier["_id"])
        return session_status_from_record(earlier)

    def _announce_start(self, principal: Principal, record: dict[str, Any], context: FrozenContext) -> None:
        """Sends the new run's job (a failed send is re-sent by the reaper), counts and audits it."""
        self._send_job(TaskName.FIND_THREATS, record["_id"], record["job"]["epoch"])
        metrics.RUNS.labels(RunKind.GENERATED).inc()
        self._audit.create_audit_record(
            AuditAction.RUN_STARTED,
            caller_actor(principal),
            audit_target(AuditTarget.SESSION, record["_id"]),
            after={
                "asset_id": record["asset_id"],
                "supporting_system_ids": record["request"]["supporting_system_ids"],
            },
            details={"missing_facts": context.missing_facts},
        )

    # Reading a run.

    def get_threat_scenario_session(self, run: SessionStatus) -> RunBoard:
        """The run's status board."""
        return build_board(run)

    def get_threat_scenario_session_status(self, session_id: str, entity_id: int) -> SessionStatus:
        """The status of a run the caller's entity owns, read by id only: 404 unknown, 403 another
        entity's."""
        record = self._sessions.get(fields="status", _id=session_id)
        return session_status_from_record(check_session_of_caller(record, session_id, entity_id))

    def get_threat_scenario_session_live_status(self, session_id: str) -> dict[str, Any] | None:
        """The run's status body read now; None while MongoDB cannot say; NotFound once the run is deleted."""
        try:
            record = self._sessions.get(fields="status", _id=session_id)
        except MONGO_UNAVAILABLE_ERRORS:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
            return None
        if record is None:
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
        return build_board(session_status_from_record(record)).model_dump(mode="json")

    # Reading scenarios.

    def list_threat_scenarios_of_session(
        self, run: SessionStatus, include_replaced: bool, offset: int, limit: int
    ) -> RunResults:
        """The run, its progress and a page of its current versions in the plan's order (the turns over the
        systems), oldest first within one path: a set's cards are written at once and finish in any order."""
        in_turns = ["content.threat.rank", "created_at"]
        page = self._scenario_list(
            self._scenario_page(in_turns, offset, limit, session_id=run.session_id), include_replaced
        )
        board = build_board(run)
        header = board.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id"})
        return RunResults(
            **header,
            progress=board.progress,
            error=board.error,
            scenarios=page.scenarios,
            total=page.total,
        )

    def get_plan_trace(self, run: SessionStatus) -> PlanTraceView:
        """How the run's plan was made: each stage's counts, each candidate left out and why, and what became
        of the planned paths; 404 before it is planned, or for a run planned before traces were kept."""
        record = self._sessions.get(fields="plan_trace", _id=run.session_id)
        if record is None or not record.get("plan_trace"):
            raise NotFound(PlanTraceMessage.NOT_PLANNED.format(session_id=run.session_id))
        paths = (record.get("plan") or {}).get("paths") or []
        return plan_trace_view(run.session_id, record["plan_trace"], paths)

    def get_threat_scenario(self, session_id: str, scenario_id: str) -> ScenarioView:
        """One scenario of the run in full, with every version it replaced; 404 when it is not in the run."""
        record = self._scenarios.get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
        if record is None:
            raise NotFound(
                SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            )
        return self._scenario_views([record], include_replaced=True)[0]

    def list_threat_scenarios_of_entity(
        self, principal: Principal, entity_id: int, decision: Decision | None, offset: int, limit: int
    ) -> ScenarioList:
        """Every run's current versions of the caller's entity, newest first; another entity's -> 403."""
        if entity_id != principal.entity_id:
            raise Forbidden(SessionMessage.ENTITY_MISMATCH)
        chosen = {} if decision is None else {"decision": decision}
        return self._scenario_list(
            self._scenario_page("-created_at", offset, limit, entity_id=entity_id, **chosen)
        )

    def _scenario_list(self, page: ScenarioPage, include_replaced: bool = False) -> ScenarioList:
        """A page of records as their views, with the total."""
        records, total = page
        return ScenarioList(scenarios=self._scenario_views(records, include_replaced), total=total)

    def _scenario_views(self, records: list[dict[str, Any]], include_replaced: bool) -> list[ScenarioView]:
        """Each record's view with its path's other versions, read once for the whole page."""
        others = self._other_versions(records, include_replaced)
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

    def _scenario_page(self, sort: str | list[str], offset: int, limit: int, **where: Any) -> ScenarioPage:
        """A page of served current tsg_scenarios versions and their total; a short last page needs no
        count."""
        shown = {"served": True, "current": True, **where}
        records = self._scenarios.list(fields="shown", sort=sort, skip=offset, limit=limit, **shown)
        if (records or offset == 0) and len(records) < limit:
            return records, offset + len(records)
        return records, self._scenarios.count(**shown)

    def _other_versions(self, records: list[dict[str, Any]], with_replaced: bool) -> list[dict[str, Any]]:
        """In one tsg_scenarios read for a page: the accepted versions of its attack paths and,
        `with_replaced`, every replaced version of them (whole records only when they are nested)."""
        paths = {(record["session_id"], record["path_id"]) for record in records if record.get("path_id")}
        if not paths:
            return []
        wanted: dict[str, Any] = (
            {"accepted_or_replaced": True} if with_replaced else {"decision": Decision.ACCEPTED}
        )
        found = self._scenarios.list(
            fields="shown" if with_replaced else "lookup",
            session_id_in=sorted({session for session, _ in paths}),
            path_id_in=sorted({path for _, path in paths}),
            served=True,
            **wanted,
        )
        return [doc for doc in found if (doc["session_id"], doc["path_id"]) in paths]

    # Accepting and rejecting: a call names every id at fault before it writes, then decides in one update
    # filtered on the decision it expects, so of two racing calls exactly one changes a scenario.

    def accept_threat_scenarios(
        self, principal: Principal, run: SessionStatus, request: AcceptRequest
    ) -> AcceptResult:
        """Accepts the chosen scenarios, or every acceptable one ("all")."""
        check_review_open(run)
        if request.scenario_ids is None:  # v1's mode "none": decides nothing, writes nothing
            return AcceptResult(accepted=[], replaced=[], skipped=[], controls_pending=[])
        replaced: list[str] = []
        if request.scenario_ids == "all":
            targets, skipped = self._everything_acceptable(run.session_id)
        else:
            targets, skipped = self._chosen(run.session_id, request.scenario_ids, Decision.ACCEPTED), []
            replaced = self._make_room(run.session_id, targets, request.replace_accepted, principal)
        accepted, newly, raced = self._decide(run.session_id, targets, Decision.ACCEPTED, principal)
        skipped += raced
        changes = {"accepted": newly, "replaced": replaced}
        self._announce_decisions(principal, run.session_id, AuditAction.SCENARIOS_ACCEPTED, changes, skipped)
        return AcceptResult(
            accepted=accepted,
            replaced=replaced,
            skipped=skipped,
            controls_pending=controls_pending(targets, accepted),
        )

    def reject_threat_scenarios(
        self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest
    ) -> RejectResult:
        """Rejects the chosen scenarios."""
        check_review_open(run)
        targets = self._chosen(run.session_id, request.scenario_ids, Decision.REJECTED)
        rejected, newly, skipped = self._decide(run.session_id, targets, Decision.REJECTED, principal)
        self._announce_decisions(
            principal, run.session_id, AuditAction.SCENARIOS_REJECTED, {"rejected": newly}, skipped
        )
        return RejectResult(rejected=rejected, skipped=skipped)

    def _list_review_targets(self, session_id: str, scenario_ids: list[str]) -> dict[str, dict[str, Any]]:
        """The scenario session's served tsg_scenarios among `scenario_ids`, by id; another's is not found."""
        found = self._scenarios.list(
            fields="target", scenario_id_in=scenario_ids, session_id=session_id, served=True
        )
        return {row["_id"]: row for row in found}

    def _accepted_version_of_attack_paths(self, session_id: str, path_ids: list[str]) -> dict[str, str]:
        """{path_id: scenario_id} of each attack path's accepted tsg_scenarios version (one at most)."""
        found = self._scenarios.list(
            fields="path_id", session_id=session_id, path_id_in=path_ids, decision=Decision.ACCEPTED
        )
        return {row["path_id"]: row["_id"] for row in found}

    def _chosen(self, session_id: str, scenario_ids: list[str], decision: Decision) -> Targets:
        """The targets in the order sent; 409 scenarios_not_decidable naming every id at fault."""
        found = self._list_review_targets(session_id, scenario_ids)
        known = known_threat_ids(self._threat_library()) if decision == Decision.ACCEPTED else frozenset()
        return decidable_targets(scenario_ids, found, decision, known)

    def _everything_acceptable(self, session_id: str) -> tuple[Targets, list[TargetSkipped]]:
        """Accept-all's targets and skips among the run's current written versions not rejected."""
        rows = self._scenarios.list(
            fields="target",
            sort="created_at",
            session_id=session_id,
            status=ScenarioStatus.DONE,
            newest=True,
            not_rejected=True,
        )
        check_something_to_accept(session_id, rows)
        path_ids = sorted({row["path_id"] for row in rows})
        accepted = self._accepted_version_of_attack_paths(session_id, path_ids)
        return split_accept_all(rows, accepted, known_threat_ids(self._threat_library()))

    def _make_room(self, session_id: str, targets: Targets, replace: bool, principal: Principal) -> list[str]:
        """One accepted version per path: the other accepted versions of the targets' paths go back to
        pending first, with replace_accepted (their ids returned), else 409 duplicate_version."""
        path_ids = list(dict.fromkeys(target["path_id"] for target in targets))
        accepted = self._accepted_version_of_attack_paths(session_id, path_ids)
        others = versions_to_replace(targets, accepted, replace)
        if others:
            # A crash before the accept leaves the path with none accepted: the same call repeated heals it.
            stamp = _new_decided_stamp(principal)
            self._scenarios.update_scenario_decisions(others, Decision.ACCEPTED, Decision.PENDING, stamp)
        return others

    def _decide(
        self, session_id: str, targets: Targets, decision: Decision, principal: Principal
    ) -> tuple[list[str], list[str], list[TargetSkipped]]:
        """(ids holding `decision` now, newly given it, skipped by a race): one update for the pending ones,
        and one re-read only when it could not change them all."""
        ids = [target["_id"] for target in targets]
        pending = [target["_id"] for target in targets if target["decision"] == Decision.PENDING]
        stamp = _new_decided_stamp(principal)
        changed = (
            self._scenarios.update_scenario_decisions(pending, Decision.PENDING, decision, stamp)
            if pending
            else 0
        )
        if changed == len(pending):
            return ids, pending, []
        now = self._list_review_targets(session_id, ids)
        return decision_outcome(ids, pending, now, decision, stamp["decision_id"])

    def _announce_decisions(
        self,
        principal: Principal,
        session_id: str,
        action: AuditAction,
        changes: dict[str, list[str]],
        skipped: list[TargetSkipped],
    ) -> None:
        """One audit row and the decision metric for what changed, then the run's counts and a live update
        (on a repeat too, which heals counts an earlier call could not refresh)."""
        decided = changes.get("accepted", changes.get("rejected", []))
        if decided or changes.get("replaced"):
            decision = Decision.ACCEPTED if action == AuditAction.SCENARIOS_ACCEPTED else Decision.REJECTED
            metrics.DECISIONS.labels(decision).inc(len(decided))
            self._audit.create_audit_record(
                action,
                caller_actor(principal),
                audit_target(AuditTarget.SESSION, session_id),
                after=changes,
                details={"skipped": [skip.model_dump(mode="json") for skip in skipped]},
            )
        self._sessions.update_scenario_session_counts(session_id)
        self._publish_session_status(session_id)

    # More work for a finished run.

    def write_next_threat_scenario_set(self, principal: Principal, run: SessionStatus) -> RunActionStarted:
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
            raise run_being_deleted(run.session_id)
        if not resumed:
            raise nothing_left_to_write(run.session_id, paths)
        self._publish_session_status(run.session_id)
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"controls_resumed": resumed}
        self._audit.create_audit_record(
            AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after=after
        )
        return _started(run, ActionStatus.MAPPING_CONTROLS, run.epoch)

    def regenerate_threat_scenarios(
        self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest
    ) -> RunActionStarted:
        """Queues a new version of each chosen scenario, or an AI outage's failure card written again in its
        place; 409 scenarios_not_regenerable names each bad id."""
        check_review_open(run)
        targets = self._list_review_targets(run.session_id, request.scenario_ids)
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
        self._refuse_without_intel_data()  # never a write job that can only fail its evidence searches
        clash = self._sessions.update_scenario_session_job(run, kind, batch, asked)
        if clash is RunClash.DELETING:
            raise run_being_deleted(run.session_id)
        if clash is RunClash.CHANGED:
            message = ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
            raise Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)
        epoch = run.epoch + 1
        if controls_were_cancelled(run):  # a cancelled run is resumed whole
            self._resume_controls(run.session_id, None)  # the new job cleared the cancel stamp it saw
        # A lost send is re-sent by the reaper.
        self._send_job(TaskName.WRITE_SCENARIOS, run.session_id, epoch)
        self._publish_session_status(run.session_id)
        action = AuditAction.RUN_NEXT_SET if kind == RunActionKind.NEXT_SET else AuditAction.RUN_REGENERATED
        target = audit_target(AuditTarget.SESSION, run.session_id)
        after = {"epoch": epoch, "batch": batch} | ({"set": asked} if asked else {})
        self._audit.create_audit_record(action, caller_actor(principal), target, after=after)
        return epoch

    def _resume_controls(self, session_id: str, cancelled_at: datetime | None) -> int | None:
        """Queues again and sends the controls a cancel stopped, unless a cancel other than the one stamped
        `cancelled_at` (the one the caller saw) landed since; None when the run is being deleted."""
        resumed = self._work_control.resume_scenario_controls(session_id, cancelled_at)
        if resumed:
            self._send_job(TaskName.MAP_CONTROLS, session_id, 0)  # the epoch is never checked for controls
        return resumed

    # Promotion: a person proposes an accepted scenario's AI-written threat to the curators as a pending row.

    def promote_threat_scenario_to_library(
        self, principal: Principal, run: SessionStatus, scenario_id: str
    ) -> PromotionResult:
        """Proposes the accepted scenario's AI threat to the curators: 404 not in the run, 409 not accepted or
        a library threat, 503 while SQL Server is down (nothing recorded) or its answer was lost (retry)."""
        scenario, threat = self._accepted_ai_threat(run.session_id, scenario_id)
        result = self._propose_threat(scenario_id, threat, scenario_actor_ids(scenario), principal)
        promotion = {
            "by": principal.user_id,
            "by_client": principal.client_id,
            "at": utc_now(),
            "results": [result.model_dump(mode="json")],
        }
        changes = {"library_promotion": promotion, "updated_at": promotion["at"]}
        if self._scenarios.update(changes, _id=scenario_id, not_promoted=True):  # set once: a repeat is quiet
            target = audit_target(AuditTarget.SCENARIO, scenario_id)
            after = {"results": promotion["results"]}
            self._audit.create_audit_record(
                AuditAction.LIBRARY_PROMOTED, caller_actor(principal), target, after=after
            )
        return PromotionResult(scenario_id=scenario_id, results=[result])

    def _accepted_ai_threat(self, session_id: str, scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """The accepted scenario and its AI threat as the frozen plan holds it."""
        scenario = self._scenarios.get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
        if scenario is None:
            message = SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            raise NotFound(message)
        key = accepted_ai_threat_key(scenario, scenario_id)
        threat = None
        if key is not None:
            found = self._sessions.get(fields="plan_threat", **{"_id": session_id, "plan.threats.key": key})
            threat = (((found or {}).get("plan") or {}).get("threats") or [None])[0]
        return scenario, threat_to_promote(threat, scenario_id)

    def _propose_threat(
        self, scenario_id: str, threat: dict[str, Any], actor_ids: tuple[int, ...], principal: Principal
    ) -> PromotedThreat:
        """The library's answer for the threat's name, in memory first: only a new name reaches SQL Server."""
        name, type_name = threat["name"], threat["type"]["name"]
        known = library_threats_named(self._threat_library(), name)
        if known is not None:
            outcome, type_id, catalogue_id = known
        else:
            proposal = ThreatProposal(
                threat["category"], type_name, name, LibrarySource.AI, principal.user_id, actor_ids
            )
            proposed, _ = self._threats.propose_threat(f"promote:{scenario_id}", proposal)
            outcome = promotion_outcome(proposed.outcome)
            type_id, catalogue_id = proposed.type_id, proposed.catalogue_id
        return PromotedThreat(
            threat=name,
            threat_type=type_name,
            threat_type_id=type_id,
            threat_catalogue_id=catalogue_id,
            outcome=outcome,
        )


def _new_run_record(
    principal: Principal, request: StartRunRequest, idempotency_key: str, context: FrozenContext
) -> dict[str, Any]:
    """A queued run with its threat-finding job."""
    now = utc_now()
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
        "plan_note": None,
        "last_action": running_action(RunActionKind.START, now),
        "counts": dict.fromkeys(_RUN_COUNTS, 0),
        "job": new_job(TaskName.FIND_THREATS, 1, now),
        "created_at": now,
        "updated_at": now,
        "idempotency_key": idempotency_key,
    }
    return record


def _started(run: SessionStatus, status: ActionStatus, epoch: int) -> RunActionStarted:
    """The 202 body: the run, its owner, what started and the job's epoch."""
    return RunActionStarted(session_id=run.session_id, user_id=run.user_id, status=status, epoch=epoch)


def _new_decided_stamp(principal: Principal) -> dict[str, Any]:
    """This call's decided stamp: now, and a new decision id."""
    return decided_stamp(principal, utc_now(), uuid.uuid4().hex)
