"""The library's curation: a person proposes an accepted scenario's AI-written threat as a pending row, and a
curator lists, approves or rejects the pending rows."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    AuditAction,
    AuditTarget,
    LibrarySource,
    SessionMessage,
)
from app.core.database import get_stored_procedure_client
from app.core.exceptions import NotFound
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.library.repository import SqlServerRepository
from app.data_access.scenario.repository import ScenarioSessionRepository, scenario_sessions, scenarios
from app.domain.library import (
    accepted_ai_threat_key,
    decision_operation_key,
    promotion_outcome,
    scenario_actor_ids,
    threat_to_promote,
)
from app.domain.scenario.plan import library_threats_named
from app.models.api_clients import Principal
from app.models.library import ThreatLibrary, ThreatProposal
from app.models.library_curation import LibraryDecisions
from app.models.scenario.views import PromotedThreat, PromotionResult, SessionStatus
from app.search.library_cache import get_library_service
from app.services.audit import admin_actor, audit_target, caller_actor


class LibraryCuration:
    def __init__(self, library: SqlServerRepository) -> None:
        self._library = library

    def list_pending(self, offset: int, limit: int) -> dict[str, Any]:
        """A page of the rows waiting for a curator, with the total."""
        items, total = self._library.list_pending_threats(offset, limit)
        return {"items": items, "total": total}

    def decide(self, decisions: LibraryDecisions, decided_by: str) -> dict[str, Any]:
        """One outcome per id in one transaction, and one audit row findable by any of its ids. The same
        decisions sent again (a retry) answer the first answer; another call on decided ids answers
        already_approved or already_rejected."""
        operation_key = decision_operation_key(decisions.approve, decisions.reject, decided_by)
        results, applied_now = self._library.decide_pending_threats(
            operation_key, decisions.approve, decisions.reject, decided_by
        )
        if not applied_now:  # answered from its operation record: audited when it was applied
            return {"results": results}
        audit_records.create_audit_record(
            AuditAction.LIBRARY_DECIDED,
            admin_actor(decided_by),
            audit_target(AuditTarget.LIBRARY_THREAT, [str(row["catalogue_id"]) for row in results]),
            details={"approve": decisions.approve, "reject": decisions.reject, "results": results},
        )
        return {"results": results}


class LibraryPromotion:
    def __init__(
        self,
        sessions: ScenarioSessionRepository,
        library: SqlServerRepository,
        threat_library: Callable[[], ThreatLibrary],
    ) -> None:
        self._sessions = sessions
        self._library, self._threat_library = library, threat_library

    def promote(self, principal: Principal, run: SessionStatus, scenario_id: str) -> PromotionResult:
        """Proposes the accepted scenario's AI threat to the curators: 404 not in the run, 409 not accepted or
        a library threat, 503 while SQL Server is down (nothing recorded) or its answer was lost (retry)."""
        scenario, threat = self._accepted_ai_threat(run.session_id, scenario_id)
        result = self._propose(scenario_id, threat, scenario_actor_ids(scenario), principal)
        promotion = {
            "by": principal.user_id,
            "by_client": principal.client_id,
            "at": datetime.now(UTC),
            "results": [result.model_dump(mode="json")],
        }
        changes = {"library_promotion": promotion, "updated_at": promotion["at"]}
        if scenarios.update(changes, _id=scenario_id, not_promoted=True):  # set once: a repeat is quiet
            target = audit_target(AuditTarget.SCENARIO, scenario_id)
            after = {"results": promotion["results"]}
            audit_records.create_audit_record(
                AuditAction.LIBRARY_PROMOTED, caller_actor(principal), target, after=after
            )
        return PromotionResult(scenario_id=scenario_id, results=[result])

    def _accepted_ai_threat(self, session_id: str, scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """The accepted scenario and its AI threat as the frozen plan holds it."""
        scenario = scenarios.get(fields="shown", _id=scenario_id, session_id=session_id, served=True)
        if scenario is None:
            message = SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            raise NotFound(message)
        key = accepted_ai_threat_key(scenario, scenario_id)
        threat = None
        if key is not None:
            found = self._sessions.get(fields="plan_threat", **{"_id": session_id, "plan.threats.key": key})
            threat = (((found or {}).get("plan") or {}).get("threats") or [None])[0]
        return scenario, threat_to_promote(threat, scenario_id)

    def _propose(
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
            proposed, _ = self._library.propose_threat(f"promote:{scenario_id}", proposal)
            outcome = promotion_outcome(proposed.outcome)
            type_id, catalogue_id = proposed.type_id, proposed.catalogue_id
        return PromotedThreat(
            threat=name,
            threat_type=type_name,
            threat_type_id=type_id,
            threat_catalogue_id=catalogue_id,
            outcome=outcome,
        )


@singleton
def get_library_curation() -> LibraryCuration:
    """The process's curation service."""
    return LibraryCuration(SqlServerRepository(get_stored_procedure_client()))


@singleton
def get_library_promotion() -> LibraryPromotion:
    """The process's promotion service."""
    return LibraryPromotion(
        scenario_sessions,
        SqlServerRepository(get_stored_procedure_client()),
        get_library_service().get_threat_library,
    )
