"""The library's curation: a person proposes an accepted scenario's AI-written threat as a pending row, and a
curator lists, approves or rejects the pending rows."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    LibrarySource,
    PromotionOutcome,
    ResolveOutcome,
    ReviewMessage,
    SessionMessage,
)
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import Conflict, NotFound
from app.core.singletons import singleton
from app.data_access.library import LibraryRepository
from app.data_access.scenario.runs import RunActionRecords
from app.data_access.scenario.scenarios import ScenarioRepository, ScenarioReview
from app.domain.scenario.plan import library_threats_named
from app.models.api_clients import Principal
from app.models.library import ThreatLibrary, ThreatProposal
from app.models.library_curation import LibraryDecisions
from app.models.scenario.views import PromotedThreat, PromotionResult, SessionStatus
from app.search.library_cache import get_library_service
from app.services.audit import admin_actor, audit_target, caller_actor, record_audit


class LibraryCuration:
    def __init__(self, library: LibraryRepository) -> None:
        self._library = library

    def list_pending(self, offset: int, limit: int) -> dict[str, Any]:
        """A page of the rows waiting for a curator, with the total."""
        items, total = self._library.list_pending(offset, limit)
        return {"items": items, "total": total}

    def decide(self, decisions: LibraryDecisions, decided_by: str) -> dict[str, Any]:
        """One outcome per id in one transaction, and one audit row findable by any of its ids; a repeat
        answers already_approved or already_rejected."""
        results = self._library.decide_pending(decisions.approve, decisions.reject, decided_by)
        record_audit(
            AuditAction.LIBRARY_DECIDED,
            admin_actor(decided_by),
            audit_target(AuditTarget.LIBRARY_THREAT, [str(row["catalogue_id"]) for row in results]),
            details={"approve": decisions.approve, "reject": decisions.reject, "results": results},
        )
        return {"results": results}


class LibraryPromotion:
    def __init__(
        self,
        scenarios: ScenarioRepository,
        review: ScenarioReview,
        runs: RunActionRecords,
        library: LibraryRepository,
        threat_library: Callable[[], ThreatLibrary],
    ) -> None:
        self._scenarios, self._review, self._runs = scenarios, review, runs
        self._library, self._threat_library = library, threat_library

    def promote(self, principal: Principal, run: SessionStatus, scenario_id: str) -> PromotionResult:
        """Proposes the accepted scenario's AI threat to the curators: 404 not in the run, 409 not accepted or
        a library threat, 503 while SQL Server is down (nothing recorded)."""
        scenario, threat = self._accepted_ai_threat(run.session_id, scenario_id)
        actors = (scenario.get("content") or {}).get("actors") or []
        result = self._propose(threat, tuple(actor["id"] for actor in actors if actor.get("id")), principal)
        promotion = {
            "by": principal.user_id,
            "by_client": principal.client_id,
            "at": datetime.now(UTC),
            "results": [result.model_dump(mode="json")],
        }
        if self._review.record_promotion(scenario_id, promotion):  # the first call only: a repeat is quiet
            target = audit_target(AuditTarget.SCENARIO, scenario_id)
            after = {"results": promotion["results"]}
            record_audit(AuditAction.LIBRARY_PROMOTED, caller_actor(principal), target, after=after)
        return PromotionResult(scenario_id=scenario_id, results=[result])

    def _accepted_ai_threat(self, session_id: str, scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """The accepted scenario and its AI threat as the frozen plan holds it."""
        scenario = self._scenarios.find_in_run(session_id, scenario_id)
        if scenario is None:
            message = SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            raise NotFound(message)
        if scenario.get("decision") != Decision.ACCEPTED:
            message = ReviewMessage.SCENARIO_NOT_ACCEPTED.format(scenario_id=scenario_id)
            raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
        reference = (scenario.get("content") or {}).get("threat") or {}
        threat = None
        if reference.get("ai_generated") and reference.get("key"):
            threat = self._runs.find_plan_threat(session_id, reference["key"])
        if threat is None:
            message = ReviewMessage.NOTHING_TO_PROMOTE.format(scenario_id=scenario_id)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_PROMOTE)
        return scenario, threat

    def _propose(
        self, threat: dict[str, Any], actor_ids: tuple[int, ...], principal: Principal
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
            proposed = self._library.propose_threat(proposal)
            created = proposed.outcome == ResolveOutcome.CREATED_PENDING
            outcome = PromotionOutcome.INSERTED if created else PromotionOutcome.EXISTING
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
    return LibraryCuration(LibraryRepository(get_stored_procedure_client()))


@singleton
def get_library_promotion() -> LibraryPromotion:
    """The process's promotion service."""
    db = get_mongodb()
    return LibraryPromotion(
        ScenarioRepository(db),
        ScenarioReview(db),
        RunActionRecords(db),
        LibraryRepository(get_stored_procedure_client()),
        get_library_service().get_threat_library,
    )
