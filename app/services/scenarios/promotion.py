"""Promoting an accepted scenario's AI-proposed threat to the library.
A person decides, and this is the only way an AI-proposed threat enters the library: as a pending
(inactive) row a curator approves or rejects. Accepting a scenario never does it.

The library in memory answers first (by normalised name, as v1): a live or pending threat is `existing`, a
wording a curator rejected is never proposed again, and only a new name reaches SQL Server, whose procedure
re-checks under lock. A repeat answers `existing` and records nothing more."""

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
from app.core.tracing import traced
from app.data_access.library import LibraryRepository
from app.data_access.run_actions import RunActionRecords
from app.data_access.scenario_review import ScenarioReview
from app.data_access.scenarios import ScenarioRepository
from app.engine.scenarios.finding.library_matcher import library_threats_named
from app.models.api_clients import Principal
from app.models.library import ThreatLibrary, ThreatProposal
from app.models.review import PromotedThreat, PromotionResult
from app.models.scenarios import SessionStatus
from app.search.library_cache import get_library_service
from app.services.audit import audit_target, caller_actor, record_audit


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

    @traced("library.promote")
    def promote(self, principal: Principal, run: SessionStatus, scenario_id: str) -> PromotionResult:
        """404 for a scenario not in the run; 409 scenario_not_accepted, or nothing_to_promote for a scenario
        built on a library threat. SQL Server down → 503, and nothing is recorded (try again)."""
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
        """The accepted scenario and its AI-proposed threat as the frozen plan holds it: the exact type name
        (an existing library type is matched, never duplicated), name and primary category."""
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
def get_library_promotion() -> LibraryPromotion:
    db = get_mongodb()
    return LibraryPromotion(
        ScenarioRepository(db),
        ScenarioReview(db),
        RunActionRecords(db),
        LibraryRepository(get_stored_procedure_client()),
        get_library_service().get_threat_library,
    )
