"""A plan for a hand-written scenario. An
Idempotency-Key is required and shares its space with run starts: the same key and body replay the first
answer (200, nothing new); the key of a generated run, of another asset or of another body is 409. A first
request makes the scenario (manual_scenarios.py), then follows the generated path."""

import hashlib
import json
from typing import Any

from app.ai import get_rerank_model
from app.core.constants import ConflictReason, Header, RemediationMessage, RunKind, SessionMessage
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import Conflict, Invalid
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.asset_context import AssetContextRepository
from app.data_access.library import LibraryRepository
from app.data_access.manual_scenarios import ManualRecords
from app.data_access.remediations import RemediationRepository
from app.data_access.run_counts import RunCounts
from app.data_access.sessions import SessionRepository
from app.engine.remediation.manual_records import manual_ids
from app.models.api_clients import Principal
from app.models.remediation import PlanRequested
from app.models.remediation_requests import ManualScenario, PlanRequest
from app.search.library_cache import get_library_service
from app.search.service import get_library_search
from app.services.remediation.manual_scenarios import ManualScenarios
from app.services.remediation.requests import PlanRequestService, get_plan_request_service


class ManualPlans:
    def __init__(
        self,
        sessions: SessionRepository,
        plans: RemediationRepository,
        scenarios: ManualScenarios,
        requests: PlanRequestService,
    ) -> None:
        self._sessions, self._plans, self._scenarios, self._requests = sessions, plans, scenarios, requests

    @traced("remediation.manual_request")
    def request(self, principal: Principal, body: PlanRequest, key: str | None) -> tuple[PlanRequested, bool]:
        """(the plan, True when it was created now; False for a replay of the same key and body)."""
        if not key:
            message = RemediationMessage.IDEMPOTENCY_KEY_REQUIRED
            raise Invalid(message, errors=[{"field": f"header.{Header.IDEMPOTENCY_KEY}", "message": message}])
        manual = body.manual_scenario
        assert manual is not None  # the route sends a generated scenario to PlanRequestService
        fingerprint = _fingerprint(body)
        scenario = self._earlier_scenario(principal, manual, key, fingerprint)
        if scenario is not None and (replayed := self._replayed(scenario["_id"])) is not None:
            return replayed, False
        if scenario is None:  # new, or an earlier attempt stopped before its scenario was saved
            scenario = self._scenarios.save(principal, body, key, fingerprint)
        try:
            return self._requests.plan_scenario(principal, body, scenario), True
        except Conflict as clash:  # the same request made at the same moment won: its answer, replayed
            replayed = self._replayed(scenario["_id"])
            if clash.reason != ConflictReason.PLAN_ALREADY_EXISTS or replayed is None:
                raise
            return replayed, False

    def _earlier_scenario(
        self, principal: Principal, manual: ManualScenario, key: str, fingerprint: str
    ) -> dict[str, Any] | None:
        """The scenario an earlier request with this key saved; 409 when the key named another request."""
        earlier = self._sessions.find_by_idempotency_key(principal.entity_id, key)
        if earlier is None:
            return None
        same = (
            earlier.get("kind") == RunKind.MANUAL
            and earlier["asset_id"] == manual.asset_id
            and earlier.get("request_hash") == fingerprint
        )
        if not same:
            message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        return self._plans.find_scenario(manual_ids(principal.entity_id, key)[1])

    def _replayed(self, scenario_id: str) -> PlanRequested | None:
        status = self._plans.find_for_scenario(scenario_id)
        if status is None:
            return None
        return PlanRequested(
            remediation_id=status.remediation_id,
            session_id=status.session_id,
            scenario_id=status.scenario_id,
            version=status.latest_version,
            status=status.latest_status,
        )


def _fingerprint(body: PlanRequest) -> str:
    """SHA-256 of the whole request (scenario and register): a key replays only the request it first named."""
    return hashlib.sha256(json.dumps(body.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


@singleton
def get_manual_plans() -> ManualPlans:
    db, procedures = get_mongodb(), get_stored_procedure_client()
    scenarios = ManualScenarios(
        AssetContextRepository(procedures),
        get_library_service(),
        LibraryRepository(procedures),
        get_library_search(),
        ManualRecords(db),
        RunCounts(db),
        get_rerank_model(),
    )
    return ManualPlans(
        SessionRepository(db), RemediationRepository(db), scenarios, get_plan_request_service()
    )
