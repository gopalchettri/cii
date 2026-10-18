"""A plan for a hand-written scenario. An
Idempotency-Key is required and shares its space with run starts: the same key and body replay the first
answer (200, nothing new); the key of a generated run, of another asset or of another body is 409. A first
request makes the scenario (manual_scenarios.py), then follows the generated path."""

from typing import Any

from app.core.constants import ConflictReason
from app.core.database import get_stored_procedure_client
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.library.repository import SqlServerRepository
from app.data_access.remediation.repository import PLANNED_SCENARIO_FIELDS
from app.data_access.scenario.repository import ScenarioSessionRepository, scenario_sessions, scenarios
from app.domain.remediation.manual_records import (
    check_manual_request,
    check_same_manual_request,
    manual_ids,
    manual_request_fingerprint,
)
from app.models.api_clients import Principal
from app.models.remediation import PlanStarted
from app.models.remediation_requests import ManualScenario, PlanRequest
from app.search.library_cache import get_library_service
from app.services.remediation.manual_scenarios import ManualScenarios
from app.services.remediation.queries import get_remediation_status_of_scenario
from app.services.remediation.requests import PlanRequestService, get_plan_request_service


class ManualPlans:
    def __init__(
        self,
        sessions: ScenarioSessionRepository,
        manual_scenarios: ManualScenarios,
        requests: PlanRequestService,
    ) -> None:
        self._sessions, self._manual_scenarios, self._requests = sessions, manual_scenarios, requests

    @traced("remediation.manual_request")
    def request(self, principal: Principal, body: PlanRequest, key: str | None) -> tuple[PlanStarted, bool]:
        """(the plan, True when it was created now; False for a replay of the same key and body)."""
        manual = check_manual_request(principal, body, key)
        assert key is not None  # check_manual_request refused a missing one
        fingerprint = manual_request_fingerprint(body)
        scenario = self._earlier_scenario(principal, manual, key, fingerprint)
        if scenario is not None and (replayed := self._replayed(scenario["_id"])) is not None:
            return replayed, False
        saved_before = scenario is not None  # an earlier call saved it, then stopped (v1: replayed)
        if scenario is None:  # the stored one: a parallel request with this key and body may have saved first
            saved = self._manual_scenarios.save(principal, body, key, fingerprint)
            scenario = scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=saved["_id"]) or saved
        try:
            started = self._requests.plan_scenario(principal, body, scenario)
            return started.model_copy(update={"replayed": saved_before}), True
        except Conflict as clash:  # the same request made at the same moment won: its answer, replayed
            replayed = self._replayed(scenario["_id"])
            if clash.reason != ConflictReason.PLAN_ALREADY_EXISTS or replayed is None:
                raise
            return replayed, False

    def _earlier_scenario(
        self, principal: Principal, manual: ManualScenario, key: str, fingerprint: str
    ) -> dict[str, Any] | None:
        """The scenario an earlier request with this key saved; 409 when the key named another request."""
        earlier = self._sessions.get(fields="replay", entity_id=principal.entity_id, idempotency_key=key)
        if earlier is None:
            return None
        check_same_manual_request(earlier, manual, fingerprint)
        return scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=manual_ids(principal.entity_id, key)[1])

    def _replayed(self, scenario_id: str) -> PlanStarted | None:
        status = get_remediation_status_of_scenario(scenario_id)
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


@singleton
def get_manual_plans() -> ManualPlans:
    procedures = get_stored_procedure_client()
    manual_scenarios = ManualScenarios(SqlServerRepository(procedures), get_library_service())
    return ManualPlans(scenario_sessions, manual_scenarios, get_plan_request_service())
