"""The scenario reads : every screen is one indexed read (+ one count for a
paged list). The caller's run was checked first (app/api/dependencies.valid_session: 404 unknown, 403
another entity's). A scenario carries everything its view shows: no other read, never SQL Server."""

from app.core.constants import Decision, SessionMessage
from app.core.database import get_mongodb
from app.core.exceptions import Forbidden, NotFound
from app.core.singletons import singleton
from app.data_access.scenarios import Page, ScenarioRepository
from app.models.api_clients import Principal
from app.models.run_board import build_board
from app.models.scenario_views import RunResults, ScenarioList, ScenarioView
from app.models.scenarios import SessionStatus


class ScenarioQueries:
    def __init__(self, scenarios: ScenarioRepository) -> None:
        self._scenarios = scenarios

    def run_results(self, run: SessionStatus, include_replaced: bool, offset: int, limit: int) -> RunResults:
        """The run, its progress, then its current versions (include_replaced: every version), oldest
        first."""
        page = self._as_list(self._scenarios.list_for_run(run.session_id, include_replaced, offset, limit))
        board = build_board(run)
        header = board.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id"})
        return RunResults(**header, progress=board.progress, scenarios=page.scenarios, total=page.total)

    def one_scenario(self, session_id: str, scenario_id: str) -> ScenarioView:
        record = self._scenarios.find_in_run(session_id, scenario_id)
        if record is None:
            raise NotFound(
                SessionMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id, session_id=session_id)
            )
        return ScenarioView.from_record(record)

    def entity_scenarios(
        self, principal: Principal, entity_id: int, decision: Decision | None, offset: int, limit: int
    ) -> ScenarioList:
        """Every run's current versions of the caller's entity, newest first; another entity's → 403."""
        if entity_id != principal.entity_id:
            raise Forbidden(SessionMessage.ENTITY_MISMATCH)
        return self._as_list(self._scenarios.list_for_entity(entity_id, decision, offset, limit))

    @staticmethod
    def _as_list(page: Page) -> ScenarioList:
        records, total = page
        return ScenarioList(scenarios=[ScenarioView.from_record(record) for record in records], total=total)


@singleton
def get_scenario_queries() -> ScenarioQueries:
    return ScenarioQueries(ScenarioRepository(get_mongodb()))
