"""A plan version's frozen input, made the same way for a first request and a regenerate, with no AI call
(G262, owner 2026-10-15): with many users at once an AI step inside the request answered 503. The register is
resolved against the current library first (a refusal is a 422, at once); then the snapshot, when the
scenario's controls and attackers are known; else a pending snapshot its plan job completes
(app/worker/plan_inputs.py), where a busy AI only means waiting. An empty control library is refused at once:
no control could ever be kept."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import ErrorCode, ErrorMessage
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.data_access.scenario.repository import ScenarioSessionRepository, scenario_sessions
from app.domain.remediation.register import register_half
from app.domain.remediation.snapshot import build_snapshot, inputs_ready, pending_snapshot
from app.models.asset_context import FrozenContext
from app.models.remediation_requests import RegisterData
from app.search.library_cache import LibraryService, get_library_service


class SnapshotMaker:
    def __init__(self, sessions: ScenarioSessionRepository, library: LibraryService) -> None:
        self._sessions, self._library = sessions, library

    def make(self, register: RegisterData, scenario: dict[str, Any], stored: bool = False) -> dict[str, Any]:
        """`stored`: the register a regenerate rebuilds from (a library change since is a warning). The
        register is resolved first: one it refuses (422) saves nothing."""
        library = self._library.get_control_library()
        if not library:
            raise Conflict(ErrorMessage.CONTROL_LIBRARY_EMPTY, reason=ErrorCode.CONTROL_LIBRARY_EMPTY)
        retired = self._library.get_retired_controls()
        register_part = register_half(register, library, datetime.now(UTC).date(), stored, retired)
        by_id = {row.control_id: row for row in library}
        if not inputs_ready(scenario, by_id):
            return pending_snapshot(scenario["_id"], register_part)
        context = FrozenContext.from_record(
            self._sessions.get_scenario_session_context(scenario["session_id"])
        )
        return build_snapshot(scenario, context, register_part, by_id)


@singleton
def get_snapshot_maker() -> SnapshotMaker:
    return SnapshotMaker(scenario_sessions, get_library_service())
