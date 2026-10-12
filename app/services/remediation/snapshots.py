"""A plan version's frozen input, made the same way for a first request and a regenerate: the
scenario's controls topped up when missing (a plan never starts without a control), its run's frozen
context, the register resolved against the current library, then the snapshot. A scenario whose mapped
controls were all retired since is mapped again: a plan never starts without a control."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import Status
from app.core.database import get_mongodb
from app.core.singletons import singleton
from app.data_access.sessions import SessionRepository
from app.engine.remediation.register import register_half
from app.engine.remediation.snapshot import build_snapshot
from app.models.asset_context import FrozenContext
from app.models.remediation_requests import RegisterData
from app.search.library_cache import LibraryService, get_library_service
from app.services.remediation.controls_top_up import ControlsTopUp, get_controls_top_up


class SnapshotMaker:
    def __init__(self, sessions: SessionRepository, library: LibraryService, top_up: ControlsTopUp) -> None:
        self._sessions, self._library, self._top_up = sessions, library, top_up

    def make(self, register: RegisterData, scenario: dict[str, Any], stored: bool = False) -> dict[str, Any]:
        """`stored`: the register a regenerate rebuilds from (a library change since is a warning). The
        register is resolved first: one it refuses (422) costs no mapping."""
        library = self._library.get_control_library()
        retired = self._library.get_retired_controls()
        register_part = register_half(register, library, datetime.now(UTC).date(), stored, retired)
        by_id = {row.control_id: row for row in library}
        controls = scenario.get("controls") or {}
        items = controls.get("items") if controls.get("status") == Status.DONE else None
        if not items:
            items = self._top_up.map_now(scenario["_id"])
        elif not any(item["control_id"] in by_id for item in items):  # every one retired since: mapped again
            items = self._top_up.map_now(scenario["_id"], remap=True)
        context = FrozenContext.from_record(self._sessions.find_context(scenario["session_id"]))
        mapped = scenario | {"controls": {"items": items}}
        return build_snapshot(mapped, context, register_part, by_id)


@singleton
def get_snapshot_maker() -> SnapshotMaker:
    return SnapshotMaker(SessionRepository(get_mongodb()), get_library_service(), get_controls_top_up())
