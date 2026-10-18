"""A plan version's frozen input, made the same way for a first request and a regenerate, with no AI call: the
register resolved against the current library (a refusal is a 422, at once) and stored as a pending snapshot
its plan job completes (app/worker/plan_inputs.py). An empty control library is refused at once: no control
could ever be kept."""

from datetime import UTC, datetime
from typing import Any

from app.core.singletons import singleton
from app.domain.remediation.register import register_half
from app.domain.remediation.snapshot import check_control_library, pending_snapshot
from app.models.remediation_requests import RegisterData
from app.search.library_cache import LibraryService, get_library_service


class SnapshotMaker:
    def __init__(self, library: LibraryService) -> None:
        self._library = library

    def make(self, register: RegisterData, scenario: dict[str, Any], stored: bool = False) -> dict[str, Any]:
        """The version's pending snapshot; `stored`: the register a regenerate rebuilds from (a library change
        since is a warning). The register is resolved first: one it refuses (422) saves nothing."""
        loaded = self._library.get_loaded_libraries()  # one library copy for every check below
        controls, today = loaded.control_library, datetime.now(UTC).date()
        check_control_library(controls)
        register_part = register_half(register, controls, today, stored, loaded.retired_controls)
        return pending_snapshot(scenario["_id"], register_part)


@singleton
def get_snapshot_maker() -> SnapshotMaker:
    return SnapshotMaker(get_library_service())
