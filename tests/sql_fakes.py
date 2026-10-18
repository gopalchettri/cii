"""Stand-ins for the SQL Server client: procedures answering given result sets, and a call whose answer is
lost after SQL Server applied it."""

from typing import Any

from app.core.constants import ErrorMessage, StoredProcedure
from app.core.database import Row, StoredProcedureClient
from app.core.exceptions import OutcomeUnknown
from app.data_access.library.repository import SqlServerRepository
from app.models.library import LoadedLibraries

_NO_THREAT_LIBRARY: list[list[Row]] = [[] for _ in range(8)]


class ProceduresByName:
    """Each procedure answers the result sets given for it: an empty library and stamp by default."""

    def __init__(
        self,
        threat_sets: list[list[Row]] | None = None,
        control_sets: list[list[Row]] | None = None,
        stamp_rows: list[Row] | None = None,
    ) -> None:
        self._sets = {
            StoredProcedure.GET_LIBRARY_STAMP: [stamp_rows or []],
            StoredProcedure.GET_THREAT_LIBRARY: threat_sets or _NO_THREAT_LIBRARY,
            StoredProcedure.GET_CONTROL_LIBRARY: control_sets or [[], []],
        }

    def execute_procedure(self, procedure: StoredProcedure, **_params: Any) -> list[list[Row]]:
        return self._sets[procedure]


def load_library_from(
    threat_sets: list[list[Row]] | None = None,
    control_sets: list[list[Row]] | None = None,
    stamp_rows: list[Row] | None = None,
) -> LoadedLibraries:
    """Both libraries as SqlServerRepository.load_library reads them from these result sets."""
    loaded = SqlServerRepository(ProceduresByName(threat_sets, control_sets, stamp_rows)).load_library()  # type: ignore[arg-type]
    assert loaded is not None
    return loaded


class AnswerLostClient:
    """The real client, but the first `lost` calls lose their answer AFTER SQL Server ran (and committed) the
    procedure, as a timeout or a broken link after the send does."""

    def __init__(self, procedures: StoredProcedureClient, lost: int = 1) -> None:
        self._procedures, self._lost = procedures, lost
        self.calls: list[tuple[StoredProcedure, dict[str, Any]]] = []

    def execute_procedure(self, procedure: StoredProcedure, **params: Any) -> list[list[Row]]:
        self.calls.append((procedure, params))
        result_sets = self._procedures.execute_procedure(procedure, **params)
        if self._lost:
            self._lost -= 1
            raise OutcomeUnknown(ErrorMessage.SQL_ANSWER_LOST)
        return result_sets
