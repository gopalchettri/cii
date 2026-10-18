"""The control library in SQL Server, through its stored procedure only."""

from app.core.constants import StoredProcedure
from app.core.database import StoredProcedureClient
from app.data_access.library.rows import control_library_from_rows
from app.models.library.library import LibraryControl


class ControlRepository:
    """The control library's procedure."""

    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def get_control_library(self) -> tuple[tuple[LibraryControl, ...], tuple[LibraryControl, ...]]:
        """(active controls, retired controls) from tsg_GetControlLibrary."""
        return control_library_from_rows(
            self._procedures.execute_procedure(StoredProcedure.GET_CONTROL_LIBRARY)
        )
