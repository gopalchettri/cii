"""The threat library in SQL Server, through stored procedures only: its stamp, the live library, proposed
threats and the curator's queue. Each write procedure runs through its tsg_sql_operations record."""

import json

from app.core.constants import ResolveOutcome, StoredProcedure
from app.core.database import Row, StoredProcedureClient
from app.data_access.library.rows import pending_threat_from_row, threat_library_from_rows
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.models.library.library import LibraryStamp, ProposedThreat, ThreatLibrary, ThreatProposal


class ThreatRepository:
    """The threat library's procedures, and the operation record each write procedure runs through."""

    def __init__(self, procedures: StoredProcedureClient, operations: SqlOperationRepository) -> None:
        self._procedures, self._operations = procedures, operations

    def get_library_stamp(self) -> LibraryStamp:
        """The fingerprint of every library table (tsg_GetLibraryStamp), in a fixed order."""
        rows = self._procedures.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)[0]
        return tuple(sorted((row["table_name"], row["fingerprint"]) for row in rows))  # UNION ALL: no order

    def get_threat_library(self) -> ThreatLibrary:
        """The live threat library (tsg_GetThreatLibrary)."""
        return threat_library_from_rows(
            self._procedures.execute_procedure(StoredProcedure.GET_THREAT_LIBRARY)
        )

    def propose_threat(self, operation_id: str, proposal: ThreatProposal) -> tuple[ProposedThreat, bool]:
        """(the library's answer, True when this call applied it) for one proposed threat (tsg_ResolveThreat):
        inserted pending unless its name is live, pending or curator-rejected already; the procedure re-checks
        under lock, so two callers proposing one name write it once."""
        parameters = {
            "CategoryName": proposal.category,
            "TypeName": proposal.type_name,
            "ThreatName": proposal.threat_name,
            "Source": proposal.source,
            "CreatedBy": proposal.created_by,
            "ActorIDs": json.dumps(list(proposal.actor_ids)),
        }
        result_sets, applied_now = self._operations.run_sql_operation(
            operation_id, StoredProcedure.RESOLVE_THREAT, parameters
        )
        (row,) = result_sets[0]
        return ProposedThreat(
            row["threat_type_id"], row["threat_catalogue_id"], ResolveOutcome(row["outcome"])
        ), applied_now

    def list_pending_threats(self, offset: int, limit: int) -> tuple[list[Row], int]:
        """One page of pending threats, oldest first, and how many wait in all (tsg_ListPendingThreats)."""
        page, total = self._procedures.execute_procedure(
            StoredProcedure.LIST_PENDING_THREATS, Offset=offset, Limit=limit
        )
        return [pending_threat_from_row(row) for row in page], total[0]["total"]

    def decide_pending_threats(
        self, operation_id: str, approve: list[int], reject: list[int], decided_by: str
    ) -> tuple[list[Row], bool]:
        """(`{catalogue_id, outcome}` per id, True when this call applied them), decided in one transaction
        (tsg_DecidePendingThreats; a pending type goes live with its first approved threat)."""
        parameters = {
            "ApproveIDs": json.dumps(approve),
            "RejectIDs": json.dumps(reject),
            "DecidedBy": decided_by,
        }
        result_sets, applied_now = self._operations.run_sql_operation(
            operation_id, StoredProcedure.DECIDE_PENDING_THREATS, parameters
        )
        return result_sets[0], applied_now
