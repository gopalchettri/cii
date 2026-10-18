"""SQL Server, through stored procedures only: the threat and control libraries, an asset's context, proposed
threats and the curator's queue. Each write procedure runs through an operation record (tsg_sql_operations),
so a call whose answer was lost is replayed with the same parameters, never guessed."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.constants import (
    Collection,
    ConflictReason,
    ErrorMessage,
    ResolveOutcome,
    SqlOperations,
    SqlOperationStatus,
    StoredProcedure,
)
from app.core.database import Row, StoredProcedureClient
from app.core.exceptions import Conflict, OutcomeUnknown
from app.data_access.base import MongoRepository
from app.data_access.library.rows import (
    control_library_from_rows,
    pending_threat_from_row,
    threat_library_from_rows,
)
from app.models.asset_context import AssetContextRows
from app.models.library import (
    LibraryStamp,
    LoadedLibraries,
    ProposedThreat,
    ThreatProposal,
)
from app.models.scenario.views import StartRunRequest


def _attempt_allowed(now: datetime) -> dict[str, Any]:
    """An operation record a new attempt may take over: rolled back, answer lost, or pending past its time."""
    stale = now - timedelta(seconds=SqlOperations.PENDING_SECONDS)
    retryable = [SqlOperationStatus.NOT_APPLIED, SqlOperationStatus.REQUIRES_RECONCILIATION]
    return {
        "$or": [
            {"status": {"$in": retryable}},
            {"status": SqlOperationStatus.PENDING, "started_at": {"$lt": stale}},
        ]
    }


#: tsg_sql_operations: one record per SQL Server write (_id "promote:{scenario_id}", "propose:{scenario_id}",
#: "decide:{payload_hash}"); a finished record expires SqlOperations.KEEP_DAYS after it finished.
sql_operations = MongoRepository(
    Collection.SQL_OPERATIONS,
    ttl=[("finished_at", SqlOperations.KEEP_DAYS * 86_400)],
    conditions={"attempt_allowed": _attempt_allowed},
    schema_version=1,
)


class SqlServerRepository:
    """Every stored procedure TSG calls, and the operation record each write procedure runs through."""

    def __init__(
        self, procedures: StoredProcedureClient, operations: MongoRepository = sql_operations
    ) -> None:
        self._procedures, self._operations = procedures, operations

    def load_library(self, loaded_stamp: LibraryStamp | None = None) -> LoadedLibraries | None:
        """The library stamp, then (when it differs from `loaded_stamp`) the control and threat libraries at
        it; None when unchanged. The stamp is read BEFORE loading, so an edit made during a load is caught by
        the next check, never missed (tsg_GetLibraryStamp, tsg_GetControlLibrary, tsg_GetThreatLibrary)."""
        rows = self._procedures.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)[0]
        stamp = tuple(sorted((row["table_name"], row["fingerprint"]) for row in rows))  # UNION ALL: no order
        if stamp == loaded_stamp:
            return None
        active, retired = control_library_from_rows(
            self._procedures.execute_procedure(StoredProcedure.GET_CONTROL_LIBRARY)
        )
        threats = threat_library_from_rows(
            self._procedures.execute_procedure(StoredProcedure.GET_THREAT_LIBRARY)
        )
        return LoadedLibraries(stamp, threats, active, retired)

    def get_asset_context(self, entity_id: int, request: StartRunRequest) -> AssetContextRows:
        """One tsg_GetAssetContext call: proves the entity owns the asset and reads every fact a run uses (the
        sub-sector when sent, else the sector, with its parent)."""
        asset, services, sector, systems, options = self._procedures.execute_procedure(
            StoredProcedure.GET_ASSET_CONTEXT,
            EntityID=entity_id,
            AssetID=request.asset_id,
            SystemIDs=json.dumps(request.supporting_system_ids),
            ServiceID=request.service_id,
            SectorID=request.sector_id,
            SubsectorID=request.subsector_id,
        )
        return AssetContextRows(
            asset=asset[0] if asset else None,
            services=services,
            sector=sector[0] if sector else None,
            systems=systems,
            options=options,
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
        result_sets, applied_now = self.run_sql_operation(
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
        result_sets, applied_now = self.run_sql_operation(
            operation_id, StoredProcedure.DECIDE_PENDING_THREATS, parameters
        )
        return result_sets[0], applied_now

    def run_sql_operation(
        self, operation_id: str, procedure: StoredProcedure, parameters: dict[str, Any]
    ) -> tuple[list[list[Row]], bool]:
        """(the procedure's result sets, True when this call ran it) through its tsg_sql_operations record,
        written before the call. Done: its stored result, no SQL call. A lost answer: the next attempt replays
        the stored parameters (every write procedure dedupes on the SQL side) and marks it reconciled. A young
        pending record: 409 operation_in_progress. A rollback SQL Server confirmed: not_applied, re-raised."""
        record = self._operations.get(_id=operation_id)
        if record is not None and record["status"] == SqlOperationStatus.DONE:
            return record["result"], False
        reconciling = record is not None and record["status"] != SqlOperationStatus.NOT_APPLIED
        if reconciling:
            parameters = record["parameters"]  # replayed exactly as first sent
        attempt = self._start_attempt(operation_id, procedure, parameters, reconciling)
        try:
            result_sets = self._procedures.execute_procedure(procedure, **parameters)
        except OutcomeUnknown as exc:
            self._finish(operation_id, attempt, {"status": SqlOperationStatus.REQUIRES_RECONCILIATION})
            message = ErrorMessage.SQL_OPERATION_UNCONFIRMED.format(operation_id=operation_id)
            raise OutcomeUnknown(message, details={"operation_id": operation_id}) from exc
        except Exception:
            changes = {"status": SqlOperationStatus.NOT_APPLIED, "finished_at": datetime.now(UTC)}
            self._finish(operation_id, attempt, changes)
            raise
        finished = {
            "status": SqlOperationStatus.DONE,
            "result": result_sets,
            "finished_at": datetime.now(UTC),
        }
        self._finish(operation_id, attempt, finished | ({"reconciled": True} if reconciling else {}))
        return result_sets, True

    def _start_attempt(
        self, operation_id: str, procedure: StoredProcedure, parameters: dict[str, Any], reconciling: bool
    ) -> str:
        """This attempt's tsg_sql_operations record, written pending before the call; its attempt id. 409
        operation_in_progress while another attempt is young (or the record became done meanwhile)."""
        now, attempt = datetime.now(UTC), uuid.uuid4().hex
        started = {
            "_id": operation_id,
            "procedure": procedure,
            "parameters": parameters,
            "status": SqlOperationStatus.PENDING,
            "started_at": now,
            "attempt": attempt,
            "reconciling": reconciling,
        }
        if not self._operations.save(started, only_if={"attempt_allowed": now}):
            message = ErrorMessage.SQL_OPERATION_IN_PROGRESS.format(operation_id=operation_id)
            details = {"operation_id": operation_id}
            raise Conflict(message, reason=ConflictReason.OPERATION_IN_PROGRESS, details=details)
        return attempt

    def _finish(self, operation_id: str, attempt: str, changes: dict[str, Any]) -> None:
        """This attempt's outcome on its tsg_sql_operations record, fenced on the attempt: a later attempt's
        record is never overwritten."""
        self._operations.update(changes, _id=operation_id, attempt=attempt)
