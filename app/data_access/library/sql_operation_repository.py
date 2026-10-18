"""tsg_sql_operations: one record per SQL Server write, written before the call, so a call whose answer was
lost is replayed with the same parameters, never guessed."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core.constants import (
    Collection,
    ConflictReason,
    ErrorMessage,
    SqlOperations,
    SqlOperationStatus,
    StoredProcedure,
)
from app.core.database import Row, StoredProcedureClient
from app.core.exceptions import OperationInProgress, OutcomeUnknown
from app.data_access.base import MongoRepository


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


class SqlOperationRepository(MongoRepository):
    """tsg_sql_operations (_id "promote:{scenario_id}", "propose:{scenario_id}", "decide:{payload_hash}"); a
    finished record expires SqlOperations.KEEP_DAYS after it finished."""

    def __init__(
        self, procedures: StoredProcedureClient, collection: str | MongoCollection = Collection.SQL_OPERATIONS
    ) -> None:
        """The operation records and the SQL Server client each write procedure runs on."""
        super().__init__(
            collection,
            ttl=[("finished_at", SqlOperations.KEEP_DAYS * 86_400)],
            conditions={"attempt_allowed": _attempt_allowed},
            schema_version=1,
        )
        self._procedures = procedures

    def run_sql_operation(
        self, operation_id: str, procedure: StoredProcedure, parameters: dict[str, Any]
    ) -> tuple[list[list[Row]], bool]:
        """(the procedure's result sets, True when this call ran it) through its tsg_sql_operations record,
        written before the call. Done: its stored result, no SQL call. A lost answer: the next attempt replays
        the stored parameters (every write procedure dedupes on the SQL side) and marks it reconciled. A young
        pending record: 409 operation_in_progress. A rollback SQL Server confirmed: not_applied, re-raised."""
        record = self.get(_id=operation_id)
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
        if not self.save(started, only_if={"attempt_allowed": now}):
            message = ErrorMessage.SQL_OPERATION_IN_PROGRESS.format(operation_id=operation_id)
            details = {"operation_id": operation_id}
            raise OperationInProgress(message, reason=ConflictReason.OPERATION_IN_PROGRESS, details=details)
        return attempt

    def _finish(self, operation_id: str, attempt: str, changes: dict[str, Any]) -> None:
        """This attempt's outcome on its tsg_sql_operations record, fenced on the attempt: a later attempt's
        record is never overwritten."""
        self.update(changes, _id=operation_id, attempt=attempt)
