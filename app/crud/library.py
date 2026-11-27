"""SQL Server library reads (threats, controls) and the SQL write-safety log, through stored procedures."""

import contextlib
import json
import uuid
from collections import defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo.collection import Collection as MongoCollection

from app.core import constants as c
from app.core.asset_types import canonical_asset_type
from app.core.clock import utc_now
from app.core.constants import DecisionOutcome, LibraryRowKind, ResolveOutcome, StoredProcedure, StrideCategory
from app.core.database import Row, StoredProcedureClient, get_stored_procedure_client, procedure_answer_shape
from app.core.exceptions import OperationInProgress, OutcomeUnknown, SetupError
from app.core.singletons import singleton
from app.crud.base import MongoRepository
from app.schemas import library as m
from app.schemas.library import LibraryControl


def _attempt_allowed(now: datetime) -> dict[str, Any]:
    stale = now - timedelta(seconds=c.SqlOperations.PENDING_SECONDS)
    retryable = [c.SqlOperationStatus.NOT_APPLIED, c.SqlOperationStatus.REQUIRES_RECONCILIATION]
    return {
        "$or": [{"status": {"$in": retryable}}, {"status": c.SqlOperationStatus.PENDING, "started_at": {"$lt": stale}}]
    }


class SqlOperationRepository(MongoRepository):
    """tsg_sql_operations: one record per write procedure call, kept KEEP_DAYS once finished."""

    def __init__(
        self, procedures: StoredProcedureClient, collection: str | MongoCollection = c.Collection.SQL_OPERATIONS
    ) -> None:
        super().__init__(
            collection,
            ttl=[("finished_at", c.SqlOperations.KEEP_DAYS * 86_400)],
            conditions={"attempt_allowed": _attempt_allowed},
            schema_version=1,
        )
        self._procedures = procedures

    def run_sql_operation(
        self, operation_id: str, procedure: c.StoredProcedure, parameters: dict[str, Any]
    ) -> tuple[list[list[Row]], bool]:
        """(result sets, True when this call ran it): done replays, a lost answer reconciles."""
        record = self.get(_id=operation_id)
        if record is not None and record["status"] == c.SqlOperationStatus.DONE:
            return record["result"], False
        reconciling = False
        if record is not None and record["status"] != c.SqlOperationStatus.NOT_APPLIED:
            reconciling, parameters = True, record["parameters"]  # replayed exactly as first sent
        attempt = self._start_attempt(operation_id, procedure, parameters, reconciling)
        try:
            result_sets = self._procedures.execute_procedure(procedure, **parameters)
        except OutcomeUnknown as exc:
            self._finish(operation_id, attempt, {"status": c.SqlOperationStatus.REQUIRES_RECONCILIATION})
            message = c.ErrorMessage.SQL_OPERATION_UNCONFIRMED.format(operation_id=operation_id)
            raise OutcomeUnknown(message, details={"operation_id": operation_id}) from exc
        except Exception:
            changes = {"status": c.SqlOperationStatus.NOT_APPLIED, "finished_at": utc_now()}
            self._finish(operation_id, attempt, changes)
            raise
        finished = {"status": c.SqlOperationStatus.DONE, "result": result_sets, "finished_at": utc_now()}
        self._finish(operation_id, attempt, finished | ({"reconciled": True} if reconciling else {}))
        return result_sets, True

    def _start_attempt(
        self, operation_id: str, procedure: c.StoredProcedure, parameters: dict[str, Any], reconciling: bool
    ) -> str:
        now, attempt = utc_now(), uuid.uuid4().hex
        started = {
            "_id": operation_id,
            "procedure": procedure,
            "parameters": parameters,
            "status": c.SqlOperationStatus.PENDING,
            "started_at": now,
            "attempt": attempt,
            "reconciling": reconciling,
        }
        if not self.save(started, only_if={"attempt_allowed": now}):
            message = c.ErrorMessage.SQL_OPERATION_IN_PROGRESS.format(operation_id=operation_id)
            details = {"operation_id": operation_id}
            raise OperationInProgress(message, reason=c.ConflictReason.OPERATION_IN_PROGRESS, details=details)
        return attempt

    def _finish(self, operation_id: str, attempt: str, changes: dict[str, Any]) -> None:
        self.update(changes, _id=operation_id, attempt=attempt)

    @contextlib.contextmanager
    def reading_answer(self, operation_id: str, procedure: c.StoredProcedure) -> Iterator[None]:
        """procedure_answer_shape for a write's answer. One the code cannot read is asked of SQL Server again on
        the next try (reconciled, as a lost answer is), never replayed from its record: once the DBA installs the
        procedure, the retry reads its answer and writes the audit (owner 2026-11-27)."""
        try:
            with procedure_answer_shape(procedure):
                yield
        except SetupError:
            self.update({"status": c.SqlOperationStatus.REQUIRES_RECONCILIATION}, _id=operation_id)
            raise


class ControlRepository:
    """The control library's procedure."""

    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def get_control_library(self) -> tuple[LibraryControl, ...]:
        """The active controls from tsg_GetControlLibrary, in id order (a retired control is never mapped)."""
        answer = self._procedures.execute_procedure(StoredProcedure.GET_CONTROL_LIBRARY)
        with procedure_answer_shape(StoredProcedure.GET_CONTROL_LIBRARY):
            return tuple(
                LibraryControl(
                    control_id=row["ControlLibraryID"],
                    code=row["ControlCode"],
                    asset_type=canonical_asset_type(row.get("AssetType")),
                    domain=row["Domain"],
                    name=row["ControlName"],
                    description=row.get("ControlDescription"),
                )
                for row in sorted(answer[0], key=lambda control: control["ControlLibraryID"])
            )


def _stride(names: set[str]) -> tuple[StrideCategory, ...]:
    return tuple(category for category in StrideCategory if category in names)  # STRIDE order


def _linked_actors(
    actors: list[Row], links: list[Row]
) -> tuple[dict[int, m.LibraryActor], dict[int, tuple[m.LibraryActor, ...]]]:
    actor_by_id = {row["ThreatActorID"]: m.LibraryActor(row["ThreatActorID"], row["ThreatActorName"]) for row in actors}
    by_type: defaultdict[int, list[m.LibraryActor]] = defaultdict(list)
    for link in links:
        if link["ThreatActorID"] in actor_by_id:
            by_type[link["ThreatTypeID"]].append(actor_by_id[link["ThreatActorID"]])
    return actor_by_id, {key: tuple(sorted(found, key=lambda actor: actor.name)) for key, found in by_type.items()}


def _threat_types(
    rows: list[Row], category_name: dict[int, str], linked: dict[int, tuple[m.LibraryActor, ...]]
) -> tuple[m.LibraryThreatType, ...]:
    return tuple(
        m.LibraryThreatType(
            type_id=row["ThreatTypeID"],
            name=row["ThreatTypeName"],
            category=next(iter(_stride({category_name.get(row["ThreatCategoryID"], "")})), None),
            linked_actors=linked.get(row["ThreatTypeID"], ()),
        )
        for row in sorted(rows, key=lambda row: row["ThreatTypeID"])
    )


def _threat_library(result_sets: list[list[Row]]) -> m.ThreatLibrary:
    categories, types, threats, actors, type_actor_links, threat_category_links, pending, rejected = result_sets
    category_name = {row["ThreatCategoryID"]: row["ThreatCategoryName"] for row in categories}
    actor_by_id, linked = _linked_actors(actors, type_actor_links)
    categories_by_threat: defaultdict[int, set[str]] = defaultdict(set)
    for link in threat_category_links:
        if link["ThreatCategoryID"] in category_name:
            categories_by_threat[link["ThreatCatalogueID"]].add(category_name[link["ThreatCategoryID"]])
    type_name = {row["ThreatTypeID"]: row["ThreatTypeName"] for row in types}
    ordered = sorted(threats, key=lambda row: row["ThreatCatalogueID"])
    return m.ThreatLibrary(
        threats=tuple(
            m.LibraryThreat(
                catalogue_id=row["ThreatCatalogueID"],
                name=row["ThreatName"],
                type_id=row["ThreatTypeID"],
                type_name=type_name[row["ThreatTypeID"]],
                categories=_stride(categories_by_threat[row["ThreatCatalogueID"]]),
                linked_actors=linked.get(row["ThreatTypeID"], ()),
                asset_type=canonical_asset_type(row.get("AssetType")),  # None fits everywhere
            )
            for row in ordered
            if categories_by_threat[row["ThreatCatalogueID"]]
        ),
        actors=tuple(sorted(actor_by_id.values(), key=lambda actor: actor.actor_id)),
        types=_threat_types(types, category_name, linked),
        category_ids=tuple(sorted(category_name.items())),
        pending=tuple(
            m.PendingLibraryRow(LibraryRowKind(row["kind"]), row["id"], row["name"], row["type_id"]) for row in pending
        ),
        curator_rejected=tuple(
            m.RejectedLibraryThreat(row["ThreatCatalogueID"], row["ThreatName"], row["ThreatTypeID"])
            for row in rejected
        ),
        threats_without_category=tuple(
            row["ThreatCatalogueID"] for row in ordered if not categories_by_threat[row["ThreatCatalogueID"]]
        ),
    )


class ThreatRepository:
    """The threat library's procedures, and the operation record each write procedure runs through."""

    def __init__(self, procedures: StoredProcedureClient, operations: SqlOperationRepository) -> None:
        self._procedures, self._operations = procedures, operations

    def get_library_stamp(self) -> m.LibraryStamp:
        """The fingerprint of every library table (tsg_GetLibraryStamp), in a fixed order."""
        answer = self._procedures.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)
        with procedure_answer_shape(StoredProcedure.GET_LIBRARY_STAMP):  # UNION ALL: no order
            return tuple(sorted((row["table_name"], row["fingerprint"]) for row in answer[0]))

    def get_threat_library(self) -> m.ThreatLibrary:
        """The live threat library (tsg_GetThreatLibrary)."""
        answer = self._procedures.execute_procedure(StoredProcedure.GET_THREAT_LIBRARY)
        with procedure_answer_shape(StoredProcedure.GET_THREAT_LIBRARY):  # its 8 result sets, as the code reads them
            return _threat_library(answer)

    def propose_threat(self, operation_id: str, proposal: m.ThreatProposal) -> tuple[m.ProposedThreat, bool]:
        """(the library's answer, True when this call applied it) for one proposed threat."""
        parameters = {
            "CategoryName": proposal.category,
            "TypeName": proposal.type_name,
            "ThreatName": proposal.threat_name,
            "Source": proposal.source,
            "CreatedBy": proposal.created_by,
            "ActorIDs": json.dumps(list(proposal.actor_ids)),
            "AssetType": proposal.asset_type,
        }
        result_sets, applied_now = self._operations.run_sql_operation(
            operation_id, StoredProcedure.RESOLVE_THREAT, parameters
        )
        with self._operations.reading_answer(operation_id, StoredProcedure.RESOLVE_THREAT):  # one row, known outcome
            (row,) = result_sets[0]
            proposed = m.ProposedThreat(
                row["threat_type_id"], row["threat_catalogue_id"], ResolveOutcome(row["outcome"])
            )
        return proposed, applied_now

    def list_pending_threats(self, offset: int, limit: int) -> tuple[list[Row], int]:
        """One page of pending threats, oldest first, and how many wait in all (tsg_ListPendingThreats)."""
        answer = self._procedures.execute_procedure(StoredProcedure.LIST_PENDING_THREATS, Offset=offset, Limit=limit)
        with procedure_answer_shape(StoredProcedure.LIST_PENDING_THREATS):
            page, total = answer
            # DATETIME2 holds UTC without saying so: said here, as every API time says it.
            shown = [
                {
                    "catalogue_id": row["catalogue_id"],
                    "threat": row["threat"],
                    "type": row["threat_type"],
                    "type_pending": bool(row["type_pending"]),
                    # .get: the list keeps working until the DBA applies the procedure that returns it
                    "asset_type": canonical_asset_type(row.get("asset_type")),
                    "categories": [category["name"] for category in json.loads(row["categories"] or "[]")],
                    "source": row["source"],
                    "created_by": row["created_by"],
                    "created_at": row["created_at"].replace(tzinfo=UTC) if row["created_at"] else None,
                }
                for row in page
            ]
            return shown, total[0]["total"]

    def decide_pending_threats(
        self, operation_id: str, approve: list[int], reject: list[int], decided_by: str
    ) -> tuple[list[Row], bool]:
        """(`{catalogue_id, outcome}` per id, True when this call applied them), in one transaction."""
        parameters = {"ApproveIDs": json.dumps(approve), "RejectIDs": json.dumps(reject), "DecidedBy": decided_by}
        result_sets, applied_now = self._operations.run_sql_operation(
            operation_id, StoredProcedure.DECIDE_PENDING_THREATS, parameters
        )
        with self._operations.reading_answer(operation_id, StoredProcedure.DECIDE_PENDING_THREATS):
            decided = [
                {"catalogue_id": row["catalogue_id"], "outcome": DecisionOutcome(row["outcome"])}
                for row in result_sets[0]
            ]
        return decided, applied_now


@singleton
def get_sql_operation_repository() -> SqlOperationRepository:
    return SqlOperationRepository(get_stored_procedure_client())


@singleton
def get_threat_repository() -> ThreatRepository:
    return ThreatRepository(get_stored_procedure_client(), get_sql_operation_repository())


@singleton
def get_control_repository() -> ControlRepository:
    return ControlRepository(get_stored_procedure_client())
