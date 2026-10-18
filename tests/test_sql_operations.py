"""Lost SQL answers: a call whose answer was lost after SQL Server applied it is replayed once with its stored
parameters, so promote, the plan job's proposal and a curator's decisions each make one SQL effect and one
audit row; and the client tells "never sent" from "sent, answer lost"."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pyodbc
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app.core.constants import (
    AuditAction,
    Collection,
    ConflictReason,
    LibrarySource,
    LibraryStatus,
    PromotionOutcome,
    ResolveOutcome,
    SqlOperationStatus,
    StoredProcedure,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.exceptions import Conflict, OutcomeUnknown, Unavailable
from app.data_access.library.repository import SqlServerRepository
from app.models.library import ThreatLibrary, ThreatProposal
from app.models.library_curation import LibraryDecisions
from app.services.library_curation import LibraryCuration, LibraryPromotion
from tests.plan_job_fakes import fake_plan_inputs
from tests.sql_fakes import AnswerLostClient

#: Deletes every row these tests made: the SQL test database is shared by the whole run, and later tests count
#: the seed library's rows exactly.
_REMOVE_TEST_ROWS = """
DELETE m FROM dbo.Threat_Catalogue_Category_Map AS m
JOIN dbo.Threat_Catalogue AS c ON c.ThreatCatalogueID = m.ThreatCatalogueID
WHERE c.ThreatName LIKE N'Lost answer %';
DELETE a FROM dbo.ThreatType_ThreatActor_Map AS a
JOIN dbo.Threat_Type AS t ON t.ThreatTypeID = a.ThreatTypeID WHERE t.ThreatTypeName LIKE N'Lost answer %';
DELETE FROM dbo.Threat_Catalogue WHERE ThreatName LIKE N'Lost answer %';
DELETE FROM dbo.Threat_Type WHERE ThreatTypeName LIKE N'Lost answer %';
"""


@pytest.fixture(autouse=True)
def no_test_rows_left(sql_test_engine: Engine) -> Iterator[None]:
    yield
    with sql_test_engine.begin() as connection:
        connection.exec_driver_sql(_REMOVE_TEST_ROWS)


def _raise(error: Exception) -> Any:
    raise error


def _client_failing(
    at_connect: Exception | None = None, at_execute: Exception | None = None
) -> StoredProcedureClient:
    """A client whose engine fails at connect, or whose cursor fails at execute."""

    def connection() -> object:
        if at_connect is not None:
            raise at_connect
        cursor = SimpleNamespace(execute=lambda *_args: _raise(at_execute))  # type: ignore[arg-type]
        return SimpleNamespace(cursor=lambda: cursor, close=lambda: None)

    return StoredProcedureClient(SimpleNamespace(raw_connection=connection))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("client", "outcome_unknown"),
    [
        (_client_failing(at_connect=pyodbc.OperationalError("08001", "no server")), False),
        (_client_failing(at_connect=PoolTimeoutError("every pooled connection busy")), False),
        (_client_failing(at_execute=pyodbc.Error("40001", "deadlock victim")), False),
        (_client_failing(at_execute=pyodbc.OperationalError("HYT00", "query timeout")), True),
        (_client_failing(at_execute=pyodbc.OperationalError("08S01", "link failure")), True),
    ],
)
def test_never_sent_and_deadlock_are_unavailable_and_a_lost_answer_is_outcome_unknown(
    client: StoredProcedureClient, outcome_unknown: bool
) -> None:
    with pytest.raises(Unavailable) as raised:
        client.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)
    assert isinstance(raised.value, OutcomeUnknown) is outcome_unknown


def _name(kind: str) -> str:
    return f"Lost answer {kind} {uuid.uuid4().hex[:8]}"


def _rows_named(engine: Engine, threat_name: str) -> int:
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT COUNT(*) FROM dbo.Threat_Catalogue WHERE ThreatName = ?", (threat_name,)
        ).scalar()


def _audit_rows(action: AuditAction, **where: Any) -> int:
    return get_mongodb()[Collection.AUDIT].count_documents({"action": action, **where})


def _proposal(threat_name: str) -> ThreatProposal:
    return ThreatProposal("Tampering", _name("type"), threat_name, LibrarySource.AI, "user-1", ())


def test_the_plan_jobs_lost_proposal_is_replayed_once_and_audited_once(
    client: TestClient, sql_test_engine: Engine
) -> None:
    lost = AnswerLostClient(StoredProcedureClient(sql_test_engine))
    inputs, _ = fake_plan_inputs(SimpleNamespace())
    inputs._proposals = SqlServerRepository(lost)  # noqa: SLF001 — the real repository on the lost-answer client
    scenario_id, threat_name = uuid.uuid4().hex, _name("threat")
    content = {
        "category": "Tampering",
        "threat": {"type": _name("type"), "name": threat_name, "type_id": None},
    }
    by = {"user_id": "user-1", "client_id": "client-1"}
    with pytest.raises(OutcomeUnknown) as raised:
        inputs._propose(scenario_id, content, (), by)  # noqa: SLF001
    assert raised.value.details == {"operation_id": f"propose:{scenario_id}"}
    replayed = inputs._propose(scenario_id, content, (), by)  # noqa: SLF001 — the job retried
    again = inputs._propose(scenario_id, content, (), by)  # noqa: SLF001 — and retried once more
    assert replayed == again and replayed["content.threat.library_status"] == LibraryStatus.PENDING
    assert len(lost.calls) == 2  # the lost call and its replay; the last answer came from the record
    assert _rows_named(sql_test_engine, threat_name) == 1
    assert _audit_rows(AuditAction.LIBRARY_PROPOSED, **{"after.threat": threat_name}) == 1
    record = get_mongodb()[Collection.SQL_OPERATIONS].find_one({"_id": f"propose:{scenario_id}"})
    assert (record["status"], record["reconciled"]) == (SqlOperationStatus.DONE, True)


def test_a_lost_promotion_is_replayed_with_its_first_parameters(
    sql_test_engine: Engine, client: TestClient
) -> None:
    lost = AnswerLostClient(StoredProcedureClient(sql_test_engine))
    promotion = LibraryPromotion(SimpleNamespace(), SqlServerRepository(lost), lambda: ThreatLibrary((), ()))  # type: ignore[arg-type]
    scenario_id, threat_name = uuid.uuid4().hex, _name("threat")
    threat = {"name": threat_name, "type": {"name": _name("type")}, "category": "Tampering"}
    principal = SimpleNamespace(user_id="user-1")
    with pytest.raises(OutcomeUnknown):
        promotion._propose(scenario_id, threat, (), principal)  # type: ignore[arg-type]  # noqa: SLF001
    other_wording = threat | {"type": {"name": _name("another type")}}
    promoted = promotion._propose(scenario_id, other_wording, (), principal)  # type: ignore[arg-type]  # noqa: SLF001
    assert promoted.outcome == PromotionOutcome.EXISTING and promoted.threat_catalogue_id is not None
    assert lost.calls[0] == lost.calls[1]  # the replay sent the stored parameters, not the new ones
    assert _rows_named(sql_test_engine, threat_name) == 1


def test_lost_decisions_are_replayed_once_and_audited_once(
    sql_test_engine: Engine, client: TestClient
) -> None:
    sql = SqlServerRepository(StoredProcedureClient(sql_test_engine))
    proposed, _ = sql.propose_threat(f"promote:{uuid.uuid4().hex}", _proposal(_name("threat")))
    lost = AnswerLostClient(StoredProcedureClient(sql_test_engine))
    curation = LibraryCuration(SqlServerRepository(lost))
    decisions = LibraryDecisions(approve=[proposed.catalogue_id])
    with pytest.raises(OutcomeUnknown):
        curation.decide(decisions, "curator-1")
    (replayed,) = curation.decide(decisions, "curator-1")["results"]
    assert curation.decide(decisions, "curator-1")["results"] == [replayed]
    assert replayed == {"catalogue_id": proposed.catalogue_id, "outcome": "already_approved"}
    assert len(lost.calls) == 2
    assert _audit_rows(AuditAction.LIBRARY_DECIDED, **{"target.id": str(proposed.catalogue_id)}) == 1


def test_a_curator_rejected_name_is_answered_curator_rejected_and_never_written_again(
    sql_test_engine: Engine, client: TestClient
) -> None:
    sql = SqlServerRepository(StoredProcedureClient(sql_test_engine))
    threat_name = _name("threat")
    first, _ = sql.propose_threat(f"promote:{uuid.uuid4().hex}", _proposal(threat_name))
    assert first.outcome == ResolveOutcome.CREATED_PENDING
    sql.decide_pending_threats(f"decide:{uuid.uuid4().hex}", [], [first.catalogue_id], "curator-1")
    again, _ = sql.propose_threat(f"promote:{uuid.uuid4().hex}", _proposal(threat_name))
    assert (again.outcome, again.type_id, again.catalogue_id) == (ResolveOutcome.CURATOR_REJECTED, None, None)
    assert _rows_named(sql_test_engine, threat_name) == 1  # the rejected row only


def test_a_running_operation_answers_409_and_a_done_one_answers_from_its_record(client: TestClient) -> None:
    calls = AnswerLostClient(SimpleNamespace(execute_procedure=lambda *_a, **_k: [[{"total": 1}]]), lost=0)  # type: ignore[arg-type]
    sql = SqlServerRepository(calls)  # type: ignore[arg-type]
    operation_id = f"decide:{uuid.uuid4().hex}"
    get_mongodb()[Collection.SQL_OPERATIONS].insert_one(
        {
            "_id": operation_id,
            "status": SqlOperationStatus.PENDING,
            "started_at": datetime.now(UTC),
            "parameters": {},
        }
    )
    with pytest.raises(Conflict) as raised:
        sql.run_sql_operation(operation_id, StoredProcedure.DECIDE_PENDING_THREATS, {})
    assert raised.value.reason == ConflictReason.OPERATION_IN_PROGRESS and not calls.calls
    done_id = f"decide:{uuid.uuid4().hex}"
    first = sql.run_sql_operation(done_id, StoredProcedure.DECIDE_PENDING_THREATS, {"DecidedBy": "c"})
    second = sql.run_sql_operation(done_id, StoredProcedure.DECIDE_PENDING_THREATS, {"DecidedBy": "c"})
    assert (first, second) == (([[{"total": 1}]], True), ([[{"total": 1}]], False)) and len(calls.calls) == 1
