"""Promoting an accepted AI-proposed threat to the library (#27): T-SCN-28..30, T-LIB-07..09.
The library is the SQL test database (tests/sql_test_database.py); runs and scenarios are written straight
into the test MongoDB."""

import dataclasses
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.constants import (
    AuditAction,
    Collection,
    ConflictReason,
    Decision,
    Header,
    PromotionOutcome,
    ResolveOutcome,
    ScenarioStatus,
    Status,
    Step,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.exceptions import Unavailable
from app.crud import admin as admin_crud
from app.crud.library import SqlOperationRepository, ThreatRepository
from app.domain.scenario import runs as scenario_runs
from app.schemas.library import ProposedThreat, ThreatProposal
from tests.planner_samples import CONTEXT
from tests.service_builders import use_scenario_parts

#: The person promoting in these tests: the library rows they create carry it (CreatedBy).
REVIEWER = f"reviewer-{uuid.uuid4().hex[:6]}"
#: An IT asset whose system 321 is OT and 322 IT (the planner samples' systems).
MIXED = dataclasses.replace(
    CONTEXT,
    asset=CONTEXT.asset | {"category_code": "IT"},
    systems=[CONTEXT.systems[0] | {"category_code": "OT"}, CONTEXT.systems[1] | {"category_code": "IT"}],
)


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = admin_crud.create_api_client(get_mongodb(), f"promote-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def proposals(
    client: TestClient, sql_test_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[ThreatProposal]]:
    """The promote service on the SQL test database; every proposal that reaches SQL Server, recorded."""
    procedures = StoredProcedureClient(sql_test_engine)
    repository = ThreatRepository(procedures, SqlOperationRepository(procedures))
    library = repository.get_threat_library()
    sent: list[ThreatProposal] = []
    propose = repository.propose_threat

    def recorded(operation_id: str, proposal: ThreatProposal) -> Any:
        sent.append(proposal)
        return propose(operation_id, proposal)

    repository.propose_threat = recorded  # type: ignore[method-assign]
    use_scenario_parts(monkeypatch, threats=repository, threat_library=lambda: library)
    yield sent
    _remove_promoted_rows(sql_test_engine)


def _remove_promoted_rows(engine: Engine) -> None:
    """The threats these tests promoted, taken out of the throwaway SQL test database again: the library
    tests that run later (tests/test_sql_procedures.py) expect exactly the seeded pending rows."""
    statements = (
        "DELETE FROM dbo.Threat_Catalogue_Category_Map WHERE ThreatCatalogueID IN (SELECT ThreatCatalogueID "
        "FROM dbo.Threat_Catalogue WHERE CreatedBy = :by AND Source = N'ai')",
        "DELETE FROM dbo.Threat_Catalogue WHERE CreatedBy = :by AND Source = N'ai'",
    )
    with engine.connect() as connection:
        for statement in statements:
            connection.execute(text(statement), {"by": REVIEWER})


def _identity(api_key: str, entity_id: int = 86) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: REVIEWER,
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _accepted(
    threat_name: str,
    ai_generated: bool = True,
    decision: Decision = Decision.ACCEPTED,
    with_systems: list[int] | None = None,
) -> tuple[str, str]:
    """A run whose plan holds one threat under the live type "Malicious code", and its scenario. `with_systems`:
    the run keeps its asset facts (an IT asset, system 321 OT, 322 IT) and the scenario names these systems."""
    record_id, scenario_id, key = uuid.uuid4().hex, uuid.uuid4().hex, f"ai:{uuid.uuid4().hex[:8]}"
    threat = {"key": key, "name": threat_name, "type": {"id": 2, "name": "Malicious code"}, "category": "Tampering"}
    facts = {} if with_systems is None else {"context": MIXED.to_record()}
    named = [system for system in MIXED.systems if system["id"] in (with_systems or [])]
    as_saved = [{"id": system["id"], "name": system["name"], "entry_point": False} for system in named]  # as a card
    systems = {} if with_systems is None else {"systems": as_saved}
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 1, "status": Status.DONE, "step": Step.SCENARIOS,
         "job": {"epoch": 1}, "plan": {"threats": [threat]}, "updated_at": datetime.now(UTC), **facts}
    )  # fmt: skip
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": record_id, "entity_id": 86, "asset_id": 1, "path_id": "p1",
         "version": 1, "source": "generated", "status": ScenarioStatus.DONE, "decision": decision,
         "superseded_by": None,
         "content": {"threat": {"key": key, "ai_generated": ai_generated, "library_id": None},
                     "actors": [{"id": 1, "name": "Insider", "role": "acting"}], **systems},
         "created_at": datetime.now(UTC)}
    )  # fmt: skip
    return record_id, scenario_id


def _promote(client: TestClient, api_key: str, record_id: str, scenario_id: str, entity_id: int = 86) -> Any:
    url = f"/v1/sessions/{record_id}/scenarios/{scenario_id}/promote-to-library"
    return client.post(url, headers=_identity(api_key, entity_id))


def test_promoting_twice_inserts_one_pending_threat_and_audits_once(
    client: TestClient, api_key: str, proposals: list[ThreatProposal], sql_test_engine: Engine
) -> None:
    """T-SCN-28 / T-LIB-07: inserted, pending (IsActive 0) under the existing type, by the person; a repeat
    answers the first answer (from its operation record, no SQL call) and records nothing more."""
    name = f"Rogue firmware pushed through the vendor portal {uuid.uuid4().hex[:6]}"
    record_id, scenario_id = _accepted(name)
    first = _promote(client, api_key, record_id, scenario_id)
    assert first.status_code == 200, first.text
    (result,) = first.json()["results"]
    assert (result["outcome"], result["threat_type_id"]) == (PromotionOutcome.INSERTED, 2)
    assert proposals[0].created_by == REVIEWER and proposals[0].actor_ids == (1,)
    with sql_test_engine.connect() as connection:
        row = connection.execute(
            text("SELECT IsActive, IsDeleted, Source FROM dbo.Threat_Catalogue WHERE ThreatCatalogueID = :id"),
            {"id": result["threat_catalogue_id"]},
        ).one()
    assert tuple(row) == (False, False, "ai")
    again = _promote(client, api_key, record_id, scenario_id).json()["results"][0]
    assert again == result
    stored = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["library_promotion"]
    assert stored["results"][0]["outcome"] == PromotionOutcome.INSERTED and stored["by"] == REVIEWER
    audits = {"target.id": scenario_id, "action": AuditAction.LIBRARY_PROMOTED}
    assert get_mongodb()[Collection.AUDIT].count_documents(audits) == 1


@pytest.mark.parametrize(("systems", "expected"), [([321], "OT"), ([322], "IT"), ([], "IT")])
def test_a_promoted_threat_is_saved_with_where_its_scenario_attacks(
    client: TestClient,
    api_key: str,
    proposals: list[ThreatProposal],
    sql_test_engine: Engine,
    systems: list[int],
    expected: str,
) -> None:
    """Owner 2026-11-24: the new library row's AssetType is the scenario's own (its systems, or the IT asset when it
    names none), and the answer shows it. Mutation: send the asset's type and the OT system's threat is saved IT."""
    record_id, scenario_id = _accepted(f"Rogue logic on a control server {uuid.uuid4().hex[:6]}", with_systems=systems)
    response = _promote(client, api_key, record_id, scenario_id)
    assert response.status_code == 200, response.text
    (result,) = response.json()["results"]
    assert (result["outcome"], result["asset_type"], proposals[-1].asset_type) == (
        PromotionOutcome.INSERTED,
        expected,
        expected,
    )
    with sql_test_engine.connect() as connection:
        saved = connection.execute(
            text("SELECT AssetType FROM dbo.Threat_Catalogue WHERE ThreatCatalogueID = :id"),
            {"id": result["threat_catalogue_id"]},
        ).scalar_one()
    assert saved == expected
    stored = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["library_promotion"]
    assert stored["results"][0]["asset_type"] == expected


def test_a_known_or_rejected_wording_never_reaches_sql_server(
    client: TestClient, api_key: str, proposals: list[ThreatProposal]
) -> None:
    """T-LIB-08/09 (FR-LIB-05): a wording a curator rejected (punctuation and case aside) is never proposed;
    a live or pending name is answered from memory with its ids."""
    rejected = _accepted("ALIEN interference with the grid!")
    live = _accepted("Malicious PLC logic upload")
    pending = _accepted("Compromised vendor software update")
    outcomes = [_promote(client, api_key, *run).json()["results"][0] for run in (rejected, live, pending)]
    assert [item["outcome"] for item in outcomes] == [
        PromotionOutcome.CURATOR_REJECTED,
        PromotionOutcome.EXISTING,
        PromotionOutcome.EXISTING,
    ]
    assert (outcomes[1]["threat_catalogue_id"], outcomes[2]["threat_catalogue_id"]) == (5, 21)
    assert outcomes[0]["threat_catalogue_id"] is None and proposals == []


def test_only_an_accepted_ai_threat_of_the_callers_run_is_promoted(
    client: TestClient, api_key: str, proposals: list[ThreatProposal]
) -> None:
    """T-SCN-29/30: pending → 409 scenario_not_accepted; a library threat → 409 nothing_to_promote; another
    run's scenario → 404; another entity → 403. Nothing reaches the library."""
    pending = _accepted("A threat not yet accepted", decision=Decision.PENDING)
    answer = _promote(client, api_key, *pending)
    assert (answer.status_code, answer.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    library = _accepted("Malicious PLC logic upload", ai_generated=False)
    answer = _promote(client, api_key, *library)
    assert (answer.status_code, answer.json()["reason"]) == (409, ConflictReason.NOTHING_TO_PROMOTE)
    assert _promote(client, api_key, pending[0], library[1]).status_code == 404
    assert _promote(client, api_key, *pending, entity_id=87).status_code == 403
    assert proposals == []


@pytest.mark.parametrize(
    ("answered", "shown"),
    [
        (ResolveOutcome.CREATED_PENDING, PromotionOutcome.INSERTED),
        (ResolveOutcome.CURATOR_REJECTED, PromotionOutcome.CURATOR_REJECTED),
        (ResolveOutcome.EXISTING_ACTIVE, PromotionOutcome.EXISTING),
        (ResolveOutcome.EXISTING_PENDING, PromotionOutcome.EXISTING),
    ],
)
def test_the_librarys_answer_is_the_promotion_outcome(
    client: TestClient,
    api_key: str,
    proposals: list[ThreatProposal],
    monkeypatch: pytest.MonkeyPatch,
    answered: ResolveOutcome,
    shown: PromotionOutcome,
) -> None:
    """A name the in-memory library does not hold yet: SQL Server's answer decides the outcome."""
    record_id, scenario_id = _accepted(f"A threat the library answers {uuid.uuid4().hex[:6]}")
    answer = (ProposedThreat(type_id=2, catalogue_id=99, outcome=answered), True)
    monkeypatch.setattr(scenario_runs.get_threat_repository(), "propose_threat", lambda *args: answer)
    result = _promote(client, api_key, record_id, scenario_id).json()["results"][0]
    assert result["outcome"] == shown


def test_sql_server_down_records_nothing(
    client: TestClient, api_key: str, proposals: list[ThreatProposal], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule S13 step 3: 503 with Retry-After; the scenario keeps no promotion, so the person tries again."""
    record_id, scenario_id = _accepted(f"A threat while SQL is down {uuid.uuid4().hex[:6]}")

    def down(operation_id: str, proposal: ThreatProposal) -> Any:
        raise Unavailable("SQL down")

    monkeypatch.setattr(scenario_runs.get_threat_repository(), "propose_threat", down)
    answer = _promote(client, api_key, record_id, scenario_id)
    assert answer.status_code == 503 and "Retry-After" in answer.headers
    assert "library_promotion" not in get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})
