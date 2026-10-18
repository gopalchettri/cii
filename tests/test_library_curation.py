"""The curator's admin API (#23 list pending threats, #24 decide them; BLUEPRINT AD1, AD2, WF-10):
T-ADM-01..03 and T-ADM-06, through the API on the SQL test database. Each test proposes its own pending
threats, so other tests' rows never matter, and removes them after."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.constants import Collection, StoredProcedure
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.library import LibraryRepository
from app.services.library_curation import LibraryCuration, get_library_curation
from tests.conftest import ADMIN

PENDING, DECISIONS = "/v1/tsg/library/pending", "/v1/tsg/library/decisions"
LIVE_THREAT = 1  # a live library threat of the seed


#: Deletes every row these tests made: the SQL test database is shared by the whole run, and later tests count
#: the seed library's rows exactly.
_REMOVE_TEST_ROWS = """
DELETE m FROM dbo.Threat_Catalogue_Category_Map AS m
JOIN dbo.Threat_Catalogue AS c ON c.ThreatCatalogueID = m.ThreatCatalogueID
WHERE c.ThreatName LIKE N'Curation test threat %';
DELETE a FROM dbo.ThreatType_ThreatActor_Map AS a
JOIN dbo.Threat_Type AS t ON t.ThreatTypeID = a.ThreatTypeID WHERE t.ThreatTypeName LIKE N'Curation type %';
DELETE FROM dbo.Threat_Catalogue WHERE ThreatName LIKE N'Curation test threat %';
DELETE FROM dbo.Threat_Type WHERE ThreatTypeName LIKE N'Curation type %';
"""


@pytest.fixture(autouse=True)
def curation_on_the_sql_test_database(client: TestClient, sql_test_engine: Engine) -> Iterator[None]:
    service = LibraryCuration(LibraryRepository(StoredProcedureClient(sql_test_engine)))
    client.app.dependency_overrides[get_library_curation] = lambda: service  # type: ignore[attr-defined]
    yield
    client.app.dependency_overrides.pop(get_library_curation, None)  # type: ignore[attr-defined]
    with sql_test_engine.connect() as connection:
        connection.exec_driver_sql(_REMOVE_TEST_ROWS)


def _propose(sql_test_engine: Engine, type_name: str) -> dict[str, Any]:
    """A new pending threat (and its type, when the type is new) as a promotion makes it."""
    return StoredProcedureClient(sql_test_engine).execute_procedure(
        StoredProcedure.RESOLVE_THREAT,
        CategoryName="Tampering",
        TypeName=type_name,
        ThreatName=f"Curation test threat {uuid.uuid4().hex[:8]}",
        Source="ai",
        CreatedBy="reviewer-1",
        ActorIDs="[1]",
    )[0][0]


def _new_type() -> str:
    return f"Curation type {uuid.uuid4().hex[:6]}"


def _pending(client: TestClient) -> dict[int, dict[str, Any]]:
    items = client.get(PENDING, params={"limit": 500}, headers=ADMIN).json()["items"]
    return {item["catalogue_id"]: item for item in items}


def _decide(client: TestClient, body: dict[str, Any], **headers: str) -> Any:
    return client.post(DECISIONS, json=body, headers=ADMIN | headers)


def test_pending_threats_are_listed_oldest_first_with_their_type_and_categories(
    client: TestClient, sql_test_engine: Engine
) -> None:
    """T-ADM-01."""
    first = _propose(sql_test_engine, _new_type())["threat_catalogue_id"]
    second = _propose(sql_test_engine, _new_type())["threat_catalogue_id"]
    listed = _pending(client)
    item = listed[first]
    assert item["type_pending"] is True and item["categories"] == ["Tampering"]
    assert (item["source"], item["created_by"]) == ("ai", "reviewer-1")
    assert item["created_at"].endswith("Z")  # SQL Server's UTC said as UTC, like every API time
    order = list(listed)
    assert order.index(first) < order.index(second)
    page = client.get(PENDING, params={"limit": 1}, headers=ADMIN).json()
    assert len(page["items"]) == 1 and page["total"] == len(listed) >= 2


def test_an_offset_past_sql_servers_int_is_refused_not_a_500(client: TestClient) -> None:
    """Review 2026-10-11: @Offset is a SQL INT; a larger offset overflowed inside the procedure (500)."""
    response = client.get(PENDING, params={"offset": 2_147_483_648}, headers=ADMIN)
    assert response.status_code == 422


@pytest.mark.parametrize("call", ["get", "post"])
def test_the_curator_api_needs_the_admin_key(client: TestClient, call: str) -> None:
    response = client.get(PENDING) if call == "get" else client.post(DECISIONS, json={"approve": [1]})
    assert response.status_code == 401


def test_one_call_approves_and_rejects_and_a_repeat_changes_nothing(
    client: TestClient, sql_test_engine: Engine
) -> None:
    """T-ADM-02: the approved threat goes live with its new type; the rejected one is gone; both leave the
    queue; the same call again answers already_*; an unknown id and a live threat asked to be rejected change
    nothing."""
    approved = _propose(sql_test_engine, _new_type())
    a_id = approved["threat_catalogue_id"]
    r_id = _propose(sql_test_engine, _new_type())["threat_catalogue_id"]
    body = {"approve": [a_id, 999_999], "reject": [r_id, LIVE_THREAT]}
    first = _decide(client, body)
    assert first.status_code == 200, first.text
    assert {row["catalogue_id"]: row["outcome"] for row in first.json()["results"]} == {
        a_id: "approved",
        r_id: "rejected",
        999_999: "not_found",
        LIVE_THREAT: "is_approved",
    }
    assert a_id not in _pending(client) and r_id not in _pending(client)
    with sql_test_engine.connect() as connection:
        type_live = connection.exec_driver_sql(
            "SELECT IsActive FROM dbo.Threat_Type WHERE ThreatTypeID = ?", (approved["threat_type_id"],)
        ).scalar()
        threat_live = connection.exec_driver_sql(
            "SELECT IsActive FROM dbo.Threat_Catalogue WHERE ThreatCatalogueID = ?", (LIVE_THREAT,)
        ).scalar()
    assert type_live and threat_live  # the new type went live; the live threat stayed live
    again = {row["catalogue_id"]: row["outcome"] for row in _decide(client, body).json()["results"]}
    assert (again[a_id], again[r_id]) == ("already_approved", "already_rejected")


@pytest.mark.parametrize(
    ("body", "says"),
    [
        ({}, "at least one id"),
        ({"approve": [], "reject": []}, "at least one id"),
        ({"approve": list(range(1, 102))}, "At most 100 ids"),
        ({"approve": [5], "reject": [5]}, "both lists"),
        ({"approve": [5, 5]}, "more than once"),
        ({"approve": [0]}, "greater than 0"),
        ({"approve": [5], "aprove": [6]}, "aprove"),
    ],
)
def test_a_wrong_decisions_body_is_refused_and_decides_nothing(
    client: TestClient, sql_test_engine: Engine, body: dict[str, Any], says: str
) -> None:
    """T-ADM-03: 5 in a body stands for a real pending threat, which stays pending."""
    pending = _propose(sql_test_engine, _new_type())["threat_catalogue_id"]
    response = _decide(client, {key: [pending if i == 5 else i for i in ids] for key, ids in body.items()})
    assert response.status_code == 422 and says in response.text
    assert pending in _pending(client)


def test_each_decisions_call_is_audited_once_with_every_outcome(
    client: TestClient, sql_test_engine: Engine
) -> None:
    """T-ADM-06: one library.decided record per call, findable by any of its ids, the X-User-Id as actor."""
    proposed = _propose(sql_test_engine, _new_type())["threat_catalogue_id"]
    _decide(client, {"approve": [proposed], "reject": [LIVE_THREAT]}, **{"X-User-Id": "curator-7"})
    records = list(get_mongodb()[Collection.AUDIT].find({"target.id": str(proposed)}))
    assert len(records) == 1
    record = records[0]
    assert record["action"] == "library.decided"
    assert record["actor"] == {"admin": True, "user_id": "curator-7"}
    assert sorted(record["target"]["id"]) == sorted([str(proposed), str(LIVE_THREAT)])
    outcomes = {row["catalogue_id"]: row["outcome"] for row in record["details"]["results"]}
    assert outcomes == {proposed: "approved", LIVE_THREAT: "is_approved"}
