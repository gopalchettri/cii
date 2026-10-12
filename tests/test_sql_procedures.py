"""TSG's SQL procedures on the SQL test database (tests/sql_test_database.py), built fresh for this
module: the asset context, the 8 library result sets, and the library writes (propose, list, decide,
import)."""

import json
import re
from typing import Any

import pytest
from sqlalchemy import Engine

from app.core.constants import AssetType, LibraryRowKind, StoredProcedure
from app.core.database import StoredProcedureClient
from app.data_access.library import LibraryRepository
from app.models.library import PendingLibraryRow, RejectedLibraryThreat
from tests.sql_test_database import REPO

Rows = list[dict[str, Any]]


@pytest.fixture(scope="module")
def procedures(sql_test_engine: Engine) -> StoredProcedureClient:
    return StoredProcedureClient(sql_test_engine)


def _rows(engine: Engine, sql: str, *params: object) -> Rows:
    with engine.connect() as connection:
        return [dict(row._mapping) for row in connection.exec_driver_sql(sql, params)]


def test_the_asset_context_proves_ownership_and_carries_every_category(
    procedures: StoredProcedureClient,
) -> None:
    sets = procedures.execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT,
        EntityID=86,
        AssetID=103,
        SystemIDs="[321, 322, 323]",
        SectorID=10,
        SubsectorID=11,
    )
    asset, services, sector, systems, options = sets
    assert asset[0]["category_code"] == "OT"
    assert {(s["id"], s["category_code"]) for s in systems} == {(321, "OT"), (322, "IT")}  # 323: not linked
    assert services == [{"id": 1, "name": "Electricity transmission", "linked": True}]
    assert (sector[0]["name"], sector[0]["parent_name"]) == ("Electricity", "Energy")
    # The platform saves an option's value (SCADA = 1, its id is 7); priority alone by id (its values repeat)
    assert {"code": "technology-used", "value": 1, "name": "SCADA"} in options
    assert {"code": "priority", "value": 1, "name": "High"} in options
    # G203: the asset row carries every asset fact, named as the AI sees it, and nothing a run must not use
    facts = asset[0]
    assert (facts["sector"], facts["sub_sector"]) == ("Energy", "Electricity")
    assert facts["critical_service"] == "Electricity transmission"
    assert facts["entity_technology_context"].startswith("Siemens S7-1500")
    assert list(facts)[-1] == "entity_technology_context"  # the landscape clips from the end
    assert facts["cii_asset_description"].startswith("Monitors") and facts["asset_type"] == "Control system"
    assert not {"criticality", "category_id", "category_name", "description", "type", "priority"} & set(facts)
    assert systems[0]["category_name"].endswith("(OT)") or systems[0]["category_name"].endswith("(IT)")
    assert "past_incidents" in systems[0] and not {"category_id", "incident_description"} & set(systems[0])
    asked = procedures.execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT, EntityID=86, AssetID=103, SystemIDs="[321]", ServiceID=2
    )
    assert asked[0][0]["critical_service"] == "Customer billing"  # the asked service, linked or not
    assert (asked[0][0]["sector"], asked[0][0]["sub_sector"]) == (None, None)  # no sector asked
    # Both sector inputs: the sub-sector's row is read when sent, else the sector's (owner 2026-10-11)
    for sent, names in (
        ({"SectorID": 10}, ("Energy", None)),
        ({"SubsectorID": 11}, ("Energy", "Electricity")),
        ({"SectorID": 10, "SubsectorID": 11}, ("Energy", "Electricity")),
    ):
        row = procedures.execute_procedure(
            StoredProcedure.GET_ASSET_CONTEXT, EntityID=86, AssetID=103, SystemIDs="[321]", **sent
        )[0][0]
        assert (row["sector"], row["sub_sector"]) == names, sent
    other_entity = procedures.execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT, EntityID=99, AssetID=103, SystemIDs="[321]"
    )
    assert other_entity[0] == []  # entity 99 does not own asset 103
    # Review 2026-10-11: another organisation gets none of the asset's systems or services either
    assert (other_entity[1], other_entity[3]) == ([], [])
    # A deleted service or sector reads as unknown (the app answers 404), and its name never reaches the AI
    deleted = procedures.execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT,
        EntityID=86,
        AssetID=103,
        SystemIDs="[321]",
        ServiceID=3,
        SubsectorID=12,
    )
    assert (deleted[1], deleted[2]) == ([], [])
    row = deleted[0][0]
    assert (row["critical_service"], row["sector"], row["sub_sector"]) == (None,) * 3


def test_the_threat_library_lists_the_pending_and_the_rejected_too(procedures: StoredProcedureClient) -> None:
    sets = procedures.execute_procedure(StoredProcedure.GET_THREAT_LIBRARY)
    assert len(sets) == 8
    categories, types, threats, actors, _, _, pending, rejected = sets
    assert (len(categories), len(types), len(threats), len(actors)) == (6, 8, 20, 6)
    assert {(row["kind"], row["id"]) for row in pending} == {("type", 9), ("threat", 21), ("threat", 22)}
    assert [row["ThreatName"] for row in rejected] == ["Alien interference with the grid"]


def test_the_control_library_lists_retired_controls_apart(procedures: StoredProcedureClient) -> None:
    """Owner, 2026-10-11: a register may name a retired control; it is loaded apart, by code, name and domain,
    and never among the controls mapped or searched."""
    active, retired = LibraryRepository(procedures).load_control_library()
    assert "AC-99" not in {control.code for control in active}
    legacy = next(control for control in retired if control.code == "AC-99")
    assert (legacy.name, legacy.domain, legacy.description) == (
        "Legacy dial-up access review",
        "Access control",
        None,
    )


def test_the_loaded_library_knows_the_pending_and_the_rejected_names(
    procedures: StoredProcedureClient,
) -> None:
    """For the name checks before a library write: reuse a pending name, never propose a rejected one."""
    library = LibraryRepository(procedures).load_threat_library()
    assert set(library.pending) == {
        PendingLibraryRow(LibraryRowKind.TYPE, 9, "Supply chain compromise", None),
        PendingLibraryRow(LibraryRowKind.THREAT, 21, "Compromised vendor software update", 9),
        PendingLibraryRow(LibraryRowKind.THREAT, 22, "Malicious USB drive in the control room", 2),
    }
    assert library.curator_rejected == (RejectedLibraryThreat(23, "Alien interference with the grid", 8),)
    assert len(library.threats) == 20  # the pending and rejected ones are never searched or written
    asset_types = {threat.catalogue_id: threat.asset_type for threat in library.threats}
    assert asset_types[1] == AssetType.IT_OT and asset_types[2] is None  # G211: the procedure returns it
    assert library.threats_unknown_asset_type == ()


def _propose(procedures: StoredProcedureClient, **params: Any) -> dict[str, Any]:
    defaults = {"CategoryName": "Tampering", "Source": "ai", "CreatedBy": "reviewer-1", "ActorIDs": "[1, 3]"}
    return procedures.execute_procedure(StoredProcedure.RESOLVE_THREAT, **(defaults | params))[0][0]


def test_a_proposed_threat_is_written_pending_once(
    procedures: StoredProcedureClient, sql_test_engine: Engine
) -> None:
    created = _propose(procedures, TypeName="Drone intrusion", ThreatName="Drone over-flight of a substation")
    assert created["outcome"] == "created_pending"
    again = _propose(procedures, TypeName="Drone intrusion", ThreatName="DRONE OVER-FLIGHT OF A SUBSTATION")
    assert again == {**created, "outcome": "existing_pending"}  # SQL Server compares names case-insensitively
    rows = _rows(
        sql_test_engine,
        "SELECT t.IsActive AS type_active, c.IsActive AS threat_active, c.Source FROM dbo.Threat_Catalogue c "
        "JOIN dbo.Threat_Type t ON t.ThreatTypeID = c.ThreatTypeID "
        "WHERE c.ThreatCatalogueID = ?",
        created["threat_catalogue_id"],
    )
    assert rows == [{"type_active": False, "threat_active": False, "Source": "ai"}]
    actors = _rows(
        sql_test_engine,
        "SELECT ThreatActorID FROM dbo.ThreatType_ThreatActor_Map WHERE ThreatTypeID = ?",
        created["threat_type_id"],
    )
    assert sorted(row["ThreatActorID"] for row in actors) == [1, 3]  # a NEW type gets the scenario's actors


def test_a_live_threat_is_answered_as_it_is_and_never_changed(
    procedures: StoredProcedureClient, sql_test_engine: Engine
) -> None:
    links = "SELECT * FROM dbo.Threat_Catalogue_Category_Map WHERE ThreatCatalogueID = 5"
    before = _rows(sql_test_engine, links)
    live = _propose(procedures, TypeName="Some other type", ThreatName="Malicious PLC logic upload")
    assert live == {"threat_type_id": 2, "threat_catalogue_id": 5, "outcome": "existing_active"}
    assert _rows(sql_test_engine, links) == before
    assert not _rows(
        sql_test_engine, "SELECT 1 AS x FROM dbo.Threat_Type WHERE ThreatTypeName = N'Some other type'"
    )


def test_a_proposal_from_an_unknown_source_is_refused(procedures: StoredProcedureClient) -> None:
    with pytest.raises(Exception, match="manual or ai"):
        _propose(procedures, Source="import", TypeName="X", ThreatName="Y")


def test_pending_threats_are_listed_oldest_first_with_a_total(procedures: StoredProcedureClient) -> None:
    page, total = procedures.execute_procedure(StoredProcedure.LIST_PENDING_THREATS, Offset=0, Limit=2)
    assert len(page) == 2 and total[0]["total"] >= 2
    assert page[0]["threat"] in {
        "Compromised vendor software update",
        "Malicious USB drive in the control room",
    }
    assert json.loads(page[0]["categories"]) == [{"name": "Tampering"}]


def test_a_curator_decides_in_one_call_with_one_outcome_per_id(
    procedures: StoredProcedureClient, sql_test_engine: Engine
) -> None:
    results = procedures.execute_procedure(
        StoredProcedure.DECIDE_PENDING_THREATS,
        ApproveIDs="[21, 23, 9999]",
        RejectIDs="[22, 1]",
        DecidedBy="curator-1",
    )[0]
    assert {row["catalogue_id"]: row["outcome"] for row in results} == {
        1: "is_approved",  # asked to reject a live threat: nothing changed
        21: "approved",
        22: "rejected",
        23: "already_rejected",
        9999: "not_found",
    }
    rows = _rows(sql_test_engine, "SELECT * FROM dbo.Threat_Catalogue WHERE ThreatCatalogueID IN (1, 21, 22)")
    state = {row["ThreatCatalogueID"]: (row["IsActive"], row["IsDeleted"]) for row in rows}
    assert state == {1: (True, False), 21: (True, False), 22: (False, True)}
    type_9 = _rows(sql_test_engine, "SELECT IsActive FROM dbo.Threat_Type WHERE ThreatTypeID = 9")
    assert type_9 == [{"IsActive": True}]  # the pending type went live with its first approved threat
    again = procedures.execute_procedure(
        StoredProcedure.DECIDE_PENDING_THREATS, ApproveIDs="[21]", RejectIDs="[]", DecidedBy="curator-1"
    )[0]
    assert again == [{"catalogue_id": 21, "outcome": "already_approved"}]


def test_rejecting_the_last_threat_of_a_pending_type_rejects_the_type(
    procedures: StoredProcedureClient, sql_test_engine: Engine
) -> None:
    proposed = _propose(procedures, TypeName="Satellite spoofing", ThreatName="Spoofed GPS time on PMUs")
    procedures.execute_procedure(
        StoredProcedure.DECIDE_PENDING_THREATS,
        ApproveIDs="[]",
        RejectIDs=f"[{proposed['threat_catalogue_id']}]",
        DecidedBy="curator-1",
    )
    type_row = _rows(
        sql_test_engine,
        "SELECT IsDeleted FROM dbo.Threat_Type WHERE ThreatTypeID = ?",
        proposed["threat_type_id"],
    )
    assert type_row == [{"IsDeleted": True}]


def _import(procedures: StoredProcedureClient, rows: list[dict[str, str]], dry_run: bool) -> dict[str, tuple]:
    counts = procedures.execute_procedure(
        StoredProcedure.IMPORT_THREAT_LIBRARY,
        Source="pytm",
        Rows=json.dumps(rows),
        Activate=False,
        DryRun=dry_run,
        CreatedBy="import-job",
    )[0]
    return {row["kind"]: (row["inserted"], row["existing"], row["skipped"]) for row in counts}


def test_an_import_inserts_only_what_is_missing_and_a_dry_run_writes_nothing(
    procedures: StoredProcedureClient, sql_test_engine: Engine
) -> None:
    rows = [
        {
            "kind": "threat",
            "category": "Tampering",
            "type": "Cable cutting",
            "threat": "Cut fibre between sites",
        },
        {
            "kind": "threat",
            "category": "Tampering",
            "type": "Malicious code",
            "threat": "Malicious PLC logic upload",
        },
        {"kind": "threat", "category": "Not a category", "type": "X", "threat": "Unknown category threat"},
        {  # rejected by a curator: never brought back by an import
            "kind": "threat",
            "category": "Tampering",
            "type": "Physical intrusion",
            "threat": "Alien interference with the grid",
        },
        {"kind": "actor", "actor_name": "Hacktivist"},
        {"kind": "actor", "actor_name": "Disgruntled contractor"},
    ]
    new_threat = (
        "SELECT IsActive, Source FROM dbo.Threat_Catalogue WHERE ThreatName = N'Cut fibre between sites'"
    )
    expected = {"actor": (1, 1, 0), "threat": (1, 1, 2), "type": (1, 1, 0)}
    assert _import(procedures, rows, dry_run=True) == expected
    assert _rows(sql_test_engine, new_threat) == []
    assert _import(procedures, rows, dry_run=False) == expected
    assert _rows(sql_test_engine, new_threat) == [
        {"IsActive": False, "Source": "pytm"}
    ]  # pending, for a curator
    assert _import(procedures, rows, dry_run=False) == {
        "actor": (0, 2, 0),
        "threat": (0, 2, 2),
        "type": (0, 2, 0),
    }


def test_grants_name_every_tsg_procedure_and_nothing_else() -> None:
    """Least privilege: the app login may run exactly TSG's procedures (a name pattern would also grant v1's
    deploy helpers)."""
    grants = (REPO / "scripts" / "sql" / "grants.sql").read_text(encoding="utf-8")
    granted = set(re.findall(r"GRANT EXECUTE ON dbo\.(\w+) TO", grants))
    shipped = {path.stem for path in (REPO / "scripts" / "sql").glob("tsg_*.sql")}
    assert granted == shipped == {procedure.value for procedure in StoredProcedure}
