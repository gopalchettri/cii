"""TSG's SQL procedures on the SQL test database (tests/sql_test_database.py), built fresh for this
module: the asset context, the 8 library result sets, and the library writes (propose, list, decide,
import)."""

import json
import re
from pathlib import Path
from typing import Any

import pyodbc
import pytest
from sqlalchemy import Engine

from app.core.constants import AssetType, ErrorMessage, LibraryRowKind, StoredProcedure
from app.core.database import StoredProcedureClient
from app.core.exceptions import Invalid, SetupError, Unavailable
from app.data_access.library.control_repository import ControlRepository
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.data_access.service_mapper.catalog_repository import ServiceCatalogRepository
from app.domain.service_mapper.catalog import build_catalog
from app.models.library.library import LoadedLibraries, PendingLibraryRow, RejectedLibraryThreat
from app.search.library_cache import load_libraries
from tests.sql_test_database import REPO, procedure_files

Rows = list[dict[str, Any]]


@pytest.fixture(scope="module")
def procedures(sql_test_engine: Engine) -> StoredProcedureClient:
    return StoredProcedureClient(sql_test_engine)


def _load_libraries(procedures: StoredProcedureClient) -> LoadedLibraries | None:
    threats = ThreatRepository(procedures, SqlOperationRepository(procedures))
    return load_libraries(threats, ControlRepository(procedures))


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
    one_sent = procedures.execute_procedure(
        StoredProcedure.GET_ASSET_CONTEXT, EntityID=86, AssetID=103, SystemIDs="[321]", SubsectorID=11
    )
    assert sorted(s["id"] for s in one_sent[3]) == [321, 322]  # every system linked to the asset, sent or not
    assert services == [{"id": 1, "name": "Electricity transmission", "linked": True}]
    assert (sector[0]["name"], sector[0]["parent_name"]) == ("Electricity", "Energy")
    # The platform saves an option's value (SCADA = 1, its id is 7); priority alone by id (its values repeat)
    assert {"code": "technology-used", "value": 1, "name": "SCADA"} in options
    assert {"code": "priority", "value": 1, "name": "High"} in options
    # G203: the asset row carries every asset fact, named as the AI sees it, and nothing a run must not use
    facts = asset[0]
    assert (facts["sector"], facts["sub_sector"]) == ("Energy", "Electricity")
    assert facts["critical_service"] == "Electricity transmission"
    assert facts["cii_asset_description"].startswith("Monitors") and facts["asset_type"] == "Control system"
    assert not {"criticality", "category_id", "category_name", "description", "type", "priority"} & set(facts)
    assert systems[0]["category_name"].endswith("(OT)") or systems[0]["category_name"].endswith("(IT)")
    # The owner's procedure shows each system's description (G217); a fact hidden there never arrives.
    assert systems[0]["description"] == "Runs the transmission grid." and "category_id" not in systems[0]
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


def test_a_malformed_multi_select_value_on_a_linked_system_reads_as_no_answer(
    sql_test_engine: Engine,
) -> None:
    """With technology_used shown (as the procedure's header invites), a value that is not a JSON list on a
    system the request did not send never stops the asset's runs: it reads as no answer. The shown fact and
    the bad value are one transaction, rolled back."""
    source = (REPO / "scripts" / "sql" / "tsg_GetAssetContext.sql").read_text(encoding="utf-8")
    shown = source.replace("--, Technology.technology_used", ", Technology.technology_used")
    assert shown != source
    connection = sql_test_engine.raw_connection()
    driver = connection.driver_connection
    assert driver is not None
    driver.autocommit = False  # the engine autocommits; this test's changes must not outlive it
    try:
        cursor = connection.cursor()
        cursor.execute(shown[shown.index("CREATE OR ALTER PROCEDURE") : shown.rindex("GO")])
        cursor.execute(
            "UPDATE dbo.onboarding_supporting_systems SET technology_used = N'not json' WHERE id = 322"
        )
        cursor.execute(
            "EXEC dbo.tsg_GetAssetContext @EntityID = 86, @AssetID = 103, @SystemIDs = N'[321]', "
            "@SubsectorID = 11"
        )
        for _ in range(3):  # the asset, services and sector come first
            cursor.nextset()
        systems = {row.id: row.technology_used for row in cursor.fetchall()}
        assert sorted(systems) == [321, 322] and systems[322] is None
    finally:
        connection.rollback()
        driver.autocommit = True
        connection.close()


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
    loaded = _load_libraries(procedures)
    assert loaded is not None
    active, retired = loaded.control_library, loaded.retired_controls
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
    loaded = _load_libraries(procedures)
    assert loaded is not None
    library = loaded.threat_library
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
    """The procedure's THROW (SQLSTATE 42000, a ProgrammingError) is a setup error, never a bare 500."""
    with pytest.raises(SetupError, match=ErrorMessage.SQL_PROCEDURE_BROKEN) as refused:
        _propose(procedures, Source="import", TypeName="X", ThreatName="Y")
    assert "manual or ai" in str(refused.value.__cause__)


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
    shipped = {path.stem for path in procedure_files()}
    external = {StoredProcedure.GET_SECTOR_SERVICE_MAPPINGS.value}  # the onboarding platform's own
    assert shipped == {procedure.value for procedure in StoredProcedure} - external
    assert granted == {procedure.value for procedure in StoredProcedure}


def test_service_mapper_associations_keep_exact_hierarchy_and_filter_deleted_rows(
    procedures: StoredProcedureClient,
) -> None:
    sectors, links, entities = procedures.execute_procedure(StoredProcedure.GET_SERVICE_MAPPER_ASSOCIATIONS)
    assert {row["sector_id"] for row in sectors} == {10, 11}
    assert next(row for row in sectors if row["sector_id"] == 11)["parent_sector_id"] == 10
    assert links == [{"service_id": 1, "sector_id": 11}, {"service_id": 2, "sector_id": 10}]
    assert entities == [{"service_id": 1, "sector_id": 11, "entity_id": 86, "entity_name": "Test Entity"}]


def test_the_onboarding_procedures_tsg_ships_feed_the_service_mapper_catalog(
    procedures: StoredProcedureClient,
) -> None:
    """TSG's own tsg_Onboarding_* procedures return what the catalog reads, without deleted rows, and agree
    with tsg_GetServiceMapperAssociations on the live top-level sectors (else the catalog is refused)."""
    (summary,) = procedures.execute_procedure(StoredProcedure.GET_SECTORS_AND_SUBSECTORS)
    (services,) = procedures.execute_procedure(StoredProcedure.GET_SERVICES_WITH_SECTOR_DETAILS)
    assert summary == [{"SectorName": "Energy", "SubsectorList": "Electricity"}]
    assert [row["service_name"] for row in services] == ["Customer billing", "Electricity transmission"]
    transmission = next(row for row in services if row["service_id"] == 1)
    assert transmission["upstream_dependencies"] == "Customer billing"
    assert transmission["downstream_dependencies"] == "Test Entity"

    class _NoOldMappings:  # the platform's own Onboarding_GetSectorServiceMappings is not in this database
        def execute_procedure(self, procedure: StoredProcedure) -> list[list[dict[str, Any]]]:
            if procedure is StoredProcedure.GET_SECTOR_SERVICE_MAPPINGS:
                return [[]]
            return procedures.execute_procedure(procedure)

    catalog = build_catalog(ServiceCatalogRepository(_NoOldMappings()).load())  # type: ignore[arg-type]
    assert catalog.sector_names == ("Energy",)
    names = [service.service_name for service in catalog.services]
    assert names == ["Electricity transmission", "Customer billing"]


def test_a_backup_copy_beside_a_procedure_is_never_installed_or_granted(tmp_path: Path) -> None:
    """G217: every tsg_*.sql file was installed and checked as a procedure, so a stale copy saved beside one
    (e.g. "tsg_GetAssetContext copy.sql") was installed too and the grants check failed."""
    for name in (
        "tsg_GetAssetContext.sql",
        "tsg_GetAssetContext copy.sql",
        "tsg_GetAssetContext (1).sql",
        "tsg_Get-Old.sql",
        "grants.sql",
    ):
        (tmp_path / name).write_text("-- a file", encoding="utf-8")
    assert [path.name for path in procedure_files(tmp_path)] == ["tsg_GetAssetContext.sql"]


class _EngineRaising:
    """An engine whose procedure call raises `error`, as pyodbc raises it from SQL Server."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.executed: list[str] = []

    def raw_connection(self) -> "_EngineRaising":
        return self

    def cursor(self) -> "_EngineRaising":
        return self

    def execute(self, sql: str, *_params: object) -> None:
        self.executed.append(sql)
        raise self.error

    def close(self) -> None:
        """Nothing to return to a pool."""


def test_only_a_stored_procedure_member_is_ever_executed() -> None:
    """Before: any string was put into the EXEC text."""
    engine = _EngineRaising(AssertionError("never executed"))
    client = StoredProcedureClient(engine)  # type: ignore[arg-type]
    with pytest.raises(SetupError, match="is not a TSG stored procedure"):
        client.execute_procedure("tsg_GetThreatLibrary; DROP TABLE dbo.Threat")  # type: ignore[arg-type]
    assert engine.executed == []


@pytest.mark.parametrize(
    ("driver_error", "expected"),
    [
        (pyodbc.DataError("22003", "Arithmetic overflow"), Invalid),
        (pyodbc.IntegrityError("23000", "Cannot insert duplicate key"), Invalid),
        (pyodbc.ProgrammingError("42000", "Could not find stored procedure"), SetupError),
        (pyodbc.OperationalError("HYT00", "Query timeout expired"), Unavailable),
        (pyodbc.InterfaceError("28000", "Login failed"), Unavailable),
    ],
)
def test_a_driver_error_from_a_procedure_becomes_its_app_error(
    driver_error: Exception, expected: type[Exception]
) -> None:
    """Before: a value SQL Server refused (DataError, IntegrityError) or a missing procedure reached the API
    as a bare 500."""
    client = StoredProcedureClient(_EngineRaising(driver_error))  # type: ignore[arg-type]
    with pytest.raises(expected) as raised:
        client.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)
    assert raised.value.__cause__ is driver_error
