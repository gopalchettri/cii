"""The library loads from the real DevTest5 procedures, notices every edit, survives a SQL Server outage."""

from types import SimpleNamespace

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import create_engine
from structlog.testing import capture_logs

from app.core.config import get_settings
from app.core.constants import AssetType, Env, ErrorMessage, LogEvent, StrideCategory
from app.core.database import get_stored_procedure_client
from app.core.exceptions import Unavailable
from app.data_access.library import LibraryRepository
from app.models.library import LibraryActor, LibraryThreatType, ThreatLibrary
from app.search.library_cache import LibraryService


class CountingRepository(LibraryRepository):
    def __init__(self) -> None:
        super().__init__(get_stored_procedure_client())
        self.threat_library_loads = 0

    def load_threat_library(self):  # type: ignore[no-untyped-def]
        self.threat_library_loads += 1
        return super().load_threat_library()


class ScriptedRepository:
    """No SQL: each stamp read takes the next scripted answer (a stamp, or an exception to raise)."""

    def __init__(self, *stamp_answers: object) -> None:
        self._stamp_answers = list(stamp_answers)
        self.loads = 0

    def read_library_stamp(self) -> object:
        answer = self._stamp_answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def load_threat_library(self) -> ThreatLibrary:
        self.loads += 1
        return ThreatLibrary(threats=(), actors=())

    def load_control_library(self) -> tuple:
        return (), ()


SQL_DOWN = Unavailable(ErrorMessage.SQL_UNREACHABLE)


def test_library_loads_threats_with_stride_categories_and_controls_with_their_asset_type() -> None:
    service = LibraryService(LibraryRepository(get_stored_procedure_client()))
    threats = service.get_threat_library().threats
    controls = service.get_control_library()
    assert threats and controls
    assert all(threat.categories for threat in threats)
    assert all(isinstance(category, StrideCategory) for threat in threats for category in threat.categories)
    assert any(threat.linked_actors for threat in threats)
    # Control_Library.AssetType (was ITOT; owner, 2026-10-09): only the four agreed values.
    assert {control.asset_type for control in controls} <= {*AssetType, None}
    assert any(control.asset_type for control in controls)


def test_the_library_stamp_covers_exactly_the_tables_the_app_reads() -> None:
    """Control_Standard and Control_Library_Standard_Map are not used (owner, 2026-10-09): an edit there must
    not reload the library, and a table the app reads must never be missing from the fingerprint."""
    stamp = dict(LibraryRepository(get_stored_procedure_client()).read_library_stamp())
    assert set(stamp) == {
        "Threat_Category",
        "Threat_Type",
        "Threat_Catalogue",
        "Threat_Actor",
        "Threat_Catalogue_Category_Map",
        "ThreatType_ThreatActor_Map",
        "Control_Library",
    }


def test_library_is_read_once_while_unchanged() -> None:
    repository = CountingRepository()
    service = LibraryService(repository)
    service.get_threat_library()
    service.get_control_library()
    service.reload_if_library_changed()
    assert repository.threat_library_loads == 1


def test_an_edit_past_the_first_255_characters_changes_the_fingerprint() -> None:
    """The cause of the old miss: BINARY_CHECKSUM read only 255 characters of a long description.

    It edits a real library row inside a transaction it rolls back: laptop database only, never auto-commit,
    and a 2 s lock wait so it cannot queue behind (or hold up) a running app's library check."""
    if get_settings().env is not Env.DEV:
        pytest.skip("edits, then rolls back, a library row: run against the laptop database only")
    repository = LibraryRepository(get_stored_procedure_client())
    before = dict(repository.read_library_stamp())
    engine = create_engine(get_settings().db_dsn)
    connection = engine.raw_connection()
    try:
        connection.dbapi_connection.autocommit = False  # type: ignore[union-attr]
        cursor = connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 2000")
        cursor.execute(
            "UPDATE dbo.Control_Library SET ControlDescription = ControlDescription + N'.'"
            " WHERE ControlLibraryID ="
            " (SELECT TOP 1 ControlLibraryID FROM dbo.Control_Library WHERE LEN(ControlDescription) > 300"
            "  ORDER BY ControlLibraryID)"
        )
        assert cursor.rowcount == 1
        cursor.execute("EXEC dbo.tsg_GetLibraryStamp")
        during = {row.table_name: row.fingerprint for row in cursor.fetchall()}
    finally:
        connection.rollback()  # the library is never changed by this test
        connection.close()
        engine.dispose()
    assert during["Control_Library"] != before["Control_Library"]
    assert {table for table in before if during[table] != before[table]} == {"Control_Library"}


def test_a_changed_fingerprint_swaps_in_both_libraries_together() -> None:
    repository = ScriptedRepository((("Control_Library", b"v1"),), (("Control_Library", b"v2"),))
    service = LibraryService(repository)  # type: ignore[arg-type]
    first = service.get_threat_library()
    service.check_library_once()
    assert repository.loads == 2 and service.get_threat_library() is not first


def test_an_outage_during_a_check_keeps_serving_the_last_good_copy() -> None:
    repository = ScriptedRepository((("Control_Library", b"v1"),), SQL_DOWN, RuntimeError("bug"))
    service = LibraryService(repository)  # type: ignore[arg-type]
    loaded = service.get_threat_library()
    failures_before = REGISTRY.get_sample_value("tsg_library_check_failures_total") or 0.0
    service.check_library_once()  # SQL unreachable: logged, not raised
    service.check_library_once()  # any other failure: logged, the checker keeps running
    assert service.get_threat_library() is loaded and repository.loads == 1
    # Counted too (LibraryCheckFailing): a check that keeps failing means library edits are not picked up.
    assert REGISTRY.get_sample_value("tsg_library_check_failures_total") == failures_before + 2


def test_the_first_load_fails_with_503_then_succeeds_once_sql_is_back() -> None:
    repository = ScriptedRepository(SQL_DOWN, (("Control_Library", b"v1"),))
    service = LibraryService(repository)  # type: ignore[arg-type]
    with pytest.raises(Unavailable):
        service.get_threat_library()
    assert service.get_threat_library() is not None and repository.loads == 1


def test_the_fingerprint_does_not_depend_on_the_order_sql_server_returns_rows() -> None:
    """The procedure's UNION ALL has no guaranteed order; a reordered answer is not a library change."""
    rows = [{"table_name": f"table_{n}", "fingerprint": bytes([n])} for n in range(5)]

    def stamp_rows(reverse: bool) -> object:
        ordered = list(reversed(rows)) if reverse else rows
        return SimpleNamespace(execute_procedure=lambda _procedure: [ordered])

    forward = LibraryRepository(stamp_rows(reverse=False)).read_library_stamp()  # type: ignore[arg-type]
    backward = LibraryRepository(stamp_rows(reverse=True)).read_library_stamp()  # type: ignore[arg-type]
    assert forward == backward


def test_callers_during_the_first_load_share_its_failure_instead_of_repeating_it() -> None:
    """Before: callers queued on a lock and each repeated the failing first load, so with SQL Server down at
    start the fifth caller waited five connect timeouts."""
    import threading
    import time

    release = threading.Event()
    stamp_reads: list[int] = []

    class SqlDown(ScriptedRepository):
        def read_library_stamp(self) -> object:
            stamp_reads.append(1)
            release.wait(5)
            raise SQL_DOWN

    service = LibraryService(SqlDown())  # type: ignore[arg-type]
    failures: list[Exception] = []

    def call() -> None:
        try:
            service.get_threat_library()
        except Unavailable as exc:
            failures.append(exc)

    threads = [threading.Thread(target=call, daemon=True) for _ in range(5)]
    for thread in threads:
        thread.start()
    time.sleep(0.3)  # every caller now waits on the one load
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(stamp_reads) == 1 and len(failures) == 5
    with pytest.raises(Unavailable):
        service.get_threat_library()  # a later call is a new attempt
    assert len(stamp_reads) == 2


class _Procedures:
    """The eight tsg_GetThreatLibrary result sets: two threats, only the first linked to a category."""

    def execute_procedure(self, _procedure: object) -> list[list[dict[str, object]]]:
        return [
            [{"ThreatCategoryID": 2, "ThreatCategoryName": "Tampering"}],
            [{"ThreatTypeID": 7, "ThreatTypeName": "Malware", "ThreatCategoryID": 2}],
            [
                {"ThreatCatalogueID": 1, "ThreatName": "Ransomware", "ThreatTypeID": 7},
                {"ThreatCatalogueID": 2, "ThreatName": "Wiper", "ThreatTypeID": 7},
            ],
            [{"ThreatActorID": 1, "ThreatActorName": "Crew"}],
            [{"ThreatTypeID": 7, "ThreatActorID": 1}],
            [{"ThreatCatalogueID": 1, "ThreatCategoryID": 2}],
            [],
            [],
        ]


def test_a_threat_without_its_own_category_is_left_out_and_counted() -> None:
    """G119 (owner, 2026-10-10; spec v4.0 §7.2.2 step 3): never given its type's category in silence."""
    library = LibraryRepository(_Procedures()).load_threat_library()  # type: ignore[arg-type]
    assert [threat.catalogue_id for threat in library.threats] == [1]
    assert library.threats_without_category == (2,)
    crew = LibraryActor(1, "Crew")
    assert library.types == (LibraryThreatType(7, "Malware", StrideCategory.TAMPERING, (crew,)),)


def test_the_old_control_procedure_still_loads_without_retired_controls() -> None:
    """Owner, 2026-10-11: an app rolled out before the DBA installs the new tsg_GetControlLibrary (one result
    set) still loads its library, with no retired controls and a warning naming what to install."""

    class _OldProcedure:
        def execute_procedure(self, _procedure: object) -> list[list[dict[str, object]]]:
            row = {"ControlLibraryID": 1, "ControlCode": "AC-01", "AssetType": "IT", "Domain": "Access",
                   "ControlName": "Account management", "ControlDescription": "Reviews."}  # fmt: skip
            return [[row]]

    with capture_logs() as logs:
        active, retired = LibraryRepository(_OldProcedure()).load_control_library()  # type: ignore[arg-type]
    assert ([control.code for control in active], retired) == (["AC-01"], ())
    assert [entry["event"] for entry in logs] == [LogEvent.LIBRARY_RETIRED_CONTROLS_MISSING]
