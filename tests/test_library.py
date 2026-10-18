"""The library loads from the real DevTest5 procedures, notices every edit, survives a SQL Server outage."""

import threading
import time

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import create_engine
from structlog.testing import capture_logs

from app.core.config import get_settings
from app.core.constants import AssetType, Env, ErrorMessage, LogEvent, StrideCategory
from app.core.database import get_stored_procedure_client
from app.core.exceptions import Unavailable
from app.data_access.library.control_repository import ControlRepository
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.models.library.library import LibraryActor, LibraryThreatType, ThreatLibrary
from app.search.library_cache import LibraryCache, load_libraries
from tests.sql_fakes import load_library_from


def _sql_threats() -> ThreatRepository:
    procedures = get_stored_procedure_client()
    return ThreatRepository(procedures, SqlOperationRepository(procedures))


def _sql_library_cache(threats: ThreatRepository | None = None) -> LibraryCache:
    return LibraryCache(threats or _sql_threats(), ControlRepository(get_stored_procedure_client()))


class CountingThreats(ThreatRepository):
    def __init__(self) -> None:
        procedures = get_stored_procedure_client()
        super().__init__(procedures, SqlOperationRepository(procedures))
        self.threat_library_loads = 0

    def get_threat_library(self) -> ThreatLibrary:
        self.threat_library_loads += 1
        return super().get_threat_library()


class ScriptedRepository:
    """No SQL: each stamp read takes the next scripted answer (a stamp, or an exception to raise)."""

    def __init__(self, *stamp_answers: object) -> None:
        self._stamp_answers = list(stamp_answers)
        self.stamp: object = None
        self.loads = 0

    def get_library_stamp(self) -> object:
        answer = self._stamp_answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        self.stamp = answer
        return answer

    def get_threat_library(self) -> ThreatLibrary:
        self.loads += 1
        return ThreatLibrary(threats=(), actors=())

    def get_control_library(self) -> tuple[tuple[()], tuple[()]]:
        return (), ()


def _scripted_cache(repository: ScriptedRepository) -> LibraryCache:
    return LibraryCache(repository, repository)  # type: ignore[arg-type]


SQL_DOWN = Unavailable(ErrorMessage.SQL_UNREACHABLE)


def test_library_loads_threats_with_stride_categories_and_controls_with_their_asset_type() -> None:
    service = _sql_library_cache()
    threats = service.get_threat_library().threats
    controls = service.get_loaded_libraries().control_library
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
    loaded = load_libraries(_sql_threats(), ControlRepository(get_stored_procedure_client()))
    stamp = dict(loaded.stamp if loaded else ())
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
    repository = CountingThreats()
    service = _sql_library_cache(repository)
    service.get_threat_library()
    service.get_loaded_libraries()
    service.reload_if_library_changed()
    assert repository.threat_library_loads == 1


def test_an_edit_past_the_first_255_characters_changes_the_fingerprint() -> None:
    """The cause of the old miss: BINARY_CHECKSUM read only 255 characters of a long description.

    It edits a real library row inside a transaction it rolls back: laptop database only, never auto-commit,
    and a 2 s lock wait so it cannot queue behind (or hold up) a running app's library check."""
    if get_settings().env is not Env.DEV:
        pytest.skip("edits, then rolls back, a library row: run against the laptop database only")
    before = dict(_sql_threats().get_library_stamp())
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
    service = _scripted_cache(repository)
    first = service.get_threat_library()
    service.check_library_once()
    assert repository.loads == 2 and service.get_threat_library() is not first


def test_an_outage_during_a_check_keeps_serving_the_last_good_copy() -> None:
    repository = ScriptedRepository((("Control_Library", b"v1"),), SQL_DOWN, RuntimeError("bug"))
    service = _scripted_cache(repository)
    loaded = service.get_threat_library()
    failures_before = REGISTRY.get_sample_value("tsg_library_check_failures_total") or 0.0
    service.check_library_once()  # SQL unreachable: logged, not raised
    service.check_library_once()  # any other failure: logged, the checker keeps running
    assert service.get_threat_library() is loaded and repository.loads == 1
    # Counted too (LibraryCheckFailing): a check that keeps failing means library edits are not picked up.
    assert REGISTRY.get_sample_value("tsg_library_check_failures_total") == failures_before + 2


def test_the_first_load_fails_with_503_then_succeeds_once_sql_is_back() -> None:
    repository = ScriptedRepository(SQL_DOWN, (("Control_Library", b"v1"),))
    service = _scripted_cache(repository)
    with pytest.raises(Unavailable):
        service.get_threat_library()
    assert service.get_threat_library() is not None and repository.loads == 1


def test_the_fingerprint_does_not_depend_on_the_order_sql_server_returns_rows() -> None:
    """The procedure's UNION ALL has no guaranteed order; a reordered answer is not a library change."""
    rows = [{"table_name": f"table_{n}", "fingerprint": bytes([n])} for n in range(5)]

    forward = load_library_from(stamp_rows=rows).stamp
    backward = load_library_from(stamp_rows=list(reversed(rows))).stamp
    assert forward == backward


def test_callers_during_the_first_load_share_its_failure_instead_of_repeating_it() -> None:
    """Before: callers queued on a lock and each repeated the failing first load, so with SQL Server down at
    start the fifth caller waited five connect timeouts."""
    release = threading.Event()
    stamp_reads: list[int] = []

    class SqlDown(ScriptedRepository):
        def get_library_stamp(self) -> object:
            stamp_reads.append(1)
            release.wait(5)
            raise SQL_DOWN

    service = _scripted_cache(SqlDown())
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


def test_concurrent_reloads_never_swap_an_older_copy_over_a_newer_one() -> None:
    """A slow load at v2, then a check that reads v3: the check waits for the load, so v3 stays."""
    v2, v3 = (("Control_Library", b"v2"),), (("Control_Library", b"v3"),)
    loading, release = threading.Event(), threading.Event()

    class SlowAtV2(ScriptedRepository):
        def get_threat_library(self) -> ThreatLibrary:
            library = super().get_threat_library()
            if self.stamp == v2:
                loading.set()
                release.wait(5)
            return library

    service = _scripted_cache(SlowAtV2(v2, v3))
    slow = threading.Thread(target=service.reload_if_library_changed, daemon=True)
    slow.start()
    assert loading.wait(5)
    later = threading.Thread(target=service.reload_if_library_changed, daemon=True)
    later.start()
    time.sleep(0.2)  # unserialised, the later check would swap v3 in now and the slow load v2 over it
    release.set()
    slow.join(5)
    later.join(5)
    assert service.get_loaded_libraries().stamp == v3


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
    library = load_library_from(_Procedures().execute_procedure(None)).threat_library
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
        loaded = load_library_from(control_sets=_OldProcedure().execute_procedure(None))
    active, retired = loaded.control_library, loaded.retired_controls
    assert ([control.code for control in active], retired) == (["AC-01"], ())
    assert [entry["event"] for entry in logs] == [LogEvent.LIBRARY_RETIRED_CONTROLS_MISSING]
