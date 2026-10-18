"""The threat and control libraries, held in memory per process and swapped in whole when SQL Server's
copy changes.

Once loaded, requests never wait on SQL Server: a background thread compares the library fingerprint every
minute. If SQL Server is unreachable then, the last good copy keeps being served (logged, checked again next
minute). Only the very first load in a process can fail a request, because there is nothing to serve yet."""

import threading
import time
from concurrent.futures import Future

import structlog

from app.core import metrics
from app.core.constants import Cache, Dependency, LogEvent
from app.core.database import get_stored_procedure_client
from app.core.exceptions import Unavailable
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.library.repository import SqlServerRepository
from app.models.library import LibraryControl, LoadedLibraries, ThreatLibrary

log = structlog.get_logger(__name__)


class LibraryService:
    # Every process checks on its own (~100 ms SQL CPU a minute each); share one check through Redis
    # if the process count ever reaches the hundreds.
    def __init__(self, repository: SqlServerRepository) -> None:
        self._repository = repository
        self._lock = threading.Lock()
        self._loaded: LoadedLibraries | None = None
        self._first_load: Future[None] | None = None
        self._checker_started = False

    def get_threat_library(self) -> ThreatLibrary:
        return self.get_loaded_libraries().threat_library

    def get_control_library(self) -> tuple[LibraryControl, ...]:
        return self.get_loaded_libraries().control_library

    def get_retired_controls(self) -> tuple[LibraryControl, ...]:
        return self.get_loaded_libraries().retired_controls

    @traced("library.reload")
    def reload_if_library_changed(self) -> None:
        """Load both libraries when any table's fingerprint changed. The fingerprint is read BEFORE
        loading, so an edit made during a load is caught by the next check, never missed."""
        previous = self._loaded
        loaded = self._repository.load_library(previous.stamp if previous else None)
        if loaded is None:
            return
        self._loaded = loaded
        changed = sorted(set(loaded.stamp) - set(previous.stamp if previous else ()))
        log.info(LogEvent.LIBRARY_RELOADED, changed_tables=[table for table, _ in changed])

    def check_library_once(self) -> None:
        """One background check. Never raises: on any failure the current copy stays, and the failure is
        logged and counted (tsg_library_check_failures_total; LibraryCheckFailing alerts when it persists,
        because library edits in SQL Server are then not picked up)."""
        try:
            self.reload_if_library_changed()
        except Unavailable:
            metrics.LIBRARY_CHECK_FAILURES.inc()
            log.warning(
                LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.SQL, serving="last loaded library"
            )
        except Exception:  # noqa: BLE001 — the loop must outlive any one failure, or checking stops for good
            metrics.LIBRARY_CHECK_FAILURES.inc()
            log.exception(LogEvent.LIBRARY_CHECK_FAILED)

    def get_loaded_libraries(self) -> LoadedLibraries:
        """Both libraries as one snapshot (search indexes a snapshot, never a threat/control mix).

        The first load is shared: callers arriving while it runs wait for it and get its outcome, the
        libraries or its error: with SQL Server down at start, the tenth caller waits one connect timeout,
        not ten."""
        loaded = self._loaded
        if loaded is not None and self._checker_started:
            return loaded
        with self._lock:
            first_load, loads_it = self._first_load, False
            if self._loaded is None and first_load is None:
                first_load = self._first_load = Future()
                loads_it = True
        if loads_it:
            assert first_load is not None
            self._load_first_copy(first_load)
        elif first_load is not None:
            first_load.result()  # the running load's outcome: done, or its error raised here too
        self._start_checker_once()
        assert self._loaded is not None
        return self._loaded

    def _load_first_copy(self, outcome: Future[None]) -> None:
        try:
            self.reload_if_library_changed()  # SQL unreachable -> Unavailable (503): nothing to serve yet
        except BaseException as exc:  # noqa: BLE001 — handed to every waiting caller, then raised here
            outcome.set_exception(exc)
            raise
        else:
            outcome.set_result(None)
        finally:
            with self._lock:
                self._first_load = None  # a later caller after a failure starts a new attempt

    def _start_checker_once(self) -> None:
        with self._lock:
            if self._checker_started:  # one checker per process (workers run threads, never forks)
                return
            self._checker_started = True
        threading.Thread(target=self._check_library_every_minute, name="library-check", daemon=True).start()

    def _check_library_every_minute(self) -> None:
        while True:
            time.sleep(Cache.LIBRARY_STAMP_EVERY_SECONDS)
            self.check_library_once()


@singleton
def get_library_service() -> LibraryService:
    return LibraryService(SqlServerRepository(get_stored_procedure_client()))
