"""The threat and control libraries, held per process and swapped whole when SQL Server's copy changes; once
loaded, no request waits on SQL Server: a thread checks the fingerprint every minute, a failed check keeps the copy."""

import threading
import time
from concurrent.futures import Future

import structlog

from app.core import metrics
from app.core.constants import Cache, Dependency, LogEvent
from app.core.exceptions import Unavailable
from app.core.lease_signal import start_thread_without_lease
from app.core.singletons import singleton
from app.crud.library import ControlRepository, ThreatRepository, get_control_repository, get_threat_repository
from app.schemas.library import LibraryStamp, LoadedLibraries, ThreatLibrary

log = structlog.get_logger(__name__)


def load_libraries(
    threats: ThreatRepository, controls: ControlRepository, loaded_stamp: LibraryStamp | None = None
) -> LoadedLibraries | None:
    """The stamp, read first, then both libraries when it differs from `loaded_stamp`; else None."""
    stamp = threats.get_library_stamp()
    if stamp == loaded_stamp:
        return None
    return LoadedLibraries(stamp, threats.get_threat_library(), controls.get_control_library())


class LibraryCache:
    # Every process checks on its own (~100 ms SQL CPU a minute each); share one check through Redis
    # if the process count ever reaches the hundreds.
    def __init__(self, threats: ThreatRepository, controls: ControlRepository) -> None:
        self._threats, self._controls = threats, controls
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()  # one reload at a time: an older load never replaces a newer
        self._loaded: LoadedLibraries | None = None
        self._first_load: Future[None] | None = None
        self._checker_started = False

    def get_threat_library(self) -> ThreatLibrary:
        return self.get_loaded_libraries().threat_library

    def reload_if_library_changed(self) -> None:
        """Load both libraries when any table's fingerprint changed, one caller at a time."""
        with self._reload_lock:
            previous = self._loaded
            loaded = load_libraries(self._threats, self._controls, previous.stamp if previous else None)
            if loaded is None:
                return
            self._loaded = loaded
        log.info(LogEvent.LIBRARY_RELOADED)

    def check_library_once(self) -> None:
        """One background check; never raises: the copy stays and the failure is logged and counted."""
        try:
            self.reload_if_library_changed()
        except Unavailable:  # SQL Server down: an expected outage, one warning, the last copy is served
            metrics.LIBRARY_CHECK_FAILURES.inc()
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.SQL, serving="last loaded library")
        except Exception:  # noqa: BLE001 — the loop must outlive any one failure, or checking stops for good
            metrics.LIBRARY_CHECK_FAILURES.inc()
            log.exception(LogEvent.LIBRARY_CHECK_FAILED)

    def get_loaded_libraries(self) -> LoadedLibraries:
        """Both libraries as one snapshot; callers during the first load share its outcome."""
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
        start_thread_without_lease("library-check", self._check_library_every_minute)

    def _check_library_every_minute(self) -> None:
        while True:
            time.sleep(Cache.LIBRARY_STAMP_EVERY_SECONDS)
            self.check_library_once()


@singleton
def get_library_cache() -> LibraryCache:
    return LibraryCache(get_threat_repository(), get_control_repository())
