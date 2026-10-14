"""The on/off switch of external intelligence: the environment's master switch AND the admin's run-time flag.

The run-time flag is read from the store at most every IntelLimits.SWITCH_CACHE_SECONDS per process, by ONE
thread at a time (the others use the value they had). A store outage keeps the last value; with none yet the
switch reads OFF (intelligence is only ever an addition, so doubt means off) and looks again soon. The
environment OFF always wins and then the store is not read at all (state() included, and nothing is ever
written). Every change is audited and logged HERE, once: this class is the one place a flag changes, so no
caller adds a second row. The admin API answers 409 before calling it while the environment is OFF."""

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

import structlog

from app.core.config import get_settings
from app.core.constants import AuditAction, AuditTarget, IntelDocId, IntelLimits, LogEvent, SwitchTiming
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS
from app.core.singletons import singleton
from app.data_access.external_intelligence.switch_flag_store import SwitchFlagStore
from app.models.external_intelligence.switch_state import SwitchState
from app.services.audit import admin_actor, audit_target, record_audit

log = structlog.get_logger(__name__)


class ExternalIntelligenceSwitch:
    def __init__(
        self, flag_store: SwitchFlagStore, env_enabled: bool, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._flags = flag_store
        self._env_enabled = env_enabled
        self._clock = clock
        self._cached: tuple[SwitchState, float] | None = None  # replaced whole, so a reader never sees half
        self._reading = threading.Lock()  # one thread asks the store; the others use the last value
        self._changes = 0  # counts admin changes: a read that began before one must not overwrite it

    def is_enabled(self) -> bool:
        return self._env_enabled and self.state().effective

    def state(self) -> SwitchState:
        if not self._env_enabled:  # OFF: no store is read, whatever it holds
            return SwitchState(env_enabled=False)
        cached = self._cached
        if cached is not None and self._clock() < cached[1]:
            return cached[0]
        if not self._reading.acquire(blocking=cached is None):  # another thread is reading
            return cached[0] if cached else SwitchState(self._env_enabled, runtime_enabled=False)
        try:
            return self._read()
        finally:
            self._reading.release()

    def change_runtime_flag(self, enabled: bool, changed_by: str) -> SwitchState:
        """Raises when the store cannot be written: the switch is then unchanged and nothing is audited. One
        audit row and one log line per change."""
        before = self.state()
        now = datetime.now(UTC)
        self._flags.write_runtime_flag(enabled, changed_by, now)
        after = SwitchState(self._env_enabled, enabled, now, changed_by)
        self._changes += 1
        self._cached = (after, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, IntelDocId.SWITCH)
        record_audit(
            AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED,
            admin_actor(changed_by),
            target,
            before=_flags(before),
            after=_flags(after),
        )
        log.info(LogEvent.EXTERNAL_INTELLIGENCE_SWITCH_CHANGED, enabled=enabled, changed_by=changed_by)
        return after

    def _read(self) -> SwitchState:
        previous = self._cached
        if previous is not None and self._clock() < previous[1]:  # read by the thread that held the lock
            return previous[0]
        changes = self._changes
        try:
            stored = self._flags.read_runtime_flag()
        except MONGO_UNAVAILABLE_ERRORS:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency="external_intelligence_switch")
            if previous is not None:  # keep the last value for a full period
                self._cached = (previous[0], self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
                return previous[0]
            unknown = SwitchState(self._env_enabled, runtime_enabled=False)
            self._cached = (unknown, self._clock() + SwitchTiming.RETRY_AFTER_OUTAGE_SECONDS)
            return unknown
        if self._changes != changes and self._cached is not None:  # an admin changed it meanwhile
            return self._cached[0]
        state = SwitchState(self._env_enabled) if stored is None else SwitchState(self._env_enabled, *stored)
        self._cached = (state, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        return state


def _flags(state: SwitchState) -> dict[str, bool]:
    return {"env_enabled": state.env_enabled, "runtime_enabled": state.runtime_enabled}


@singleton
def get_external_intelligence_switch() -> ExternalIntelligenceSwitch:
    return ExternalIntelligenceSwitch(
        SwitchFlagStore(get_mongodb()), get_settings().external_intelligence_enabled
    )
