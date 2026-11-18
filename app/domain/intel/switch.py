"""The on/off switch of external intelligence."""

import threading
import time
from collections.abc import Callable
from typing import Any

import structlog

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import ErrorMessage, IntelDocId, IntelLimits, LogEvent
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Unavailable
from app.core.singletons import singleton
from app.crud.intel import IntelFeedRepository, get_intel_feed_repository
from app.schemas.intel_records import SwitchState

log = structlog.get_logger(__name__)
RETRY_AFTER_OUTAGE_SECONDS = 5.0  # with no value yet, the store is asked again this soon


class IntelligenceSwitch:
    """The one place the flag is read and changed."""

    def __init__(
        self, feeds: IntelFeedRepository, env_enabled: Callable[[], bool], clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._feeds = feeds  # tsg_external_feed_status, whose switch document holds the run-time flag
        self._env_enabled = env_enabled  # reads EXTERNAL_INTELLIGENCE_ENABLED from the settings at each call
        self._clock = clock
        self._cached: tuple[SwitchState, float] | None = None  # replaced whole, so a reader never sees half
        self._reading = threading.Lock()  # one thread asks the store; the others use the last value
        self._changes = 0  # counts admin changes: a read that began before one must not overwrite it

    def is_on(self, sure: bool = False) -> bool:
        """True when both switches are on."""
        state = self.state()
        if sure and not state.known:
            raise Unavailable(ErrorMessage.MONGO_UNREACHABLE)
        return state.effective

    def state(self) -> SwitchState:
        """The switch state: from the cache while fresh, else read by one thread at a time."""
        if not self._env_enabled():  # OFF: no store is read, whatever it holds
            return SwitchState(env_enabled=False)
        cached = self._cached
        if cached is not None and self._clock() < cached[1]:
            return cached[0]
        if not self._reading.acquire(blocking=cached is None):  # another thread is reading
            assert cached is not None  # with no value yet, this thread waited for the lock
            return cached[0]
        try:
            return self._read()
        finally:
            self._reading.release()

    def save(self, enabled: bool, changed_by: str) -> SwitchState:
        """Write the admin's change and return the new state."""
        now = utc_now()
        self._feeds.save({"_id": IntelDocId.SWITCH, "enabled": enabled, "changed_by": changed_by, "changed_at": now})
        after = SwitchState(self._env_enabled(), enabled, now, changed_by)
        self._changes += 1
        self._cached = (after, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        return after

    def _read(self) -> SwitchState:
        previous = self._cached
        if previous is not None and self._clock() < previous[1]:  # read by the thread that held the lock
            return previous[0]
        changes = self._changes
        try:
            stored = self._feeds.get(_id=IntelDocId.SWITCH)
        except MONGO_UNAVAILABLE_ERRORS:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency="external_intelligence_switch")
            if previous is not None and previous[0].known:  # keep the last value for a full period
                self._cached = (previous[0], self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
                return previous[0]
            unknown = SwitchState(True, runtime_enabled=False, known=False)
            self._cached = (unknown, self._clock() + RETRY_AFTER_OUTAGE_SECONDS)
            return unknown
        if self._changes != changes and self._cached is not None:  # an admin changed it meanwhile
            return self._cached[0]
        state = SwitchState(True) if stored is None else _stored_state(True, stored)
        self._cached = (state, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        return state


def _stored_state(env_enabled: bool, stored: dict[str, Any]) -> SwitchState:
    return SwitchState(
        env_enabled, bool(stored.get("enabled", True)), stored.get("changed_at"), stored.get("changed_by")
    )


@singleton
def get_intelligence_switch() -> IntelligenceSwitch:
    return IntelligenceSwitch(get_intel_feed_repository(), lambda: get_settings().external_intelligence_enabled)
