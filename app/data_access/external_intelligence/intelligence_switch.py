"""The on/off switch of external intelligence: the env master switch, read at each call, and the admin's
run-time flag, read from the store at most every SWITCH_CACHE_SECONDS; with the env off the store is never
read or written."""

import threading
import time
from collections.abc import Callable
from typing import Any

import structlog

from app.core.clock import utc_now
from app.core.constants import ErrorMessage, IntelDocId, IntelLimits, LogEvent, SwitchTiming
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Unavailable
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.models.external_intelligence.switch_state import SwitchState

log = structlog.get_logger(__name__)


class IntelligenceSwitch:
    """The one place the flag is read and changed."""

    def __init__(
        self,
        feeds: IntelFeedRepository,
        env_enabled: Callable[[], bool],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._feeds = feeds  # tsg_external_feed_status, whose switch document holds the run-time flag
        self._env_enabled = env_enabled  # reads EXTERNAL_INTELLIGENCE_ENABLED from the settings at each call
        self._clock = clock
        self._cached: tuple[SwitchState, float] | None = None  # replaced whole, so a reader never sees half
        self._reading = threading.Lock()  # one thread asks the store; the others use the last value
        self._changes = 0  # counts admin changes: a read that began before one must not overwrite it

    def is_on(self, sure: bool = False) -> bool:
        """True when both switches are on; a switch in doubt (its store unread, no value kept) reads off, or
        with `sure` raises Unavailable, so a writer that must be sure waits."""
        state = self.state()
        if sure and not state.known:
            raise Unavailable(ErrorMessage.MONGO_UNREACHABLE)
        return state.effective

    def state(self) -> SwitchState:
        """The switch state: from the cache while fresh, else read by one thread at a time (the others use the
        last value, or wait for the first one)."""
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
        """Write the admin's change and return the new state; raises when the store cannot be written
        (nothing changed)."""
        now = utc_now()
        self._feeds.save(
            {"_id": IntelDocId.SWITCH, "enabled": enabled, "changed_by": changed_by, "changed_at": now}
        )
        after = SwitchState(self._env_enabled(), enabled, now, changed_by)
        self._changes += 1
        self._cached = (after, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        return after

    def _read(self) -> SwitchState:
        """Read the flag from the store (the env switch is on); an outage keeps the last known value, or
        reads off (in doubt) and looks again soon; a change an admin made meanwhile wins over the read."""
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
            self._cached = (unknown, self._clock() + SwitchTiming.RETRY_AFTER_OUTAGE_SECONDS)
            return unknown
        if self._changes != changes and self._cached is not None:  # an admin changed it meanwhile
            return self._cached[0]
        state = SwitchState(True) if stored is None else _stored_state(True, stored)
        self._cached = (state, self._clock() + IntelLimits.SWITCH_CACHE_SECONDS)
        return state


def _stored_state(env_enabled: bool, stored: dict[str, Any]) -> SwitchState:
    """The switch document as a SwitchState: enabled unless set off, with who changed it and when."""
    return SwitchState(
        env_enabled, bool(stored.get("enabled", True)), stored.get("changed_at"), stored.get("changed_by")
    )
