"""One clock for every pod: this process's clock corrected to MongoDB's, so pods whose clocks disagree still
agree on when a job is due, when a lease ends and when a worker last beat. Read "now" only from here."""

import threading
import time
from datetime import UTC, datetime

import structlog

from app.core import metrics
from app.core.constants import Clock, LogEvent
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS

log = structlog.get_logger(__name__)

_local_epoch = time.time  # this pod's own clock; nothing else in the app reads it


class StoreClock:
    """This process's clock plus its offset to MongoDB's, measured again every Clock.CHECK_EVERY_SECONDS.
    While MongoDB cannot answer, the last offset stands (0 before the first answer)."""

    def __init__(self) -> None:
        self._measuring = threading.Lock()
        self._offset = 0.0  # seconds to add to this pod's clock
        self._next_check = 0.0  # time.monotonic() of the next measurement
        self._off = False  # logged as off: warned once, until it is back within Clock.WARN_OVER_SECONDS

    def epoch_seconds(self) -> float:
        if time.monotonic() >= self._next_check:
            self._measure()
        return _local_epoch() + self._offset

    def _measure(self) -> None:
        # One thread measures; the others go on with the last offset instead of waiting for MongoDB.
        if not self._measuring.acquire(blocking=False):
            return
        try:
            if time.monotonic() < self._next_check:
                return
            self._next_check = time.monotonic() + Clock.CHECK_EVERY_SECONDS
            try:
                sent = _local_epoch()
                server = get_mongodb().command("hello")["localTime"]
                received = _local_epoch()
            except MONGO_UNAVAILABLE_ERRORS:
                return
            if server.tzinfo is None:
                server = server.replace(tzinfo=UTC)
            self._offset = server.timestamp() - (sent + received) / 2  # half the round trip each way
        finally:
            self._measuring.release()
        metrics.CLOCK_OFFSET.set(self._offset)
        off = abs(self._offset) > Clock.WARN_OVER_SECONDS
        if off and not self._off:
            log.warning(LogEvent.CLOCK_OFF, offset_seconds=round(self._offset, 3))
        self._off = off


_clock = StoreClock()


def epoch_seconds() -> float:
    """Now as Unix seconds, on MongoDB's clock."""
    return _clock.epoch_seconds()


def utc_now() -> datetime:
    """Now (UTC), on MongoDB's clock."""
    return datetime.fromtimestamp(_clock.epoch_seconds(), UTC)
