"""One clock for every pod: this process's clock corrected to MongoDB's. Read "now" only from here."""

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

_measuring = threading.Lock()
_offset = 0.0  # seconds to add to this pod's clock
_next_check = 0.0  # time.monotonic() of the next measurement
_off = False  # logged as off: warned once, until it is back within Clock.WARN_OVER_SECONDS


def _measure() -> None:
    global _offset, _next_check, _off
    if not _measuring.acquire(blocking=False):
        return
    try:
        if time.monotonic() < _next_check:
            return
        _next_check = time.monotonic() + Clock.CHECK_EVERY_SECONDS
        try:
            sent = _local_epoch()
            server = get_mongodb().command("hello")["localTime"]
            received = _local_epoch()
        except MONGO_UNAVAILABLE_ERRORS:
            return
        if server.tzinfo is None:
            server = server.replace(tzinfo=UTC)
        _offset = server.timestamp() - (sent + received) / 2  # half the round trip each way
    finally:
        _measuring.release()
    metrics.CLOCK_OFFSET.set(_offset)
    off = abs(_offset) > Clock.WARN_OVER_SECONDS
    if off and not _off:
        log.warning(LogEvent.CLOCK_OFF, offset_seconds=round(_offset, 3))
    _off = off


def epoch_seconds() -> float:
    """Now as Unix seconds, on MongoDB's clock."""
    if time.monotonic() >= _next_check:
        _measure()
    return _local_epoch() + _offset


def utc_now() -> datetime:
    """Now (UTC), on MongoDB's clock."""
    return datetime.fromtimestamp(epoch_seconds(), UTC)
