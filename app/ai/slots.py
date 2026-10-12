"""The AI call limiter: at most CII_MAX_CONCURRENT_AI_CALLS calls at once across every pod.

One Redis sorted set holds the calls in progress (member = a random id, score = when its slot expires). A Lua
script drops expired slots and takes a free one in one atomic step, timed by the Redis server's own clock, so
pods whose clocks differ still agree. A slot expires after its call's longest possible run, so a process that
dies mid-call frees its slot by itself."""

import math
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import structlog
from redis import Redis

from app.ai.common import seconds_left
from app.core.config import get_settings
from app.core.constants import AiLimits, ErrorMessage, LogEvent
from app.core.database import get_redis_client
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, Unavailable
from app.core.lease_signal import raise_if_lease_lost
from app.core.singletons import singleton

log = structlog.get_logger(__name__)

#: KEYS[1] the slots · ARGV[1] the cap · ARGV[2] seconds the slot is held at most · ARGV[3] the call's id.
#: 1 = taken, 0 = every slot is busy.
_TAKE_FREE_SLOT_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[1]) then
  redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
  return 1
end
return 0
"""

#: KEYS[1] the slots. The number of calls in progress now.
_COUNT_SLOTS_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
return redis.call('ZCARD', KEYS[1])
"""

#: How long this process waits for a free slot: the API answers callers, so it waits briefly; a worker waits
#: longer, because its job would otherwise only be retried later (set_ai_slot_wait_seconds).
_wait_seconds: float = AiLimits.API_SLOT_WAIT_SECONDS


def set_ai_slot_wait_seconds(seconds: float) -> None:
    """Call once at process start, before the first AI call (a worker: AiLimits.WORKER_SLOT_WAIT_SECONDS)."""
    global _wait_seconds
    _wait_seconds = seconds


def max_slot_hold_seconds(timeout_seconds: int) -> int:
    """A slot outlives its call's longest run (every retry at its full timeout) by a margin, never less."""
    return timeout_seconds * (AiLimits.RETRIES + 1) + AiLimits.SLOT_GRACE_SECONDS


class AiSlots:
    """`cap` 0 = no limit: no Redis call at all."""

    def __init__(self, redis: Redis | None, cap: int, wait_seconds: float) -> None:
        self._redis = redis
        self._cap = cap
        self._wait_seconds = wait_seconds

    @contextmanager
    def hold_slot(self, hold_seconds: int) -> Iterator[None]:
        """Holds one slot while the call runs; Unavailable when none frees up within the wait. LeaseLost,
        before the wait and after it, for a job that lost its lease meanwhile (its owner cancelled it, G214):
        every AI call passes here, so a stopped job spends nothing more, holding no slot another run needs."""
        raise_if_lease_lost()
        if self._redis is None or self._cap == 0:
            yield
            return
        call_id = uuid.uuid4().hex
        self._wait_for_free_slot(call_id, hold_seconds)
        try:
            raise_if_lease_lost()
            yield
        finally:
            self._release_slot(call_id)

    def count_calls_in_progress(self) -> float:
        """Calls in progress across every pod (the tsg_ai_slots_in_use gauge); NaN when Redis cannot say, so a
        scrape never fails and never shows a stale number."""
        if self._redis is None or self._cap == 0:
            return 0.0
        try:
            return float(self._redis.eval(_COUNT_SLOTS_SCRIPT, 1, AiLimits.SLOTS_KEY))  # type: ignore[arg-type]
        except REDIS_UNAVAILABLE_ERRORS:
            return math.nan

    def _wait_for_free_slot(self, call_id: str, hold_seconds: int) -> None:
        assert self._redis is not None
        left = seconds_left()  # a caller's own deadline (ai_deadline) shortens the wait, never lengthens it
        wait = self._wait_seconds if left is None else min(self._wait_seconds, left)
        deadline = time.monotonic() + wait
        pause = AiLimits.SLOT_FIRST_PAUSE_SECONDS
        while not self._redis.eval(
            _TAKE_FREE_SLOT_SCRIPT, 1, AiLimits.SLOTS_KEY, str(self._cap), str(hold_seconds), call_id
        ):
            if time.monotonic() + pause > deadline:
                log.warning(LogEvent.AI_SLOTS_BUSY, cap=self._cap, waited_seconds=round(wait, 1))
                raise Unavailable(ErrorMessage.AI_BUSY.format(seconds=round(wait)))
            time.sleep(pause)
            pause = min(pause * 2, AiLimits.SLOT_MAX_PAUSE_SECONDS)

    def _release_slot(self, call_id: str) -> None:
        assert self._redis is not None
        try:
            self._redis.zrem(AiLimits.SLOTS_KEY, call_id)
        except REDIS_UNAVAILABLE_ERRORS:  # the slot expires by itself; the call's answer must not be lost
            log.warning(LogEvent.AI_SLOT_FREE_FAILED, exc_info=True)


#: Tests and any caller that needs no limit.
UNLIMITED_AI_SLOTS = AiSlots(None, 0, 0)


@singleton
def get_ai_slots() -> AiSlots:
    cap = get_settings().max_concurrent_ai_calls
    return AiSlots(get_redis_client() if cap else None, cap, _wait_seconds)
