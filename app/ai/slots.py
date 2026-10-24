"""The AI call limiters: at most CII_MAX_CONCURRENT_AI_CALLS calls at once and each model's own requests a
minute (CII_CHAT_REQUESTS_PER_MINUTE and its siblings), across every pod.

One Redis sorted set holds the calls in progress (member = a random id, score = when its slot expires). A Lua
script drops expired slots and takes a free one in one atomic step, timed by the Redis server's own clock, so
pods whose clocks differ still agree. A slot expires after its call's longest possible run, so a process that
dies mid-call frees its slot by itself. Each model's request rate is its own Redis key, its next send time:
each request to that model reserves it the same way and waits for it. A request the provider rate-limits
(HTTP 429) waits as AiRequestRate.wait_after_rate_limit says."""

import math
import random
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import structlog
from redis import Redis

from app.core import metrics
from app.core.constants import AI_OUTAGE_MESSAGES, AiLimits, AiOutage, ErrorMessage, LogEvent
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, Unavailable
from app.core.lease_signal import raise_if_lease_lost

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

#: KEYS[1] the next send time · ARGV[1] seconds between two requests · ARGV[2] the longest wait accepted.
#: The seconds to wait, that send time then reserved; -1, nothing reserved, when the wait would be longer.
_RESERVE_SEND_TIME_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local send_at = math.max(now, tonumber(redis.call('GET', KEYS[1]) or now))
local wait = send_at - now
if wait > tonumber(ARGV[2]) then
  return '-1'
end
local interval = tonumber(ARGV[1])
redis.call('SET', KEYS[1], tostring(send_at + interval), 'PX', math.ceil((wait + interval) * 1000))
return tostring(wait)
"""


def sleep_unless_lease_lost(seconds: float) -> None:
    """Sleeps `seconds`, checking the job's lease every AiLimits.LEASE_CHECK_SECONDS: LeaseLost once lost."""
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        time.sleep(min(left, AiLimits.LEASE_CHECK_SECONDS))
        raise_if_lease_lost()


def rate_limited_wait(retry_after: str | None, attempt: int, waited: float) -> float | None:
    """How long a rate-limited request waits before it is asked again: its Retry-After header's seconds, at
    most RATE_LIMITED_MAX_WAIT_SECONDS, else the attempt's RATE_LIMITED_WAITS_SECONDS +-RATE_LIMITED_JITTER;
    never past RATE_LIMITED_TOTAL_WAIT_SECONDS in all. None: asked enough, the outage reaches the caller."""
    left = AiLimits.RATE_LIMITED_TOTAL_WAIT_SECONDS - waited
    if attempt >= len(AiLimits.RATE_LIMITED_WAITS_SECONDS) or left <= 0:
        return None
    try:
        asked = float(retry_after or "")
    except ValueError:  # none, or an HTTP date (LiteLLM's proxy sends seconds)
        jitter = random.uniform(-AiLimits.RATE_LIMITED_JITTER, AiLimits.RATE_LIMITED_JITTER)  # noqa: S311
        wait = AiLimits.RATE_LIMITED_WAITS_SECONDS[attempt] * (1 + jitter)
    else:
        wait = min(AiLimits.RATE_LIMITED_MAX_WAIT_SECONDS, max(0.0, asked))  # this order: "nan" waits 0
    return min(wait, left)


def busy_retry_wait(attempt: int) -> float | None:
    """A busy request's wait before it is asked again: 0.5 s, doubling; None after AiLimits.RETRIES."""
    return AiLimits.RETRY_FIRST_WAIT_SECONDS * 2**attempt if attempt < AiLimits.RETRIES else None


def max_slot_hold_seconds(timeout_seconds: int, turn_wait_seconds: float) -> int:
    """A slot outlives its call's longest run (every request at its full timeout after its longest
    request-rate turn, a rate-limited one's waits too) by a margin, never less."""
    requests = max(AiLimits.RETRIES, len(AiLimits.RATE_LIMITED_WAITS_SECONDS)) + 1
    longest_run = math.ceil((timeout_seconds + turn_wait_seconds) * requests)
    return longest_run + AiLimits.RATE_LIMITED_TOTAL_WAIT_SECONDS + AiLimits.SLOT_GRACE_SECONDS


class AiSlots:
    """`cap` 0 = no limit: no Redis call at all. `key`: the sorted set, AiLimits.SLOTS_KEY by default."""

    def __init__(self, redis: Redis | None, cap: int, wait_seconds: float, key: str = "") -> None:
        self._redis = redis
        self._cap = cap
        self.wait_seconds = wait_seconds
        self._key = key or AiLimits.SLOTS_KEY
        if redis is not None and cap:  # registered: each poll sends EVALSHA, not the whole script
            self._take_free_slot = redis.register_script(_TAKE_FREE_SLOT_SCRIPT)
            self._count_slots = redis.register_script(_COUNT_SLOTS_SCRIPT)

    @contextmanager
    def hold_slot(self, hold_seconds: int, waits: bool = True) -> Iterator[None]:
        """Holds one slot while the call runs; Unavailable when none frees up within the wait (none at all
        with `waits` false). LeaseLost, before the wait, while it waits and after it, for a job that lost its
        lease meanwhile (its owner cancelled it): every AI call passes here, so a stopped job spends nothing
        more, holding no slot another run needs."""
        raise_if_lease_lost()
        if self._redis is None or self._cap == 0:
            yield
            return
        call_id = uuid.uuid4().hex
        self._wait_for_free_slot(call_id, hold_seconds, self.wait_seconds if waits else 0)
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
            return float(self._count_slots(keys=[self._key]))
        except REDIS_UNAVAILABLE_ERRORS:
            return math.nan

    def _wait_for_free_slot(self, call_id: str, hold_seconds: int, wait: float) -> None:
        assert self._redis is not None
        deadline = time.monotonic() + wait
        pause = AiLimits.SLOT_FIRST_PAUSE_SECONDS
        while not self._take_free_slot(keys=[self._key], args=[self._cap, hold_seconds, call_id]):
            raise_if_lease_lost()
            if time.monotonic() + pause > deadline:
                log.warning(
                    LogEvent.AI_SLOTS_BUSY, key=self._key, cap=self._cap, waited_seconds=round(wait, 1)
                )
                raise Unavailable(ErrorMessage.AI_BUSY.format(seconds=round(wait)), reason=AiOutage.BUSY)
            # Jittered, so the threads that found every slot busy together do not all poll again together.
            time.sleep(pause * random.uniform(0.5, 1.0))  # noqa: S311 — timing jitter, not a secret
            pause = min(pause * 2, AiLimits.SLOT_MAX_PAUSE_SECONDS)

    def _release_slot(self, call_id: str) -> None:
        assert self._redis is not None
        try:
            self._redis.zrem(self._key, call_id)
        except REDIS_UNAVAILABLE_ERRORS:  # the slot expires by itself; the call's answer must not be lost
            log.warning(LogEvent.AI_SLOT_FREE_FAILED, exc_info=True)


class AiRequestRate:
    """One model's requests (each model has its own limit), each retry included, spaced 60 / `per_minute` s
    apart on its own Redis key. `per_minute` 0 = no limit: no Redis call at all. `waits_out_rate_limits`: true
    in a worker, false in the API (wait_after_rate_limit)."""

    def __init__(
        self,
        redis: Redis | None,
        model: str,
        per_minute: int,
        wait_seconds: float,
        waits_out_rate_limits: bool = True,
    ) -> None:
        self._redis = redis
        self._model = model
        self._key = AiLimits.REQUEST_RATE_KEY.format(model=model)
        self._per_minute = per_minute
        self.wait_seconds = wait_seconds
        self._waits_out_rate_limits = waits_out_rate_limits
        if redis is not None and per_minute:
            self._reserve_send_time = redis.register_script(_RESERVE_SEND_TIME_SCRIPT)

    def wait_for_turn(self) -> float:
        """Waits for the send time it reserves; the seconds waited. Unavailable, nothing reserved, when that
        time is further away than the wait; LeaseLost before and while it waits, for a job that lost its
        lease."""
        if self._redis is None or self._per_minute == 0:
            return 0.0
        raise_if_lease_lost()
        interval = 60 / self._per_minute
        wait = float(self._reserve_send_time(keys=[self._key], args=[interval, self.wait_seconds]))
        if wait < 0:
            log.warning(
                LogEvent.AI_REQUEST_RATE_BUSY,
                model=self._model,
                per_minute=self._per_minute,
                wait_seconds=self.wait_seconds,
            )
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)
        metrics.AI_REQUEST_RATE_WAIT.labels(self._model).observe(wait)
        sleep_unless_lease_lost(wait)
        return wait

    def wait_after_rate_limit(self, retry_after: str | None, attempt: int, waited: float) -> float | None:
        """How long a rate-limited request (HTTP 429) waits before it is asked again: as rate_limited_wait
        says in a worker, as any busy request in the API (it answers a caller); None: not asked again."""
        if self._waits_out_rate_limits:
            return rate_limited_wait(retry_after, attempt, waited)
        return busy_retry_wait(attempt)


#: Tests and any caller that needs no limit.
UNLIMITED_AI_SLOTS = AiSlots(None, 0, 0)
UNLIMITED_AI_REQUEST_RATE = AiRequestRate(None, "", 0, 0)
