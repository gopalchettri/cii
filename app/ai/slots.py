"""The AI call limiters, across every pod: the AI calls in flight, at most CII_MAX_CONCURRENT_AI_CALLS (0 = no
fixed limit) or the lower limit a gateway 429 set, and each model's own requests a minute.

One Redis sorted set holds the calls in progress (member = a random id, score = when its slot's lease ends). A
Lua script (app/ai/limiter_scripts.py) drops ended leases and takes a free slot in one atomic step; while a
limit is in force, waiters stand in a line there and a freed slot goes to the first in it. Each process
renews the leases of the calls it runs, so a process that dies mid-call frees its slots within a lease. A
429 sets a limit beside it: half the calls then in flight, raised a little by each answer, gone a few minutes
after the last 429. Each model's request rate is its own Redis key, its next send time: each request to that
model reserves it the same way and waits for it. A Redis failure is an outage, never an AI error."""

import math
import random
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import NoReturn, cast

import structlog
from redis import Redis
from redis.exceptions import RedisError

from app.ai import limiter_scripts
from app.core import metrics
from app.core.config import get_settings
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiLimits,
    AiOutage,
    AiOutageSource,
    ChatModule,
    ErrorMessage,
    LogEvent,
)
from app.core.database import get_redis_client
from app.core.exceptions import Unavailable
from app.core.lease_signal import raise_if_lease_lost, start_thread_without_lease
from app.core.singletons import singleton

log = structlog.get_logger(__name__)


def sleep_unless_lease_lost(seconds: float) -> None:
    """Sleeps `seconds`, checking the job's lease every AiLimits.LEASE_CHECK_SECONDS: LeaseLost once lost."""
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        time.sleep(min(left, AiLimits.LEASE_CHECK_SECONDS))
        raise_if_lease_lost()


def rate_limited_wait(retry_after: str | None, attempt: int, waited: float) -> float | None:
    """A 429's wait: its step or a longer Retry-After, capped, jittered, never past the total; None: asked enough."""
    left = AiLimits.RATE_LIMITED_TOTAL_WAIT_SECONDS - waited
    if attempt >= len(AiLimits.RATE_LIMITED_WAITS_SECONDS) or left <= 0:
        return None
    try:
        asked = float(retry_after or "")  # none, or an HTTP date (LiteLLM's proxy sends seconds): 0
    except ValueError:
        asked = 0.0
    asked = asked if math.isfinite(asked) else 0.0  # "nan" or "inf" asks for nothing
    capped = min(max(AiLimits.RATE_LIMITED_WAITS_SECONDS[attempt], asked), AiLimits.RATE_LIMITED_MAX_WAIT_SECONDS)
    # Jittered after the cap: every LiteLLM 429 asks for 60 s, so capped waits would all be the same.
    jitter = random.uniform(-AiLimits.RATE_LIMITED_JITTER, AiLimits.RATE_LIMITED_JITTER)  # noqa: S311
    return min(capped * (1 + jitter), left)


def busy_retry_wait(attempt: int) -> float | None:
    """A busy request's wait before it is asked again: 0.5 s, doubling; None after AiLimits.RETRIES."""
    return AiLimits.RETRY_FIRST_WAIT_SECONDS * 2**attempt if attempt < AiLimits.RETRIES else None


class AiSlots:
    """AI calls in flight across the pods (sorted set `key`), started only below `cap` or a 429's lower limit."""

    def __init__(self, redis: Redis | None, cap: int, wait_seconds: float, key: str = "") -> None:
        self._redis = redis
        self._cap = cap
        self.wait_seconds = wait_seconds if redis is not None else 0  # no limit: no wait for a slot
        self._key = key or AiLimits.SLOTS_KEY
        self._limit_key = f"{key}:limit" if key else AiLimits.SLOTS_LIMIT_KEY
        self._held: set[str] = set()  # this process's calls in flight: the slots its renewer renews
        self._unreleased: set[str] = set()  # slots whose release a Redis failure missed: freed by the next take
        self._skip_redis_until = 0.0  # time.monotonic(): set at cap 0 by a Redis failure
        self._untracked_logged = False
        if redis is not None:  # registered: each poll sends EVALSHA, not the whole script
            self._take_free_slot = redis.register_script(limiter_scripts.TAKE_FREE_SLOT_SCRIPT)
            self._free_slot = redis.register_script(limiter_scripts.FREE_SLOT_SCRIPT)
            self._count_slots = redis.register_script(limiter_scripts.COUNT_SLOTS_SCRIPT)
            self._cut_limit = redis.register_script(limiter_scripts.CUT_LIMIT_SCRIPT)
            self._renew_leases = redis.register_script(limiter_scripts.RENEW_LEASES_SCRIPT)
            start_thread_without_lease("ai-slot-leases", self._renew_leases_forever)

    @contextmanager
    def hold_slot(self, task: str) -> Iterator[None]:
        """Holds one slot while the call runs; Unavailable after the wait, LeaseLost for a job that lost its lease."""
        raise_if_lease_lost()
        call_id = uuid.uuid4().hex
        if not self._redis_in_use() or not self._take_slot(call_id, task):
            yield
            return
        self._held.add(call_id)
        answered = False
        try:
            raise_if_lease_lost()
            yield
            answered = True
        finally:
            self._held.discard(call_id)
            self._release_slot(call_id, answered)

    def note_rate_limited(self) -> None:
        """A gateway 429: halves this pool's limit on every pod, floored, until ADAPTIVE_LIMIT_TTL_SECONDS pass."""
        if not self._redis_in_use():
            return
        floor, ttl = AiLimits.ADAPTIVE_LIMIT_FLOOR, AiLimits.ADAPTIVE_LIMIT_TTL_SECONDS
        args = [floor, AiLimits.ADAPTIVE_CUT_SPACING_SECONDS, ttl]
        try:
            cut = int(self._cut_limit(keys=[self._key, self._limit_key], args=args))
        except RedisError:  # logged, never raised: the call's retry must not be lost
            self._note_redis_failure()
            return
        if cut:
            log.info(LogEvent.AI_LIMIT_CUT, limiter=self._key, limit=cut)

    def count_calls_in_progress(self) -> float:
        """Calls in progress on every pod (tsg_ai_slots_in_use); NaN when Redis cannot say, never stale."""
        if self._redis is None:
            return 0.0
        try:
            return float(self._count_slots(keys=[self._key]))
        except RedisError:  # down, or refusing the script's write (READONLY, MISCONF, OOM)
            return math.nan

    def current_limit(self) -> float:
        """The limit in force (tsg_ai_slots_cap): `cap` or a 429's, the lower; 0 = none; NaN when unknown."""
        if self._redis is None:
            return float(self._cap)
        try:
            shared = cast(str | None, self._redis.hget(self._limit_key, "limit"))  # decoded: a str
        except RedisError:
            return math.nan
        limits = [limit for limit in (self._cap, math.floor(float(shared or 0))) if limit]
        return float(min(limits, default=0))

    def _redis_in_use(self) -> bool:
        return self._redis is not None and time.monotonic() >= self._skip_redis_until

    def _take_slot(self, call_id: str, task: str) -> bool:
        wait = self.wait_seconds
        deadline, pause = time.monotonic() + wait, AiLimits.SLOT_FIRST_PAUSE_SECONDS
        keys = [self._key, self._limit_key, f"{self._key}:line", f"{self._key}:line_polls"]
        stale = AiLimits.SLOT_WAITER_STALE_SECONDS
        args = [str(self._cap), str(AiLimits.SLOT_LEASE_SECONDS), call_id, str(stale), str(self.wait_seconds)]
        missed = list(self._unreleased)  # freed by the script before it counts the calls in flight
        try:
            while True:
                last_try = time.monotonic() + pause > deadline  # refused now, it also leaves the line
                if self._take_free_slot(keys=keys, args=[*args, int(last_try), *missed]):
                    break
                raise_if_lease_lost()
                if last_try:
                    limit, waited = self.current_limit(), round(wait, 1)  # the cap or a 429's, the lower
                    log.warning(LogEvent.AI_SLOTS_BUSY, limiter=self._key, limit=limit, waited_seconds=waited)
                    metrics.AI_OUTAGES.labels(task, AiOutage.BUSY, AiOutageSource.LIMITER).inc()
                    raise Unavailable(ErrorMessage.AI_BUSY.format(seconds=round(wait)), reason=AiOutage.BUSY)
                # Jittered: the threads that found every slot busy together do not all poll again together.
                time.sleep(pause * random.uniform(0.5, 1.0))  # noqa: S311 — timing jitter, not a secret
                pause = min(pause * 2, AiLimits.SLOT_MAX_PAUSE_SECONDS)
        except RedisError as exc:  # down, or refusing writes (MISCONF, OOM, READONLY)
            if self._cap:
                raise Unavailable(ErrorMessage.REDIS_UNREACHABLE) from exc
            self._note_redis_failure()
            return False
        self._untracked_logged = False
        self._unreleased.difference_update(missed)
        return True

    def _release_slot(self, call_id: str, answered: bool) -> None:
        if not self._redis_in_use():
            self._unreleased.add(call_id)  # else it counted as in flight until its lease ended
            return
        try:
            self._free_slot(keys=[self._key, self._limit_key], args=[call_id, int(answered)])
        except RedisError:  # the call's answer must not be lost: the next take frees the slot
            self._unreleased.add(call_id)
            if self._cap:
                log.warning(LogEvent.AI_SLOT_FREE_FAILED, exc_info=True)
            else:
                self._note_redis_failure()

    def _renew_leases_forever(self) -> None:
        while True:
            time.sleep(AiLimits.SLOT_RENEW_SECONDS)
            if held := self._held.copy():
                try:
                    self._renew_leases(keys=[self._key], args=[AiLimits.SLOT_LEASE_SECONDS, *held])
                except Exception:  # noqa: BLE001 — a dead renewer would end every lease of this process
                    self._note_redis_failure()

    def _note_redis_failure(self) -> None:
        if not self._cap:  # a hung Redis would cost every call its timeout; a cap must still hold
            self._skip_redis_until = time.monotonic() + AiLimits.REDIS_SKIP_SECONDS
        if not self._untracked_logged:
            self._untracked_logged = True
            log.warning(LogEvent.AI_SLOTS_UNTRACKED, limiter=self._key, exc_info=True)


class AiRequestRate:
    """One model's request spacing in a `scope` on its own Redis key, by requests and tokens a minute."""

    def __init__(  # noqa: PLR0913 — one model's two limits, its scope and how its process waits
        self,
        redis: Redis | None,
        model: str,
        per_minute: int,
        wait_seconds: float,
        waits_out_rate_limits: bool = True,
        tokens_per_minute: int = 0,
        scope: str = "",
    ) -> None:
        self._redis, self._model = redis, model
        self._key = AiLimits.REQUEST_RATE_KEY.format(model=f"{scope}:{model}" if scope else model)
        self._pause_key = f"{self._key}:paused"  # a 429's pause end
        self._line_key = f"{self._key}:chain"  # the id of the line of turns the send time ends
        self._booked = threading.local()  # .turn: (tokens, line id) this thread reserved last, or None
        self._per_minute, self._tokens_per_minute = per_minute, tokens_per_minute
        limited = bool(per_minute or tokens_per_minute)
        self.wait_seconds = wait_seconds if limited else 0  # no limit: no turn, so no wait for one
        self._waits_out_rate_limits = waits_out_rate_limits
        self._skip_redis_until = 0.0  # time.monotonic(): set by a Redis failure
        if redis is not None and limited:
            self._reserve_send_time = redis.register_script(limiter_scripts.RESERVE_SEND_TIME_SCRIPT)
            self._seconds_to_send_time = redis.register_script(limiter_scripts.SECONDS_TO_SEND_TIME_SCRIPT)
            self._pause_send_time = redis.register_script(limiter_scripts.PAUSE_SEND_TIME_SCRIPT)
            self._give_back_send_time = redis.register_script(limiter_scripts.GIVE_BACK_SEND_TIME_SCRIPT)

    def wait_for_turn(self, task: str, tokens: int = 0) -> float:
        """Waits for the send time it reserves for about `tokens`; the seconds waited (a Redis error: none)."""
        self._booked.turn = None
        interval = self._spacing(tokens)
        if interval == 0 or not self._in_use():
            return 0.0
        raise_if_lease_lost()
        keys = [self._key, self._line_key, self._pause_key]
        args = [interval, self.wait_seconds, AiLimits.RATE_BURST_SECONDS]
        try:
            wait, line = self._reserve_send_time(keys=keys, args=args)
        except RedisError:  # down, hung, or refusing writes (MISCONF, OOM, READONLY)
            return self._redis_failed()
        if (wait := float(wait)) < 0:
            self._refuse(task)
        self._booked.turn = (tokens, line)
        metrics.AI_REQUEST_RATE_WAIT.labels(self._model).observe(wait)
        sleep_unless_lease_lost(wait)
        return wait

    def wait_for_send_time(self, task: str) -> float:
        """Waits, holding no slot, for the model's next send time (a 429's pause or a long line); the seconds."""
        if not self._in_use():
            return 0.0
        raise_if_lease_lost()
        keys, args = [self._key, self._pause_key], [AiLimits.RATE_BURST_SECONDS]
        try:
            wait = longest = float(self._seconds_to_send_time(keys=keys, args=args))
        except RedisError:  # down, hung, or refusing writes (MISCONF, OOM, READONLY)
            return self._redis_failed()
        if wait > self.wait_seconds:
            self._refuse(task)
        waited = 0.0
        while wait > 0:
            step = min(wait, AiLimits.LEASE_CHECK_SECONDS)
            sleep_unless_lease_lost(step)
            waited += step
            try:
                wait = min(float(self._seconds_to_send_time(keys=keys, args=args)), longest - waited)
            except RedisError:
                self._redis_failed()
                break
        return waited

    def pause(self, seconds: float) -> float:
        """A 429: the model's next send time on every pod moves `seconds` away and its burst is used up; `seconds`."""
        if self._in_use():
            try:
                keys = [self._key, self._pause_key, self._line_key]
                self._pause_send_time(keys=keys, args=[seconds, AiLimits.RATE_BURST_SECONDS])
            except RedisError:  # its own retry still waits; the others may meet a 429 of their own
                self._redis_failed()
        return seconds

    def give_back(self, used: int) -> float:
        """Moves back, on every pod, the part of this thread's last turn the answer did not use, once."""
        turn, self._booked.turn = getattr(self._booked, "turn", None), None
        if turn is None:
            return 0.0
        booked, line = turn
        unused = self._spacing(booked) - self._spacing(used)
        if unused <= 0 or not self._in_use():
            return 0.0
        keys = [self._key, self._pause_key, self._line_key]
        try:
            return float(self._give_back_send_time(keys=keys, args=[unused, line]))
        except RedisError:  # the booking stays: later requests only wait longer
            return self._redis_failed()

    def _spacing(self, tokens: int) -> float:
        return max(
            60 / self._per_minute if self._per_minute else 0.0,
            tokens * 60 / self._tokens_per_minute if self._tokens_per_minute else 0.0,
        )

    def _in_use(self) -> bool:
        limited = self._per_minute or self._tokens_per_minute
        return self._redis is not None and bool(limited) and time.monotonic() >= self._skip_redis_until

    def _redis_failed(self) -> float:
        self._skip_redis_until = time.monotonic() + AiLimits.REDIS_SKIP_SECONDS
        log.warning(LogEvent.AI_SLOTS_UNTRACKED, limiter=self._key, exc_info=True)
        return 0.0

    def _refuse(self, task: str) -> NoReturn:
        limits = {"per_minute": self._per_minute, "tokens_per_minute": self._tokens_per_minute}
        log.warning(LogEvent.AI_REQUEST_RATE_BUSY, model=self._model, wait_seconds=self.wait_seconds, **limits)
        metrics.AI_OUTAGES.labels(task, AiOutage.BUSY, AiOutageSource.LIMITER).inc()
        raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)

    def wait_after_rate_limit(self, retry_after: str | None, attempt: int, waited: float) -> float | None:
        """A 429's wait: rate_limited_wait's in a worker, a busy wait's in the API; None: not asked again."""
        if self._waits_out_rate_limits:
            return rate_limited_wait(retry_after, attempt, waited)
        return busy_retry_wait(attempt)


#: Tests and any caller that needs no limit.
UNLIMITED_AI_SLOTS = AiSlots(None, 0, 0)
UNLIMITED_AI_REQUEST_RATE = AiRequestRate(None, "", 0, 0)


#: This process's wait for a slot or request turn, and whether it waits out a 429: the API waits briefly and
#: retries a 429 as any busy answer; a worker waits longer and waits out a 429 (app/worker/lifecycle.py).
_ai_slot_wait_seconds: float = AiLimits.API_SLOT_WAIT_SECONDS
_waits_out_rate_limits = False


@singleton
def get_ai_slots() -> AiSlots:
    """The search calls' slots (embedding, reranker); at cap 0 a 429 still limits the calls in flight."""
    return AiSlots(get_redis_client(), get_settings().max_concurrent_ai_calls, _ai_slot_wait_seconds)


@singleton
def get_module_ai_slots() -> dict[ChatModule, AiSlots]:
    """Each module's own chat slots: its 429s never slow another module or the search calls."""
    redis, settings, key = get_redis_client(), get_settings(), AiLimits.SLOTS_KEY
    caps = {module: settings.chat_of(module).max_concurrent_ai_calls for module in ChatModule}
    return {module: AiSlots(redis, cap, _ai_slot_wait_seconds, f"{key}:{module}") for module, cap in caps.items()}


def ai_request_rate_for(model: str, per_minute: int, tokens_per_minute: int = 0, scope: str = "") -> AiRequestRate:
    """`model`'s own request-rate limiter in `scope` (a module's), with this process's waits."""
    redis = get_redis_client() if per_minute or tokens_per_minute else None
    return AiRequestRate(
        redis, model, per_minute, _ai_slot_wait_seconds, _waits_out_rate_limits, tokens_per_minute, scope
    )
