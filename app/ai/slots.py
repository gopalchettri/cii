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
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import NoReturn, cast

import structlog
from redis import Redis
from redis.exceptions import RedisError

from app.ai import limiter_scripts
from app.ai.retry_waits import busy_retry_wait, rate_limited_wait
from app.core import metrics
from app.core.constants import AI_OUTAGE_MESSAGES, AiLimits, AiOutage, AiOutageSource, ErrorMessage, LogEvent
from app.core.exceptions import Unavailable
from app.core.lease_signal import raise_if_lease_lost, start_thread_without_lease

log = structlog.get_logger(__name__)


def sleep_unless_lease_lost(seconds: float) -> None:
    """Sleeps `seconds`, checking the job's lease every AiLimits.LEASE_CHECK_SECONDS: LeaseLost once lost."""
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        time.sleep(min(left, AiLimits.LEASE_CHECK_SECONDS))
        raise_if_lease_lost()


class AiSlots:
    """Records every AI call in flight across the pods (the sorted set `key`, AiLimits.SLOTS_KEY by default)
    and starts one only while fewer run than the limit: `cap` (0 = none), or the lower limit a gateway 429
    set (note_rate_limited) until a few minutes pass with no 429. `redis` None: no limit, none recorded. A
    daemon thread renews this process's slots every SLOT_RENEW_SECONDS; a slot not renewed for
    SLOT_LEASE_SECONDS ends, so a process that died stops counting within a lease."""

    def __init__(self, redis: Redis | None, cap: int, wait_seconds: float, key: str = "") -> None:
        self._redis = redis
        self._cap = cap
        self.wait_seconds = wait_seconds if redis is not None else 0  # no limit: no wait for a slot
        self._key = key or AiLimits.SLOTS_KEY
        self._limit_key = f"{key}:limit" if key else AiLimits.SLOTS_LIMIT_KEY
        self._held: set[str] = set()  # this process's calls in flight: the slots its renewer renews
        self._unreleased: set[str] = (
            set()
        )  # slots whose release a Redis failure missed: freed by the next take
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
    def hold_slot(self, task: str, waits: bool = True) -> Iterator[float]:
        """Holds one slot while the call runs, giving the seconds it waited; Unavailable when its turn does
        not come within the wait (none with `waits` false); an answered call raises a 429's limit by 1 /
        limit. LeaseLost before, during and after the wait for a job whose lease was lost (cancelled), so a
        stopped job holds no slot another run needs. `task`: whose refusal tsg_ai_outages_total counts."""
        raise_if_lease_lost()
        call_id, started = uuid.uuid4().hex, time.monotonic()
        if not self._redis_in_use() or not self._take_slot(call_id, task, waits):
            yield time.monotonic() - started
            return
        self._held.add(call_id)
        answered = False
        try:
            raise_if_lease_lost()
            yield time.monotonic() - started
            answered = True
        finally:
            self._held.discard(call_id)
            self._release_slot(call_id, answered)

    def note_rate_limited(self) -> None:
        """A gateway 429: this pool's limit on every pod becomes half its calls in flight, at most once each
        ADAPTIVE_CUT_SPACING_SECONDS, never below the floor, until ADAPTIVE_LIMIT_TTL_SECONDS with no 429."""
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
        """A client, and no Redis failure at cap 0 in the last REDIS_SKIP_SECONDS."""
        return self._redis is not None and time.monotonic() >= self._skip_redis_until

    def _take_slot(self, call_id: str, task: str, waits: bool) -> bool:
        """True once recorded, when its turn comes within the wait (else Unavailable). A Redis error with no
        cap never fails the call: False, unrecorded (logged once); with a cap, an outage the job retries."""
        wait = self.wait_seconds if waits else 0
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
        """Frees the slot, raising a 429's limit when the call was answered: one round trip."""
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
        """Every SLOT_RENEW_SECONDS, one script renews the slots this process holds; no error ends it."""
        while True:
            time.sleep(AiLimits.SLOT_RENEW_SECONDS)
            if held := self._held.copy():
                try:
                    self._renew_leases(keys=[self._key], args=[AiLimits.SLOT_LEASE_SECONDS, *held])
                except Exception:  # noqa: BLE001 — a dead renewer would end every lease of this process
                    self._note_redis_failure()

    def _note_redis_failure(self) -> None:
        """Redis failed and the call went on without it: logged once, until a slot is recorded again."""
        if not self._cap:  # a hung Redis would cost every call its timeout; a cap must still hold
            self._skip_redis_until = time.monotonic() + AiLimits.REDIS_SKIP_SECONDS
        if not self._untracked_logged:
            self._untracked_logged = True
            log.warning(LogEvent.AI_SLOTS_UNTRACKED, limiter=self._key, exc_info=True)


class AiRequestRate:
    """One model's requests in a `scope` (a module's own, or none), retries included, on their own Redis key:
    60 / `per_minute` s apart, or a large request's tokens x 60 / `tokens_per_minute` s; a 429 pauses it
    (pause). Both 0 = no limit, no Redis call. `waits_out_rate_limits`: true in a worker, false in the API."""

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
        self._per_minute, self._tokens_per_minute = per_minute, tokens_per_minute
        limited = bool(per_minute or tokens_per_minute)
        self.wait_seconds = wait_seconds if limited else 0  # no limit: no turn, so no wait for one
        self._waits_out_rate_limits = waits_out_rate_limits
        self._skip_redis_until = 0.0  # time.monotonic(): set by a Redis failure
        if redis is not None and limited:
            self._reserve_send_time = redis.register_script(limiter_scripts.RESERVE_SEND_TIME_SCRIPT)
            self._seconds_to_send_time = redis.register_script(limiter_scripts.SECONDS_TO_SEND_TIME_SCRIPT)
            self._pause_send_time = redis.register_script(limiter_scripts.PAUSE_SEND_TIME_SCRIPT)

    def wait_for_turn(self, task: str, tokens: int = 0) -> float:
        """Waits for the send time it reserves for a request of about `tokens`; the seconds waited.
        Unavailable, nothing reserved, when that time is further off than the wait; LeaseLost for a job that
        lost its lease. A Redis error never fails the request: it goes ahead unspaced (_redis_failed)."""
        interval = max(
            60 / self._per_minute if self._per_minute else 0.0,
            tokens * 60 / self._tokens_per_minute if self._tokens_per_minute else 0.0,
        )
        if interval == 0 or not self._in_use():
            return 0.0
        raise_if_lease_lost()
        try:
            wait = float(self._reserve_send_time(keys=[self._key], args=[interval, self.wait_seconds]))
        except RedisError:  # down, hung, or refusing writes (MISCONF, OOM, READONLY)
            return self._redis_failed()
        if wait < 0:
            self._refuse(task)
        metrics.AI_REQUEST_RATE_WAIT.labels(self._model).observe(wait)
        sleep_unless_lease_lost(wait)
        return wait

    def wait_for_send_time(self, task: str) -> float:
        """Waits, reserving nothing and holding no AI slot, for the model's next send time (a 429's pause or a
        line of turns); the seconds waited. Unavailable when further off than the wait, LeaseLost as above."""
        if not self._in_use():
            return 0.0
        raise_if_lease_lost()
        try:
            wait = float(self._seconds_to_send_time(keys=[self._key]))
        except RedisError:  # down, hung, or refusing writes (MISCONF, OOM, READONLY)
            return self._redis_failed()
        if wait > self.wait_seconds:
            self._refuse(task)
        sleep_unless_lease_lost(wait)
        return wait

    def pause(self, seconds: float) -> float:
        """A 429 from this model: its next send time, on every pod, becomes at least `seconds` away, so the
        calls queued for it wait (wait_for_send_time) instead of each drawing a 429 of its own; `seconds`."""
        if self._in_use():
            try:
                self._pause_send_time(keys=[self._key], args=[seconds])
            except RedisError:  # its own retry still waits; the others may meet a 429 of their own
                self._redis_failed()
        return seconds

    def _in_use(self) -> bool:
        """A Redis client and a limit, and no Redis failure in the last REDIS_SKIP_SECONDS."""
        limited = self._per_minute or self._tokens_per_minute
        return self._redis is not None and bool(limited) and time.monotonic() >= self._skip_redis_until

    def _redis_failed(self) -> float:
        """Redis is left alone for REDIS_SKIP_SECONDS, logged; the request waits none."""
        self._skip_redis_until = time.monotonic() + AiLimits.REDIS_SKIP_SECONDS
        log.warning(LogEvent.AI_SLOTS_UNTRACKED, limiter=self._key, exc_info=True)
        return 0.0

    def _refuse(self, task: str) -> NoReturn:
        """No turn within the wait: TSG's own refusal, counted for `task` (Unavailable, busy)."""
        limits = {"per_minute": self._per_minute, "tokens_per_minute": self._tokens_per_minute}
        log.warning(
            LogEvent.AI_REQUEST_RATE_BUSY, model=self._model, wait_seconds=self.wait_seconds, **limits
        )
        metrics.AI_OUTAGES.labels(task, AiOutage.BUSY, AiOutageSource.LIMITER).inc()
        raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)

    def wait_after_rate_limit(self, retry_after: str | None, attempt: int, waited: float) -> float | None:
        """How long a rate-limited request (HTTP 429) waits before it is asked again: as rate_limited_wait
        says in a worker, as any busy request in the API (it answers a caller); None: not asked again."""
        if self._waits_out_rate_limits:
            return rate_limited_wait(retry_after, attempt, waited)
        return busy_retry_wait(attempt)


#: Tests and any caller that needs no limit.
UNLIMITED_AI_SLOTS = AiSlots(None, 0, 0)
UNLIMITED_AI_REQUEST_RATE = AiRequestRate(None, "", 0, 0)
