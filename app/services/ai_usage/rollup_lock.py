"""The AI usage add-up's Redis lock: one add-up at a time across workers and tools. Only its holder renews or
releases it, each in one Redis script, so a run whose lock ran out never extends or frees another run's."""

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from redis import Redis

from app.core.constants import AiUsageLimits, AiUsageMessage
from app.core.exceptions import Unavailable

_RENEW_IF_HELD = """if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('expire', KEYS[1], ARGV[2]) end return 0"""
_RELEASE_IF_HELD = """if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1]) end return 0"""
#: The token of an add-up with no Redis to share a lock through (one process): always held.
NO_REDIS = "no-redis"


@contextmanager
def held_rollup_lock(redis: Redis | None, wait_seconds: float = 0) -> Iterator[str | None]:
    """The lock's token once held, waited for up to `wait_seconds`; None while another add-up keeps it.
    Released at the end only while still this holder's."""
    if redis is None:
        yield NO_REDIS
        return
    token, deadline = uuid.uuid4().hex, time.monotonic() + wait_seconds
    key, seconds = AiUsageLimits.ROLLUP_LOCK_KEY, AiUsageLimits.ROLLUP_LOCK_SECONDS
    while not (held := bool(redis.set(key, token, nx=True, ex=seconds))) and time.monotonic() < deadline:
        time.sleep(1)  # ponytail: a poll a second; the add-up holding it takes seconds, rarely minutes
    try:
        yield token if held else None
    finally:
        if held:
            redis.eval(_RELEASE_IF_HELD, 1, key, token)


def renew_rollup_lock(redis: Redis | None, token: str) -> None:
    """Another ROLLUP_LOCK_SECONDS for its holder; Unavailable when it ran out (another add-up may hold it
    now, so this one must stop writing)."""
    if redis is None:
        return
    key, seconds = AiUsageLimits.ROLLUP_LOCK_KEY, AiUsageLimits.ROLLUP_LOCK_SECONDS
    if not redis.eval(_RENEW_IF_HELD, 1, key, token, str(seconds)):
        raise Unavailable(AiUsageMessage.ROLLUP_LOCK_LOST)
