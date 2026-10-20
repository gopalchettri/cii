"""The AI call limiter (app/ai/slots.py) on the test Redis: at most `cap` calls at once across every pod."""

import math
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.ai import slots
from app.ai.slots import AiSlots
from app.core.constants import AiLimits, AiOutage
from app.core.database import get_redis_client
from app.core.exceptions import LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal


@pytest.fixture(autouse=True)
def own_slots_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test its own sorted set, so no test sees another's slots."""
    key = f"tsg:test_ai_slots:{uuid.uuid4().hex}"
    monkeypatch.setattr(AiLimits, "SLOTS_KEY", key)
    yield
    get_redis_client().delete(key)


def test_two_calls_with_one_slot_run_one_after_the_other() -> None:
    """Step 6 Verify: with CII_MAX_CONCURRENT_AI_CALLS=1, two calls made at once run one after the other."""
    limiter = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    spans: dict[str, tuple[float, float]] = {}

    def call(name: str) -> None:
        with limiter.hold_slot(hold_seconds=60):
            started = time.monotonic()
            time.sleep(0.3)
            spans[name] = (started, time.monotonic())

    callers = [threading.Thread(target=call, args=(name,)) for name in ("first", "second")]
    for caller in callers:
        caller.start()
    for caller in callers:
        caller.join()
    (_, first_end), (second_start, _) = sorted(spans.values())
    assert second_start >= first_end  # never both at once


def test_no_free_slot_within_the_wait_is_unavailable() -> None:
    busy = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    impatient = AiSlots(get_redis_client(), cap=1, wait_seconds=0.2)
    with (
        busy.hold_slot(hold_seconds=60),
        pytest.raises(Unavailable, match="AI slot") as raised,
        impatient.hold_slot(hold_seconds=60),
    ):
        pass
    assert raised.value.reason == AiOutage.BUSY
    with impatient.hold_slot(hold_seconds=60):  # freed when the first call ended
        pass


def test_a_job_that_loses_its_lease_while_waiting_for_a_slot_stops_waiting() -> None:
    busy = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    patient = AiSlots(get_redis_client(), cap=1, wait_seconds=30)
    with busy.hold_slot(hold_seconds=60), lease_lost_signal("cancelled-run") as lost:
        threading.Timer(0.2, lost.set).start()
        started = time.monotonic()
        with pytest.raises(LeaseLost), patient.hold_slot(hold_seconds=60):
            pass
        assert time.monotonic() - started < 3


def test_the_slot_of_a_process_that_died_frees_itself() -> None:
    """A process killed mid-call never frees its slot: the slot expires after its hold time instead."""
    limiter = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    limiter._wait_for_free_slot("killed-process", hold_seconds=1)  # taken and never freed
    started = time.monotonic()
    with limiter.hold_slot(hold_seconds=60):
        assert 0.5 < time.monotonic() - started < 3


def test_no_limit_makes_no_redis_call() -> None:
    class NoRedis:
        def __getattr__(self, name: str) -> None:
            raise AssertionError(f"Redis was called ({name}) with no limit set")

    unlimited = AiSlots(NoRedis(), cap=0, wait_seconds=5)  # type: ignore[arg-type]
    with unlimited.hold_slot(hold_seconds=60):
        pass
    assert unlimited.count_calls_in_progress() == 0


def test_the_slots_in_use_are_counted_and_unknown_when_redis_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = AiSlots(get_redis_client(), cap=4, wait_seconds=5)
    with limiter.hold_slot(hold_seconds=60), limiter.hold_slot(hold_seconds=60):
        assert limiter.count_calls_in_progress() == 2
    assert limiter.count_calls_in_progress() == 0

    def redis_is_down(*_: object) -> None:
        raise RedisConnectionError("refused")

    monkeypatch.setattr(limiter._redis, "evalsha", redis_is_down)
    assert math.isnan(
        limiter.count_calls_in_progress()
    )  # unknown, never a stale number; the scrape still works


def test_a_slot_wait_sends_the_registered_script_never_its_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every poll for a free slot is an EVALSHA: the script's text is sent once, not on every poll."""
    limiter = AiSlots(get_redis_client(), cap=1, wait_seconds=5)

    def script_text_sent(*_: object) -> None:
        raise AssertionError("EVAL sent the whole script")

    monkeypatch.setattr(limiter._redis, "eval", script_text_sent)
    with limiter.hold_slot(hold_seconds=60):
        assert limiter.count_calls_in_progress() == 1


def test_a_slot_outlives_its_call_s_longest_run() -> None:
    assert slots.max_slot_hold_seconds(120) == 120 * (AiLimits.RETRIES + 1) + AiLimits.SLOT_GRACE_SECONDS
