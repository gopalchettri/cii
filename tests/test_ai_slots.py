"""The AI call limiters (app/ai/slots.py) on the test Redis: at most `cap` calls at once, and requests spaced
to the rate, across every pod."""

import math
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from prometheus_client import REGISTRY
from redis.exceptions import ConnectionError as RedisConnectionError

from app.ai import slots
from app.ai.slots import AiRequestRate, AiSlots
from app.core.constants import AiLimits, AiOutage
from app.core.database import get_redis_client
from app.core.exceptions import LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal


@pytest.fixture(autouse=True)
def own_slots_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test its own sorted set and request-rate keys, so no test sees another's slots or turns."""
    key = f"tsg:test_ai_slots:{uuid.uuid4().hex}"
    monkeypatch.setattr(AiLimits, "SLOTS_KEY", key)
    monkeypatch.setattr(AiLimits, "REQUEST_RATE_KEY", f"{key}:rate:{{model}}")
    yield
    get_redis_client().delete(key, *get_redis_client().keys(f"{key}:rate:*"))


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
    limiter._wait_for_free_slot("killed-process", hold_seconds=1, wait=5)  # taken and never freed
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
    unlimited_rate = AiRequestRate(NoRedis(), "kimi", per_minute=0, wait_seconds=5)  # type: ignore[arg-type]
    assert unlimited_rate.wait_for_turn() == 0


def test_requests_from_every_pod_are_spaced_and_a_turn_too_far_off_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CII_CHAT_REQUESTS_PER_MINUTE=20: every pod's requests go 3 s apart, by Redis's clock. A turn further
    off than the caller waits reserves nothing and is Unavailable (busy); a lost lease ends the wait."""
    lease_checking_sleep = slots.sleep_unless_lease_lost
    slept: list[float] = []
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", slept.append)
    pod_a, pod_b = (AiRequestRate(get_redis_client(), "kimi", 20, wait_seconds=10) for _ in range(2))
    pod_a.wait_for_turn()
    pod_b.wait_for_turn()
    with pytest.raises(Unavailable) as refused:
        AiRequestRate(get_redis_client(), "kimi", per_minute=20, wait_seconds=4).wait_for_turn()  # 6 s off
    assert refused.value.reason == AiOutage.BUSY
    pod_a.wait_for_turn()
    assert slept[0] < 0.5 and slept[1:] == [pytest.approx(3, abs=0.5), pytest.approx(6, abs=0.5)]
    with lease_lost_signal("cancelled-run") as lost:
        threading.Timer(0.2, lost.set).start()
        started = time.monotonic()
        with pytest.raises(LeaseLost):
            lease_checking_sleep(30)
        assert time.monotonic() - started < 3


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
    # 5 requests at most (a 429 is asked again 4 times), each after its request-rate turn (a worker's 300 s at
    # most), up to 35 s of 429 waits, then the margin.
    assert slots.max_slot_hold_seconds(120, 300) == (120 + 300) * 5 + 35 + AiLimits.SLOT_GRACE_SECONDS


def test_every_request_turn_s_wait_is_measured_and_none_with_no_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tsg_ai_request_rate_wait_seconds{model}: how long each model's requests wait for its limiter, 0
    included."""
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", lambda _seconds: None)

    def measured(name: str, model: str) -> float:
        sample = f"tsg_ai_request_rate_wait_seconds_{name}"
        return REGISTRY.get_sample_value(sample, {"model": model}) or 0.0

    count, total = measured("count", "kimi"), measured("sum", "kimi")
    limiter = AiRequestRate(get_redis_client(), "kimi", per_minute=60, wait_seconds=10)
    limiter.wait_for_turn()  # no wait
    limiter.wait_for_turn()  # 1 s after the first
    AiRequestRate(None, "glm", per_minute=0, wait_seconds=5).wait_for_turn()  # no limit: not measured
    assert measured("count", "kimi") == count + 2
    assert measured("sum", "kimi") - total == pytest.approx(1, abs=0.2)
    assert measured("count", "glm") == 0


def test_a_model_s_saturated_limit_never_delays_another_model_s_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """192 requests a minute is kimi-k2.5's own limit: before, one budget for every model made an embedding or
    rerank request wait for kimi's turns, and spent kimi's budget."""
    slept: list[float] = []
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", slept.append)
    kimi = AiRequestRate(get_redis_client(), "kimi", per_minute=1, wait_seconds=5)
    kimi.wait_for_turn()  # kimi's next turn is now 60 s away
    with pytest.raises(Unavailable):
        kimi.wait_for_turn()
    for model in ("embedder", "reranker"):
        assert AiRequestRate(get_redis_client(), model, per_minute=1, wait_seconds=5).wait_for_turn() < 0.5
    assert max(slept) < 0.5
