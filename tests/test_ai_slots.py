"""The AI call limiters (app/ai/slots.py) on the test Redis: at most `cap` calls at once, and requests spaced
to the rate, across every pod; slots leased and renewed; two Redis round trips per call."""

import math
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from prometheus_client import REGISTRY, generate_latest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError
from structlog.testing import capture_logs

from app.ai import slots
from app.ai.common import call_with_retries
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, AiRequestRate, AiSlots
from app.core import metrics
from app.core.constants import AiLimits, AiOutage, AiTask
from app.core.database import get_redis_client
from app.core.exceptions import LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal

TASK = AiTask.RELEVANCE_GATE


@pytest.fixture(autouse=True)
def own_slots_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test its own sorted set and request-rate keys, so no test sees another's slots or turns."""
    key = f"tsg:test_ai_slots:{uuid.uuid4().hex}"
    monkeypatch.setattr(AiLimits, "SLOTS_KEY", key)
    monkeypatch.setattr(AiLimits, "SLOTS_LIMIT_KEY", f"{key}:limit")
    monkeypatch.setattr(AiLimits, "REQUEST_RATE_KEY", f"{key}:rate:{{model}}")
    yield
    get_redis_client().delete(key, f"{key}:limit", *get_redis_client().keys(f"{key}:rate:*"))


def test_two_calls_with_one_slot_run_one_after_the_other() -> None:
    """Step 6 Verify: with CII_MAX_CONCURRENT_AI_CALLS=1, two calls made at once run one after the other."""
    limiter = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    spans: dict[str, tuple[float, float]] = {}

    def call(name: str) -> None:
        with limiter.hold_slot(TASK):
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
        busy.hold_slot(TASK),
        pytest.raises(Unavailable, match="AI slot") as raised,
        impatient.hold_slot(TASK),
    ):
        pass
    assert raised.value.reason == AiOutage.BUSY
    with impatient.hold_slot(TASK):  # freed when the first call ended
        pass


def test_a_job_that_loses_its_lease_while_waiting_for_a_slot_stops_waiting() -> None:
    busy = AiSlots(get_redis_client(), cap=1, wait_seconds=5)
    patient = AiSlots(get_redis_client(), cap=1, wait_seconds=30)
    with busy.hold_slot(TASK), lease_lost_signal("cancelled-run") as lost:
        threading.Timer(0.2, lost.set).start()
        started = time.monotonic()
        with pytest.raises(LeaseLost), patient.hold_slot(TASK):
            pass
        assert time.monotonic() - started < 3


def test_slots_left_by_a_process_that_died_stop_counting_once_their_lease_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process killed mid-call (out of memory, a lost node) never frees its slots nor renews them: at the
    floor, 4 of them refuse every call only until their lease ends."""
    monkeypatch.setattr(AiLimits, "SLOT_LEASE_SECONDS", 1)
    limiter = AiSlots(get_redis_client(), cap=0, wait_seconds=0.2)
    limiter.note_rate_limited()  # nothing in flight: the floor, 4
    for call in range(AiLimits.ADAPTIVE_LIMIT_FLOOR):
        limiter._take_slot(f"killed-{call}", TASK, waits=True)  # taken, then never freed nor renewed
    with pytest.raises(Unavailable), limiter.hold_slot(TASK):
        pass
    time.sleep(1)
    with limiter.hold_slot(TASK):
        assert limiter.count_calls_in_progress() == 1


def test_a_call_that_runs_longer_than_a_lease_stays_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Its process renews its slot while it runs: a long call never stops counting, so the cap still holds."""
    monkeypatch.setattr(AiLimits, "SLOT_LEASE_SECONDS", 1)
    monkeypatch.setattr(AiLimits, "SLOT_RENEW_SECONDS", 0.2)
    limiter = AiSlots(get_redis_client(), cap=1, wait_seconds=0.1)
    with limiter.hold_slot(TASK):
        time.sleep(1.5)
        assert limiter.count_calls_in_progress() == 1
        with pytest.raises(Unavailable), limiter.hold_slot(TASK):
            pass
    assert limiter.count_calls_in_progress() == 0


def test_no_limit_makes_no_redis_call() -> None:
    """No Redis client (the unlimited slots), or a model with no request rate: no Redis call at all. With a
    client, cap 0 still records each call (test_ai_adaptive_limit.py)."""

    class NoRedis:
        def __getattr__(self, name: str) -> None:
            raise AssertionError(f"Redis was called ({name}) with no limit set")

    unlimited = AiSlots(None, cap=0, wait_seconds=5)
    with unlimited.hold_slot(TASK):
        pass
    assert unlimited.count_calls_in_progress() == 0
    unlimited_rate = AiRequestRate(NoRedis(), "kimi", per_minute=0, wait_seconds=5)  # type: ignore[arg-type]
    assert unlimited_rate.wait_for_turn(TASK) == 0


def test_requests_from_every_pod_are_spaced_and_a_turn_too_far_off_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module's CHAT_REQUESTS_PER_MINUTE=20: every pod's requests go 3 s apart, by Redis's clock. A turn
    further off than the caller waits reserves nothing and is Unavailable (busy); a lost lease ends the
    wait."""
    lease_checking_sleep = slots.sleep_unless_lease_lost
    slept: list[float] = []
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", slept.append)
    pod_a, pod_b = (AiRequestRate(get_redis_client(), "kimi", 20, wait_seconds=10) for _ in range(2))
    pod_a.wait_for_turn(TASK)
    pod_b.wait_for_turn(TASK)
    with pytest.raises(Unavailable) as refused:
        AiRequestRate(get_redis_client(), "kimi", per_minute=20, wait_seconds=4).wait_for_turn(
            TASK
        )  # 6 s off
    assert refused.value.reason == AiOutage.BUSY
    pod_a.wait_for_turn(TASK)
    assert slept[0] < 0.5 and slept[1:] == [pytest.approx(3, abs=0.5), pytest.approx(6, abs=0.5)]
    with lease_lost_signal("cancelled-run") as lost:
        threading.Timer(0.2, lost.set).start()
        started = time.monotonic()
        with pytest.raises(LeaseLost):
            lease_checking_sleep(30)
        assert time.monotonic() - started < 3


def test_a_tokens_a_minute_limit_spaces_requests_by_their_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """UAT's 429s say limit_type "tokens": a module's CHAT_TOKENS_PER_MINUTE=60000 spaces a 600-token request
    0.6 s from the next, a 6000-token one 6 s more; the requests-a-minute spacing applies when it is longer; a
    request of no stated size, or no tokens limit, is not spaced by tokens."""
    slept: list[float] = []
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", slept.append)
    redis = get_redis_client()
    sized = AiRequestRate(redis, "tokens-only", per_minute=0, wait_seconds=30, tokens_per_minute=60_000)
    for tokens in (600, 6000, 600):  # each request's size spaces the one after it; no sleep is real here
        sized.wait_for_turn(TASK, tokens)
    assert slept[0] < 0.1 and slept[1:] == [pytest.approx(0.6, abs=0.1), pytest.approx(6.6, abs=0.1)]
    assert sized.wait_for_turn(TASK, 0) == 0 and len(slept) == 3  # no stated size: not spaced, no Redis call
    both = AiRequestRate(redis, "both-limits", per_minute=20, wait_seconds=30, tokens_per_minute=60_000)
    for _ in range(2):
        both.wait_for_turn(TASK, 600)  # 3 s a request beats 0.6 s of tokens
    assert slept[-1] == pytest.approx(3, abs=0.1)
    assert AiRequestRate(redis, "m", 0, 30, tokens_per_minute=0).wait_for_turn(TASK, 10**6) == 0


def test_a_429_pauses_its_model_on_every_pod(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once a refused call frees its slot, the calls queued for its model would each draw a 429 of their own.
    A 429 moves the model's next send time its wait away on every pod: a worker waits it out holding no slot,
    the API answers its caller at once; a shorter pause never cuts a longer one; a model with no limit is not
    paused (no Redis)."""
    slept: list[float] = []
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", slept.append)
    redis = get_redis_client()
    pod_a, pod_b = (AiRequestRate(redis, "paused", per_minute=600, wait_seconds=120) for _ in range(2))
    assert pod_a.pause(60) == 60
    pod_b.pause(10)
    assert pod_b.wait_for_send_time(TASK) == pytest.approx(60, abs=0.5) and slept == [slept[0]]
    with pytest.raises(Unavailable):
        AiRequestRate(redis, "paused", per_minute=600, wait_seconds=30).wait_for_send_time(TASK)
    unlimited = AiRequestRate(None, "free", per_minute=0, wait_seconds=5)
    assert unlimited.pause(60) == 60 and unlimited.wait_for_send_time(TASK) == 0


def test_the_slots_in_use_are_counted_and_unknown_when_redis_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = AiSlots(get_redis_client(), cap=4, wait_seconds=5)
    with limiter.hold_slot(TASK), limiter.hold_slot(TASK):
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
    with limiter.hold_slot(TASK):
        assert limiter.count_calls_in_progress() == 1


def test_a_redis_that_refuses_writes_shows_unknown_and_never_breaks_a_scrape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """READONLY (a replica after a failover) or MISCONF: the count script writes, so it fails. Both gauges
    show NaN and /metrics still answers, instead of a 500 for every metric."""
    limiter = AiSlots(get_redis_client(), cap=4, wait_seconds=5)
    metrics.AI_SLOTS_IN_USE.labels(AiLimits.SEARCH_POOL).set_function(limiter.count_calls_in_progress)
    metrics.AI_SLOTS_CAP.labels(AiLimits.SEARCH_POOL).set_function(limiter.current_limit)

    def read_only(*_: object, **__: object) -> None:
        raise ResponseError("READONLY You can't write against a read only replica.")

    with monkeypatch.context() as replica:
        replica.setattr(limiter._redis, "execute_command", read_only)
        scraped = generate_latest().decode()
    assert all(f'tsg_ai_slots_{gauge}{{pool="search"}} NaN' in scraped for gauge in ("in_use", "cap"))


def test_an_answered_call_costs_two_redis_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    """At cap 0 (UAT): the take, then the free, which also raises a 429's limit for the answer. A call that
    fails inside its slot is no answer: the limit stays."""
    redis = get_redis_client()
    limiter = AiSlots(redis, cap=0, wait_seconds=5)
    with limiter.hold_slot(TASK):  # each script loaded once: from now on EVALSHA alone
        pass
    sent: list[str] = []
    send = redis.execute_command

    def recorded(*args: object, **options: object) -> object:
        sent.append(str(args[0]))
        return send(*args, **options)

    with monkeypatch.context() as watched:
        watched.setattr(redis, "execute_command", recorded)
        call_with_retries(lambda: "answer", UNLIMITED_AI_REQUEST_RATE, limiter, model="m", task=TASK)
    assert sent == ["EVALSHA", "EVALSHA"]
    limiter.note_rate_limited()  # nothing in flight: the floor, 4
    with pytest.raises(RuntimeError), limiter.hold_slot(TASK):
        raise RuntimeError("no answer")
    assert redis.hget(AiLimits.SLOTS_LIMIT_KEY, "limit") == "4"
    with limiter.hold_slot(TASK):
        pass
    assert redis.hget(AiLimits.SLOTS_LIMIT_KEY, "limit") == "4.25"


def test_at_cap_0_a_redis_that_failed_is_left_alone_for_a_while(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung Redis costs each command its timeout (5 s): after one failure the calls go ahead, unlimited and
    with no Redis call, until REDIS_SKIP_SECONDS pass; then Redis is asked again."""
    monkeypatch.setattr(AiLimits, "REDIS_SKIP_SECONDS", 0.5)
    redis = get_redis_client()
    limiter = AiSlots(redis, cap=0, wait_seconds=5)
    sent: list[str] = []

    def timed_out(*args: object, **_: object) -> None:
        sent.append(str(args[0]))
        raise RedisTimeoutError("Timeout reading from socket")

    with monkeypatch.context() as hung, capture_logs():  # captured: no time spent printing the traceback
        hung.setattr(redis, "execute_command", timed_out)
        for _ in range(2):
            with limiter.hold_slot(TASK):
                limiter.note_rate_limited()
        assert sent == ["EVALSHA"]  # the first take alone
        time.sleep(0.6)
        with limiter.hold_slot(TASK):
            pass
        assert sent == ["EVALSHA", "EVALSHA"]


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
    limiter.wait_for_turn(TASK)  # no wait
    limiter.wait_for_turn(TASK)  # 1 s after the first
    AiRequestRate(None, "glm", per_minute=0, wait_seconds=5).wait_for_turn(TASK)  # no limit: not measured
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
    kimi.wait_for_turn(TASK)  # kimi's next turn is now 60 s away
    with pytest.raises(Unavailable):
        kimi.wait_for_turn(TASK)
    for model in ("embedder", "reranker"):
        assert (
            AiRequestRate(get_redis_client(), model, per_minute=1, wait_seconds=5).wait_for_turn(TASK) < 0.5
        )
    assert max(slept) < 0.5


def test_a_slot_whose_release_redis_missed_is_freed_by_the_next_call() -> None:
    """A call that ends while Redis is being skipped (a blip) could not free its slot, so it still counted as
    in flight until its lease ended (60 s): with a 429's limit in force, every new call waited for nothing.
    The next call's take frees it first."""
    key = f"tsg:test_phantom:{uuid.uuid4().hex}"
    redis = get_redis_client()
    slots = AiSlots(redis, cap=0, wait_seconds=5, key=key)
    redis.hset(f"{key}:limit", "limit", 1)  # a 429 cut this pool to one call at once
    try:
        with slots.hold_slot(AiTask.RELEVANCE_GATE):
            slots._skip_redis_until = time.monotonic() + 60  # Redis fails while the call runs
        assert redis.zcard(key) == 1  # its release was skipped
        slots._skip_redis_until = 0.0  # Redis is back
        with slots.hold_slot(AiTask.RELEVANCE_GATE, waits=False):  # no wait at all: refused if not free
            assert redis.zcard(key) == 1  # itself alone, the missed slot freed
    finally:
        redis.delete(key, f"{key}:limit", f"{key}:line", f"{key}:line_polls")
