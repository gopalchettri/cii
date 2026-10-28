"""The limit a gateway 429 sets on the AI calls in flight (app/ai/slots.py AiSlots), on the test Redis: none
until a 429, then half the calls in flight, raised by each answer, gone a while after the last 429. Also:
TSG's own refusals are counted apart from the gateway's."""

import random
import statistics
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, suppress

import litellm
import pytest
from prometheus_client import REGISTRY
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError
from structlog.testing import capture_logs

from app import ai, container
from app.ai import slots as slots_module
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, AiRequestRate, AiSlots
from app.core.constants import AiLimits, AiOutage, AiOutageSource, AiTask, LogEvent
from app.core.database import get_mongodb, get_redis_client
from app.core.exceptions import Unavailable
from app.core.singletons import singleton
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.models.ai.profiles import ChatModelProfile
from app.worker import lifecycle

TASK = AiTask.RELEVANCE_GATE
FIRST = ChatModelProfile(
    max_output_tokens=100,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=20_100,
)
FALLBACK = ChatModelProfile(
    max_output_tokens=50,
    timeout_seconds=9,
    supports_json_mode=False,
    reasoning_effort=None,
    context_tokens=20_050,
)


@pytest.fixture(autouse=True)
def own_slots_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Each test its own calls in flight, limit and request turns, so no test sees another's."""
    key = f"tsg:test_ai_limit:{uuid.uuid4().hex}"
    monkeypatch.setattr(AiLimits, "SLOTS_KEY", key)
    monkeypatch.setattr(AiLimits, "SLOTS_LIMIT_KEY", f"{key}:limit")
    monkeypatch.setattr(AiLimits, "REQUEST_RATE_KEY", f"{key}:rate:{{model}}")
    yield key
    if keys := get_redis_client().keys(f"{key}*"):
        get_redis_client().delete(*keys)


def _limited() -> AiSlots:
    """The main slots as UAT runs them: no fixed cap (CII_MAX_CONCURRENT_AI_CALLS=0)."""
    return AiSlots(get_redis_client(), cap=0, wait_seconds=30)


def test_with_no_cap_and_no_429_no_call_ever_waits_and_each_is_counted() -> None:
    """Full speed until the gateway answers 429, each call recorded so a 429 knows how many are in flight."""
    slots, callers = _limited(), 40
    everyone_inside, done = threading.Barrier(callers + 1, timeout=10), threading.Event()
    waited: list[float] = []

    def call() -> None:
        started = time.monotonic()
        with slots.hold_slot(TASK):
            waited.append(time.monotonic() - started)
            everyone_inside.wait()
            done.wait(10)

    threads = [threading.Thread(target=call) for _ in range(callers)]
    for thread in threads:
        thread.start()
    everyone_inside.wait()  # all 40 hold a slot at the same time: none waited for another
    assert (slots.count_calls_in_progress(), slots.current_limit()) == (callers, 0)
    done.set()
    for thread in threads:
        thread.join()
    assert max(waited) < 1 and slots.count_calls_in_progress() == 0


def test_a_429_halves_the_calls_in_flight_once_per_burst_and_never_below_the_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slots = AiSlots(get_redis_client(), cap=0, wait_seconds=0.2)
    with ExitStack() as first_half, ExitStack() as second_half:
        for stack in (first_half, second_half):
            for _ in range(10):
                stack.enter_context(slots.hold_slot(TASK))
        slots.note_rate_limited()
        assert slots.current_limit() == 10  # half of 20 in flight
        first_half.close()
        slots.note_rate_limited()  # the same burst of 429s: no second cut, though 10 are in flight now
        assert slots.current_limit() == 10
        with pytest.raises(Unavailable), slots.hold_slot(TASK):  # 10 in flight, limit 10: refused
            pass
    monkeypatch.setattr(AiLimits, "ADAPTIVE_CUT_SPACING_SECONDS", 0)
    slots.note_rate_limited()  # a later 429 with nothing in flight
    assert slots.current_limit() == AiLimits.ADAPTIVE_LIMIT_FLOOR
    capped = AiSlots(get_redis_client(), cap=2, wait_seconds=0.2)  # a fixed cap stays the ceiling
    with capped.hold_slot(TASK), capped.hold_slot(TASK):
        assert capped.current_limit() == 2
        with pytest.raises(Unavailable), capped.hold_slot(TASK):
            pass


def test_a_429_that_would_not_lower_the_limit_leaves_it_and_logs_no_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calls waiting out a 429 keep their slots, so more can be in flight than the limit: half of them is no
    cut, and the raises the answers made stay."""
    monkeypatch.setattr(AiLimits, "ADAPTIVE_CUT_SPACING_SECONDS", 0)
    slots = _limited()
    with ExitStack() as held, capture_logs() as logs:
        for _ in range(20):
            held.enter_context(slots.hold_slot(TASK))
        with slots.hold_slot(TASK):
            slots.note_rate_limited()  # half of 21
        slots.note_rate_limited()  # answered: 10.1; half of 20: not lower
        assert slots.current_limit() == 10
    assert [entry["limit"] for entry in logs if entry["event"] == LogEvent.AI_LIMIT_CUT] == [10]


def _answer(slots: AiSlots) -> None:
    """One call that ends with no error: answered."""
    with slots.hold_slot(TASK):
        pass


def test_each_answer_raises_the_limit_by_one_over_the_limit() -> None:
    """About one call more at once per round of answers; no answer makes a limit when no 429 set one."""
    slots = _limited()
    _answer(slots)
    assert slots.current_limit() == 0
    slots.note_rate_limited()  # nothing in flight: the floor, 4
    for _ in range(4):
        _answer(slots)  # 4.25, 4.49, 4.71, 4.92
    assert slots.current_limit() == AiLimits.ADAPTIVE_LIMIT_FLOOR
    _answer(slots)  # 5.12
    assert slots.current_limit() == AiLimits.ADAPTIVE_LIMIT_FLOOR + 1


def test_the_limit_lives_under_its_pinned_redis_name(
    monkeypatch: pytest.MonkeyPatch, own_slots_key: str
) -> None:
    """tsg:ai_slots:limit is AiLimits.SLOTS_LIMIT_KEY (pinned in tests/contract/tsg_names.json), never a name
    built in the code."""
    pinned = f"{own_slots_key}:pinned_limit"
    monkeypatch.setattr(AiLimits, "SLOTS_LIMIT_KEY", pinned)
    _limited().note_rate_limited()
    assert get_redis_client().hget(pinned, "limit") == str(AiLimits.ADAPTIVE_LIMIT_FLOOR)


def test_the_limit_is_gone_a_while_after_the_last_429(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every 429 renews the limit's time to live and an answer does not: with no 429 for that long, TSG is
    back to no limit."""
    monkeypatch.setattr(AiLimits, "ADAPTIVE_LIMIT_TTL_SECONDS", 1)
    monkeypatch.setattr(AiLimits, "ADAPTIVE_CUT_SPACING_SECONDS", 0)
    slots = AiSlots(get_redis_client(), cap=0, wait_seconds=0)
    slots.note_rate_limited()
    time.sleep(0.7)
    slots.note_rate_limited()
    time.sleep(0.5)  # 1.2 s after the first 429, 0.5 s after the last
    _answer(slots)
    assert slots.current_limit() == AiLimits.ADAPTIVE_LIMIT_FLOOR
    time.sleep(0.7)  # 1.2 s after the last 429, 0.7 s after the answer
    assert slots.current_limit() == 0
    with ExitStack() as held:  # more calls at once than the floor, none refused
        for _ in range(AiLimits.ADAPTIVE_LIMIT_FLOOR + 2):
            held.enter_context(slots.hold_slot(TASK))


class _Gateway:
    """A gateway key that takes `parallel` calls at once and answers 429 above that (LiteLLM's
    max_parallel_requests); each answer takes about 0.1 s."""

    def __init__(self, parallel: int) -> None:
        self.parallel = parallel
        self.lock = threading.Lock()
        self.in_flight = 0
        self.answered: list[float] = []  # when each answer and each 429 was given
        self.refused: list[float] = []

    def answer(self) -> str:
        with self.lock:
            if self.in_flight >= self.parallel:
                self.refused.append(time.monotonic())
                raise litellm.RateLimitError("busy", llm_provider="litellm_proxy", model="m")
            self.in_flight += 1
        time.sleep(random.uniform(0.08, 0.12))  # noqa: S311 — timing jitter, not a secret
        with self.lock:
            self.in_flight -= 1
            self.answered.append(time.monotonic())
        return "ok"


def test_against_a_gateway_that_takes_n_calls_at_once_tsg_settles_near_n_with_few_429s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three times as many threads as the key takes, at cap 0: the 429s slow them to about what it takes."""
    parallel, threads, seconds = 16, 48, 4.0
    monkeypatch.setattr(AiLimits, "ADAPTIVE_CUT_SPACING_SECONDS", 0.2)  # ~2 answers' time, as 5 s is in UAT
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_WAITS_SECONDS", (0.05, 0.1, 0.2, 0.4))
    monkeypatch.setattr(AiLimits, "SLOT_FIRST_PAUSE_SECONDS", 0.005)
    monkeypatch.setattr(AiLimits, "SLOT_MAX_PAUSE_SECONDS", 0.01)
    gateway, slots = _Gateway(parallel), _limited()
    started = time.monotonic()
    second_half, stop = started + seconds / 2, started + seconds
    at_the_gateway: list[int] = []

    def ask_until_stop() -> None:
        while time.monotonic() < stop:
            # A call given up after its waits (RateLimitError) is the job's to back off.
            with slots.hold_slot(TASK), suppress(litellm.RateLimitError):
                ai.common.call_with_retries(
                    gateway.answer, UNLIMITED_AI_REQUEST_RATE, slots, model="m", task=TASK
                )

    callers = [threading.Thread(target=ask_until_stop) for _ in range(threads)]
    for caller in callers:
        caller.start()
    while time.monotonic() < stop:
        if time.monotonic() > second_half:
            at_the_gateway.append(gateway.in_flight)
        time.sleep(0.005)
    for caller in callers:
        caller.join()
    answered = sum(1 for at in gateway.answered if at > second_half)
    refused = sum(1 for at in gateway.refused if at > second_half)
    assert refused <= 0.1 * answered, (refused, answered)  # settled: few 429s
    assert statistics.mean(at_the_gateway) >= 0.5 * parallel, statistics.mean(at_the_gateway)  # near N
    assert parallel / 2 <= slots.current_limit() <= 2 * parallel


def test_a_429_from_the_fallback_model_limits_every_ai_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """kimi and glm share the gateway's key with the embedder and the reranker: a 429 from either sets the
    one limit on the main slots. A request no model answered never raises it."""
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_WAITS_SECONDS", (0, 0, 0, 0))
    monkeypatch.setattr(AiLimits, "RETRY_FIRST_WAIT_SECONDS", 0)

    def answer(**kwargs: object) -> None:
        if kwargs["model"] == "first":
            raise litellm.Timeout("no answer in time", model="first", llm_provider="openai")
        raise litellm.RateLimitError("busy", llm_provider="openai", model="fallback")

    monkeypatch.setattr(litellm, "completion", answer)
    slots = _limited()
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    chat = ai.ChatModel(
        [("first", FIRST), ("fallback", FALLBACK)], "http://ai.invalid", "key", records, slots=slots
    )
    with pytest.raises(Unavailable):
        chat.ask_for_checked_json(TASK, "system", "user", lambda _answer: [])
    assert get_redis_client().hget(AiLimits.SLOTS_LIMIT_KEY, "limit") == str(AiLimits.ADAPTIVE_LIMIT_FLOOR)


@pytest.mark.parametrize("error", [RedisConnectionError, ResponseError])  # down; or MISCONF, OOM, READONLY
def test_with_no_cap_a_redis_outage_never_fails_an_ai_call_and_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, error: type[RedisError]
) -> None:
    """The call goes ahead unlimited and uncounted; with a fixed cap, the job retries it as an outage."""
    redis = get_redis_client()

    def redis_is_down(*_: object) -> None:
        raise error("refused")

    slots, capped = _limited(), AiSlots(redis, cap=4, wait_seconds=5)
    answered = 0
    with capture_logs() as logs:
        with slots.hold_slot(TASK):  # recorded; Redis goes down before the call is freed
            monkeypatch.setattr(redis, "evalsha", redis_is_down)
        for _ in range(3):
            with slots.hold_slot(TASK):
                answered += 1
            slots.note_rate_limited()
    assert answered == 3
    assert [entry["event"] for entry in logs] == [LogEvent.AI_SLOTS_UNTRACKED]
    with pytest.raises(Unavailable), capped.hold_slot(TASK):
        pass


def _provide(getter: str, built: AiSlots, monkeypatch: pytest.MonkeyPatch) -> None:
    """The container hands out `built` as if it had built it."""
    provider = singleton(lambda: built)
    provider()
    monkeypatch.setattr(container, getter, provider)


def test_the_dashboard_shows_the_limit_in_force_and_every_call_in_flight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tsg_ai_slots_cap is the limit in force (0 = none); tsg_ai_slots_in_use counts calls at cap 0 too."""
    slots = _limited()
    _provide("get_ai_slots", slots, monkeypatch)
    for kept in ("_ai_slot_wait_seconds", "_waits_out_rate_limits"):  # set_up_worker changes them
        monkeypatch.setattr(container, kept, getattr(container, kept))
    for builder in ("create_all_indexes", "get_chat_model", "get_embedding_model", "get_rerank_model"):
        monkeypatch.setattr(container, builder, lambda *_: None)
    lifecycle._prepare_stores_and_models()
    assert REGISTRY.get_sample_value("tsg_ai_slots_cap") == 0
    with slots.hold_slot(TASK), slots.hold_slot(TASK):
        slots.note_rate_limited()
        shown = (
            REGISTRY.get_sample_value("tsg_ai_slots_in_use"),
            REGISTRY.get_sample_value("tsg_ai_slots_cap"),
        )
    assert shown == (2, AiLimits.ADAPTIVE_LIMIT_FLOOR)


def test_tsg_s_own_refusals_are_counted_apart_from_the_gateway_s(monkeypatch: pytest.MonkeyPatch) -> None:
    """tsg_ai_outages_total{source="limiter"}: no slot free within the wait, or a request turn too far off."""

    def counted() -> float:
        labels = {"task": TASK, "reason": AiOutage.BUSY, "source": AiOutageSource.LIMITER}
        return REGISTRY.get_sample_value("tsg_ai_outages_total", labels) or 0.0

    before = counted()
    full = AiSlots(get_redis_client(), cap=1, wait_seconds=0.1)
    with full.hold_slot(TASK), pytest.raises(Unavailable), full.hold_slot(TASK):
        pass
    monkeypatch.setattr(slots_module, "sleep_unless_lease_lost", lambda _seconds: None)
    kimi = AiRequestRate(get_redis_client(), "kimi", per_minute=1, wait_seconds=5)
    kimi.wait_for_turn(TASK)  # the next turn is 60 s away now
    with pytest.raises(Unavailable):
        kimi.wait_for_turn(TASK)
    assert counted() == before + 2
