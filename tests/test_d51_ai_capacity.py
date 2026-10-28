"""AI capacity on the test Redis: a freed AI slot goes to the caller that has waited longest (the API's
callers first), a worker waits for AI capacity until its lease ends, and a Redis failure in a limiter is an
outage: a request turn goes ahead unspaced, a fixed cap refuses as Unavailable, never an AI error."""

import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import ExitStack

import pytest
from prometheus_client import REGISTRY
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError
from structlog.testing import capture_logs

from app.ai import slots
from app.ai.common import call_with_retries, count_and_convert_ai_errors
from app.ai.slots import UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core.constants import AiLimits, AiOutcome, AiTask, LogEvent
from app.core.database import get_redis_client
from app.core.exceptions import TEMPORARY_ERRORS, LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal
from app.domain.external_intelligence.rerank_gate import rerank_gate_for

TASK = AiTask.RELEVANCE_GATE
MISCONF = "MISCONF Redis is configured to save RDB snapshots, but it's currently unable to persist to disk."


@pytest.fixture(autouse=True)
def own_slots_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Each test its own slots, line and request-rate keys."""
    key = f"tsg:test_d51_ai_capacity:{uuid.uuid4().hex}"
    monkeypatch.setattr(AiLimits, "SLOTS_KEY", key)
    monkeypatch.setattr(AiLimits, "SLOTS_LIMIT_KEY", f"{key}:limit")
    monkeypatch.setattr(AiLimits, "REQUEST_RATE_KEY", f"{key}:rate:{{model}}")
    yield key
    if keys := get_redis_client().keys(f"{key}*"):
        get_redis_client().delete(*keys)


def _polls_without_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each waiter polls at 0.05, 0.1, 0.2, 0.4, 0.8 s, then every 1 s: the old waiter polls slowest."""
    monkeypatch.setattr(slots.random, "uniform", lambda _low, high: high)
    monkeypatch.setattr(AiLimits, "SLOT_MAX_PAUSE_SECONDS", 1.0)


def _waiter(limiter: AiSlots, name: str, served: list[str]) -> threading.Thread:
    """A thread that waits for a slot, notes its name once served and frees the slot."""

    def wait_for_slot() -> None:
        with limiter.hold_slot(TASK):
            served.append(name)

    waiter = threading.Thread(target=wait_for_slot)
    waiter.start()
    return waiter


def test_a_freed_slot_goes_to_the_caller_that_has_waited_longest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The oldest waiter polls once a second, a newcomer every 0.05 s: without a line the newcomer wins."""
    _polls_without_jitter(monkeypatch)
    limiter, served = AiSlots(get_redis_client(), cap=1, wait_seconds=10), []
    with ExitStack() as held:
        held.enter_context(limiter.hold_slot(TASK))
        oldest = _waiter(limiter, "oldest", served)
        time.sleep(1.6)  # its polls are 1 s apart now
        newest = _waiter(limiter, "newest", served)
        time.sleep(0.1)
    oldest.join(), newest.join()
    assert served == ["oldest", "newest"]


def test_an_api_caller_is_served_before_a_worker_that_came_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker polls at 2.55 s, the API caller at 1.95 and 2.95 s; the slot frees at 2.2 s."""
    _polls_without_jitter(monkeypatch)
    redis, served = get_redis_client(), []
    worker = AiSlots(redis, cap=1, wait_seconds=AiLimits.WORKER_SLOT_WAIT_SECONDS)
    api = AiSlots(redis, cap=1, wait_seconds=AiLimits.API_SLOT_WAIT_SECONDS)
    with ExitStack() as held:
        held.enter_context(worker.hold_slot(TASK))
        waiting_worker = _waiter(worker, "worker", served)
        time.sleep(0.4)
        waiting_api = _waiter(api, "api", served)
        time.sleep(1.8)
    waiting_worker.join(), waiting_api.join()
    assert served == ["api", "worker"]


def test_a_waiter_that_stopped_asking_leaves_the_line_and_a_refused_one_leaves_at_once(
    monkeypatch: pytest.MonkeyPatch, own_slots_key: str
) -> None:
    """A job cancelled while it waited keeps its place only until it has not asked for
    SLOT_WAITER_STALE_SECONDS; a caller refused on its last try (no wait, or its wait over) leaves then."""
    monkeypatch.setattr(AiLimits, "SLOT_WAITER_STALE_SECONDS", 0.5)
    redis = get_redis_client()
    cancelled, patient = (AiSlots(redis, cap=1, wait_seconds=5) for _ in range(2))  # in arrival order
    with ExitStack() as held:
        held.enter_context(patient.hold_slot(TASK))
        with pytest.raises(Unavailable), patient.hold_slot(TASK, waits=False):
            pass
        assert redis.zcard(f"{own_slots_key}:line") == 0
        with lease_lost_signal("cancelled-run") as lost:
            threading.Timer(0.2, lost.set).start()
            with pytest.raises(LeaseLost), cancelled.hold_slot(TASK):
                pass
        assert redis.zcard(f"{own_slots_key}:line") == 1  # it stopped asking, still in the line
    started = time.monotonic()
    with patient.hold_slot(TASK):
        assert time.monotonic() - started < 2


def test_a_worker_waits_for_ai_capacity_until_its_lease_ends(monkeypatch: pytest.MonkeyPatch) -> None:
    """No clock of its own gives up on an AI slot, a request turn or a remote rerank place: only a lost
    lease (a cancel, or the reaper taking a stalled job over) ends a worker's wait, so no attempt is spent
    on other runs' load."""

    class TenMinutesPerLook:
        """Each look at the clock: ten more minutes gone."""

        sleep, now = staticmethod(time.sleep), 0.0

        @classmethod
        def monotonic(cls) -> float:
            cls.now += 600
            return cls.now

    redis, served = get_redis_client(), []
    worker = AiSlots(redis, cap=1, wait_seconds=AiLimits.WORKER_SLOT_WAIT_SECONDS)
    with monkeypatch.context() as hours_pass, ExitStack() as held:
        hours_pass.setattr(slots, "time", TenMinutesPerLook)
        held.enter_context(worker.hold_slot(TASK))
        waiting = _waiter(worker, "worker", served)
        time.sleep(0.5)
    waiting.join()
    assert served == ["worker"] and TenMinutesPerLook.now >= 1_800
    monkeypatch.setattr(slots, "sleep_unless_lease_lost", lambda _seconds: None)
    kimi = AiRequestRate(redis, "kimi", per_minute=1, wait_seconds=AiLimits.WORKER_SLOT_WAIT_SECONDS)
    assert [kimi.wait_for_turn(TASK) for _ in range(8)][-1] == pytest.approx(420, abs=1)
    assert rerank_gate_for("http://proxy.invalid")._wait_seconds is None  # noqa: SLF001


def _ai_errors(model: str) -> float:
    """tsg_ai_calls_total{outcome=error} for `model`."""
    labels = {"task": TASK, "model": model, "outcome": AiOutcome.ERROR}
    return REGISTRY.get_sample_value("tsg_ai_calls_total", labels) or 0


@pytest.mark.parametrize(
    "error", [RedisConnectionError("refused"), RedisTimeoutError("Timeout reading"), ResponseError(MISCONF)]
)
def test_a_request_turn_s_redis_failure_lets_the_request_go_ahead_and_leaves_redis_alone_a_while(
    monkeypatch: pytest.MonkeyPatch, error: RedisError
) -> None:
    """Down, hung or MISCONF (no subclass in redis-py): the request is sent unspaced, never counted as an AI
    error; Redis is not asked again for REDIS_SKIP_SECONDS (a hung one costs each command 5 s)."""
    monkeypatch.setattr(AiLimits, "REDIS_SKIP_SECONDS", 0.5)
    redis, sent = get_redis_client(), []
    kimi = AiRequestRate(redis, "kimi", per_minute=60, wait_seconds=5)
    errors_before = _ai_errors("kimi")

    def failing(*args: object, **_: object) -> None:
        sent.append(str(args[0]))
        raise error

    def ask() -> str:
        with count_and_convert_ai_errors(TASK, "kimi"):
            return call_with_retries(lambda: "answer", kimi, UNLIMITED_AI_SLOTS, model="kimi", task=TASK)[0]

    with monkeypatch.context() as broken, capture_logs() as logs:
        broken.setattr(redis, "execute_command", failing)
        assert [ask(), ask()] == ["answer", "answer"]
        assert sent == ["EVALSHA"]
        time.sleep(0.6)
        assert ask() == "answer" and sent == ["EVALSHA", "EVALSHA"]
    assert _ai_errors("kimi") == errors_before
    assert [entry["event"] for entry in logs] == [LogEvent.AI_SLOTS_UNTRACKED] * 2


def test_at_a_fixed_cap_a_redis_that_refuses_writes_is_an_outage_never_an_ai_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MISCONF at a fixed cap: no call is made (the cap must hold), and the job retries it as an outage
    instead of failing for good as an internal error."""
    redis = get_redis_client()
    capped = AiSlots(redis, cap=4, wait_seconds=5)
    errors_before = _ai_errors("m")

    def misconf(*_: object, **__: object) -> None:
        raise ResponseError(MISCONF)

    with monkeypatch.context() as refusing, pytest.raises(Unavailable) as refused:
        refusing.setattr(redis, "execute_command", misconf)
        with count_and_convert_ai_errors(TASK, "m"), capped.hold_slot(TASK):
            pytest.fail("the call ran with no slot recorded")
    assert isinstance(refused.value, TEMPORARY_ERRORS) and _ai_errors("m") == errors_before
