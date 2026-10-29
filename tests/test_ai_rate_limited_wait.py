"""After a gateway 429 (app/ai/retry_waits.py rate_limited_wait, app/ai/common.py): a worker waits at least
TSG's own step, longer when the gateway's Retry-After asks (up to CII_AI_BUSY_MAX_WAIT_SECONDS, 20 s), +-20%
after that cap, 60 s in all; the outage is logged with the gateway's Retry-After and limit type, never its
message, and counted as the gateway's."""

import random
import re
from pathlib import Path

import httpx
import litellm
import pytest
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import ai
from app.ai.common import _counted_outage
from app.ai.retry_waits import gateway_limit, rate_limited_wait
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS
from app.core.ai_tuning_settings import AiTuningSettings
from app.core.constants import AiLimits, AiOutage, AiOutageSource, AiTask, LogEvent
from app.core.exceptions import Unavailable

TASK = AiTask.RELEVANCE_GATE
_GATEWAY_MESSAGE = "Rate limit exceeded for api_key: sk-hidden-123. Limit type: requests."
LITELLM_WINDOW_SECONDS = 60  # LiteLLM's Retry-After: always its whole minute window
CONFIG_MAP = Path(__file__).resolve().parents[1] / "deploy" / "configmap.yaml"


def _rate_limited(retry_after: str, limit_type: str = "") -> litellm.RateLimitError:
    """A LiteLLM proxy's 429: its Retry-After and, from its v3 limiter, the limit that refused."""
    headers = {"retry-after": retry_after} | ({"rate_limit_type": limit_type} if limit_type else {})
    told = httpx.Response(429, headers=headers)
    return litellm.RateLimitError(_GATEWAY_MESSAGE, llm_provider="litellm_proxy", model="m", response=told)


def test_a_short_retry_after_is_not_asked_again_before_tsg_s_own_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway still full may ask for under 1 s: each wait is still at least TSG's own step (2, 5, 10, 15 s
    +-20%), so 5 tries of one model do not all land within a few seconds."""
    clock, sent_at = [0.0], []

    def wait(seconds: float) -> None:
        clock[0] += seconds

    def gateway_still_full() -> None:
        sent_at.append(clock[0])
        raise _rate_limited("0.8")

    monkeypatch.setattr(ai.common, "sleep_unless_lease_lost", wait)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_MAX_WAIT_SECONDS", 20)  # the code's defaults, not .env's
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_TOTAL_WAIT_SECONDS", 60)
    with pytest.raises(litellm.RateLimitError):
        ai.common.call_with_retries(
            gateway_still_full, UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, model="m", task=TASK
        )
    steps = AiLimits.RATE_LIMITED_WAITS_SECONDS
    gaps = [later - earlier for earlier, later in zip(sent_at, sent_at[1:], strict=False)]
    assert len(sent_at) == len(steps) + 1
    assert all(
        gap >= step * (1 - AiLimits.RATE_LIMITED_JITTER) for gap, step in zip(gaps, steps, strict=True)
    )
    assert sent_at[-1] >= sum(steps) * (1 - AiLimits.RATE_LIMITED_JITTER)  # spread over TSG's own steps


def test_a_longer_retry_after_is_honoured_up_to_the_longest_wait_and_the_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jitter aside: a Retry-After under the longest wait is waited as asked, a longer one is cut to it, and
    the last wait to what the total leaves. An unusable one waits TSG's own step."""
    first_step = AiLimits.RATE_LIMITED_WAITS_SECONDS[0]
    for unusable in (None, "", "nan", "inf", "-5", "Wed, 21 Oct 2015 07:28:00 GMT"):
        wait = rate_limited_wait(unusable, attempt=0, waited=0)
        assert wait is not None and abs(wait - first_step) <= first_step * AiLimits.RATE_LIMITED_JITTER
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_JITTER", 0)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_MAX_WAIT_SECONDS", 20)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_TOTAL_WAIT_SECONDS", 60)
    assert rate_limited_wait("12", attempt=0, waited=0) == 12
    assert rate_limited_wait("60", attempt=0, waited=0) == 20
    assert rate_limited_wait("60", attempt=2, waited=50) == 10  # the rest of the minute
    assert rate_limited_wait("60", attempt=3, waited=60) is None  # asked enough: the fallback model answers


def _busy_waits_setting(source: str, key: str) -> int:
    """`key`'s value as the code's default or as deploy/configmap.yaml sets it; never the gitignored .env."""
    if source == "code default":
        return int(AiTuningSettings.model_fields[key.removeprefix("CII_").lower()].default)
    found = re.search(rf'^\s+{key}: "(\d+)"', CONFIG_MAP.read_text(encoding="utf-8"), re.M)
    assert found is not None, key
    return int(found.group(1))


@pytest.mark.parametrize("source", ["code default", "configmap"])
@pytest.mark.parametrize("jitter", [-1, 0, 1])
def test_litellm_s_60_s_retry_after_is_never_waited_whole_yet_the_last_try_lands_after_its_window(
    monkeypatch: pytest.MonkeyPatch, source: str, jitter: int
) -> None:
    """UAT 29 Oct: the room a refused call needs comes back within seconds, so one 60 s wait idles the
    budget. No one wait is the whole window; the tries (about 0/20/40/60 s) still reach its end before the
    fallback model, at the jitter's lowest, none and highest."""
    for name in ("MAX", "TOTAL"):
        setting = _busy_waits_setting(source, f"CII_AI_BUSY_{name}_WAIT_SECONDS")
        monkeypatch.setattr(AiLimits, f"RATE_LIMITED_{name}_WAIT_SECONDS", setting)
    monkeypatch.setattr(random, "uniform", lambda low, high: (low, 0, high)[jitter + 1])
    waits: list[float] = []
    while (wait := rate_limited_wait(str(LITELLM_WINDOW_SECONDS), len(waits), sum(waits))) is not None:
        waits.append(wait)
    assert max(waits) < LITELLM_WINDOW_SECONDS
    assert len(waits) >= 3 and sum(waits) == pytest.approx(LITELLM_WINDOW_SECONDS)  # 4 tries or more


def test_capped_waits_are_jittered_so_pods_refused_together_ask_again_apart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every LiteLLM 429 asks for 60 s and every pod cuts it to the same longest wait: jittered after that
    cut, refused pods do not all ask the gateway again in the same second."""
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_MAX_WAIT_SECONDS", 20)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_TOTAL_WAIT_SECONDS", 60)
    waits = [rate_limited_wait("60", attempt=0, waited=0) for _ in range(20)]
    spread = 20 * AiLimits.RATE_LIMITED_JITTER
    assert all(wait is not None and 20 - spread <= wait <= 20 + spread for wait in waits)
    assert len(set(waits)) > 1


def test_the_outage_log_carries_the_gateway_s_retry_after_and_limit_type_never_its_message() -> None:
    """Which limit refused (requests, tokens or max_parallel_requests) and how long the gateway asked to wait
    decide the cure; the message may hold the key or the gateway's address."""
    labels = {"task": TASK, "reason": AiOutage.BUSY, "source": AiOutageSource.GATEWAY}
    before = REGISTRY.get_sample_value("tsg_ai_outages_total", labels) or 0.0
    with (
        capture_logs() as logs,
        pytest.raises(Unavailable),
        ai.common.count_and_convert_ai_errors(TASK, "m"),
    ):
        raise _rate_limited("60", "max_parallel_requests")
    outage = next(entry for entry in logs if entry["event"] == LogEvent.AI_CALL_UNAVAILABLE)
    logged = (outage["status"], outage["retry_after"], outage["limit_type"])
    assert logged == (429, "60", "max_parallel_requests")
    assert "sk-hidden" not in str(outage)
    assert REGISTRY.get_sample_value("tsg_ai_outages_total", labels) == before + 1


LITELLM_429 = (
    'litellm.RateLimitError: RateLimitError: Litellm_proxyException - {"error":{"message":"Rate limit '
    "exceeded for team: efd5f7f8-e398-46ac-9d89-81fa998d0fca. Limit type: tokens. Current limit: 300000, "
    'Remaining: 0. Limit resets at: 2026-10-28 10:19:52 UTC","type":"None","param":"None","code":"429"}}'
)


def test_a_gateway_429_logs_the_budget_it_names_never_who_owns_it() -> None:
    """UAT's 429s said only "tokens": which budget (team, user, key) and its size were thrown away with the
    message. Now the kind and the numbers are logged, never the team, user or key the message names."""
    error = litellm.RateLimitError(LITELLM_429, llm_provider="litellm_proxy", model="litellm_proxy/kimi-k2.5")
    assert gateway_limit(error) == {"limit_scope": "team", "limit": 300_000, "limit_remaining": 0}
    assert gateway_limit(litellm.RateLimitError("busy", llm_provider="openai", model="m")) == {}
    with capture_logs() as logs:
        _counted_outage(AiTask.RELEVANCE_GATE, "litellm_proxy/kimi-k2.5", error)
    [logged] = [entry for entry in logs if entry["event"] == LogEvent.AI_CALL_UNAVAILABLE]
    assert (logged["limit_scope"], logged["limit"], logged["limit_remaining"]) == ("team", 300_000, 0)
    assert "efd5f7f8" not in repr(logged)


def test_no_wait_after_a_429_is_longer_than_the_longest_wait_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """CII_AI_BUSY_MAX_WAIT_SECONDS is the longest one wait before its +-20%, TSG's own 10 and 15 s steps too:
    before, only a Retry-After was cut to it. CII_AI_BUSY_TOTAL_WAIT_SECONDS counts within the 4 retries."""
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_JITTER", 0)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_MAX_WAIT_SECONDS", 5)
    waits = [rate_limited_wait(None, attempt, waited=0) for attempt in range(4)]
    assert all(wait is not None and wait <= 5 for wait in waits)
    assert rate_limited_wait(None, attempt=4, waited=0) is None  # asked enough: the backup model answers
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_MAX_WAIT_SECONDS", 60)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_TOTAL_WAIT_SECONDS", 240)  # UAT's Retry-After 60, four times
    assert [rate_limited_wait("60", n, waited=60 * n) for n in range(5)] == [60] * 4 + [None]
