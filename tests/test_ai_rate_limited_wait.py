"""After a gateway 429 (app/ai/retry_waits.py rate_limited_wait, app/ai/common.py): a worker waits at least
TSG's own step, longer when the gateway's Retry-After asks (up to 60 s), 60 s in all; the outage is logged
with the gateway's Retry-After and limit type, never its message, and counted as the gateway's."""

import httpx
import litellm
import pytest
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import ai
from app.ai.retry_waits import rate_limited_wait
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS
from app.core.constants import AiLimits, AiOutage, AiOutageSource, AiTask, LogEvent
from app.core.exceptions import Unavailable

TASK = AiTask.RELEVANCE_GATE
_GATEWAY_MESSAGE = "Rate limit exceeded for api_key: sk-hidden-123. Limit type: requests."


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


def test_a_longer_retry_after_is_honoured_up_to_a_minute_and_a_minute_in_all() -> None:
    assert rate_limited_wait("45", attempt=0, waited=0) == 45
    assert rate_limited_wait("45", attempt=1, waited=45) == 15  # the rest of the minute
    assert rate_limited_wait("45", attempt=2, waited=60) is None  # asked enough: the fallback model answers
    assert rate_limited_wait("600", attempt=0, waited=0) == AiLimits.RATE_LIMITED_MAX_WAIT_SECONDS == 60
    first_step = AiLimits.RATE_LIMITED_WAITS_SECONDS[0]
    for unusable in (None, "", "nan", "inf", "-5", "Wed, 21 Oct 2015 07:28:00 GMT"):
        wait = rate_limited_wait(unusable, attempt=0, waited=0)
        assert wait is not None and abs(wait - first_step) <= first_step * AiLimits.RATE_LIMITED_JITTER


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
