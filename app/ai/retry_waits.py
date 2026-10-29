"""How long an AI request waits before it is asked again: after a busy answer, or after a rate limit (HTTP
429)."""

import math
import random
import re
from typing import Final

from app.core.constants import AiLimits

#: LiteLLM's proxy words a 429 "Rate limit exceeded for <kind>: <who>. Limit type: tokens. Current limit: N,
#: Remaining: R. ..." (parallel_request_limiter_v3): only the kind and the numbers are read, never <who>.
_GATEWAY_LIMIT: Final = re.compile(
    r"Rate limit exceeded for (\w+):.*?Current limit: (\d+), Remaining: (\d+)", re.S
)


def rate_limited_wait(retry_after: str | None, attempt: int, waited: float) -> float | None:
    """How long a rate-limited request waits before it is asked again: the attempt's
    RATE_LIMITED_WAITS_SECONDS +-RATE_LIMITED_JITTER, or its Retry-After header's seconds when longer; each
    wait at most RATE_LIMITED_MAX_WAIT_SECONDS, never past RATE_LIMITED_TOTAL_WAIT_SECONDS in all. None:
    asked enough (one retry a step), the outage reaches the caller."""
    left = AiLimits.RATE_LIMITED_TOTAL_WAIT_SECONDS - waited
    if attempt >= len(AiLimits.RATE_LIMITED_WAITS_SECONDS) or left <= 0:
        return None
    jitter = random.uniform(-AiLimits.RATE_LIMITED_JITTER, AiLimits.RATE_LIMITED_JITTER)  # noqa: S311
    own_step = AiLimits.RATE_LIMITED_WAITS_SECONDS[attempt] * (1 + jitter)
    try:
        asked = float(retry_after or "")
    except ValueError:  # none, or an HTTP date (LiteLLM's proxy sends seconds)
        asked = 0.0
    # A gateway still full answers 429 again: a Retry-After shorter than our own step is not asked again
    # sooner. "nan" or "inf" asks for nothing.
    asked = asked if math.isfinite(asked) else 0.0
    return min(max(own_step, asked), AiLimits.RATE_LIMITED_MAX_WAIT_SECONDS, left)


def busy_retry_wait(attempt: int) -> float | None:
    """A busy request's wait before it is asked again: 0.5 s, doubling; None after AiLimits.RETRIES."""
    return AiLimits.RETRY_FIRST_WAIT_SECONDS * 2**attempt if attempt < AiLimits.RETRIES else None


def gateway_limit(error: Exception) -> dict[str, str | int]:
    """The budget a gateway 429 names: its kind (team, user, api_key ...), its size and what was left; {} when
    the answer names none. Never the key, user or address the message also holds."""
    found = _GATEWAY_LIMIT.search(str(error))
    if found is None:
        return {}
    scope, limit, remaining = found.groups()
    return {"limit_scope": scope, "limit": int(limit), "limit_remaining": int(remaining)}
