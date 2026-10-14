"""What every AI gateway shares: which provider errors mean "busy or down", the answer errors, the key
header, the retries and how each call's outcome is counted."""

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

import litellm
import structlog

from app.core import metrics
from app.core.constants import AiLimits, AiOutcome, ErrorCode, ErrorMessage, LogEvent
from app.core.exceptions import JobFailed, LeaseLost, Unavailable

log = structlog.get_logger(__name__)

#: Provider errors meaning "busy or unreachable now": API answers 503 + Retry-After; workers retry.
#: BadGatewayError (HTTP 502) is its own class in litellm: a proxy or gateway restart answers with it.
AI_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (
    litellm.RateLimitError,
    litellm.Timeout,
    litellm.APIConnectionError,
    litellm.ServiceUnavailableError,
    litellm.InternalServerError,
    litellm.BadGatewayError,
)


#: Provider answers no retry can change: a refused or revoked key, no permission, a model the gateway does not
#: know. The job fails at once with ai_misconfigured, never one failure per path or category (S16-S31 review).
AI_CONFIGURATION_ERRORS: tuple[type[Exception], ...] = (
    litellm.AuthenticationError,
    litellm.PermissionDeniedError,
    litellm.NotFoundError,
)


class IncompleteAiAnswer(Exception):
    """The answer has missing, extra or repeated positions: pairing it with the inputs would be wrong."""


class UnusableAiAnswer(JobFailed):
    """An answer no retry can fix (vectors of the wrong size or non-finite, rerank scores outside 0-1: a wrong
    model profile or provider setting). Counted unreadable and raised as it is: the job fails with
    ai_answer_unusable and this message, never as an unexpected error, and is never retried (G112)."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.AI_ANSWER_UNUSABLE, message)


#: What call_with_retries asks again: the provider busy or down, or an answer that came back short (a gateway
#: glitch; one bad answer must not fail a whole run).
_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (*AI_UNAVAILABLE_ERRORS, IncompleteAiAnswer)


def build_api_key_header(header: str, api_key: str, option: str = "extra_headers") -> dict[str, Any]:
    """{option: {header: key}} for a gateway that reads the key from its own header (settings.ai_key_header);
    {} when none is set. litellm's rerank takes `headers` (it drops `extra_headers`); chat and embedding take
    `extra_headers`."""
    return {option: {header: api_key}} if header else {}


#: When (time.monotonic()) this caller needs its AI answers by; None = each call's own profile timeout. A
#: context variable: set in one thread, it reaches every thread given a copy of that thread's context.
_DEADLINE: ContextVar[float | None] = ContextVar("ai_deadline", default=None)


@contextmanager
def ai_deadline(until: float) -> Iterator[None]:
    """Every AI call inside ends by `until` (a time.monotonic() value): its timeout is the time left, it is
    never retried, and it waits that long at most for a slot; one that would start too late is Unavailable
    at once.
    A request that gives up at its deadline (a plan request's control top-up, R1T) never leaves calls running
    behind it, holding AI slots the jobs need."""
    token = _DEADLINE.set(until)
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def seconds_left() -> float | None:
    """The time the caller's deadline leaves (never below 0); None without a deadline."""
    until = _DEADLINE.get()
    return None if until is None else max(until - time.monotonic(), 0.0)


def call_timeout(profile_timeout: float) -> float:
    """One provider call's timeout: its profile's, or the deadline's time left when that is sooner."""
    left = seconds_left()
    if left is None:
        return profile_timeout
    if left <= 0:
        raise Unavailable(ErrorMessage.AI_DEADLINE_PASSED)
    return min(profile_timeout, left)


def call_with_retries[Answer](call: Callable[[], Answer]) -> Answer:
    """Run an AI call (and the check of its answer), retrying AiLimits.RETRIES times, 0.5 s, 1 s, 2 s apart,
    when the provider is busy or unreachable or the answer came back short. The only retries: litellm's own
    are switched off (app/ai/__init__.py), so one call is at most RETRIES + 1 requests.

    A call that timed out is not asked again here (owner, 2026-10-10): the provider is overloaded, and asking
    again would hold the worker another full timeout (90-120 s) each time and add to its load. The fallback
    model answers instead, or the job's own back-off asks later. Under a deadline (ai_deadline): one try."""
    if _DEADLINE.get() is not None:
        return call()
    for attempt in range(AiLimits.RETRIES):
        try:
            return call()
        except litellm.Timeout:
            raise
        except _RETRYABLE_ERRORS:
            time.sleep(AiLimits.RETRY_FIRST_WAIT_SECONDS * 2**attempt)
    return call()  # the last try: its outage reaches the caller


@contextmanager
def count_and_convert_ai_errors(task: str, model: str) -> Iterator[None]:
    """Counts a failed AI call in tsg_ai_calls_total by its outcome (each gateway counts its own "ok"), and
    turns the provider busy or down, or an answer still short after the retries, into Unavailable: the job
    backs off and retries."""
    try:
        yield
    except LeaseLost:
        raise  # its job was stopped (G214): not an AI failure, so never counted as one (G222)
    except Unavailable:
        raise  # no provider answered: counted already, or no slot was free (app/ai/slots.py)
    except AI_UNAVAILABLE_ERRORS as exc:
        metrics.AI_CALLS.labels(task, model, AiOutcome.UNAVAILABLE).inc()
        # Which outage it was (rate limit, timeout, lost connection, gateway restart) decides the cure, so it
        # is logged: the class and the HTTP status only, never the message (it may hold the gateway URL).
        log.warning(
            LogEvent.AI_CALL_UNAVAILABLE,
            task=task,
            model=model,
            error=type(exc).__name__,
            status=getattr(exc, "status_code", None),
        )
        raise Unavailable(ErrorMessage.AI_UNREACHABLE) from exc
    except AI_CONFIGURATION_ERRORS as exc:
        metrics.AI_CALLS.labels(task, model, AiOutcome.ERROR).inc()
        status = getattr(exc, "status_code", None)
        log.error(LogEvent.AI_CALL_REFUSED, task=task, model=model, error=type(exc).__name__, status=status)
        message = ErrorMessage.AI_MISCONFIGURED.format(model=model, error=type(exc).__name__, status=status)
        raise JobFailed(ErrorCode.AI_MISCONFIGURED, message) from exc
    except IncompleteAiAnswer as exc:
        metrics.AI_CALLS.labels(task, model, AiOutcome.UNREADABLE).inc()
        raise Unavailable(str(exc)) from exc
    except UnusableAiAnswer:
        metrics.AI_CALLS.labels(task, model, AiOutcome.UNREADABLE).inc()
        raise
    except Exception:
        metrics.AI_CALLS.labels(task, model, AiOutcome.ERROR).inc()
        raise
