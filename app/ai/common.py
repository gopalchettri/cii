"""What every AI gateway shares: which provider errors mean "busy or down", the answer errors, the key
header, the retries and how each call's outcome is counted."""

import os
import re
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final
from urllib.parse import urlsplit

import litellm
import structlog

from app.ai.slots import AiRequestRate, AiSlots, busy_retry_wait, sleep_unless_lease_lost
from app.core import metrics
from app.core.config import Settings, get_settings
from app.core.constants import (
    AI_BUSY_STATUSES,
    AI_OUTAGE_MESSAGES,
    AI_TIMED_OUT_STATUSES,
    LITELLM_MODEL_PREFIX,
    AiOutage,
    AiOutageSource,
    AiOutcome,
    ChatModule,
    ErrorCode,
    ErrorMessage,
    LogEvent,
)
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, JobFailed, LeaseLost, Unavailable
from app.core.singletons import singleton

log = structlog.get_logger(__name__)

#: LiteLLM's 429 text "Rate limit exceeded for <kind>: <who>. ... Current limit: N, Remaining: R": <who> never read.
_GATEWAY_LIMIT: Final = re.compile(r"Rate limit exceeded for (\w+):.*?Current limit: (\d+), Remaining: (\d+)", re.S)

#: Provider errors meaning "busy or unreachable now" (BadGatewayError too: a gateway restart answers 502).
AI_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (
    litellm.RateLimitError,
    litellm.Timeout,
    litellm.APIConnectionError,
    litellm.ServiceUnavailableError,
    litellm.InternalServerError,
    litellm.BadGatewayError,
)


def ai_outage_of(error: Exception) -> AiOutage:
    """Which outage a provider error is: by its class (a timeout first), else by its HTTP status."""
    if isinstance(error, litellm.Timeout):
        return AiOutage.TIMED_OUT
    if isinstance(error, litellm.APIConnectionError):
        return AiOutage.UNREACHABLE
    if isinstance(error, (litellm.RateLimitError, litellm.ServiceUnavailableError)):
        return AiOutage.BUSY
    status = getattr(error, "status_code", None)
    if status in AI_TIMED_OUT_STATUSES:
        return AiOutage.TIMED_OUT
    return AiOutage.BUSY if status in AI_BUSY_STATUSES else AiOutage.DOWN  # any other server error: down


def is_unmapped_outage(error: Exception) -> bool:
    """A plain litellm.APIError that is an outage: a 5xx, a 408 or no status (a 4xx stays an error)."""
    status = getattr(error, "status_code", None)
    return isinstance(error, litellm.APIError) and (status is None or status == 408 or status >= 500)


#: Answers no retry can change (bad key, no permission, unknown model): the job fails at once, ai_misconfigured.
AI_CONFIGURATION_ERRORS: tuple[type[Exception], ...] = (
    litellm.AuthenticationError,
    litellm.PermissionDeniedError,
    litellm.NotFoundError,
)


#: Chat replies refusing the prompt or breaking the response contract: read as unreadable, never our fault.
AI_REFUSED_REPLY_ERRORS: tuple[type[Exception], ...] = (
    litellm.ContentPolicyViolationError,
    litellm.exceptions.RejectedRequestError,
    litellm.APIResponseValidationError,
)


class IncompleteAiAnswer(Exception):
    """The answer has missing, extra or repeated positions: pairing it with the inputs would be wrong."""


class UnusableAiAnswer(JobFailed):
    """An answer no retry can fix (wrong vector size, non-finite, rerank score outside 0-1): fails the job (G112)."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.AI_ANSWER_UNUSABLE, message)


#: What call_with_retries asks again: the provider busy or down, or a short answer (a gateway glitch).
_RETRYABLE_ERRORS: tuple[type[Exception], ...] = (*AI_UNAVAILABLE_ERRORS, IncompleteAiAnswer)


def apply_proxy_settings(settings: Settings) -> None:
    """Sets the process's proxy (CII_PROXY_URL, else Windows' when bypassing), the gateways on NO_PROXY."""
    if proxy := settings.proxy_url.get_secret_value():
        _set_proxy_variables({"http": proxy, "https": proxy})
    elif settings.ai_bypass_proxy:
        _keep_windows_proxy()
    if settings.ai_bypass_proxy:
        hosts = {host for kind, host in _gateways(settings) if kind == LITELLM_MODEL_PREFIX}
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = merged_no_proxy(os.environ, hosts)
    _log_gateway_routes(settings)


@singleton
def apply_proxy_once() -> None:
    """Sets the proxy of the process's outside calls, before the first AI gateway or source refresh."""
    apply_proxy_settings(get_settings())


def _gateways(settings: Settings) -> set[tuple[str, str]]:
    models = [(settings.embedding_model, settings.embedding_base_url)]
    models += [(settings.rerank_model, settings.rerank_base_url)]
    chats = [settings.chat_of(module) for module in ChatModule]
    models += [(chat.model, chat.base_url) for chat in chats]
    return {
        (LITELLM_MODEL_PREFIX if model.startswith(LITELLM_MODEL_PREFIX) else "", host)
        for model, url in models
        if model and url and (host := urlsplit(url if "//" in url else f"//{url}").hostname)
    }


def merged_no_proxy(environment: Mapping[str, str], hosts: Iterable[str]) -> str:
    """One NO_PROXY list from both spellings (Python reads the lowercase one alone) and `hosts`, each once."""
    listed = [entry.strip() for name in ("NO_PROXY", "no_proxy") for entry in environment.get(name, "").split(",")]
    return ",".join(dict.fromkeys(entry for entry in [*listed, *sorted(hosts)] if entry))


def _log_gateway_routes(settings: Settings) -> None:
    proxies = urllib.request.getproxies()
    for host in sorted({host for _, host in _gateways(settings)}):
        proxy = urlsplit(proxies.get("https", ""))
        if not proxy.hostname or urllib.request.proxy_bypass(host):
            log.info(LogEvent.AI_GATEWAY_ROUTE, host=host, route="direct")
        else:
            log.info(LogEvent.AI_GATEWAY_ROUTE, host=host, route="proxy", proxy=f"{proxy.hostname}:{proxy.port}")


_PROXY_VARIABLES: Final = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")


def _keep_windows_proxy() -> None:
    read_windows_setting = getattr(urllib.request, "getproxies_registry", None)
    if read_windows_setting is None or any(os.environ.get(name) for name in _PROXY_VARIABLES):
        return
    # ponytail: Windows' bypass list (ProxyOverride) is not copied: the gateway, on NO_PROXY, is the only
    # internal HTTP host the app calls. Copy it when another internal HTTP host appears.
    _set_proxy_variables(read_windows_setting())


def _set_proxy_variables(proxies: dict[str, str]) -> None:
    for scheme, url in proxies.items():
        if scheme in ("http", "https"):
            os.environ[f"{scheme.upper()}_PROXY"] = os.environ[f"{scheme}_proxy"] = url


def build_api_key_header(header: str, api_key: str, option: str = "extra_headers") -> dict[str, Any]:
    """{option: {header: key}} when settings.ai_key_header is set, else {}; rerank takes `headers`."""
    return {option: {header: api_key}} if header else {}


def call_with_retries[Answer](
    call: Callable[[], Answer], rate: AiRequestRate, slots: AiSlots, *, model: str, task: str, tokens: int = 0
) -> Answer:
    """`call`'s answer, each try in a slot; retried when busy or short, a 429 as `rate` says; a timeout never."""
    attempt, rate_limited_waits = 0, 0.0
    while True:
        rate.wait_for_send_time(task)  # a 429's pause or a long line: waited holding no slot
        try:
            with slots.hold_slot(task):  # per attempt: a 429's Retry-After keeps no slot
                rate.wait_for_turn(task, tokens)  # spaced as sent, after any slot wait
                answer = call()
        except litellm.Timeout:
            raise
        except litellm.RateLimitError as exc:
            metrics.AI_RATE_LIMITED.labels(model).inc()
            slots.note_rate_limited()  # the gateway is full: fewer calls at once, on every pod
            retry_after = exc.response.headers.get("retry-after")
            wait = rate.wait_after_rate_limit(retry_after, attempt, rate_limited_waits)
            if wait is None:
                raise
            rate_limited_waits += rate.pause(wait)  # the model waits too, so no line of 429s follows
        except Exception as exc:
            unmapped = is_unmapped_outage(exc)  # a timed-out status is a timeout too: not asked again
            if unmapped and ai_outage_of(exc) is AiOutage.TIMED_OUT:
                raise
            wait = busy_retry_wait(attempt)
            if wait is None or not (unmapped or isinstance(exc, _RETRYABLE_ERRORS)):
                raise
        else:
            return answer
        sleep_unless_lease_lost(wait)
        attempt += 1


def _counted_outage(task: str, model: str, error: Exception, outage: AiOutage) -> Unavailable:
    metrics.AI_OUTAGES.labels(task, outage, AiOutageSource.GATEWAY).inc()
    # Retry-After, limit type and the 429's budget, never the message (it may hold the gateway URL or key owner).
    headers = getattr(getattr(error, "response", None), "headers", None) or {}
    log.warning(
        LogEvent.AI_CALL_UNAVAILABLE,
        ai_task=task,
        model=model,
        error_type=type(error).__name__,
        status=getattr(error, "status_code", None),
        reason=outage,
        retry_after=headers.get("retry-after"),
        limit_type=headers.get("rate_limit_type"),  # LiteLLM's: requests, tokens or max_parallel_requests
        **gateway_limit(error),
    )
    return Unavailable(AI_OUTAGE_MESSAGES[outage], reason=outage)


def gateway_limit(error: Exception) -> dict[str, str | int]:
    """The budget a gateway 429 names (its kind, size and what was left), never its key or user; {} for none."""
    found = _GATEWAY_LIMIT.search(str(error))
    if found is None:
        return {}
    scope, limit, remaining = found.groups()
    return {"limit_scope": scope, "limit": int(limit), "limit_remaining": int(remaining)}


def attempt_outcome(error: Exception) -> tuple[AiOutcome, AiOutage | None]:
    """A failed attempt's outcome and outage: the one classifier of every AI failure."""
    if isinstance(error, AI_UNAVAILABLE_ERRORS) or is_unmapped_outage(error):
        return AiOutcome.UNAVAILABLE, ai_outage_of(error)
    if isinstance(error, (IncompleteAiAnswer, UnusableAiAnswer, *AI_REFUSED_REPLY_ERRORS)):
        return AiOutcome.UNREADABLE, None
    return AiOutcome.ERROR, None


@contextmanager
def count_and_convert_ai_errors(task: str, model: str) -> Iterator[None]:
    """Counts a failed AI call by outcome and turns an outage into Unavailable, a bad key or model into JobFailed."""
    not_ai_failures: tuple[type[Exception], ...] = (LeaseLost, Unavailable, *REDIS_UNAVAILABLE_ERRORS)
    try:
        yield
    except not_ai_failures:
        raise  # a stopped job (G214), a limiter refusal or the limiters' Redis down: no AI failure (G222)
    except Exception as exc:
        outcome, outage = attempt_outcome(exc)
        metrics.AI_CALLS.labels(task, model, outcome).inc()
        if outage is not None:
            raise _counted_outage(task, model, exc, outage) from exc
        if isinstance(exc, IncompleteAiAnswer):
            raise Unavailable(str(exc)) from exc
        if isinstance(exc, AI_CONFIGURATION_ERRORS):
            status, error_type = getattr(exc, "status_code", None), type(exc).__name__
            log.error(LogEvent.AI_CALL_REFUSED, ai_task=task, model=model, error_type=error_type, status=status)
            message = ErrorMessage.AI_MISCONFIGURED.format(model=model, error=error_type, status=status)
            raise JobFailed(ErrorCode.AI_MISCONFIGURED, message) from exc
        raise
