"""What every AI gateway shares: which provider errors mean "busy or down", the answer errors, the key
header, the retries and how each call's outcome is counted."""

import os
import time
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final
from urllib.parse import urlsplit

import litellm
import structlog

from app.ai.module_chat import module_chat
from app.ai.retry_waits import busy_retry_wait
from app.ai.slots import AiRequestRate, AiSlots, sleep_unless_lease_lost
from app.core import metrics
from app.core.config import Settings
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
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, AppError, JobFailed, LeaseLost, Unavailable

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


def ai_outage_of(error: Exception) -> AiOutage:
    """Which outage a provider error is: by its class, else by its HTTP status. A timeout is tested first:
    litellm's Timeout is a lost connection too."""
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
    """A plain litellm.APIError (a status litellm maps to no class of its own, e.g. a 524 origin timeout or a
    529 overloaded) that is an outage: a server's status (5xx), a request timeout (408) or none at all. Any
    other (a 4xx) stays an error."""
    status = getattr(error, "status_code", None)
    return isinstance(error, litellm.APIError) and (status is None or status == 408 or status >= 500)


def outage_reason(error: BaseException) -> AiOutage | None:
    """Which AI outage an error carries (an Unavailable's reason); None for any other error or outage (a
    store, a SQL write still in progress)."""
    reason = error.reason if isinstance(error, AppError) else None
    return AiOutage(reason) if reason and reason in AiOutage else None


#: Provider answers no retry can change: a refused or revoked key, no permission, a model the gateway does not
#: know. The job fails at once with ai_misconfigured, never one failure per path or category (S16-S31 review).
AI_CONFIGURATION_ERRORS: tuple[type[Exception], ...] = (
    litellm.AuthenticationError,
    litellm.PermissionDeniedError,
    litellm.NotFoundError,
)


#: Chat replies that refuse the prompt or break the response contract: the chat gateway reads each as an
#: unreadable reply, never as a fault of ours.
AI_REFUSED_REPLY_ERRORS: tuple[type[Exception], ...] = (
    litellm.ContentPolicyViolationError,
    litellm.exceptions.RejectedRequestError,
    litellm.APIResponseValidationError,
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


def apply_proxy_settings(settings: Settings) -> None:
    """Which proxy the outside calls use. litellm takes no per-call proxy setting, hence the process
    environment. The container calls it once (app/container.py apply_proxy_once) before it builds any AI
    gateway or the source refresher; a *_model_from factory called directly skips it.
    1. CII_PROXY_URL, when set, is the proxy (HTTP(S)_PROXY) of the whole process: the intel feeds, and the AI
       calls unless step 2 skips it. Empty: the HTTP(S)_PROXY variables already set, else, when step 2 runs,
       Windows' own proxy setting (_keep_windows_proxy).
    2. CII_AI_BYPASS_PROXY=true (v1's TSG_LITELLM_BYPASS_PROXY): the host of every LiteLLM gateway model
       (litellm_proxy/...) goes on NO_PROXY, so those calls go direct; every other host keeps the proxy.
    The pods list the gateway on NO_PROXY themselves (deploy/*.yaml, D23); this keeps the app right without.
    Then each AI gateway's route is logged (ai.gateway_route), so a call sent to the proxy shows."""
    if proxy := settings.proxy_url.get_secret_value():
        _set_proxy_variables({"http": proxy, "https": proxy})
    elif settings.ai_bypass_proxy:
        _keep_windows_proxy()
    if settings.ai_bypass_proxy:
        hosts = {host for kind, host in _gateways(settings) if kind == LITELLM_MODEL_PREFIX}
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = merged_no_proxy(os.environ, hosts)
    _log_gateway_routes(settings)


def _gateways(settings: Settings) -> set[tuple[str, str]]:
    """(LITELLM_MODEL_PREFIX or "", host) of every AI model's base URL: which hosts the AI calls go to."""
    models = [(settings.embedding_model, settings.embedding_base_url)]
    models += [(settings.rerank_model, settings.rerank_base_url)]
    for chat in (module_chat(settings, module) for module in ChatModule):  # each module's main and fallback
        models += [(chat.model, chat.base_url), (chat.fallback_model, chat.base_url)]
    return {
        (LITELLM_MODEL_PREFIX if model.startswith(LITELLM_MODEL_PREFIX) else "", host)
        for model, url in models
        if model and url and (host := urlsplit(url if "//" in url else f"//{url}").hostname)
    }


def merged_no_proxy(environment: Mapping[str, str], hosts: Iterable[str]) -> str:
    """One NO_PROXY list from both spellings and `hosts`, each entry once. Linux has two variables and Python
    reads the lowercase one alone, so writing the gateway into it alone hid the pod's own entries."""
    listed = [
        entry.strip() for name in ("NO_PROXY", "no_proxy") for entry in environment.get(name, "").split(",")
    ]
    return ",".join(dict.fromkeys(entry for entry in [*listed, *sorted(hosts)] if entry))


def _log_gateway_routes(settings: Settings) -> None:
    """One line per AI gateway host: direct, or through which proxy (its host and port only: a proxy address
    can carry a password), as the HTTP clients will decide from this process's environment."""
    proxies = urllib.request.getproxies()
    for host in sorted({host for _, host in _gateways(settings)}):
        proxy = urlsplit(proxies.get("https", ""))
        if not proxy.hostname or urllib.request.proxy_bypass(host):
            log.info(LogEvent.AI_GATEWAY_ROUTE, host=host, route="direct")
        else:
            log.info(
                LogEvent.AI_GATEWAY_ROUTE, host=host, route="proxy", proxy=f"{proxy.hostname}:{proxy.port}"
            )


_PROXY_VARIABLES: Final = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")


def _keep_windows_proxy() -> None:
    """G263 (UAT, 2026-10-16): Python reads Windows' own proxy setting (Internet Options) only while no
    *_PROXY variable is set, so the NO_PROXY written for the gateway switched it off for every other host:
    the intel feeds went straight to the firewall ("did not answer"). It is copied into HTTP(S)_PROXY first,
    read from Windows directly (a NO_PROXY set before cannot hide it); a proxy variable already set wins.
    Windows only: nowhere else does Python read a system setting."""
    read_windows_setting = getattr(urllib.request, "getproxies_registry", None)
    if read_windows_setting is None or any(os.environ.get(name) for name in _PROXY_VARIABLES):
        return
    # ponytail: Windows' bypass list (ProxyOverride) is not copied: the gateway, on NO_PROXY, is the only
    # internal HTTP host the app calls. Copy it when another internal HTTP host appears.
    _set_proxy_variables(read_windows_setting())


def _set_proxy_variables(proxies: dict[str, str]) -> None:
    """Both spellings: Windows has one variable per name, Linux two (and some tools read only one)."""
    for scheme, url in proxies.items():
        if scheme in ("http", "https"):
            os.environ[f"{scheme.upper()}_PROXY"] = os.environ[f"{scheme}_proxy"] = url


def build_api_key_header(header: str, api_key: str, option: str = "extra_headers") -> dict[str, Any]:
    """{option: {header: key}} for a gateway that reads the key from its own header (settings.ai_key_header);
    {} when none is set. litellm's rerank takes `headers` (it drops `extra_headers`); chat and embedding take
    `extra_headers`."""
    return {option: {header: api_key}} if header else {}


def call_with_retries[Answer](
    call: Callable[[], Answer], rate: AiRequestRate, slots: AiSlots, *, model: str, task: str, tokens: int = 0
) -> tuple[Answer, float]:
    """(the answer, its seconds without the request-turn and slot waits) of an AI call to `model` for `task`
    and the check of its answer. Each attempt waits out `rate`'s pause or line holding no slot, then holds a
    slot of `slots` for its own turn (`tokens`: its size) and the call alone. A 429 pauses `rate` on every pod
    and is told to `slots`. Asked again when busy, unreachable or short: AiLimits.RETRIES times, 0.5, 1, 2 s
    apart; a 429 (counted) as rate.wait_after_rate_limit says. A timed-out call is not asked again."""
    started, attempt = time.perf_counter(), 0
    waits = rate_limited_waits = 0.0  # request turns and AI slots: not the call's own seconds
    while True:
        waits += rate.wait_for_send_time(task)  # a 429's pause or a long line: waited holding no slot
        try:
            with slots.hold_slot(task) as slot_wait:  # per attempt: a 429's Retry-After keeps no slot
                waits += slot_wait + rate.wait_for_turn(task, tokens)  # spaced as sent, after any slot wait
                answer, seconds = call(), time.perf_counter() - started - waits
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
            return answer, seconds
        sleep_unless_lease_lost(wait)
        attempt += 1


def _counted_outage(task: str, model: str, error: Exception) -> Unavailable:
    """A provider outage, counted and logged, as the Unavailable that tells the UI which outage it was."""
    metrics.AI_CALLS.labels(task, model, AiOutcome.UNAVAILABLE).inc()
    # Which outage it was (rate limit, timeout, lost connection, gateway restart) decides the cure, so it is
    # logged with the gateway's Retry-After and limit type, never the message (it may hold the gateway URL).
    outage = ai_outage_of(error)
    metrics.AI_OUTAGES.labels(task, outage, AiOutageSource.GATEWAY).inc()
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
    )
    return Unavailable(AI_OUTAGE_MESSAGES[outage], reason=outage)


@contextmanager
def count_and_convert_ai_errors(
    task: str, model: str, unreadable_errors: tuple[type[Exception], ...] = ()
) -> Iterator[None]:
    """Counts a failed AI call in tsg_ai_calls_total by its outcome (each gateway counts its own "ok"), and
    turns the provider busy or down, or an answer still short after the retries, into Unavailable: the job
    backs off and retries. `unreadable_errors` are counted unreadable and raised as they are."""
    unreadable: tuple[type[Exception], ...] = (UnusableAiAnswer, *unreadable_errors)
    try:
        yield
    except LeaseLost:
        raise  # its job was stopped (G214): not an AI failure, so never counted as one (G222)
    except Unavailable:
        raise  # no provider answered: counted already, or no slot or request turn free (app/ai/slots.py)
    except REDIS_UNAVAILABLE_ERRORS:
        raise  # the limiters' Redis is down, not the AI: the job retries as for any store outage
    except AI_UNAVAILABLE_ERRORS as exc:
        raise _counted_outage(task, model, exc) from exc
    except litellm.APIError as exc:  # a status litellm maps to no class: an outage when a server's (5xx)
        if is_unmapped_outage(exc):
            raise _counted_outage(task, model, exc) from exc
        metrics.AI_CALLS.labels(task, model, AiOutcome.ERROR).inc()
        raise
    except AI_CONFIGURATION_ERRORS as exc:
        metrics.AI_CALLS.labels(task, model, AiOutcome.ERROR).inc()
        status, error_type = getattr(exc, "status_code", None), type(exc).__name__
        log.error(LogEvent.AI_CALL_REFUSED, ai_task=task, model=model, error_type=error_type, status=status)
        message = ErrorMessage.AI_MISCONFIGURED.format(model=model, error=error_type, status=status)
        raise JobFailed(ErrorCode.AI_MISCONFIGURED, message) from exc
    except IncompleteAiAnswer as exc:
        metrics.AI_CALLS.labels(task, model, AiOutcome.UNREADABLE).inc()
        raise Unavailable(str(exc)) from exc
    except unreadable:
        metrics.AI_CALLS.labels(task, model, AiOutcome.UNREADABLE).inc()
        raise
    except Exception:
        metrics.AI_CALLS.labels(task, model, AiOutcome.ERROR).inc()
        raise
