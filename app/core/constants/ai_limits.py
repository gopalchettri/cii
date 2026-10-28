"""The AI call limiters' values: retries and their waits, the AI slots, and the limit a gateway 429 sets."""

from enum import StrEnum
from typing import Final


class AiOutageSource(StrEnum):
    """tsg_ai_outages_total{source}: who refused the call."""

    GATEWAY = "gateway"  # the AI gateway or its provider: busy, down, timed out or not reached
    LIMITER = "limiter"  # TSG's own limiter: no request turn or AI slot free within the wait


class AiLimits:
    """The same for every model; per-model values live in app/ai/profiles.py."""

    RETRIES: Final = 3  # a busy or unreachable provider is retried this many times, with back-off
    RETRY_FIRST_WAIT_SECONDS: Final = 0.5  # then doubling
    # A worker asks a rate-limited (HTTP 429) model again, not its fallback (55-99 s), as rate_limited_wait
    # says; the API retries a 429 as any busy answer.
    RATE_LIMITED_WAITS_SECONDS: Final = (2, 5, 10, 15)
    RATE_LIMITED_JITTER: Final = 0.2
    RATE_LIMITED_MAX_WAIT_SECONDS: Final = 60  # a longer Retry-After is honoured up to one gateway window
    RATE_LIMITED_TOTAL_WAIT_SECONDS: Final = 60  # one call's 429 waits in all: one window, then the fallback
    # A gateway 429 limits the AI calls in flight on every pod (AiSlots.note_rate_limited):
    ADAPTIVE_LIMIT_FLOOR: Final = 4  # never below: every running job still moves; fewer only starves them
    ADAPTIVE_CUT_SPACING_SECONDS: Final = 5  # one cut per burst of 429s: about one kimi answer (3-8 s)
    ADAPTIVE_LIMIT_TTL_SECONDS: Final = 180  # gone after 3 minutes with no 429: three 60 s gateway windows
    LEASE_CHECK_SECONDS: Final = 1.0  # a job waiting to ask the AI checks its lease this often
    CALL_RECORD_DAYS: Final = 14  # tsg_ai_calls retention
    # Prompt characters per token: 4.3-6.1 measured on Kimi-K2.6; 3 leaves room for glm and non-English text.
    PROMPT_CHARS_PER_TOKEN: Final = 3
    MODEL_COOL_DOWN_SECONDS: Final = 120  # a timed-out or still rate-limited model is asked last this long
    SLOTS_KEY: Final = "tsg:ai_slots"  # the AI call limiter's Redis sorted set, shared by every pod
    SLOTS_LIMIT_KEY: Final = "tsg:ai_slots:limit"  # the limit a gateway 429 set on it (a Redis hash)
    FALLBACK_SLOTS_KEY: Final = "tsg:ai_fallback_slots"  # the same for the fallback model's calls alone
    REQUEST_RATE_KEY: Final = "tsg:ai_next_request:{model}"  # when that model's next request may be sent
    API_SLOT_WAIT_SECONDS: Final = 30  # the API answers a caller: it waits briefly for a free slot
    # ponytail: a day stands for "no clock of its own": a worker waits for an AI slot or request turn until
    # its job's lease ends (a cancel, or the reaper taking a stalled job over), long before this.
    WORKER_SLOT_WAIT_SECONDS: Final = 86_400
    SLOT_LEASE_SECONDS: Final = 60  # a slot not renewed this long ends: a dead process frees it this soon
    SLOT_RENEW_SECONDS: Final = 20  # each process renews the slots it holds this often
    # AI calls (at cap 0) and request turns leave a Redis that just failed alone this long
    REDIS_SKIP_SECONDS: Final = 30
    SLOT_FIRST_PAUSE_SECONDS: Final = 0.05  # polls for a free slot start this often, doubling ...
    SLOT_MAX_PAUSE_SECONDS: Final = 0.25  # ... up to this: the first in line sees a freed slot this soon
    SLOT_WAITER_STALE_SECONDS: Final = 5  # a waiter that has not polled this long leaves the line
    LOCAL_RERANK_TURN_DOCUMENTS: Final = 6  # documents one turn at the local CPU reranker scores
    REASK_MAX_PROBLEMS: Final = 20  # the one corrective re-ask lists at most this many problems ...
    REASK_PROBLEM_CHARS: Final = 200  # ... each cut to this
    REASK_MESSAGE: Final = (
        "Your previous reply was rejected:\n{problems}\n"
        "Return the corrected JSON object only, in exactly the requested format."
    )
