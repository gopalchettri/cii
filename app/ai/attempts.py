"""AI usage rows (tsg_ai_usage): one per attempt sent to a model, failed and retried ones too, and one per
earlier answer reused, each saying who it served (module, API call, session, request, caller) and grouped by
the ask it served. An ask's rows are written when it ends, in one write and outside any AI slot; a write that
fails never fails the AI call: its rows go to the log (AiUsageLogEvent.ROW_SPILLED) for replay."""

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

import pymongo
import structlog
from bson import ObjectId

from app.ai import common
from app.ai.common import (
    AI_REFUSED_REPLY_ERRORS,
    AI_UNAVAILABLE_ERRORS,
    IncompleteAiAnswer,
    UnusableAiAnswer,
    ai_outage_of,
    is_unmapped_outage,
)
from app.ai.slots import AiRequestRate, AiSlots
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import AiOutage, AiOutcome, AiUsageLogEvent, AiUsageOutcome, Timeouts, ai_bucket
from app.core.lease_signal import shared_work
from app.data_access.admin.ai_usage_repository import AiUsageRepository

log = structlog.get_logger(__name__)

#: The log fields a usage row copies: the job, the delivery and who the job works for.
_JOB_FIELDS = (
    "module",
    "record_id",
    "epoch",
    "attempt",
    "session_id",
    "request_id",
    "api",
    "client_id",
    "entity_id",
)


class _Ask:
    """One logical ask: its id, the thread that asked, its attempts so far and the rows still to write."""

    def __init__(self) -> None:
        self.id = ObjectId()
        self.thread = threading.get_ident()
        self.tries = 0
        self.rows: list[dict[str, Any]] = []


_ASK: ContextVar[_Ask | None] = ContextVar("ai_ask", default=None)


def _open_ask() -> _Ask | None:
    """The ask open on this thread; a copy of a job's context in a pool thread starts its own."""
    ask = _ASK.get()
    return ask if ask is not None and ask.thread == threading.get_ident() else None


@contextmanager
def one_ask() -> Iterator[None]:
    """Groups every AI attempt inside it under one ask (the outermost on this thread) and writes their rows
    when it ends, however it ends."""
    if _open_ask() is not None:
        yield
        return
    ask = _Ask()
    token = _ASK.set(ask)
    try:
        yield
    finally:
        _ASK.reset(token)
        write_usage_rows(ask.rows)


def note_ai_usage(task: str, model: str, outcome: AiUsageOutcome | AiOutcome, **measures: Any) -> None:
    """One usage row: added to the open ask (written when it ends), else written now. `measures`: call_id
    (the call text's _id), reason, error_type, tokens_in, tokens_out, seconds, reask."""
    ask = _open_ask()
    row = _usage_row(task, model, outcome, measures)
    _count(row)
    if ask is not None:
        ask.rows.append(row)
    else:
        write_usage_rows([row])


def call_with_retries[Answer](
    call: Callable[[], Answer], rate: AiRequestRate, slots: AiSlots, *, model: str, task: str, tokens: int = 0
) -> tuple[Answer, float]:
    """common.call_with_retries as one ask, each failed attempt noted (the call's own failure, never a wait
    for a slot or a turn: nothing was sent then). The seconds are the answering attempt's own, never its
    failed tries' or the waits between, so its usage row, its text, its log line and its metric all agree."""
    with one_ask():
        answered: list[float] = []
        noted = _noting_failures(call, task, model, answered)
        answer, _ = common.call_with_retries(noted, rate, slots, model=model, task=task, tokens=tokens)
        return answer, answered[-1]


def _noting_failures[Answer](
    call: Callable[[], Answer], task: str, model: str, answered: list[float]
) -> Callable[[], Answer]:
    """`call` timed: a failure noted with its own seconds; an answer's seconds added to `answered`."""

    def attempt() -> Answer:
        started = time.perf_counter()
        try:
            answer = call()
            answered.append(time.perf_counter() - started)
            return answer
        except Exception as exc:
            outcome, reason = attempt_outcome(exc)
            seconds = time.perf_counter() - started
            note_ai_usage(task, model, outcome, reason=reason, error_type=type(exc).__name__, seconds=seconds)
            raise

    return attempt


def attempt_outcome(error: Exception) -> tuple[AiOutcome, AiOutage | None]:
    """A failed attempt's outcome and outage, as count_and_convert_ai_errors counts its failure."""
    if isinstance(error, AI_UNAVAILABLE_ERRORS) or is_unmapped_outage(error):
        return AiOutcome.UNAVAILABLE, ai_outage_of(error)
    if isinstance(error, (IncompleteAiAnswer, UnusableAiAnswer, *AI_REFUSED_REPLY_ERRORS)):
        return AiOutcome.UNREADABLE, None
    return AiOutcome.ERROR, None


def write_usage_rows(rows: list[dict[str, Any]]) -> None:
    """Writes the rows in one write within RECORD_WRITE_SECONDS; on any failure, logs each whole row (for
    replay) and counts it, never raising: tracking never fails the AI call."""
    if not rows:
        return
    started = time.perf_counter()
    try:
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            AiUsageRepository().create_rows(rows)
    except Exception:  # noqa: BLE001 - ponytail: the rows are logged instead; ai_usage_tools replay
        for row in rows:
            log.error(AiUsageLogEvent.ROW_SPILLED, row=_loggable(row), exc_info=True)
        metrics.AI_USAGE_SPILLED.inc(len(rows))
        return
    metrics.AI_USAGE_WRITE_SECONDS.observe(time.perf_counter() - started)


def _usage_row(task: str, model: str, outcome: str, measures: dict[str, Any]) -> dict[str, Any]:
    """The row: who it served (none on a shared thread), what was asked, how it went, and its ask; a reused
    answer is no attempt, so it takes no try number."""
    bound, shared = structlog.contextvars.get_contextvars(), shared_work()
    job_task = shared or bound.get("task")
    ask = _open_ask()
    attempted = outcome != AiUsageOutcome.REUSED
    if ask is not None and attempted:
        ask.tries += 1
    row = {
        "_id": measures.pop("call_id", None) or ObjectId(),
        "created_at": utc_now(),
        **({} if shared else {name: bound.get(name) for name in _JOB_FIELDS}),
        "bucket": ai_bucket(task, None if shared else job_task),
        "job_task": job_task,
        "task": task,
        "model": model or None,
        "outcome": outcome,
        "ask_id": ask.id if ask is not None else None,
        "try_no": (ask.tries if ask is not None else 1) if attempted else None,
        **measures,
    }
    return {name: value for name, value in row.items() if value is not None}


def _count(row: dict[str, Any]) -> None:
    """The row in the low-cardinality Prometheus counters (no ids: those stay in tsg_ai_usage)."""
    module, api = row.get("module", "none"), row.get("api", "none")
    labels = (module, api, row["bucket"], row["task"], row.get("model", "none"), row["outcome"])
    metrics.AI_USAGE_CALLS.labels(*labels, row.get("reason", "none")).inc()
    for direction in ("in", "out"):
        if tokens := row.get(f"tokens_{direction}"):
            metrics.AI_USAGE_TOKENS.labels(module, api, direction).inc(tokens)


def _loggable(row: dict[str, Any]) -> dict[str, Any]:
    """The row as JSON can hold it: ids and times as text (the replay script turns them back)."""
    return {name: str(value) if isinstance(value, ObjectId) else value for name, value in row.items()} | {
        "created_at": row["created_at"].isoformat()
    }
