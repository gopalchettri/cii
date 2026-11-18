"""AI usage rows (tsg_ai_usage): one per attempt sent to a model, failed and retried ones too, and one per
earlier answer reused, each saying who it served (module, API call, session, request, caller) and grouped by
the ask it served. An ask's rows are written when it ends, in one write and outside any AI slot; a write that
fails never fails the AI call: its rows go to the log (AiUsageLogEvent.ROW_SPILLED) for replay."""

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

import pymongo
import structlog
from bson import ObjectId

from app.ai import common
from app.ai.common import attempt_outcome
from app.ai.slots import AiRequestRate, AiSlots
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import AiOutcome, AiUsageLogEvent, AiUsageOutcome, Timeouts, ai_bucket
from app.core.database import get_mongodb
from app.core.lease_signal import shared_work
from app.crud import ai_usage

log = structlog.get_logger(__name__)

#: The log fields a usage row copies: the job, the delivery and who the job works for.
_JOB_FIELDS = ("module", "record_id", "epoch", "attempt", "session_id", "request_id", "api", "client_id", "entity_id")


@dataclass
class _Ask:
    """One logical ask: its id, the thread that asked, its attempts so far and the rows still to write."""

    id: ObjectId = field(default_factory=ObjectId)
    thread: int = field(default_factory=threading.get_ident)
    tries: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)


_ASK: ContextVar[_Ask | None] = ContextVar("ai_ask", default=None)


def _open_ask() -> _Ask | None:
    ask = _ASK.get()  # a copy of a job's context in a pool thread starts its own ask
    return ask if ask is not None and ask.thread == threading.get_ident() else None


@contextmanager
def one_ask() -> Iterator[None]:
    """Groups every AI attempt inside it under one ask (this thread's outermost) and writes its rows as it ends."""
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
    """One usage row, counted: added to the open ask (written as it ends), else written now."""
    bound, shared = structlog.contextvars.get_contextvars(), shared_work()
    job_task = shared or bound.get("task")
    ask = _open_ask()
    attempted = outcome != AiUsageOutcome.REUSED  # a reused answer is no attempt: no try number
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
    row = {name: value for name, value in row.items() if value is not None}
    # The low-cardinality Prometheus counters (no ids): tokens by module and API call, and by task and model.
    module, api, model = row.get("module", "none"), row.get("api", "none"), row.get("model", "none")
    labels = (module, api, row["bucket"], task, model, outcome, row.get("reason", "none"))
    metrics.AI_USAGE_CALLS.labels(*labels).inc()
    for direction in ("in", "out"):
        if tokens := row.get(f"tokens_{direction}"):
            metrics.AI_USAGE_TOKENS.labels(module, api, direction).inc(tokens)
            metrics.AI_TOKENS.labels(task, model, direction).inc(tokens)
    if ask is not None:
        ask.rows.append(row)
    else:
        write_usage_rows([row])


def search_tokens(response: Any) -> dict[str, int]:
    """An embedding or rerank answer's tokens as the gateway counts them (LiteLLM's order); {} for none."""
    prompt_tokens = getattr(getattr(response, "usage", None), "prompt_tokens", None)
    if prompt_tokens:
        return {"tokens_in": int(prompt_tokens)}
    meta = getattr(response, "meta", None) or {}
    tokens = meta.get("tokens") or {}
    if tokens.get("input_tokens") or tokens.get("output_tokens"):
        return {"tokens_in": int(tokens.get("input_tokens") or 0), "tokens_out": int(tokens.get("output_tokens") or 0)}
    billed = (meta.get("billed_units") or {}).get("total_tokens")
    return {"tokens_in": int(billed)} if billed else {}


def call_with_retries[Answer](
    call: Callable[[], Answer], rate: AiRequestRate, slots: AiSlots, *, model: str, task: str, tokens: int = 0
) -> tuple[Answer, float]:
    """common.call_with_retries as one ask, each failed try noted; the seconds are the answering try's own."""
    answered: list[float] = []

    def attempt() -> Answer:
        started = time.perf_counter()
        try:
            answer = call()
        except Exception as exc:
            outcome, reason = attempt_outcome(exc)
            seconds = time.perf_counter() - started
            note_ai_usage(task, model, outcome, reason=reason, error_type=type(exc).__name__, seconds=seconds)
            raise
        answered.append(time.perf_counter() - started)
        return answer

    with one_ask():
        answer = common.call_with_retries(attempt, rate, slots, model=model, task=task, tokens=tokens)
        return answer, answered[-1]


def write_usage_rows(rows: list[dict[str, Any]]) -> None:
    """One write of the rows; on any failure each row is logged (for replay) and counted, never raised."""
    if not rows:
        return
    started = time.perf_counter()
    try:
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            ai_usage.insert_rows(get_mongodb(), rows)
    except Exception:  # noqa: BLE001 - ponytail: the rows are logged instead; ai_usage_tools replay
        for row in rows:  # ids and times as text: the replay script turns them back
            text = {name: str(value) if isinstance(value, ObjectId) else value for name, value in row.items()}
            text["created_at"] = row["created_at"].isoformat()
            log.error(AiUsageLogEvent.ROW_SPILLED, row=text, exc_info=True)
        metrics.AI_USAGE_SPILLED.inc(len(rows))
        return
    metrics.AI_USAGE_WRITE_SECONDS.observe(time.perf_counter() - started)
