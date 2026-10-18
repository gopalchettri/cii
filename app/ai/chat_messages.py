"""What a chat call sends and gets back: the conversation, its size, the answer's JSON object and the call's
record (metrics, log line, tsg_ai_calls copy). No AI call here: app/ai/chat.py makes them."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core import metrics
from app.core.constants import AiOutcome, AiTask, LogEvent
from app.data_access.ai_calls import AiCallRecords

log = structlog.get_logger(__name__)


def _remove_markdown_code_fence(answer: str) -> str:
    text = answer.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0]
    return text.strip()


def parse_json_object(reply: str) -> dict[str, Any] | None:
    """The reply's JSON object; None when it is not one (a JSON array or string is no answer either: dict()
    would turn ["ab"] into {"a": "b"})."""
    try:
        parsed = json.loads(_remove_markdown_code_fence(reply))
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def count_prompt_chars(messages: list[dict[str, str]]) -> int:
    return sum(len(message["content"]) for message in messages)


def build_conversation(system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
    return [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]


def build_call_record(  # noqa: PLR0913 — one chat call, whole
    task: AiTask, model: str, messages: list[dict], response: Any, seconds: float, outcome: AiOutcome
) -> dict[str, Any]:
    """The audit copy of one chat call, with the run and the request it served (from the log context)."""
    context = structlog.contextvars.get_contextvars()
    return {
        "created_at": datetime.now(UTC),
        "task": task,
        "model": model,
        "outcome": outcome,
        "record_id": context.get("record_id"),
        "task_id": context.get("task_id"),  # G244: a retry of this job reuses this answer
        "prompt_hash": prompt_hash(messages),
        "request_id": context.get("request_id"),
        "prompt": _without_system_prompt_text(messages),
        "response": response.choices[0].message.content or "",
        "tokens_in": getattr(response.usage, "prompt_tokens", 0) or 0,
        "tokens_out": getattr(response.usage, "completion_tokens", 0) or 0,
        "seconds": seconds,
    }


def _without_system_prompt_text(messages: list[dict]) -> list[dict]:
    """The conversation as stored: a system prompt (6-30 KB, the same on every call of a task) is kept as a
    short hash of its text; the user, assistant and correction turns are kept whole."""
    return [
        {"role": "system", "content_sha256": _short_hash(message["content"])}
        if message["role"] == "system"
        else message
        for message in messages
    ]


def _short_hash(text: str) -> str:
    """The first 16 hex characters of the text's SHA-256: enough to tell two prompt texts apart."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def prompt_hash(messages: list[dict]) -> str:
    """The exact conversation's fingerprint (G244): equal only for the same messages in the same order."""
    text = json.dumps(messages, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def update_call_metrics(
    task: AiTask, model: str, outcome: AiOutcome, tokens_in: int, tokens_out: int, seconds: float
) -> None:
    """The metrics and the log line of one chat call."""
    metrics.AI_CALLS.labels(task, model, outcome).inc()
    metrics.AI_TOKENS.labels(task, model, "in").inc(tokens_in)
    metrics.AI_TOKENS.labels(task, model, "out").inc(tokens_out)
    metrics.AI_SECONDS.labels(task, model).observe(seconds)
    log.info(
        LogEvent.AI_CALL,
        task=task,
        model=model,
        outcome=outcome,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        seconds=round(seconds, 2),
    )


def record_chat_call(  # noqa: PLR0913 - one chat call, whole, and where it is kept
    records: AiCallRecords,
    task: AiTask,
    model: str,
    messages: list[dict],
    response: Any,
    seconds: float,
    outcome: AiOutcome,
) -> None:
    """One outcome per call: counted and logged, then copied to tsg_ai_calls (the system prompt as its
    hash), so every user prompt and answer of a run can be found (and a retry reuses a usable one, G244)."""
    record = build_call_record(task, model, messages, response, seconds, outcome)
    update_call_metrics(task, model, outcome, record["tokens_in"], record["tokens_out"], seconds)
    try:
        records.insert(record)
    except Exception:  # noqa: BLE001 - ponytail: the audit copy must never fail the AI call; logged instead
        log.warning(LogEvent.AI_CALL_RECORD_FAILED, task=task, exc_info=True)
