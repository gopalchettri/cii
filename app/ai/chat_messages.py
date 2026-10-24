"""What a chat call sends and gets back: the conversation, its size, its request options, the answer's JSON
object and the call's record (metrics, log line, tsg_ai_calls copy, read back by the job's next delivery). No
AI call here: app/ai/chat.py makes them."""

import hashlib
import json
from collections.abc import Callable
from typing import Any

import structlog

from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    CHAT_MAX_OUTPUT_TOKENS,
    CHAT_TEMPERATURES,
    LITELLM_MODEL_PREFIX,
    THINKING_OFF_TEMPLATE_KWARGS,
    AiOutcome,
    AiTask,
    LogEvent,
)
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.models.ai.profiles import ChatModelProfile

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


def max_answer_tokens(profile: ChatModelProfile, task: AiTask, thinking: bool, capped: bool = True) -> int:
    """The task's answer cap (CHAT_MAX_OUTPUT_TOKENS) under the model's own limit; the model's limit when not
    `capped` or when it thinks (its hidden thinking counts too: the caps, measured with thinking off, would
    cut it)."""
    if thinking or not capped:
        return profile.max_output_tokens
    return min(profile.max_output_tokens, CHAT_MAX_OUTPUT_TOKENS.get(task, profile.max_output_tokens))


def build_request_options(
    profile: ChatModelProfile, task: AiTask, model: str, thinking: bool, capped: bool = True
) -> dict[str, Any]:
    """The request options this model accepts (its profile) for this task (its temperature, R-2, and answer
    length, max_answer_tokens), with its thinking switched off unless `thinking` (CII_*_MODEL_THINKING)."""
    # stream=False on the wire: a proxy entry pinning stream=true (UAT glm-5.3's) would otherwise
    # pick the shape.
    options: dict[str, Any] = {
        "max_tokens": max_answer_tokens(profile, task, thinking, capped),
        "timeout": profile.timeout_seconds,
        "stream": False,
    }
    if profile.supports_json_mode:
        options["response_format"] = {"type": "json_object"}
    temperature = CHAT_TEMPERATURES.get(task)
    if temperature is not None:  # None: not sent at all, so the provider's default applies (as v1)
        options["temperature"] = temperature
    if profile.reasoning_effort is not None:
        # allowed_openai_params is load-bearing: without it litellm may drop a parameter its own model
        # table thinks unsupported (v1 saw this on openai/Kimi-K2.6), and thinking silently stays on.
        options["reasoning_effort"] = profile.reasoning_effort
        options["allowed_openai_params"] = ["reasoning_effort"]
    if not thinking and model.startswith(LITELLM_MODEL_PREFIX):
        # The gateway's vLLM models switch thinking in their chat template (UAT probe). Gateway models only:
        # another provider (dev Azure) may refuse a parameter it does not know.
        options["extra_body"] = {"chat_template_kwargs": dict(THINKING_OFF_TEMPLATE_KWARGS)}
    return options


def build_call_record(  # noqa: PLR0913 — one chat call, whole
    task: AiTask, model: str, messages: list[dict], response: Any, seconds: float, outcome: AiOutcome
) -> dict[str, Any]:
    """The audit copy of one chat call, with the job, the delivery and the request it served (from the log
    context)."""
    context = structlog.contextvars.get_contextvars()
    return {
        "created_at": utc_now(),
        "task": task,
        "model": model,
        "outcome": outcome,
        **_job_of(context),  # with prompt_hash: finds one job's AI calls
        "task_id": context.get("task_id"),
        "prompt_hash": prompt_hash(messages),
        "request_id": context.get("request_id"),
        "prompt": _without_system_prompt_text(messages),
        "response": response.choices[0].message.content or "",
        "tokens_in": getattr(response.usage, "prompt_tokens", 0) or 0,
        "tokens_out": getattr(response.usage, "completion_tokens", 0) or 0,
        "seconds": seconds,
    }


def _job_of(context: dict[str, Any]) -> dict[str, Any]:
    """The leased job a call serves: its record, epoch and stage (job.task), the same for every delivery of
    it (app/worker/jobs.py run_leased_job binds them); epoch None outside a leased job."""
    return {
        "record_id": context.get("record_id"),
        "epoch": context.get("epoch"),
        "job_task": context.get("task"),
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
    """The exact conversation's fingerprint: equal only for the same messages in the same order."""
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
    records: AiCallRepository,
    task: AiTask,
    model: str,
    messages: list[dict],
    response: Any,
    seconds: float,
    outcome: AiOutcome,
) -> None:
    """One outcome per call: counted and logged, then copied to tsg_ai_calls (the system prompt as its
    hash), so every user prompt and answer of a run can be found."""
    record = build_call_record(task, model, messages, response, seconds, outcome)
    update_call_metrics(task, model, outcome, record["tokens_in"], record["tokens_out"], seconds)
    try:
        records.create(record)
    except Exception:  # noqa: BLE001 - ponytail: the audit copy must never fail the AI call; logged instead
        log.warning(LogEvent.AI_CALL_RECORD_FAILED, task=task, exc_info=True)


def find_earlier_answer(
    records: AiCallRepository,
    task: AiTask,
    messages: list[dict],
    check: Callable[[dict[str, Any]], list[str]],
) -> tuple[dict[str, Any], str] | None:
    """(answer, reply) of this job's newest ok call with exactly these messages, from any of its deliveries,
    when `check` accepts that answer: a rejected one is asked again, as the job's retry after it means to.
    None outside a leased job (the API), when there is none, or when tsg_ai_calls cannot be read (the AI is
    asked then)."""
    job = _job_of(structlog.contextvars.get_contextvars())
    if None in job.values():
        return None
    try:
        reply = records.find_ok_response(job, prompt_hash(messages))
    except Exception:  # noqa: BLE001 - ponytail: a failed lookup only costs the AI call it would save
        log.warning(LogEvent.AI_ANSWER_LOOKUP_FAILED, task=task, exc_info=True)
        return None
    if reply is None or (answer := parse_json_object(reply)) is None or check(answer):
        return None
    log.info(LogEvent.AI_ANSWER_REUSED, task=task)
    return answer, reply
