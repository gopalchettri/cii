"""What a chat call sends and gets back: the conversation, its size and the answer's JSON object. No AI call
here: app/ai/chat.py makes them."""

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.constants import AiOutcome, AiTask


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
        "request_id": context.get("request_id"),
        "prompt": messages,
        "response": response.choices[0].message.content or "",
        "tokens_in": getattr(response.usage, "prompt_tokens", 0) or 0,
        "tokens_out": getattr(response.usage, "completion_tokens", 0) or 0,
        "seconds": seconds,
    }
