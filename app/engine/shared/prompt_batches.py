"""Packing many items into as few prompts as fit (v1 relevance.batches): every batch stays within the model's
input, with room left for its one corrective re-ask; a limit means more calls, never a dropped item."""

import json
from collections.abc import Callable, Iterator
from typing import Any

from app.ai import CORRECTION_MESSAGE_MAX_CHARS
from app.core.constants import ThreatFinding
from app.engine.shared.ask_ai import ChatPrompt


def max_batch_prompt_chars(max_prompt_chars: int) -> int:
    """The most characters one batched prompt may use: a share of the input limit, never so much that its
    re-ask would not fit after it."""
    return min(
        int(max_prompt_chars * ThreatFinding.PROMPT_SHARE), max_prompt_chars - CORRECTION_MESSAGE_MAX_CHARS
    )


def prompt_length(prompt: ChatPrompt) -> int:
    return len(prompt[0]) + len(prompt[1])


def batches_that_fit(
    build_prompt: Callable[[list[dict[str, Any]]], ChatPrompt],
    items: list[dict[str, Any]],
    room: int,
    max_items: int | None = None,
) -> Iterator[list[dict[str, Any]]]:
    """`items`, in order, packed into batches whose prompt (`build_prompt(batch)`) stays within `room`, and of
    at most `max_items` items: a limit means more calls, never one oversize call or a dropped item."""
    empty_size = prompt_length(build_prompt([]))
    batch: list[dict[str, Any]] = []
    size = empty_size
    for item in items:
        item_size = len(json.dumps(item, ensure_ascii=False)) + 2
        if batch and (size + item_size > room or (max_items is not None and len(batch) >= max_items)):
            yield batch
            batch, size = [], empty_size
        batch.append(item)
        size += item_size
    if batch:
        yield batch
