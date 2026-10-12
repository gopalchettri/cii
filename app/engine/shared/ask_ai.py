"""Asking the AI and checking its answer, for the planner, the writer and remediation alike (v1
threat_identification/model_calls.py): every answer is checked by code; one with problems is asked again once,
with the problems listed."""

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ValidationError

from app.ai import ChatModel
from app.core.constants import AiTask

#: (system prompt, user prompt)
ChatPrompt = tuple[str, str]

#: A task's reading of one answer: (what it means, the problems found); no problems = a usable answer.
AnswerReader = Callable[[dict[str, Any]], tuple[Any, list[str]]]


def ask_ai_and_check(chat: ChatModel, task: AiTask, prompt: ChatPrompt, read_answer: AnswerReader) -> Any:
    """What a checked answer means. An answer with problems is asked again once with them; raises
    UnreadableAiAnswer when the second is still wrong, TruncatedAiAnswer when one was cut off."""
    answer = chat.ask_for_checked_json(task, *prompt, lambda candidate: read_answer(candidate)[1])
    meaning, _ = read_answer(answer)
    return meaning


def ask_ai_again_with_problems(  # noqa: PLR0913 — one conversation, whole
    chat: ChatModel,
    task: AiTask,
    prompt: ChatPrompt,
    earlier_answer: dict[str, Any],
    problems: list[str],
    read_answer: AnswerReader,
) -> Any:
    """What a new checked answer means, asked in the conversation that gave `earlier_answer` with its
    `problems` listed (the scenario writer's one rewrite); raises as ask_ai_and_check does."""
    answer = chat.ask_again_for_checked_json(
        task, *prompt, earlier_answer, problems, lambda candidate: read_answer(candidate)[1]
    )
    meaning, _ = read_answer(answer)
    return meaning


def answer_item_problems(contract: type[BaseModel], item: Any, where: str) -> list[str]:
    """One answer item checked against its contract (app/models/planner_replies.py), as re-ask problems; only
    the fields the contract declares are judged (v1 reply_problems)."""
    if not isinstance(item, dict):
        return [f"{where}: must be a JSON object"]
    try:
        contract.model_validate({key: value for key, value in item.items() if key in contract.model_fields})
    except ValidationError as exc:
        return [
            f"{where}: "
            + " ".join([*map(str, error["loc"]), str(error["msg"]).removeprefix("Value error, ")])
            for error in exc.errors()
        ]
    return []


def answers_for_asked_slots(
    answer: dict[str, Any], key: str, asked: set[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """The items of `answer[key]` that answer a slot that was asked, once each; with the problems of the rest
    and of every slot left unanswered."""
    items = answer.get(key)
    if not isinstance(items, list):
        return [], [f'the reply must be {{"{key}": [...]}}']
    kept: list[dict[str, Any]] = []
    answered: set[str] = set()
    problems: list[str] = []
    for item in items:
        slot = str(item.get("slot") or "") if isinstance(item, dict) else ""
        if slot not in asked or slot in answered:
            problems.append(f"slot {slot or '?'} is unknown or answered twice")
            continue
        answered.add(slot)
        kept.append(item)
    problems += [f"slot {slot} has no answer" for slot in sorted(asked - answered)]
    return kept, problems
