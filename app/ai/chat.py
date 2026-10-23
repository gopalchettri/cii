"""Chat gateway: JSON answers from the configured model, a fallback model when it is busy or down, one
corrective re-ask for a task that checks its answer, and one record per call (metrics, log line, audit copy in
tsg_ai_calls)."""

import time
from collections.abc import Callable
from functools import partial
from typing import Any

import litellm

from app.ai.chat_messages import (
    build_conversation,
    count_prompt_chars,
    parse_json_object,
    record_chat_call,
    update_call_metrics,
)
from app.ai.common import (
    AI_REFUSED_REPLY_ERRORS,
    build_api_key_header,
    call_with_retries,
    count_and_convert_ai_errors,
)
from app.ai.profiles import CHAT_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_SLOTS, AiSlots, max_slot_hold_seconds
from app.core.config import Settings
from app.core.constants import (
    CHAT_TEMPERATURES,
    LITELLM_MODEL_PREFIX,
    THINKING_OFF_TEMPLATE_KWARGS,
    AiLimits,
    AiOutcome,
    AiTask,
    ErrorMessage,
)
from app.core.exceptions import Unavailable
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.models.ai.profiles import ChatModelProfile

#: A task's own check of an answer: the problems found, an empty list when the answer is right.
AnswerChecker = Callable[[dict[str, Any]], list[str]]


class UnreadableAiAnswer(Exception):
    """The model answered, but not with the JSON the task asked for (after the re-ask, when there is one)."""


class TruncatedAiAnswer(Exception):
    """The prompt was too long for the model, or the answer was cut off at its length limit: the caller sends
    less (e.g. halves the batch) instead of asking the same again."""


def _reask_build_correction_message(problems: list[str]) -> str:
    """§9's exact re-ask: at most REASK_MAX_PROBLEMS problems, each cut to REASK_PROBLEM_CHARS."""
    shown = problems[: AiLimits.REASK_MAX_PROBLEMS]
    lines = [f"- {problem[: AiLimits.REASK_PROBLEM_CHARS]}" for problem in shown]
    return AiLimits.REASK_MESSAGE.format(problems="\n".join(lines))


def _build_request_options(
    profile: ChatModelProfile, task: AiTask, model: str, thinking: bool
) -> dict[str, Any]:
    """The request options this model accepts (its profile) for this task (its temperature, R-2), with its
    thinking switched off unless `thinking` (CII_*_MODEL_THINKING)."""
    # stream=False on the wire: a proxy entry pinning stream=true (UAT glm-5's) would otherwise
    # pick the shape.
    options: dict[str, Any] = {
        "max_tokens": profile.max_output_tokens,
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


class ChatModel:
    """JSON answers from the configured model; the fallback model answers only when the first is busy/down.
    Each model is called with ITS OWN profile (litellm's built-in fallbacks would reuse the first's
    options)."""

    def __init__(
        self,
        models: list[tuple[str, ChatModelProfile]],
        base_url: str,
        api_key: str,
        call_records: AiCallRepository,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
        thinking_on: frozenset[str] = frozenset(),
    ):
        self._models = models
        self._thinking_on = thinking_on  # models whose thinking stays on; every other one's is switched off
        self._base_url = base_url
        self._api_key = api_key
        self._call_records = call_records
        self._key_header = build_api_key_header(key_header, api_key)
        self._slots = slots
        # One slot covers the whole request, fallback included: the cap counts calls, not models.
        self._slot_hold = sum(max_slot_hold_seconds(profile.timeout_seconds) for _, profile in models)
        self._max_input_chars = min(profile.max_input_chars for _, profile in models)

    def ask_for_checked_json(
        self,
        task: AiTask,
        system_prompt: str,
        user_prompt: str,
        check_answer: AnswerChecker,
        first_answer_check: AnswerChecker | None = None,
    ) -> dict[str, Any]:
        """A JSON answer `check_answer` accepts. A rejected first answer is asked again once, in the same
        conversation, with its problems (§9); a second rejection raises UnreadableAiAnswer. A usable first
        answer `first_answer_check` faults is asked again too, and kept when the re-ask is unusable."""
        messages = build_conversation(system_prompt, user_prompt)
        answer, reply = self._ask_and_read_answer(task, messages)
        problems = _find_answer_problems(answer, check_answer)
        usable = answer if answer is not None and not problems else None
        if usable is not None:
            problems = first_answer_check(usable) if first_answer_check is not None else []
            if not problems:
                return usable
        correction = _with_correction_turn(messages, reply, problems, self._max_input_chars)
        try:
            answer, _ = self._ask_and_read_answer(task, correction)
        except (UnreadableAiAnswer, TruncatedAiAnswer):
            if usable is None:
                raise
            return usable
        retry_problems = _find_answer_problems(answer, check_answer)
        if answer is not None and not retry_problems:
            return answer
        if usable is not None:
            return usable
        summary = "; ".join(retry_problems[:3])
        raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REJECTED.format(task=task, problems=summary))

    @property
    def max_prompt_chars(self) -> int:
        """The most prompt characters every configured model takes: a batched caller fills its prompts to a
        share of this (the fallback model's limit included, so either can answer)."""
        return self._max_input_chars

    def _ask_and_read_answer(
        self, task: AiTask, messages: list[dict[str, str]]
    ) -> tuple[dict[str, Any] | None, str]:
        """(the answer's JSON object or None, the raw reply), recorded once with its outcome."""
        prompt_chars = count_prompt_chars(messages)
        if prompt_chars > self._max_input_chars:
            raise TruncatedAiAnswer(
                ErrorMessage.AI_PROMPT_TOO_LONG.format(
                    task=task, chars=prompt_chars, limit=self._max_input_chars
                )
            )
        model, response, seconds = self._call_first_available_model(task, messages)
        if not response.choices:
            update_call_metrics(task, model, AiOutcome.UNREADABLE, 0, 0, seconds)
            raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error="no choices"))
        choice = response.choices[0]
        reply = choice.message.content or ""
        if getattr(choice, "finish_reason", None) == "length":
            record_chat_call(
                self._call_records, task, model, messages, response, seconds, AiOutcome.UNREADABLE
            )
            raise TruncatedAiAnswer(ErrorMessage.AI_ANSWER_TRUNCATED.format(task=task, model=model))
        answer = parse_json_object(reply)
        # One outcome per call in the metrics, never "ok" AND "unreadable".
        outcome = AiOutcome.UNREADABLE if answer is None else AiOutcome.OK
        record_chat_call(self._call_records, task, model, messages, response, seconds, outcome)
        return answer, reply

    def _call_first_available_model(self, task: AiTask, messages: list[dict]) -> tuple[str, Any, float]:
        """(model that answered, its response, seconds). Tries each model in order, each with its retries."""
        outage: Unavailable | None = None
        with self._slots.hold_slot(self._slot_hold):
            for model, profile in self._models:
                started = time.perf_counter()
                thinking = model in self._thinking_on
                options = self._key_header | _build_request_options(profile, task, model, thinking)
                try:
                    with count_and_convert_ai_errors(task, model, AI_REFUSED_REPLY_ERRORS):
                        # num_retries=0: call_with_retries is the only retry (litellm's own needs tenacity).
                        response = call_with_retries(
                            partial(
                                litellm.completion,
                                model=model,
                                messages=messages,
                                api_base=self._base_url,
                                api_key=self._api_key,
                                num_retries=0,
                                **options,
                            )
                        )
                except Unavailable as exc:  # busy or down after its retries: the next model answers
                    outage = exc
                    continue
                except AI_REFUSED_REPLY_ERRORS as exc:  # an answer, if a refusal: no other model is asked
                    refused = ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error=type(exc).__name__)
                    raise UnreadableAiAnswer(refused) from exc
                return model, response, time.perf_counter() - started
        assert outage is not None  # at least one model is configured
        raise outage


def _with_correction_turn(
    messages: list[dict[str, str]], reply: str, problems: list[str], max_chars: int
) -> list[dict[str, str]]:
    """The conversation plus the corrective turn: the rejected answer quoted while the whole conversation
    still fits the input limit, else only what was wrong (v1 _reask). A batch fills up to 80% of the limit, so
    quoting a long answer after it would make the re-ask too long to send."""
    correction = {"role": "user", "content": _reask_build_correction_message(problems)}
    quoted = [*messages, {"role": "assistant", "content": reply}, correction]
    if reply and count_prompt_chars(quoted) <= max_chars:
        return quoted
    return [*messages, correction]


def _find_answer_problems(answer: dict[str, Any] | None, check_answer: AnswerChecker) -> list[str]:
    return [ErrorMessage.AI_REPLY_NOT_A_JSON_OBJECT] if answer is None else check_answer(answer)


def chat_model_from(settings: Settings, calls: AiCallRepository, slots: AiSlots) -> ChatModel:
    """The chat model the settings name, with its fallback, its call records and its limiter."""
    model_names = [settings.chat_model] + (
        [settings.chat_fallback_model] if settings.chat_fallback_model else []
    )
    thinking_on = {
        name
        for name, on in (
            (settings.chat_model, settings.chat_model_thinking),
            (settings.chat_fallback_model, settings.chat_fallback_model_thinking),
        )
        if on
    }
    return ChatModel(
        [(name, find_model_profile(CHAT_MODEL_PROFILES, name)) for name in model_names],
        settings.chat_base_url,
        settings.chat_api_key.get_secret_value(),
        calls,
        settings.ai_key_header,
        slots,
        frozenset(thinking_on),
    )
