"""Chat gateway: JSON answers from the configured model, a fallback model when it is busy or down, one
corrective re-ask for a task that checks its answer, and one record per call (metrics, log line, audit copy in
tsg_ai_calls)."""

import time
from collections.abc import Callable
from functools import partial
from typing import Any

import litellm
import structlog

from app.ai.chat_messages import (
    build_conversation,
    build_request_options,
    count_prompt_chars,
    find_earlier_answer,
    max_answer_tokens,
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
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core.config import Settings
from app.core.constants import (
    AiLimits,
    AiOutage,
    AiOutcome,
    AiTask,
    ErrorMessage,
    LogEvent,
)
from app.core.exceptions import Unavailable
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.models.ai.profiles import ChatModelProfile

log = structlog.get_logger(__name__)

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


class ChatModel:
    """JSON answers from the configured model; the fallback model answers only when the first is busy/down
    (or cooling down). Each model is called with ITS OWN profile (litellm's built-in fallbacks would reuse the
    first's options)."""

    def __init__(
        self,
        models: list[tuple[str, ChatModelProfile]],
        base_url: str,
        api_key: str,
        call_records: AiCallRepository,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
        thinking_on: frozenset[str] = frozenset(),
        request_rate: AiRequestRate = UNLIMITED_AI_REQUEST_RATE,
        fallback_slots: AiSlots = UNLIMITED_AI_SLOTS,
        fallback_request_rate: AiRequestRate = UNLIMITED_AI_REQUEST_RATE,
    ):
        self._models = models
        self._fallback_slots = fallback_slots
        self._cooling_until: dict[str, float] = {}  # model -> time.monotonic() its cool-down ends
        self._request_rates = dict.fromkeys(dict(models), fallback_request_rate)  # each model's own limiter
        self._request_rates[models[0][0]] = request_rate
        self._thinking_on = thinking_on  # models whose thinking stays on; every other one's is switched off
        # num_retries=0: call_with_retries is the only retry (litellm's own needs tenacity).
        self._connection = {"api_base": base_url, "api_key": api_key, "num_retries": 0}
        self._connection |= build_api_key_header(key_header, api_key)
        self._call_records = call_records
        self._slots = slots
        self._max_input_chars = min(profile.max_input_chars for _, profile in models)

    def ask_for_checked_json(
        self,
        task: AiTask,
        system_prompt: str,
        user_prompt: str,
        check_answer: AnswerChecker,
        first_answer_check: AnswerChecker | None = None,
        reuse_earlier_answer: bool = False,
    ) -> dict[str, Any]:
        """A JSON answer `check_answer` accepts. A rejected first answer is asked again once, in the same
        conversation, with its problems (§9); a second rejection raises UnreadableAiAnswer. A usable first
        answer `first_answer_check` faults is asked again too, and kept when the re-ask is unusable or finds
        the AI unavailable.
        `reuse_earlier_answer`: an ask this job already got an answer to that `check_answer` accepts (any
        delivery of the same record, epoch and stage) takes that answer from tsg_ai_calls, with no AI call."""
        messages = build_conversation(system_prompt, user_prompt)
        reuse_check = check_answer if reuse_earlier_answer else None
        answer, reply, capped = self._ask_and_read_answer(task, messages, reuse_check, capped=True)
        problems = _find_answer_problems(answer, check_answer)
        usable = answer if answer is not None and not problems else None
        if usable is not None:
            problems = first_answer_check(usable) if first_answer_check is not None else []
            if not problems:
                return usable
        correction = _with_correction_turn(messages, reply, problems, self._max_input_chars)
        try:  # a first answer cut off at the task's cap: the re-ask goes at the model's own limit at once
            answer, _, _ = self._ask_and_read_answer(task, correction, reuse_check, capped)
        except (UnreadableAiAnswer, TruncatedAiAnswer, Unavailable) as exc:
            if usable is None:
                raise
            log.info(LogEvent.AI_FIRST_ANSWER_KEPT, ai_task=task, error_type=type(exc).__name__)
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
        self, task: AiTask, messages: list[dict[str, str]], reuse_check: AnswerChecker | None, capped: bool
    ) -> tuple[dict[str, Any] | None, str, bool]:
        """(the answer's JSON object or None, the raw reply, still capped), recorded once with its outcome;
        with `reuse_check`, this job's earlier answer to these messages it accepts, when there is one."""
        prompt_chars, limit = count_prompt_chars(messages), self._max_input_chars
        if prompt_chars > limit:
            too_long = ErrorMessage.AI_PROMPT_TOO_LONG.format(task=task, chars=prompt_chars, limit=limit)
            raise TruncatedAiAnswer(too_long)
        if reuse_check and (earlier := find_earlier_answer(self._call_records, task, messages, reuse_check)):
            return *earlier, capped
        model, response, seconds, capped = self._ask_for_whole_answer(task, messages, capped)
        reply = response.choices[0].message.content or ""
        answer = parse_json_object(reply)
        # One outcome per call in the metrics, never "ok" AND "unreadable".
        outcome = AiOutcome.UNREADABLE if answer is None else AiOutcome.OK
        record_chat_call(self._call_records, task, model, messages, response, seconds, outcome)
        return answer, reply, capped

    def _ask_for_whole_answer(
        self, task: AiTask, messages: list[dict], capped: bool
    ) -> tuple[str, Any, float, bool]:
        """(model, response, seconds, capped) of an answer not cut off: one cut off at the cap is recorded
        truncated and asked once more at the model's own limit (TruncatedAiAnswer when cut off there too)."""
        model, response, seconds = self._call_first_available_model(task, messages, capped)
        if not response.choices:
            update_call_metrics(task, model, AiOutcome.UNREADABLE, 0, 0, seconds)
            raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error="no choices"))
        if getattr(response.choices[0], "finish_reason", None) != "length":
            return model, response, seconds, capped
        record_chat_call(self._call_records, task, model, messages, response, seconds, AiOutcome.TRUNCATED)
        profile, thinking = dict(self._models)[model], model in self._thinking_on
        if capped and max_answer_tokens(profile, task, thinking) < profile.max_output_tokens:
            return self._ask_for_whole_answer(task, messages, capped=False)
        raise TruncatedAiAnswer(ErrorMessage.AI_ANSWER_TRUNCATED.format(task=task, model=model))

    def _call_first_available_model(
        self, task: AiTask, messages: list[dict], capped: bool
    ) -> tuple[str, Any, float]:
        """(model that answered, its response, seconds). Tries each model in order, each with its retries; one
        timed out or still rate-limited (each has its own limit) goes last for MODEL_COOL_DOWN_SECONDS."""
        outage: Unavailable | None = None
        now = time.monotonic()
        in_order = sorted(self._models, key=lambda pair: self._cooling_until.get(pair[0], 0) > now)
        with self._slots.hold_slot(task):  # one slot for the whole request: the cap counts calls, not models
            for model, profile in in_order:
                slots = UNLIMITED_AI_SLOTS if model == self._models[0][0] else self._fallback_slots
                try:  # only the last model left waits for a fallback slot: one still to try answers sooner
                    with slots.hold_slot(task, waits=model == in_order[-1][0]):
                        response, seconds = self._call_model(task, messages, model, profile, capped)
                except Unavailable as exc:  # busy or down after its retries: the next model answers
                    if exc.reason == AiOutage.TIMED_OUT or isinstance(exc.__cause__, litellm.RateLimitError):
                        self._cooling_until[model] = time.monotonic() + AiLimits.MODEL_COOL_DOWN_SECONDS
                    outage = exc
                    continue
                self._cooling_until.pop(model, None)
                return model, response, seconds
            assert outage is not None  # at least one model is configured
            raise outage  # inside the hold: a request no model answered never raises a 429's limit

    def _call_model(
        self, task: AiTask, messages: list[dict], model: str, profile: ChatModelProfile, capped: bool
    ) -> tuple[Any, float]:
        """One model's response and seconds, with retries."""
        options = build_request_options(profile, task, model, model in self._thinking_on, capped)
        ask = partial(litellm.completion, model=model, messages=messages, **self._connection, **options)
        try:
            with count_and_convert_ai_errors(task, model, AI_REFUSED_REPLY_ERRORS):
                return call_with_retries(ask, self._request_rates[model], self._slots, model=model, task=task)
        except AI_REFUSED_REPLY_ERRORS as exc:  # an answer, if a refusal: no other model is asked
            refused = ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error=type(exc).__name__)
            raise UnreadableAiAnswer(refused) from exc


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


def chat_model_from(
    settings: Settings,
    calls: AiCallRepository,
    slots: AiSlots,
    request_rate: AiRequestRate,
    fallback_slots: AiSlots,
    fallback_request_rate: AiRequestRate,
) -> ChatModel:
    """The chat model the settings name, with its fallback, its call records and its limiters."""
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
        request_rate,
        fallback_slots,
        fallback_request_rate,
    )
