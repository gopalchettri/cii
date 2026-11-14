"""Chat gateway: JSON answers from the module's model, one corrective re-ask for a task that checks its
answer, and one record per call (metrics, log line, audit copy in tsg_ai_calls)."""

import dataclasses
from collections.abc import Callable
from functools import partial
from typing import Any

import litellm
import structlog

from app.ai.attempts import call_with_retries
from app.ai.chat_messages import (
    build_conversation,
    build_request_options,
    count_prompt_chars,
    count_reply_tokens,
    find_earlier_answer,
    max_answer_tokens,
    parse_json_object,
    record_chat_call,
    update_call_metrics,
)
from app.ai.common import (
    AI_REFUSED_REPLY_ERRORS,
    build_api_key_header,
    count_and_convert_ai_errors,
)
from app.ai.profiles import CHAT_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core.constants import (
    AiLimits,
    AiOutcome,
    AiTask,
    AiUsageReason,
    ErrorMessage,
    LogEvent,
)
from app.core.exceptions import Unavailable
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.models.ai.module_chat import ModuleChat
from app.models.ai.profiles import ChatModelProfile

log = structlog.get_logger(__name__)

#: A task's own check of an answer: the problems found, an empty list when the answer is right.
AnswerChecker = Callable[[dict[str, Any]], list[str]]
#: An answer with no choice at all: its usage row's reason.
_NO_CHOICES = AiUsageReason.NO_CHOICES


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


def _earlier_answer(
    chat: "ChatModel", task: AiTask, messages: list[dict[str, str]], check: AnswerChecker
) -> tuple[dict[str, Any], str] | None:
    """The job's own earlier answer to these messages, else for threat finding any recent run's answered by
    the chat's model with its thinking as set now (find_earlier_answer): no AI call."""
    return find_earlier_answer(chat._call_records, task, messages, check, [(chat._model, chat._thinking)])


def _record_call(  # noqa: PLR0913 - one chat call, whole
    chat: "ChatModel",
    task: AiTask,
    messages: list[dict[str, str]],
    response: Any,
    seconds: float,
    outcome: AiOutcome,
) -> None:
    """record_chat_call, noting whether the model's thinking was on."""
    records, model, thinking = chat._call_records, chat._model, chat._thinking
    record_chat_call(records, task, model, messages, response, seconds, outcome, thinking)


class ChatModel:
    """JSON answers from one model, called with its own profile."""

    def __init__(  # noqa: PLR0913 - one model, its gateway and its limiters
        self,
        model: str,
        profile: ChatModelProfile,
        base_url: str,
        api_key: str,
        call_records: AiCallRepository,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
        thinking: bool = False,
        request_rate: AiRequestRate = UNLIMITED_AI_REQUEST_RATE,
    ):
        self._model, self._profile = model, profile
        self._thinking = thinking  # false: the model's thinking is switched off
        self._request_rate = request_rate
        # num_retries=0: call_with_retries is the only retry (litellm's own needs tenacity).
        self._connection = {"api_base": base_url, "api_key": api_key, "num_retries": 0}
        self._connection |= build_api_key_header(key_header, api_key)
        self._call_records = call_records
        self._slots = slots

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
        delivery of this record, epoch and stage) takes that answer from tsg_ai_call_texts: no AI call."""
        messages = build_conversation(system_prompt, user_prompt)
        reuse_check = check_answer if reuse_earlier_answer else None
        answer, reply, capped = self._ask_and_read_answer(task, messages, reuse_check, capped=True)
        problems = _find_answer_problems(answer, check_answer)
        usable = answer if answer is not None and not problems else None
        if usable is not None:
            problems = first_answer_check(usable) if first_answer_check is not None else []
            if not problems:
                return usable
        correction = _with_correction_turn(messages, reply, problems, self.max_prompt_chars)
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
        """The most prompt characters the model takes: a batched caller fills its prompts to a share."""
        return self._profile.max_input_chars

    def _ask_and_read_answer(
        self, task: AiTask, messages: list[dict[str, str]], reuse_check: AnswerChecker | None, capped: bool
    ) -> tuple[dict[str, Any] | None, str, bool]:
        """(the answer's JSON object or None, the raw reply, still capped), recorded once with its outcome;
        with `reuse_check`, this job's earlier answer to these messages it accepts, when there is one."""
        prompt_chars, limit = count_prompt_chars(messages), self.max_prompt_chars
        if prompt_chars > limit:
            too_long = ErrorMessage.AI_PROMPT_TOO_LONG.format(task=task, chars=prompt_chars, limit=limit)
            raise TruncatedAiAnswer(too_long)
        if reuse_check and (earlier := _earlier_answer(self, task, messages, reuse_check)):
            return *earlier, capped
        response, seconds, capped = self._ask_for_whole_answer(task, messages, capped)
        reply = response.choices[0].message.content or ""
        answer = parse_json_object(reply)
        # One outcome per call in the metrics, never "ok" AND "unreadable".
        outcome = AiOutcome.UNREADABLE if answer is None else AiOutcome.OK
        _record_call(self, task, messages, response, seconds, outcome)
        return answer, reply, capped

    def _ask_for_whole_answer(
        self, task: AiTask, messages: list[dict], capped: bool
    ) -> tuple[Any, float, bool]:
        """(response, seconds, capped) of an answer not cut off: one cut off at the cap is recorded truncated
        and asked once more at the model's own limit (TruncatedAiAnswer when cut off there too)."""
        model, profile = self._model, self._profile
        response, seconds = self._call_model(task, messages, capped)
        if not response.choices:
            update_call_metrics(task, model, AiOutcome.UNREADABLE, 0, 0, seconds, reason=_NO_CHOICES)
            raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error="no choices"))
        if getattr(response.choices[0], "finish_reason", None) != "length":
            return response, seconds, capped
        _record_call(self, task, messages, response, seconds, AiOutcome.TRUNCATED)
        if capped and max_answer_tokens(profile, task, self._thinking) < profile.max_output_tokens:
            return self._ask_for_whole_answer(task, messages, capped=False)
        raise TruncatedAiAnswer(ErrorMessage.AI_ANSWER_TRUNCATED.format(task=task, model=model))

    def _call_model(self, task: AiTask, messages: list[dict], capped: bool) -> tuple[Any, float]:
        """The model's response and seconds, with retries; paced by prompt + answer room, as LiteLLM is."""
        model, rate = self._model, self._request_rate
        options = build_request_options(self._profile, task, model, self._thinking, capped)
        ask = partial(litellm.completion, model=model, messages=messages, **self._connection, **options)
        tokens = _estimated_tokens(messages) + options["max_tokens"]
        try:
            with count_and_convert_ai_errors(task, model, AI_REFUSED_REPLY_ERRORS):
                return _call_and_give_back_unused(ask, rate, self._slots, model, task, tokens)
        except AI_REFUSED_REPLY_ERRORS as exc:  # an answer, if a refusal
            refused = ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error=type(exc).__name__)
            raise UnreadableAiAnswer(refused) from exc


def _call_and_give_back_unused(  # noqa: PLR0913 - call_with_retries' own inputs
    ask: Callable[[], Any], rate: AiRequestRate, slots: AiSlots, model: str, task: AiTask, tokens: int
) -> tuple[Any, float]:
    """call_with_retries, then the answer's unused booking back to `rate`: LiteLLM holds the prompt and the
    whole answer room while a call runs, and counts only what it used once answered."""
    response, seconds = call_with_retries(ask, rate, slots, model=model, task=task, tokens=tokens)
    if used := sum(count_reply_tokens(response)):  # ponytail: a failed try's booking is never given back
        rate.give_back(tokens, used)
    return response, seconds


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


def _estimated_tokens(messages: list[dict]) -> int:
    """A prompt's tokens, erring high (3 chars a token; 4.3-6.1 measured)."""
    return count_prompt_chars(messages) // AiLimits.PROMPT_CHARS_PER_TOKEN


def _profile_of(
    model: str, max_input: int | None, max_output: int | None, timeout: int | None
) -> ChatModelProfile:
    """`model`'s profile (app/ai/profiles.py) with the module's own longest question and answer, in tokens,
    and wait for an answer (CII_<MODULE>_CHAT_...); each None keeps the profile's."""
    profile = find_model_profile(CHAT_MODEL_PROFILES, model)
    output = max_output or profile.max_output_tokens
    question = max_input or profile.context_tokens - profile.max_output_tokens
    timeout = timeout or profile.timeout_seconds
    return dataclasses.replace(
        profile, max_output_tokens=output, context_tokens=question + output, timeout_seconds=timeout
    )


def _find_answer_problems(answer: dict[str, Any] | None, check_answer: AnswerChecker) -> list[str]:
    return [ErrorMessage.AI_REPLY_NOT_A_JSON_OBJECT] if answer is None else check_answer(answer)


def chat_model_from(
    chat: ModuleChat, key_header: str, calls: AiCallRepository, slots: AiSlots, request_rate: AiRequestRate
) -> ChatModel:
    """A module's chat model, its call records and its limiters."""
    limits = (chat.max_input_tokens, chat.max_output_tokens, chat.timeout_seconds)
    return ChatModel(
        chat.model,
        _profile_of(chat.model, *limits),
        chat.base_url,
        chat.api_key.get_secret_value(),
        calls,
        key_header,
        slots,
        chat.model_thinking,
        request_rate,
    )
