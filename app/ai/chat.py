"""Chat gateway: JSON answers from the configured model, a fallback model when it is busy or down, one
corrective re-ask for a task that checks its answer, and one record per call (metrics, log line, audit copy in
tsg_ai_calls)."""

import json
import time
from collections.abc import Callable
from functools import partial
from typing import Any

import litellm
import structlog

from app.ai.chat_messages import (
    build_call_record,
    build_conversation,
    count_prompt_chars,
    parse_json_object,
)
from app.ai.common import (
    build_api_key_header,
    call_timeout,
    call_with_retries,
    count_and_convert_ai_errors,
)
from app.ai.profiles import CHAT_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_SLOTS, AiSlots, get_ai_slots, max_slot_hold_seconds
from app.core import metrics
from app.core.config import get_settings
from app.core.constants import (
    CHAT_TEMPERATURES,
    AiLimits,
    AiOutcome,
    AiTask,
    Collection,
    ErrorMessage,
    LogEvent,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.core.singletons import singleton
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.data_access.ai_calls import AiCallRecords
from app.models.ai import ChatModelProfile

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


#: The most characters a corrective re-ask adds: a batched prompt leaves this much room below the limit.
CORRECTION_MESSAGE_MAX_CHARS = len(
    _reask_build_correction_message(["x" * AiLimits.REASK_PROBLEM_CHARS] * AiLimits.REASK_MAX_PROBLEMS)
)


def _build_request_options(profile: ChatModelProfile, task: AiTask) -> dict[str, Any]:
    """The request options this model accepts (its profile) for this task (its temperature, R-2)."""
    # stream=False on the wire: a proxy entry pinning stream=true (UAT glm-5's) would otherwise
    # pick the shape.
    options: dict[str, Any] = {
        "max_tokens": profile.max_output_tokens,
        "timeout": call_timeout(profile.timeout_seconds),  # less under a caller's deadline (ai_deadline)
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
        call_records: AiCallRecords,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
    ):
        self._models = models
        self._base_url = base_url
        self._api_key = api_key
        self._call_records = call_records
        self._key_header = build_api_key_header(key_header, api_key)
        self._slots = slots
        # One slot covers the whole request, fallback included: the cap counts calls, not models.
        self._slot_hold = sum(max_slot_hold_seconds(profile.timeout_seconds) for _, profile in models)
        self._max_input_chars = min(profile.max_input_chars for _, profile in models)

    def ask_for_json(self, task: AiTask, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """One JSON answer, never asked again. Raises Unavailable (every model busy or down),
        TruncatedAiAnswer or UnreadableAiAnswer."""
        answer, _ = self._ask_and_read_answer(task, build_conversation(system_prompt, user_prompt))
        if answer is None:
            raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_UNREADABLE.format(task=task))
        return answer

    def ask_for_checked_json(
        self, task: AiTask, system_prompt: str, user_prompt: str, check_answer: AnswerChecker
    ) -> dict[str, Any]:
        """A JSON answer `check_answer` accepts. A rejected first answer is asked again once, in the same
        conversation, with its problems (§9); a second rejection raises UnreadableAiAnswer."""
        return self._ask_until_checked(task, build_conversation(system_prompt, user_prompt), check_answer)

    def ask_again_for_checked_json(  # noqa: PLR0913 — one conversation, whole
        self,
        task: AiTask,
        system_prompt: str,
        user_prompt: str,
        earlier_answer: dict[str, Any],
        problems: list[str],
        check_answer: AnswerChecker,
    ) -> dict[str, Any]:
        """A new answer in the conversation that gave `earlier_answer`: it is quoted back with `problems` in
        §9's correction turn, and the new answer is checked as ask_for_checked_json checks (one re-ask). The
        scenario writer's one rewrite (Step 12)."""
        earlier = json.dumps(earlier_answer, ensure_ascii=False)
        messages = build_conversation(system_prompt, user_prompt)
        return self._ask_until_checked(
            task, _with_correction_turn(messages, earlier, problems, self._max_input_chars), check_answer
        )

    def _ask_until_checked(
        self, task: AiTask, messages: list[dict[str, str]], check_answer: AnswerChecker
    ) -> dict[str, Any]:
        answer, reply = self._ask_and_read_answer(task, messages)
        problems = _find_answer_problems(answer, check_answer)
        if answer is not None and not problems:
            return answer
        if step_detail_enabled():
            record_detail("re-ask problems", given={"task": task}, produced={"problems": "; ".join(problems)})
        answer, _ = self._ask_and_read_answer(
            task, _with_correction_turn(messages, reply, problems, self._max_input_chars)
        )
        problems = _find_answer_problems(answer, check_answer)
        if answer is not None and not problems:
            return answer
        summary = "; ".join(problems[:3])
        raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REJECTED.format(task=task, problems=summary))

    @property
    def max_prompt_chars(self) -> int:
        """The most prompt characters every configured model takes: a batched caller fills its prompts to a
        share of this (the fallback model's limit included, so either can answer)."""
        return self._max_input_chars

    @traced("ai.chat")
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
        choice = response.choices[0]
        reply = choice.message.content or ""
        if getattr(choice, "finish_reason", None) == "length":
            self._record_chat_call(task, model, messages, response, seconds, AiOutcome.UNREADABLE)
            raise TruncatedAiAnswer(ErrorMessage.AI_ANSWER_TRUNCATED.format(task=task, model=model))
        answer = parse_json_object(reply)
        # One outcome per call in the metrics, never "ok" AND "unreadable".
        outcome = AiOutcome.UNREADABLE if answer is None else AiOutcome.OK
        self._record_chat_call(task, model, messages, response, seconds, outcome)
        return answer, reply

    def _call_first_available_model(self, task: AiTask, messages: list[dict]) -> tuple[str, Any, float]:
        """(model that answered, its response, seconds). Tries each model in order, each with its retries."""
        outage: Unavailable | None = None
        with self._slots.hold_slot(self._slot_hold):
            for model, profile in self._models:
                started = time.perf_counter()
                options = self._key_header | _build_request_options(profile, task)
                try:
                    with count_and_convert_ai_errors(task, model):
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
                return model, response, time.perf_counter() - started
        assert outage is not None  # at least one model is configured
        raise outage

    def _record_chat_call(
        self,
        task: AiTask,
        model: str,
        messages: list[dict],
        response: Any,
        seconds: float,
        outcome: AiOutcome,
    ) -> None:
        """One outcome per call: counted and logged, then copied to tsg_ai_calls, so every prompt and answer
        of a run can be found."""
        record = build_call_record(task, model, messages, response, seconds, outcome)
        _update_call_metrics(task, model, outcome, record["tokens_in"], record["tokens_out"], seconds)
        try:
            self._call_records.insert(record)
        except Exception:  # noqa: BLE001 — ponytail: the audit copy must never fail the AI call; logged instead
            log.warning(LogEvent.AI_CALL_RECORD_FAILED, task=task, exc_info=True)


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


def _update_call_metrics(
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


@singleton
def get_chat_model() -> ChatModel:
    settings = get_settings()
    call_records = AiCallRecords(get_mongodb()[Collection.AI_CALLS])
    model_names = [settings.chat_model] + (
        [settings.chat_fallback_model] if settings.chat_fallback_model else []
    )
    return ChatModel(
        [(name, find_model_profile(CHAT_MODEL_PROFILES, name)) for name in model_names],
        settings.chat_base_url,
        settings.chat_api_key.get_secret_value(),
        call_records,
        settings.ai_key_header,
        get_ai_slots(),
    )
