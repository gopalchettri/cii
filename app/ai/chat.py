"""Chat gateway: JSON answers from the module's model, one corrective re-ask for a task that checks its
answer, and one record per call (metrics, log line, usage row, audit copy in tsg_ai_call_texts)."""

import dataclasses
import hashlib
import json
from collections.abc import Callable
from datetime import timedelta
from functools import partial
from typing import Any

import litellm
import structlog
from bson import ObjectId
from pymongo.collection import Collection as MongoCollection

from app.ai import common
from app.ai import slots as ai_slots
from app.ai.attempts import call_with_retries, note_ai_usage
from app.ai.common import AI_REFUSED_REPLY_ERRORS, build_api_key_header, count_and_convert_ai_errors
from app.ai.profiles import CHAT_MODEL_PROFILES, ChatModelProfile, find_model_profile
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core import metrics
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    CHAT_MAX_OUTPUT_TOKENS,
    CHAT_TEMPERATURES,
    LITELLM_MODEL_PREFIX,
    REUSED_ACROSS_RUNS,
    THINKING_OFF_TEMPLATE_KWARGS,
    AiLimits,
    AiOutcome,
    AiTask,
    AiUsageOutcome,
    AiUsageReason,
    ChatModule,
    Collection,
    ErrorMessage,
    LogEvent,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.core.singletons import singleton
from app.crud import ai_calls

log = structlog.get_logger(__name__)

#: A task's own check of an answer: the problems found, an empty list when the answer is right.
AnswerChecker = Callable[[dict[str, Any]], list[str]]


class UnreadableAiAnswer(Exception):
    """The model answered, but not with the JSON the task asked for (after the re-ask, when there is one)."""


class TruncatedAiAnswer(Exception):
    """The prompt was too long or the answer cut off at its limit: the caller sends less, never the same again."""


class ChatModel:
    """JSON answers from one model, called with its own profile."""

    def __init__(  # noqa: PLR0913 - one model, its gateway and its limiters
        self,
        model: str,
        profile: ChatModelProfile,
        base_url: str,
        api_key: str,
        call_records: MongoCollection,
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
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        reuse_check = check_answer if reuse_earlier_answer else None
        answer, reply, capped = self._ask_and_read_answer(task, messages, reuse_check, capped=True)
        problems = _answer_problems(answer, check_answer)
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
        retry_problems = _answer_problems(answer, check_answer)
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

    def get_answer_room(self, task: AiTask) -> int:
        """The answer tokens a first call of `task` asks for: a batched caller counts them in its size."""
        return max_answer_tokens(self._profile, task, self._thinking)

    def _ask_and_read_answer(
        self, task: AiTask, messages: list[dict[str, str]], reuse_check: AnswerChecker | None, capped: bool
    ) -> tuple[dict[str, Any] | None, str, bool]:
        prompt_chars, limit = _prompt_chars(messages), self.max_prompt_chars
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
        _record(self, task, messages, response, seconds, outcome)
        return answer, reply, capped

    def _ask_for_whole_answer(
        self, task: AiTask, messages: list[dict], capped: bool, asked_again: bool = False
    ) -> tuple[Any, float, bool]:
        model, profile = self._model, self._profile
        response, seconds = self._call_model(task, messages, capped)
        if not response.choices:
            _note_call(task, model, AiOutcome.UNREADABLE, 0, 0, seconds, reason=AiUsageReason.NO_CHOICES)
            raise UnreadableAiAnswer(ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error="no choices"))
        choice = response.choices[0]
        if getattr(choice, "finish_reason", None) != "length":
            return response, seconds, capped
        reply = choice.message.content or ""
        if (whole := read_cut_off_reply(reply)) is not None:
            closed = len(whole) - len(reply.rstrip())  # 1: its last brace was added
            log.info(LogEvent.AI_CUT_OFF_ANSWER_READ, ai_task=task, model=model, closed=closed)
            choice.message.content = whole
            return response, seconds, capped
        _record(self, task, messages, response, seconds, AiOutcome.TRUNCATED)
        runaway = is_runaway_reply(reply)  # more room only buys more of it: once more at the same limit
        if capped and runaway and not asked_again:
            return self._ask_for_whole_answer(task, messages, capped, asked_again=True)
        if capped and not runaway and max_answer_tokens(profile, task, self._thinking) < profile.max_output_tokens:
            return self._ask_for_whole_answer(task, messages, capped=False)
        raise TruncatedAiAnswer(ErrorMessage.AI_ANSWER_TRUNCATED.format(task=task, model=model))

    def _call_model(self, task: AiTask, messages: list[dict], capped: bool) -> tuple[Any, float]:
        model, rate = self._model, self._request_rate
        options = build_request_options(self._profile, task, model, self._thinking, capped)
        ask = partial(litellm.completion, model=model, messages=messages, **self._connection, **options)
        tokens = _prompt_chars(messages) // AiLimits.PROMPT_CHARS_PER_TOKEN + options["max_tokens"]
        try:
            with count_and_convert_ai_errors(task, model):
                response, seconds = call_with_retries(ask, rate, self._slots, model=model, task=task, tokens=tokens)
                if used := sum(_reply_tokens(response)):
                    rate.give_back(used)
                return response, seconds
        except AI_REFUSED_REPLY_ERRORS as exc:  # an answer, if a refusal
            refused = ErrorMessage.AI_ANSWER_REFUSED.format(task=task, error=type(exc).__name__)
            raise UnreadableAiAnswer(refused) from exc


def _record(  # noqa: PLR0913 - one chat call, whole
    chat: ChatModel, task: AiTask, messages: list[dict], response: Any, seconds: float, outcome: AiOutcome
) -> None:
    context = structlog.contextvars.get_contextvars()
    tokens_in, tokens_out = _reply_tokens(response)
    system_hash = lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]  # noqa: E731
    record = {
        "_id": ObjectId(),
        "created_at": utc_now(),
        "task": task,
        "model": chat._model,
        "thinking": chat._thinking,
        "outcome": outcome,
        **_job_of(context),  # with prompt_hash: finds one job's AI calls
        "task_id": context.get("task_id"),
        "prompt_hash": prompt_hash(messages),
        "request_id": context.get("request_id"),
        "prompt": [
            {"role": "system", "content_sha256": system_hash(m["content"])} if m["role"] == "system" else m
            for m in messages
        ],
        "response": response.choices[0].message.content or "",
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "seconds": seconds,
    }
    reask = len(messages) > 2 or None  # a correction turn added
    _note_call(task, chat._model, outcome, tokens_in, tokens_out, seconds, call_id=record["_id"], reask=reask)
    try:
        ai_calls.insert_call(chat._call_records, record)
    except Exception:  # noqa: BLE001 - ponytail: the audit copy must never fail the AI call; logged instead
        log.warning(LogEvent.AI_CALL_RECORD_FAILED, ai_task=task, exc_info=True)


def _earlier_answer(
    chat: ChatModel, task: AiTask, messages: list[dict], check: AnswerChecker
) -> tuple[dict[str, Any], str] | None:
    job, digest = _job_of(structlog.contextvars.get_contextvars()), prompt_hash(messages)
    if None in job.values():
        return None
    try:
        found = ai_calls.find_ok_response(chat._call_records, job, digest)
        if found is None and task in REUSED_ACROSS_RUNS and AiLimits.REUSE_ACROSS_RUNS_HOURS > 0:
            since = utc_now() - timedelta(hours=AiLimits.REUSE_ACROSS_RUNS_HOURS)
            models = [(chat._model, chat._thinking)]
            found = ai_calls.find_recent_ok_response(chat._call_records, task, digest, models, since)
    except Exception:  # noqa: BLE001 - ponytail: a failed lookup only costs the AI call it would save
        log.warning(LogEvent.AI_ANSWER_LOOKUP_FAILED, ai_task=task, exc_info=True)
        return None
    reply, model = found or ("", "")
    if found is None or (answer := parse_json_object(reply)) is None or check(answer):
        return None
    log.info(LogEvent.AI_ANSWER_REUSED, ai_task=task)
    note_ai_usage(task, model, AiUsageOutcome.REUSED)
    return answer, reply


def parse_json_object(reply: str) -> dict[str, Any] | None:
    """The reply's JSON object, a code fence allowed; None for anything else (a JSON array or string too)."""
    text = reply.strip()
    if text.startswith("```"):
        text = (text.split("\n", 1)[1] if "\n" in text else "").rsplit("```", 1)[0]
    try:
        parsed = json.loads(text.strip())
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def read_cut_off_reply(reply: str) -> str | None:
    """The JSON object of a cut-off reply that is whole, its own last brace closed after a long run of whitespace."""
    text = reply.rstrip()
    if parse_json_object(text) is not None:
        return text
    # Only the answer's own brace: closing a list the model left open would read a part of it as the whole.
    closed = text + "}"
    if len(reply) - len(text) >= AiLimits.RUNAWAY_TAIL_CHARS and parse_json_object(closed):
        return closed
    return None


def is_runaway_reply(reply: str) -> bool:
    """Whether a cut-off reply ends in whitespace, one piece said over and over, or a string that never closes."""
    tail, string = reply[-AiLimits.RUNAWAY_TAIL_CHARS :], reply[-AiLimits.RUNAWAY_STRING_CHARS :]
    if len(tail) < AiLimits.RUNAWAY_TAIL_CHARS:
        return False
    if not tail.strip() or (len(string) == AiLimits.RUNAWAY_STRING_CHARS and '"' not in string):
        return True
    return any(tail[size:] == tail[:-size] for size in range(1, AiLimits.RUNAWAY_PIECE_CHARS + 1))


def max_answer_tokens(profile: ChatModelProfile, task: AiTask, thinking: bool, capped: bool = True) -> int:
    """The task's answer cap under the model's limit; the model's own limit when not `capped` or when it thinks."""
    if thinking or not capped:
        return profile.max_output_tokens
    return min(profile.max_output_tokens, CHAT_MAX_OUTPUT_TOKENS.get(task, profile.max_output_tokens))


def build_request_options(
    profile: ChatModelProfile, task: AiTask, model: str, thinking: bool, capped: bool = True
) -> dict[str, Any]:
    """The request options this model's profile accepts for this task, its thinking off unless `thinking`."""
    # stream=False on the wire: a proxy entry pinning stream=true (UAT glm-5.3) would pick the shape.
    options: dict[str, Any] = {
        "max_tokens": max_answer_tokens(profile, task, thinking, capped),
        "timeout": profile.timeout_seconds,
        "stream": False,
    }
    if profile.supports_json_mode:
        options["response_format"] = {"type": "json_object"}
    if (temperature := CHAT_TEMPERATURES.get(task)) is not None:  # None: the provider's default applies
        options["temperature"] = temperature
    if profile.reasoning_effort is not None:
        # allowed_openai_params is load-bearing: else litellm may drop it (v1, Kimi-K2.6) and thinking stays on.
        options["reasoning_effort"] = profile.reasoning_effort
        options["allowed_openai_params"] = ["reasoning_effort"]
    if not thinking and model.startswith(LITELLM_MODEL_PREFIX):
        # The gateway's vLLM models switch thinking in their chat template; another provider may refuse it.
        options["extra_body"] = {"chat_template_kwargs": dict(THINKING_OFF_TEMPLATE_KWARGS)}
    return options


def prompt_hash(messages: list[dict]) -> str:
    """The exact conversation's fingerprint: equal only for the same messages in the same order."""
    text = json.dumps(messages, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _note_call(  # noqa: PLR0913 - one chat call, whole
    task: AiTask, model: str, outcome: AiOutcome, tokens_in: int, tokens_out: int, seconds: float, **usage: Any
) -> None:
    note_ai_usage(task, model, outcome, tokens_in=tokens_in, tokens_out=tokens_out, seconds=seconds, **usage)
    metrics.AI_CALLS.labels(task, model, outcome).inc()
    metrics.AI_SECONDS.labels(task, model).observe(seconds)
    log.info(
        LogEvent.AI_CALL,
        ai_task=task,
        model=model,
        outcome=outcome,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        seconds=round(seconds, 2),
    )


def _reply_tokens(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    return getattr(usage, "prompt_tokens", 0) or 0, getattr(usage, "completion_tokens", 0) or 0


def _job_of(context: dict[str, Any]) -> dict[str, Any]:
    return {"record_id": context.get("record_id"), "epoch": context.get("epoch"), "job_task": context.get("task")}


def _prompt_chars(messages: list[dict[str, str]]) -> int:
    return sum(len(message["content"]) for message in messages)


def _answer_problems(answer: dict[str, Any] | None, check_answer: AnswerChecker) -> list[str]:
    return [ErrorMessage.AI_REPLY_NOT_A_JSON_OBJECT] if answer is None else check_answer(answer)


def _with_correction_turn(
    messages: list[dict[str, str]], reply: str, problems: list[str], max_chars: int
) -> list[dict[str, str]]:
    lines = [f"- {problem[: AiLimits.REASK_PROBLEM_CHARS]}" for problem in problems[: AiLimits.REASK_MAX_PROBLEMS]]
    correction = {"role": "user", "content": AiLimits.REASK_MESSAGE.format(problems="\n".join(lines))}
    quoted = [*messages, {"role": "assistant", "content": reply}, correction]
    if reply and _prompt_chars(quoted) <= max_chars:
        return quoted
    return [*messages, correction]


def _chat_model_of(module: ChatModule) -> ChatModel:
    common.apply_proxy_once()
    settings = get_settings()
    chat = settings.chat_of(module)
    profile = find_model_profile(CHAT_MODEL_PROFILES, chat.model)
    output = chat.max_output_tokens or profile.max_output_tokens  # each CII_<MODULE>_CHAT_ None keeps the profile's
    question = chat.max_input_tokens or profile.context_tokens - profile.max_output_tokens
    timeout = chat.timeout_seconds or profile.timeout_seconds
    profile = dataclasses.replace(
        profile, max_output_tokens=output, context_tokens=question + output, timeout_seconds=timeout
    )
    request_rate = ai_slots.ai_request_rate_for(chat.model, chat.requests_per_minute, chat.tokens_per_minute, module)
    slots, calls = ai_slots.get_module_ai_slots()[module], get_mongodb()[Collection.AI_CALLS]
    key, header = chat.api_key.get_secret_value(), settings.ai_key_header
    return ChatModel(chat.model, profile, chat.base_url, key, calls, header, slots, chat.model_thinking, request_rate)


@singleton
def get_scenario_chat_model() -> ChatModel:
    """Threat finding and scenario writing."""
    return _chat_model_of(ChatModule.SCENARIO)


@singleton
def get_remediation_chat_model() -> ChatModel:
    return _chat_model_of(ChatModule.REMEDIATION)


@singleton
def get_service_mapper_chat_model() -> ChatModel:
    return _chat_model_of(ChatModule.SERVICE_MAPPER)
