"""A run's threat finding takes the answer an earlier run got to the very same question, within
CII_THREAT_FINDING_REUSE_HOURS: a second Start on an unchanged asset asks the AI nothing for it."""

import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import structlog

from app import ai
from app.core.clock import utc_now
from app.core.constants import AiLimits, AiTask, AiUsageCollection, AiUsageOutcome, TaskName
from app.core.database import get_mongodb
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.domain.shared.ask_ai import ask_ai_and_check
from app.models.ai.profiles import ChatModelProfile

PROFILE = ChatModelProfile(
    max_output_tokens=100,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=20_100,
)
TEXTS = "test_ai_call_texts"


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Each AI call's model; reuse across runs on for 24 hours, as shipped."""
    made: list[str] = []
    monkeypatch.setattr(AiLimits, "REUSE_ACROSS_RUNS_HOURS", 24)

    def answer(model: str, **_: Any) -> Any:
        made.append(model)
        message = SimpleNamespace(content='{"verdicts": "%s"}' % uuid.uuid4().hex)  # noqa: UP031 - JSON braces
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)

    monkeypatch.setattr(litellm, "completion", answer)
    return made


def _chat(model: str = "test-chat", thinking: bool = False) -> ai.ChatModel:
    records = AiCallRepository(get_mongodb()[TEXTS])
    on = frozenset({model} if thinking else ())
    return ai.ChatModel([(model, PROFILE)], "http://ai.invalid", "key", records, thinking_on=on)


def _run() -> dict[str, Any]:
    """A new run's threat-finding job (a new session, record and request)."""
    record = uuid.uuid4().hex
    return {
        "record_id": record,
        "epoch": 1,
        "task": TaskName.FIND_THREATS,
        "attempt": 1,
        "session_id": record,
    }


def _ask(chat: ai.ChatModel, run: dict[str, Any], question: str, task: AiTask = AiTask.RELEVANCE_GATE) -> Any:
    with structlog.contextvars.bound_contextvars(**run, request_id=run["record_id"]):
        return ask_ai_and_check(
            chat, task, ("system", question), lambda a: (a, []), reuse_earlier_answer=True
        )


def test_a_second_run_asking_the_same_question_takes_the_first_runs_answer_with_no_ai_call(
    calls: list[str],
) -> None:
    """Mutation: drop the across-runs lookup, or reuse a writer's ask (its answer must differ per run)."""
    chat, question, second = _chat(), f"gate {uuid.uuid4().hex}", _run()
    first_answer = _ask(chat, _run(), question)
    assert _ask(chat, second, question) == first_answer and len(calls) == 1
    rows = get_mongodb()[AiUsageCollection.USAGE].find({"request_id": second["record_id"]})
    assert [row["outcome"] for row in rows] == [AiUsageOutcome.REUSED]
    _ask(chat, _run(), f"gate {uuid.uuid4().hex}")  # another asset's question: asked
    _ask(chat, _run(), question, AiTask.GAP_FILL)  # the same text as another task: asked
    writer = f"write {uuid.uuid4().hex}"
    _ask(chat, _run(), writer, AiTask.WRITE_SCENARIO)
    _ask(chat, _run(), writer, AiTask.WRITE_SCENARIO)  # a writer's ask is never taken from another run
    assert len(calls) == 5


def test_an_answer_older_than_its_hours_from_another_model_or_with_reuse_off_is_asked_again(
    calls: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: drop the `since` or the model filter."""
    chat, question = _chat(), f"gate {uuid.uuid4().hex}"
    _ask(chat, _run(), question)
    _ask(_chat("other-chat"), _run(), question)  # another model's answer is not this model's
    assert calls == ["test-chat", "other-chat"]
    old = utc_now() - timedelta(hours=25)
    get_mongodb()[TEXTS].update_many(
        {"model": "test-chat", "created_at": {"$gte": old}}, {"$set": {"created_at": old}}
    )
    _ask(chat, _run(), question)  # 25 hours old: asked again
    assert len(calls) == 3
    monkeypatch.setattr(AiLimits, "REUSE_ACROSS_RUNS_HOURS", 0)
    _ask(chat, _run(), question)  # off: asked again, though a fresh answer exists
    assert len(calls) == 4


def test_a_thinking_switch_is_asked_afresh_and_an_ask_outside_a_job_never_takes_another_runs_answer(
    calls: list[str],
) -> None:
    """A ConfigMap change of the model's thinking takes effect at once, and a script or replay outside a job
    (no record bound) asks the AI. Mutation: drop the thinking match, or the leased-job guard."""
    question = f"gate {uuid.uuid4().hex}"
    _ask(_chat(), _run(), question)  # thinking off
    _ask(_chat(thinking=True), _run(), question)  # thinking on: asked afresh
    _ask(_chat(thinking=True), _run(), question)  # then reused, from the thinking-on answer
    assert len(calls) == 2
    ask_ai_and_check(
        _chat(), AiTask.RELEVANCE_GATE, ("system", question), lambda a: (a, []), reuse_earlier_answer=True
    )
    assert len(calls) == 3  # no job bound: asked, though fresh answers exist
