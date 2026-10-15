"""G244 (owner 2026-10-14, run 45b8c63b): a retried job reuses the usable answers its earlier attempt got
(one timed-out batch in 20 made planning ask all 20 three times); a first attempt reads nothing and asks."""

import uuid

import litellm
import pytest
import structlog
from structlog.testing import capture_logs

from app import ai
from app.core.constants import AiTask
from app.core.database import get_mongodb
from tests.test_ai import _chat_model, _json_response


def _count_calls(monkeypatch: pytest.MonkeyPatch, answer: str) -> list[int]:
    calls: list[int] = []

    def provider(**_: object) -> object:
        calls.append(1)
        return _json_response(answer)

    monkeypatch.setattr(litellm, "completion", provider)
    return calls


def test_a_retry_reuses_the_usable_answer_its_first_attempt_got_and_asks_only_what_is_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = uuid.uuid4().hex
    calls = _count_calls(monkeypatch, '{"first": true}')
    with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=1):
        assert _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch 1") == {"first": True}
    record = get_mongodb()["test_ai_calls"].find_one({"task_id": task_id})
    assert record is not None and len(record["prompt_hash"]) == 64  # what a retry finds it by
    calls = _count_calls(monkeypatch, '{"first": false}')
    with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=2), capture_logs() as logs:
        assert _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch 1") == {"first": True}
        assert calls == []  # the earlier answer, no AI call
        assert _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch 2") == {"first": False}
        assert calls == [1]  # a prompt not answered before is asked
    assert [entry["event"] for entry in logs].count("ai.call_reused") == 1
    assert get_mongodb()["test_ai_calls"].count_documents({"task_id": task_id}) == 2  # no copy of the reuse


def test_a_first_attempt_another_job_or_an_unusable_answer_is_never_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = uuid.uuid4().hex
    _count_calls(monkeypatch, "not json")
    unreadable = pytest.raises(ai.UnreadableAiAnswer)
    with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=1), unreadable:
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch")
    calls = _count_calls(monkeypatch, '{"ok": 1}')
    with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=2):
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch")  # the unreadable one: asked
    with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=1):
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch")  # a first attempt: asked
    with structlog.contextvars.bound_contextvars(task_id=uuid.uuid4().hex, attempt=2):
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch")  # another job: asked
    assert calls == [1, 1, 1]


def test_a_record_store_that_cannot_be_read_never_stops_the_call(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _count_calls(monkeypatch, '{"ok": 1}')
    chat = _chat_model()

    def down(*_: object) -> None:
        raise OSError("the store is down")

    monkeypatch.setattr(chat._call_records, "find_usable_reply", down)  # noqa: SLF001 - the store, failing
    with structlog.contextvars.bound_contextvars(task_id=uuid.uuid4().hex, attempt=3), capture_logs() as logs:
        assert chat.ask_for_json(AiTask.RELEVANCE_GATE, "system", "batch") == {"ok": 1}
    assert calls == [1] and "ai.call_reuse_failed" in [entry["event"] for entry in logs]
