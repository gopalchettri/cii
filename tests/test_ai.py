"""AI gateway logic with litellm faked: outage handling, JSON reading, call records, embedding cache."""

import dataclasses
import hashlib
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import litellm
import numpy as np
import pytest
import structlog
from prometheus_client import REGISTRY
from pydantic import SecretStr
from structlog.testing import capture_logs

from app import ai, container
from app.ai.common import UnusableAiAnswer
from app.ai.profiles import CHAT_MODEL_PROFILES
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core.ai_tuning_settings import TUNING
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    CHAT_MAX_OUTPUT_TOKENS,
    AiLimits,
    AiOutage,
    AiTask,
    ChatModule,
    EmbeddingCorpus,
    ErrorCode,
    TaskName,
)
from app.core.database import get_mongodb, get_redis_client
from app.core.exceptions import JobFailed, LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.base import MongoRepository, VectorRepository
from app.models.ai.profiles import ChatModelProfile, EmbeddingModelProfile, RerankModelProfile

JSON_CHAT = ChatModelProfile(
    max_output_tokens=100,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=20_100,  # 60,000 prompt characters
)
PLAIN_CHAT = ChatModelProfile(
    max_output_tokens=50,
    timeout_seconds=9,
    supports_json_mode=False,
    reasoning_effort=None,
    context_tokens=20_050,
)


def _chat_model(*models: tuple[str, ChatModelProfile]) -> ai.ChatModel:
    return ai.ChatModel(
        list(models) or [("test-chat", JSON_CHAT)],
        "http://ai.invalid",
        "key",
        AiCallRepository(get_mongodb()["test_ai_calls"]),
    )


#: call_with_retries' request rate and slots when a test needs no limit (a worker's: 429s waited out).
_UNLIMITED = (UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS)


def _ask(chat: ai.ChatModel, task: AiTask, system_prompt: str = "system", user_prompt: str = "user") -> dict:
    """One answer, checked by a reader that accepts any JSON object."""
    return chat.ask_for_checked_json(task, system_prompt, user_prompt, lambda _answer: [])


def _json_response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))], usage=None)


def test_provider_outage_becomes_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_waiting(monkeypatch)

    def busy_provider(**_: object) -> None:
        raise litellm.RateLimitError(message="queue full at gw-7", llm_provider="openai", model="test-chat")

    monkeypatch.setattr(litellm, "completion", busy_provider)
    with capture_logs() as logs, pytest.raises(Unavailable):
        _ask(_chat_model(), AiTask.RELEVANCE_GATE)
    # S29 review (G125): the outage's kind is logged (a rate limit told from a timeout), never its text.
    outage = next(entry for entry in logs if entry["event"] == "ai.call_unavailable")
    logged = (outage["error_type"], outage["status"], outage["model"], outage["reason"])
    assert logged == ("RateLimitError", 429, "test-chat", AiOutage.BUSY)
    assert "gw-7" not in str(outage)


@pytest.mark.parametrize(
    ("error", "outage"),
    [
        (litellm.InternalServerError("down", llm_provider="openai", model="m"), AiOutage.DOWN),
        (litellm.BadGatewayError("bad gateway", llm_provider="openai", model="m"), AiOutage.DOWN),
        (litellm.APIConnectionError("refused", llm_provider="openai", model="m"), AiOutage.UNREACHABLE),
        (litellm.RateLimitError("busy", llm_provider="openai", model="m"), AiOutage.BUSY),
        (litellm.ServiceUnavailableError("overloaded", llm_provider="openai", model="m"), AiOutage.BUSY),
        (litellm.Timeout("no answer in time", model="m", llm_provider="openai"), AiOutage.TIMED_OUT),
        # Statuses litellm maps to no class of its own come as a plain APIError: the status tells the outage.
        (litellm.APIError(524, "origin timed out", llm_provider="openai", model="m"), AiOutage.TIMED_OUT),
        (litellm.APIError(529, "overloaded", llm_provider="openai", model="m"), AiOutage.BUSY),
        (litellm.APIError(500, "server error", llm_provider="openai", model="m"), AiOutage.DOWN),
    ],
)
def test_each_ai_outage_tells_the_ui_which_it_was(error: Exception, outage: AiOutage) -> None:
    """Down, unreachable, busy or timed out: its own reason and message (litellm's Timeout is also a lost
    connection, so a timeout must never read "unreachable"), and counted by that reason for the dashboard."""
    labels = {"task": AiTask.RELEVANCE_GATE, "reason": outage, "source": "gateway"}
    before = REGISTRY.get_sample_value("tsg_ai_outages_total", labels) or 0
    with (
        pytest.raises(Unavailable) as raised,
        ai.common.count_and_convert_ai_errors(AiTask.RELEVANCE_GATE, "m"),
    ):
        raise error
    assert (raised.value.reason, raised.value.detail) == (outage, AI_OUTAGE_MESSAGES[outage])
    assert REGISTRY.get_sample_value("tsg_ai_outages_total", labels) == before + 1


def test_an_unmapped_server_error_is_retried_and_a_client_error_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain APIError with a 5xx is an outage (asked again, then Unavailable for the job to back off);
    with a 4xx it is no outage: raised as it is, asked once."""
    _no_waiting(monkeypatch)
    asked: list[int] = []

    def failing(status: int) -> None:
        asked.append(status)
        raise litellm.APIError(status, "gateway said no", llm_provider="openai", model="m")

    with pytest.raises(Unavailable), ai.common.count_and_convert_ai_errors(AiTask.RELEVANCE_GATE, "m"):
        ai.common.call_with_retries(lambda: failing(529), *_UNLIMITED, model="m", task=AiTask.RELEVANCE_GATE)
    with pytest.raises(litellm.APIError), ai.common.count_and_convert_ai_errors(AiTask.RELEVANCE_GATE, "m"):
        ai.common.call_with_retries(lambda: failing(413), *_UNLIMITED, model="m", task=AiTask.RELEVANCE_GATE)
    assert asked == [529] * (AiLimits.RETRIES + 1) + [413]


def test_an_unmapped_timed_out_status_is_not_asked_again_and_is_told_as_timed_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner 2026-10-10: a call that timed out is not asked again in the call (a 524 is a timeout as much as
    litellm's Timeout); the fallback model or the job's back-off asks later, told "ai_timed_out"."""
    _no_waiting(monkeypatch)
    asked: list[int] = []

    def origin_timed_out() -> None:
        asked.append(524)
        raise litellm.APIError(524, "origin timed out", llm_provider="openai", model="m")

    with (
        pytest.raises(Unavailable) as raised,
        ai.common.count_and_convert_ai_errors(AiTask.RELEVANCE_GATE, "m"),
    ):
        ai.common.call_with_retries(origin_timed_out, *_UNLIMITED, model="m", task=AiTask.RELEVANCE_GATE)
    assert asked == [524] and raised.value.reason == AiOutage.TIMED_OUT


def test_fenced_json_answer_is_read_and_the_call_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = uuid.uuid4().hex  # finds its own record: "the newest" can be another test's (same millisecond)
    answer = SimpleNamespace(content=f'```json\n{{"relevant": true, "marker": "{marker}"}}\n```')
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=answer)],
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7),
    )
    monkeypatch.setattr(litellm, "completion", lambda **_: response)
    assert _ask(_chat_model(), AiTask.RELEVANCE_GATE)["relevant"] is True
    record = get_mongodb()["test_ai_calls"].find_one({"response": answer.content})
    assert record["task"] == AiTask.RELEVANCE_GATE and record["tokens_in"] == 11


def test_a_retried_job_asks_again_and_each_call_record_keeps_the_system_prompt_as_a_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id, system_prompt = uuid.uuid4().hex, "You are the relevance gate. " * 400
    calls: list[int] = []
    monkeypatch.setattr(litellm, "completion", lambda **_: calls.append(1) or _json_response('{"ok": 1}'))
    for attempt in (1, 2):
        with structlog.contextvars.bound_contextvars(task_id=task_id, attempt=attempt):
            assert _ask(_chat_model(), AiTask.RELEVANCE_GATE, system_prompt, "batch") == {"ok": 1}
    assert calls == [1, 1]  # the retry asked the AI again
    records = list(get_mongodb()["test_ai_calls"].find({"task_id": task_id}))
    assert len(records) == 2 and all(len(record["prompt_hash"]) == 64 for record in records)
    assert "relevance gate" not in str(records)
    system, user = records[0]["prompt"]
    assert system["role"] == "system" and len(system["content_sha256"]) == 16
    assert user == {"role": "user", "content": "batch"}


def test_a_job_takes_the_answers_any_of_its_deliveries_already_got_when_asked_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With reuse_earlier_answer, an ask the job (record, epoch, stage) already got an ok answer to is read
    from tsg_ai_calls (no AI call, no new record), whichever delivery got it: a reaper re-send has a new
    Celery task_id. Not when the check rejects that answer (the job retries to get another), nor for another
    epoch or stage, nor outside a leased job (the API)."""
    calls: list[int] = []

    def numbered_answer(**_: object) -> SimpleNamespace:
        calls.append(1)
        return _json_response(f'{{"n": {len(calls)}}}')

    monkeypatch.setattr(litellm, "completion", numbered_answer)
    chat = _chat_model()
    job = {"record_id": uuid.uuid4().hex, "epoch": 1, "task": TaskName.FIND_THREATS, "task_id": "first"}
    resent = job | {"task_id": "resent"}

    def ask(context: dict, lowest_accepted: int = 1) -> dict:
        with structlog.contextvars.bound_contextvars(**context):
            return chat.ask_for_checked_json(
                AiTask.RELEVANCE_GATE,
                "s",
                "batch",
                lambda answer: [] if answer["n"] >= lowest_accepted else ["rejected"],
                reuse_earlier_answer=True,
            )

    assert ask(job) == {"n": 1}  # the first delivery asks
    with capture_logs() as logs:
        assert ask(resent) == {"n": 1}  # a re-send reads the answer back
    with pytest.raises(ai.UnreadableAiAnswer):
        ask(job, lowest_accepted=4)  # an answer the check rejects is not read back: asked, then re-asked
    assert len(calls) == 3
    assert ask(job, lowest_accepted=4) == {"n": 4}  # so the job's retry gets another answer
    assert ask(resent, lowest_accepted=4) == {"n": 4}  # and the newest answer is the one read back
    assert ask(job | {"epoch": 2}) == {"n": 5}  # a new run of the record asks
    assert ask(job | {"task": TaskName.WRITE_SCENARIOS}) == {"n": 6}  # so does another stage
    api = {"request_id": "req-1"}
    assert [ask(api), ask(api)] == [{"n": 7}, {"n": 8}]  # outside a leased job, every ask is sent
    assert len(calls) == 8 and [entry["event"] for entry in logs] == ["ai.answer_reused"]
    assert get_mongodb()["test_ai_calls"].count_documents({"record_id": job["record_id"]}) == 6


def test_unreadable_answer_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm, "completion", lambda **_: _json_response("not json"))
    with pytest.raises(ai.UnreadableAiAnswer):
        _ask(_chat_model(), AiTask.WRITE_SCENARIO)


def test_fallback_model_answers_an_outage_with_its_own_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict] = []

    def first_model_busy(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs)
        if kwargs["model"] == "first":
            raise litellm.RateLimitError(message="busy", llm_provider="openai", model="first")
        return _json_response('{"ok": true}')

    _no_waiting(monkeypatch)
    monkeypatch.setattr(litellm, "completion", first_model_busy)
    answer = _ask(_chat_model(("first", JSON_CHAT), ("fallback", PLAIN_CHAT)), AiTask.RELEVANCE_GATE)
    *firsts, fallback = sent
    first = firsts[0]
    assert answer == {"ok": True}
    # The first model rate-limited (429): asked again after each of its waits, then the fallback.
    assert len(firsts) == len(AiLimits.RATE_LIMITED_WAITS_SECONDS) + 1
    assert first["response_format"] == {"type": "json_object"} and first["reasoning_effort"] == "none"
    assert first["temperature"] == fallback["temperature"] == 0.0  # R-2: the task's, for either model
    # The fallback gets ITS limits and none of the options its profile says it does not accept.
    assert fallback["max_tokens"] == 50 and fallback["timeout"] == 9
    assert "response_format" not in fallback and "reasoning_effort" not in fallback


def test_a_rate_limited_model_is_asked_again_as_told_before_the_slow_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 429 waits 2, 5, 10, 15 s, or its Retry-After when longer (at most CII_AI_BUSY_MAX_WAIT_SECONDS),
    +-20%, at most 60 s in all, and asks the same model again: kimi answers in ~5 s, the fallback glm-5.3 in
    55-99 s."""
    waits: list[float] = []
    monkeypatch.setattr(ai.common, "sleep_unless_lease_lost", waits.append)
    retry_after = iter(["20", "3", "", "", ""])
    asked: list[str] = []

    def first_model_rate_limited(**kwargs: object) -> SimpleNamespace:
        asked.append(str(kwargs["model"]))
        if kwargs["model"] == "first":
            told = httpx.Response(429, headers={"retry-after": next(retry_after)})
            raise litellm.RateLimitError("busy", llm_provider="openai", model="first", response=told)
        return _json_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", first_model_rate_limited)
    assert _ask(_chat_model(("first", JSON_CHAT), ("fallback", PLAIN_CHAT)), AiTask.RELEVANCE_GATE) == {
        "ok": True
    }
    assert asked == ["first"] * 5 + ["fallback"]
    assert 16 <= waits[0] <= 24 and 4 <= waits[1] <= 6 and 8 <= waits[2] <= 12 and 12 <= waits[3] <= 18
    assert sum(waits) <= AiLimits.RATE_LIMITED_TOTAL_WAIT_SECONDS


def test_an_ai_call_s_seconds_leave_out_its_request_rate_and_slot_waits() -> None:
    """tsg_ai_seconds and the call records time the AI alone: a model's pause, its turn and a busy AI slot
    (each waited 0.2 s here) are left out, so a 429 episode never reads as a slow model."""

    class SlowTurn:
        def wait_for_send_time(self, _task: str) -> float:
            time.sleep(0.2)
            return 0.2

        def wait_for_turn(self, _task: str, _tokens: int = 0) -> float:
            time.sleep(0.2)
            return 0.2

    slots = AiSlots(get_redis_client(), cap=1, wait_seconds=5, key=f"tsg:test_seconds:{uuid.uuid4().hex}")
    busy, release = threading.Event(), threading.Event()

    def hold_a_while() -> None:
        with slots.hold_slot("t"):
            busy.set()
            release.wait(5)

    holder = threading.Thread(target=hold_a_while)
    holder.start()
    assert busy.wait(5)
    threading.Timer(0.4, release.set).start()  # the slot frees 0.2 s after the pause ends
    started = time.monotonic()
    _, seconds = ai.common.call_with_retries(lambda: None, SlowTurn(), slots, model="m", task="t")  # type: ignore[arg-type]
    holder.join(5)
    assert time.monotonic() - started >= 0.55 and seconds < 0.1


def test_a_task_s_answer_cap_applies_under_its_model_s_limit_unless_the_model_thinks() -> None:
    """A cap measured with thinking off; a model thinking counts its hidden thinking too."""
    large = dataclasses.replace(JSON_CHAT, max_output_tokens=12_288)

    def max_tokens(profile: ChatModelProfile, task: AiTask, thinking: bool = False) -> int:
        return ai.chat_messages.build_request_options(profile, task, "m", thinking)["max_tokens"]

    assert max_tokens(large, AiTask.PLAN_CHECK) == CHAT_MAX_OUTPUT_TOKENS[AiTask.PLAN_CHECK] < 12_288
    assert max_tokens(JSON_CHAT, AiTask.PLAN_CHECK) == 100  # the model's own limit is lower
    assert max_tokens(large, AiTask.GAP_FILL) == CHAT_MAX_OUTPUT_TOKENS[AiTask.GAP_FILL] < 12_288
    assert (
        max_tokens(large, AiTask.REMEDIATION_PLAN) == CHAT_MAX_OUTPUT_TOKENS[AiTask.REMEDIATION_PLAN] < 12_288
    )
    assert max_tokens(large, AiTask.PLAN_CHECK, thinking=True) == 12_288


def test_thinking_is_switched_off_per_gateway_model_unless_its_env_line_says_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UAT probe (2026-10-23): reasoning_effort alone left GLM thinking; its chat template switch stops it.
    Each model has its own .env line; a non-gateway model (dev Azure) never gets the template switch."""
    sent: list[dict] = []

    def first_model_busy(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs)
        if not str(kwargs["model"]).endswith("fallback"):
            raise litellm.RateLimitError(message="busy", llm_provider="openai", model="m")
        return _json_response('{"ok": true}')

    _no_waiting(monkeypatch)
    monkeypatch.setattr(litellm, "completion", first_model_busy)
    off = {"chat_template_kwargs": {"thinking": False, "enable_thinking": False}}
    models = [("litellm_proxy/main", JSON_CHAT), ("litellm_proxy/fallback", JSON_CHAT)]
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    for thinking_on, main_body, fallback_body in (
        (frozenset(), off, off),  # the default: both off
        (frozenset({"litellm_proxy/fallback"}), off, None),  # main off, fallback on
    ):
        sent.clear()
        chat = ai.ChatModel(models, "http://ai.invalid", "key", records, thinking_on=thinking_on)
        _ask(chat, AiTask.RELEVANCE_GATE)
        assert sent[0].get("extra_body") == main_body and sent[-1].get("extra_body") == fallback_body
    sent.clear()
    _ask(_chat_model(("litellm_proxy/x", JSON_CHAT), ("openai/fallback", JSON_CHAT)), AiTask.RELEVANCE_GATE)
    assert "extra_body" not in sent[-1]  # not a gateway model


@pytest.fixture
def busy_provider() -> Iterator[tuple[str, list[str]]]:
    """A local OpenAI-style endpoint answering every request 503: (its URL, the paths requested)."""
    requested: list[str] = []

    class Busy(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — the http.server method name
            requested.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = b'{"error": {"message": "busy"}}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Busy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", requested
    server.shutdown()


def test_a_busy_provider_is_retried_by_us_alone_then_the_fallback_then_unavailable(
    monkeypatch: pytest.MonkeyPatch, busy_provider: tuple[str, list[str]]
) -> None:
    """The real litellm, not a stand-in. Before: litellm's own chat retry needed tenacity (not installed), so
    an outage became a bare Exception and the fallback model was never tried; and every embedding batch was
    sent 12 times (litellm read our max_retries=0 as "use the default", 2, under each of our 4 attempts)."""
    _no_waiting(monkeypatch)
    url, requested = busy_provider
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    chat = ai.ChatModel([("openai/first", JSON_CHAT), ("openai/fallback", PLAIN_CHAT)], url, "key", records)
    models = ("openai/first", "openai/fallback")
    before = [_ai_calls(AiTask.RELEVANCE_GATE, model, "unavailable") for model in models]
    with pytest.raises(Unavailable):
        _ask(chat, AiTask.RELEVANCE_GATE)
    assert [_ai_calls(AiTask.RELEVANCE_GATE, model, "unavailable") for model in models] == [
        n + 1 for n in before
    ]
    assert len(requested) == 2 * (AiLimits.RETRIES + 1)  # each model: our retries only, then the fallback
    requested.clear()
    profile = EmbeddingModelProfile(dimensions=2, batch_size=8, timeout_seconds=5, max_text_chars=100)
    stores = (
        EmbeddingRepository(get_mongodb()["test_embeddings"]),
        VectorRepository(get_mongodb()["test_query_vectors"]),
    )
    embed_before = _ai_calls(AiTask.EMBED, "openai/embed", "unavailable")
    with pytest.raises(Unavailable):
        ai.EmbeddingModel("openai/embed", profile, url, "key", *stores).embed_search_queries(
            [uuid.uuid4().hex], EmbeddingCorpus.CONTROL
        )
    assert len(requested) == AiLimits.RETRIES + 1
    assert _ai_calls(AiTask.EMBED, "openai/embed", "unavailable") == embed_before + 1


def test_each_text_is_embedded_once_then_read_from_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[list[str]] = []

    def fake_embedding(**kwargs: object) -> SimpleNamespace:
        batch = list(kwargs["input"])  # type: ignore[call-overload]
        requested.append(batch)
        return SimpleNamespace(data=[{"index": i, "embedding": [3.0, 4.0]} for i in range(len(batch))])

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    first = _embedding_model(dimensions=2).embed_search_queries(
        ["alpha", "beta", "alpha"], EmbeddingCorpus.CONTROL
    )
    second = _embedding_model(dimensions=2).embed_search_queries(["beta", "alpha"], EmbeddingCorpus.CONTROL)
    assert requested == [["alpha", "beta"]]
    assert np.allclose(first[0], [0.6, 0.8]) and np.allclose(second[1], first[0])


def test_a_vector_of_the_wrong_size_is_refused_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    three_numbers = SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 2.0, 3.0]}])
    monkeypatch.setattr(litellm, "embedding", lambda **_: three_numbers)
    cache = get_mongodb()["test_query_vectors"]
    cached_before, unreadable_before = (
        cache.count_documents({}),
        _ai_calls(AiTask.EMBED, "test-embed", "unreadable"),
    )
    with pytest.raises(ai.EmbeddingSizeMismatch, match="returned 3 numbers per text, not 2"):
        _embedding_model(dimensions=2).embed_search_queries(["gamma"], EmbeddingCorpus.CONTROL)
    assert cache.count_documents({}) == cached_before
    assert _ai_calls(AiTask.EMBED, "test-embed", "unreadable") == unreadable_before + 1  # not "error"


def _embedding_model(
    dimensions: int, key_header: str = "", *, library: str = "test_embeddings", **profile: int
) -> ai.EmbeddingModel:
    values = {"batch_size": 8, "timeout_seconds": 5, "max_text_chars": 1_000} | profile
    return ai.EmbeddingModel(
        "test-embed",
        EmbeddingModelProfile(dimensions=dimensions, **values),
        "http://ai.invalid",
        "key",
        EmbeddingRepository(get_mongodb()[library]),
        VectorRepository(get_mongodb()["test_query_vectors"]),
        key_header,
    )


def test_an_embedding_answer_with_a_repeated_index_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_waiting(monkeypatch)
    repeated = SimpleNamespace(
        data=[{"index": 0, "embedding": [1.0, 0.0]}, {"index": 0, "embedding": [0.0, 1.0]}]
    )
    monkeypatch.setattr(litellm, "embedding", lambda **_: repeated)
    # Still short after the retries: an outage the job retries later, not a bug that fails it for good.
    with pytest.raises(Unavailable, match="did not match its 2 inputs"):
        _embedding_model(dimensions=2).embed_search_queries(["delta", "epsilon"], EmbeddingCorpus.CONTROL)


def test_a_rerank_answer_missing_a_document_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_waiting(monkeypatch)
    one_of_two = SimpleNamespace(results=[{"index": 1, "relevance_score": 0.9}])
    monkeypatch.setattr(litellm, "rerank", lambda **_: one_of_two)
    profile = RerankModelProfile(timeout_seconds=5)
    with pytest.raises(Unavailable):
        ai.RerankModel("test-rerank", profile, "http://ai.invalid", "key").score_relevance("q", ["a", "b"])


@pytest.mark.parametrize("vector", [[float("nan"), 1.0], [float("inf"), 0.0], [0.0, 0.0]])
def test_an_embedding_with_a_nan_or_no_value_is_refused_not_cached(
    monkeypatch: pytest.MonkeyPatch, vector: list[float]
) -> None:
    """G112: such a vector would score 0 or NaN against everything, in silence, and stay in the cache."""
    monkeypatch.setattr(
        litellm, "embedding", lambda **_: SimpleNamespace(data=[{"index": 0, "embedding": vector}])
    )
    cache = get_mongodb()["test_query_vectors"]
    cached_before = cache.count_documents({})
    with pytest.raises(ai.EmbeddingNotFinite) as refused:
        _embedding_model(dimensions=2).embed_search_queries([f"zeta {vector}"], EmbeddingCorpus.CONTROL)
    assert refused.value.code == ErrorCode.AI_ANSWER_UNUSABLE  # the job fails with this code, never retried
    assert cache.count_documents({}) == cached_before


@pytest.mark.parametrize("score", [1.7, -2.3, float("nan")])
def test_a_rerank_score_outside_0_to_1_is_refused(monkeypatch: pytest.MonkeyPatch, score: float) -> None:
    """G112: a raw logit times 100 would pass the 75 bar or the 60 control cut-off by accident."""
    answer = SimpleNamespace(results=[{"index": 0, "relevance_score": score}])
    monkeypatch.setattr(litellm, "rerank", lambda **_: answer)
    profile = RerankModelProfile(timeout_seconds=5)
    model = ai.RerankModel("test-rerank", profile, "http://ai.invalid", "key")
    with pytest.raises(UnusableAiAnswer, match="outside 0-1"):
        model.score_relevance("q", ["a"])


def test_changing_the_retention_updates_the_index_instead_of_stopping_start_up() -> None:
    collection = get_mongodb()["test_retention"]
    MongoRepository(collection, ttl=[("created_at", 14 * 86_400)]).create_indexes()
    MongoRepository(collection, ttl=[("created_at", 30 * 86_400)]).create_indexes()  # IndexOptionsConflict
    ttl = next(index for index in collection.list_indexes() if index["key"] == {"created_at": 1})
    assert ttl["expireAfterSeconds"] == 30 * 86_400


def test_a_bad_gateway_from_the_proxy_becomes_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP 502 is its own class in litellm; a proxy restart answers with it, and it must be retried."""
    _no_waiting(monkeypatch)

    def gateway_restarting(**_: object) -> None:
        raise litellm.BadGatewayError(message="bad gateway", llm_provider="openai", model="test-chat")

    monkeypatch.setattr(litellm, "completion", gateway_restarting)
    with pytest.raises(Unavailable):
        _ask(_chat_model(), AiTask.RELEVANCE_GATE)


def _calls(outcome: str) -> float:
    labels = {"task": AiTask.WRITE_SCENARIO, "model": "test-chat", "outcome": outcome}
    return REGISTRY.get_sample_value("tsg_ai_calls_total", labels) or 0.0


def test_an_unreadable_answer_is_counted_once_as_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm, "completion", lambda **_: _json_response("not json"))
    ok_before, unreadable_before = _calls("ok"), _calls("unreadable")
    with pytest.raises(ai.UnreadableAiAnswer):
        _ask(_chat_model(), AiTask.WRITE_SCENARIO)
    # The answer and its one re-ask: each call counted once, as unreadable, never also "ok".
    assert (_calls("ok"), _calls("unreadable")) == (ok_before, unreadable_before + 2)


def test_a_refusal_or_a_reply_with_no_choices_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(**_: object) -> None:
        raise litellm.ContentPolicyViolationError(message="blocked", model="test-chat", llm_provider="openai")

    for reply in (refused, lambda **_: SimpleNamespace(choices=[], usage=None)):
        monkeypatch.setattr(litellm, "completion", reply)
        error_before, unreadable_before = _calls("error"), _calls("unreadable")
        with pytest.raises(ai.UnreadableAiAnswer, match="refused or malformed"):
            _ask(_chat_model(), AiTask.WRITE_SCENARIO)
        assert (_calls("error"), _calls("unreadable")) == (error_before, unreadable_before + 1)


def _fake_vectors(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Every text answers [3, 4]; returns the batches sent, in order."""
    requested: list[list[str]] = []

    def fake_embedding(**kwargs: object) -> SimpleNamespace:
        batch = list(kwargs["input"])  # type: ignore[call-overload]
        requested.append(batch)
        return SimpleNamespace(data=[{"index": i, "embedding": [3.0, 4.0]} for i in range(len(batch))])

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    return requested


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_a_query_vector_expires_and_its_text_is_never_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    """A search query holds an organization's asset description: only its hash is stored."""
    requested = _fake_vectors(monkeypatch)
    text = f"query {uuid.uuid4().hex}"
    model = _embedding_model(dimensions=2)
    model.embed_search_queries([text], EmbeddingCorpus.CONTROL)
    model.embed_search_queries([text], EmbeddingCorpus.CONTROL)
    assert requested == [[text]]
    stored = get_mongodb()["test_query_vectors"].find_one({"_id": f"test-embed|{_sha(text)}"})
    assert "text" not in stored and stored["text_hash"] == _sha(text) and stored["dimensions"] == 2
    assert timedelta(days=13) < stored["expires_at"] - stored["created_at"] <= timedelta(days=14)


def test_a_library_vector_says_what_it_is_and_which_rows_use_it(monkeypatch: pytest.MonkeyPatch) -> None:
    requested = _fake_vectors(monkeypatch)
    get_mongodb().drop_collection("test_library_vectors")
    rows = [{"table": "Control_Library", "id": n, "label": f"C-{n}"} for n in (1, 2, 3)]
    _embedding_model(2, library="test_library_vectors").embed_library_texts(
        EmbeddingCorpus.CONTROL, ["Backup: offline", "Backup: offline", "Training: phishing"], rows
    )
    assert requested == [["Backup: offline", "Training: phishing"]]  # IT/OT twins share one vector
    stored = get_mongodb()["test_library_vectors"].find_one({"text": "Backup: offline"})
    assert stored["_id"] == f"test-embed|control|{_sha('Backup: offline')}"
    assert (stored["corpus"], stored["model"], stored["dimensions"]) == ("control", "test-embed", 2)
    assert stored["text_hash"] == _sha("Backup: offline") and stored["sources"] == rows[:2]
    assert "created_at" in stored and "retired_at" not in stored


def test_a_changed_text_retires_the_old_vector_as_history_and_a_returning_text_is_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = _fake_vectors(monkeypatch)
    get_mongodb().drop_collection("test_library_vectors")
    vectors = get_mongodb()["test_library_vectors"]
    model = _embedding_model(2, library="test_library_vectors")
    row = {"table": "Control_Library", "id": 12, "label": "AC-2"}
    model.embed_library_texts(
        EmbeddingCorpus.THREAT, ["Malware: ransomware"], [{"table": "Threat_Catalogue", "id": 7}]
    )
    model.embed_library_texts(EmbeddingCorpus.CONTROL, ["Account management: old"], [row])
    model.embed_library_texts(
        EmbeddingCorpus.CONTROL, ["Account management: new"], [row]
    )  # the row's text changed
    old = vectors.find_one({"text": "Account management: old"})
    assert old["sources"] == [row] and old["expires_at"] - old["retired_at"] == timedelta(days=365)
    assert "retired_at" not in vectors.find_one({"text": "Account management: new"})
    history = vectors.find({"corpus": "control", "sources.id": 12}).sort("created_at", 1)
    assert [doc["text"] for doc in history] == ["Account management: old", "Account management: new"]
    model.embed_library_texts(EmbeddingCorpus.CONTROL, ["Account management: old"], [row])  # changed back
    assert len(requested) == 3  # no new AI call: the retired vector is used again
    assert not {"retired_at", "expires_at"} & vectors.find_one({"text": "Account management: old"}).keys()
    assert "retired_at" in vectors.find_one({"text": "Account management: new"})
    assert "retired_at" not in vectors.find_one({"corpus": "threat"})  # another corpus is never touched


def test_a_stored_vector_of_another_size_is_embedded_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """The provider changed the model behind the same name: the old vectors would give wrong scores."""
    requested = _fake_vectors(monkeypatch)
    get_mongodb().drop_collection("test_library_vectors")
    vectors = get_mongodb()["test_library_vectors"]
    key = f"test-embed|control|{_sha('Size: changed')}"
    vectors.insert_one({"_id": key, "corpus": "control", "dimensions": 3, "vector": bytes(12), "sources": []})
    matrix = _embedding_model(2, library="test_library_vectors").embed_library_texts(
        EmbeddingCorpus.CONTROL, ["Size: changed"], [{"table": "Control_Library", "id": 1, "label": "C-1"}]
    )
    assert requested == [["Size: changed"]] and vectors.find_one({"_id": key})["dimensions"] == 2
    assert np.allclose(matrix[0], [0.6, 0.8])


def _busy() -> litellm.RateLimitError:
    return litellm.RateLimitError("busy", llm_provider="litellm_proxy", model="m")


def _no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    # Our retry wait set to 0, not time.sleep replaced: that is the one time module of the whole process, and
    # a litellm thread that waits with sleep() then spun 200 million times and starved the test (2 s/request).
    monkeypatch.setattr(AiLimits, "RETRY_FIRST_WAIT_SECONDS", 0)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_WAITS_SECONDS", (0, 0, 0, 0))


@pytest.mark.parametrize(
    ("key_header", "expected"), [("x-litellm-api-key", {"x-litellm-api-key": "key"}), ("", None)]
)
def test_the_key_goes_in_the_gateways_own_header_on_every_call(
    monkeypatch: pytest.MonkeyPatch, key_header: str, expected: dict | None
) -> None:
    """UAT's LiteLLM reads the key from x-litellm-api-key: before, only Authorization: Bearer was sent."""
    sent: dict[str, object] = {}

    def capture(name: str, answer: object):  # noqa: ANN202
        def call(**kwargs: object) -> object:
            sent[name] = kwargs.get("headers" if name == "rerank" else "extra_headers")
            return answer

        return call

    monkeypatch.setattr(litellm, "completion", capture("chat", _json_response("{}")))
    monkeypatch.setattr(
        litellm, "embedding", capture("embed", SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}]))
    )
    monkeypatch.setattr(
        litellm, "rerank", capture("rerank", SimpleNamespace(results=[{"index": 0, "relevance_score": 1}]))
    )
    chat = ai.ChatModel(
        [("test-chat", JSON_CHAT)],
        "http://ai.invalid",
        "key",
        AiCallRepository(get_mongodb()["test_ai_calls"]),
        key_header,
    )
    _ask(chat, AiTask.WRITE_SCENARIO, "s", "u")
    _embedding_model(2, key_header).embed_search_queries(
        [f"header {uuid.uuid4().hex}"], EmbeddingCorpus.CONTROL
    )
    profile = RerankModelProfile(timeout_seconds=5)
    ai.RerankModel("test-rerank", profile, "http://ai.invalid", "key", key_header).score_relevance("q", ["a"])
    assert sent == {"chat": expected, "embed": expected, "rerank": expected}


def test_a_text_longer_than_the_model_takes_is_cut_before_it_is_sent_and_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UAT's embedding model takes 4,000 characters: before, a longer library text failed the whole build."""
    sent: list[str] = []

    def fake_embedding(**kwargs: object) -> SimpleNamespace:
        sent.extend(kwargs["input"])  # type: ignore[arg-type]
        return SimpleNamespace(data=[{"index": i, "embedding": [1.0, 0.0]} for i in range(len(sent))])

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    head = uuid.uuid4().hex
    _embedding_model(2, max_text_chars=40).embed_search_queries([head + "x" * 100], EmbeddingCorpus.CONTROL)
    _embedding_model(2, max_text_chars=40).embed_search_queries(
        [head + "x" * 500], EmbeddingCorpus.CONTROL
    )  # same first 40: read from the cache
    assert sent == [(head + "x" * 100)[:40]]


def test_batches_go_out_together_up_to_the_models_concurrency_and_stay_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: ~100 batches of a library build went one after another."""
    lock, active, peak = threading.Lock(), [0], [0]

    def fake_embedding(**kwargs: object) -> SimpleNamespace:
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        texts = list(kwargs["input"])  # type: ignore[call-overload]
        return SimpleNamespace(
            data=[{"index": i, "embedding": [float(len(t)), 1.0]} for i, t in enumerate(texts)]
        )

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    texts = [uuid.uuid4().hex + "x" * n for n in range(9)]
    matrix = _embedding_model(2, batch_size=1, concurrency=3).embed_search_queries(
        texts, EmbeddingCorpus.CONTROL
    )
    assert peak[0] == 3
    lengths = np.array([len(t) for t in texts], dtype=np.float32)
    expected = np.stack([lengths, np.ones(9, dtype=np.float32)], axis=1)
    assert np.allclose(matrix, expected / np.linalg.norm(expected, axis=1, keepdims=True))


def test_a_failed_batch_stops_the_batches_not_yet_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def first_batch_breaks(**kwargs: object) -> SimpleNamespace:
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("bad answer")
        time.sleep(0.05)
        return SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}])

    monkeypatch.setattr(litellm, "embedding", first_batch_breaks)
    with pytest.raises(ValueError, match="bad answer"):
        _embedding_model(2, batch_size=1, concurrency=2).embed_search_queries(
            [uuid.uuid4().hex for _ in range(20)], EmbeddingCorpus.CONTROL
        )
    assert len(calls) < 20


@pytest.mark.parametrize("call", ["rerank", "embedding"])
def test_a_busy_provider_is_retried_for_rerank_and_embeddings(
    monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    """Before: litellm retried chat calls only, so one busy moment failed a rerank or an embedding batch."""
    _no_waiting(monkeypatch)
    attempts: list[int] = []
    answer = (
        SimpleNamespace(results=[{"index": 0, "relevance_score": 0.5}])
        if call == "rerank"
        else SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}])
    )

    def busy_twice(**_: object) -> SimpleNamespace:
        attempts.append(1)
        if len(attempts) <= 2:
            raise _busy()
        return answer

    monkeypatch.setattr(litellm, call, busy_twice)
    if call == "rerank":
        profile = RerankModelProfile(timeout_seconds=5)
        assert ai.RerankModel("test-rerank", profile, "http://ai.invalid", "key").score_relevance(
            "q", ["a"]
        ) == [50.0]
    else:
        _embedding_model(2).embed_search_queries([f"retry {uuid.uuid4().hex}"], EmbeddingCorpus.CONTROL)
    assert len(attempts) == 3


@pytest.mark.parametrize(("task", "expected"), [(AiTask.RELEVANCE_GATE, 0.0), (AiTask.WRITE_SCENARIO, None)])
def test_temperature_follows_the_task_as_v1_does(
    monkeypatch: pytest.MonkeyPatch, task: AiTask, expected: float | None
) -> None:
    """R-2: 0.0 where the same input must give the same answer; none at all for scenario writing, so a
    regenerated scenario really differs (a model-wide 0.0 would have made variants near-identical)."""
    sent: list[dict] = []

    def capture(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs)
        return _json_response("{}")

    monkeypatch.setattr(litellm, "completion", capture)
    _ask(_chat_model(), task)
    assert sent[0].get("temperature", None) == expected
    assert ("temperature" in sent[0]) is (expected is not None)


def _ai_calls(task: AiTask, model: str, outcome: str) -> float:
    labels = {"task": task, "model": model, "outcome": outcome}
    return REGISTRY.get_sample_value("tsg_ai_calls_total", labels) or 0.0


def test_a_json_array_is_not_an_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: dict(json.loads(...)) turned ["ab", "cd"] into {"a": "b", "c": "d"} and counted it "ok"."""
    answer = f'["ab", "{uuid.uuid4().hex}"]'  # its own record: "the newest" can be another test's (same ms)
    monkeypatch.setattr(litellm, "completion", lambda **_: _json_response(answer))
    with pytest.raises(ai.UnreadableAiAnswer):
        _ask(_chat_model(), AiTask.RELEVANCE_GATE)
    record = get_mongodb()["test_ai_calls"].find_one({"response": answer})
    assert record["outcome"] == "unreadable"


def test_a_short_embedding_answer_is_asked_again_and_counted_only_once_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: a short answer failed the run at once (no retry) and was first counted "ok"."""
    _no_waiting(monkeypatch)
    answers = [
        SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}]),  # one vector for two texts
        SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}, {"index": 1, "embedding": [0.0, 1.0]}]),
    ]
    monkeypatch.setattr(litellm, "embedding", lambda **_: answers.pop(0))
    ok_before = _ai_calls(AiTask.EMBED, "test-embed", "ok")
    matrix = _embedding_model(2).embed_search_queries(
        [f"short {uuid.uuid4().hex}", f"short {uuid.uuid4().hex}"], EmbeddingCorpus.CONTROL
    )
    assert matrix.shape == (2, 2) and answers == []
    assert _ai_calls(AiTask.EMBED, "test-embed", "ok") == ok_before + 1


def test_a_bad_answer_that_stays_bad_is_counted_unreadable_not_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_waiting(monkeypatch)
    monkeypatch.setattr(litellm, "embedding", lambda **_: SimpleNamespace(data=[]))
    monkeypatch.setattr(litellm, "rerank", lambda **_: SimpleNamespace(results=[]))
    embed_ok, embed_bad = (
        _ai_calls(AiTask.EMBED, "test-embed", "ok"),
        _ai_calls(AiTask.EMBED, "test-embed", "unreadable"),
    )
    rerank_bad = _ai_calls(AiTask.RERANK, "test-rerank", "unreadable")
    with pytest.raises(Unavailable):
        _embedding_model(2).embed_search_queries(
            [f"never answered {uuid.uuid4().hex}"], EmbeddingCorpus.CONTROL
        )
    profile = RerankModelProfile(timeout_seconds=5)
    with pytest.raises(Unavailable):
        ai.RerankModel("test-rerank", profile, "http://ai.invalid", "key").score_relevance("q", ["a"])
    assert _ai_calls(AiTask.EMBED, "test-embed", "ok") == embed_ok
    assert _ai_calls(AiTask.EMBED, "test-embed", "unreadable") == embed_bad + 1
    assert _ai_calls(AiTask.RERANK, "test-rerank", "unreadable") == rerank_bad + 1


def test_a_refused_key_is_counted_as_an_error_on_every_ai_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: only outages and bad answers were counted, so a wrong key or a bad request (not retried, the
    job fails) left tsg_ai_calls_total flat and the AI-errors panel showed nothing while every call failed."""

    def refused(**_: object) -> None:
        raise litellm.AuthenticationError(message="bad key", llm_provider="openai", model="m")

    for kind in ("completion", "embedding", "rerank"):
        monkeypatch.setattr(litellm, kind, refused)
    before = [
        _ai_calls(AiTask.WRITE_SCENARIO, "test-chat", "error"),
        _ai_calls(AiTask.EMBED, "test-embed", "error"),
        _ai_calls(AiTask.RERANK, "test-rerank", "error"),
    ]
    rerank = ai.RerankModel("test-rerank", RerankModelProfile(timeout_seconds=5), "http://ai.invalid", "key")
    calls = (
        lambda: _ask(_chat_model(), AiTask.WRITE_SCENARIO),
        lambda: _embedding_model(2).embed_search_queries(
            [f"refused {uuid.uuid4().hex}"], EmbeddingCorpus.CONTROL
        ),
        lambda: rerank.score_relevance("q", ["a"]),
    )
    for (
        call
    ) in calls:  # S16-S31 review: a setting to fix fails the job once, with a clear code, never per path
        with pytest.raises(JobFailed) as refused_once:
            call()
        assert refused_once.value.code == ErrorCode.AI_MISCONFIGURED
        assert "AuthenticationError, HTTP 401" in refused_once.value.message and "bad key" not in str(
            refused_once.value
        )
    after = [
        _ai_calls(AiTask.WRITE_SCENARIO, "test-chat", "error"),
        _ai_calls(AiTask.EMBED, "test-embed", "error"),
        _ai_calls(AiTask.RERANK, "test-rerank", "error"),
    ]
    assert after == [count + 1 for count in before]


def test_batches_already_paid_for_are_cached_even_when_another_batch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: answers were read in order, so a slow batch still in flight when an earlier one failed was
    paid for and thrown away, and paid for again on the retry."""
    failing, slow = f"fails {uuid.uuid4().hex}", f"slow {uuid.uuid4().hex}"
    slow_sent = threading.Event()

    def answer(**kwargs: object) -> SimpleNamespace:
        (text,) = kwargs["input"]  # type: ignore[misc]
        if text == failing:
            slow_sent.wait(5)  # fails while the slow batch is in flight
            raise ValueError("bad gateway answer")
        slow_sent.set()
        time.sleep(0.2)
        return SimpleNamespace(data=[{"index": 0, "embedding": [1.0, 0.0]}])

    monkeypatch.setattr(litellm, "embedding", answer)
    with pytest.raises(ValueError, match="bad gateway answer"):
        _embedding_model(2, batch_size=1, concurrency=2).embed_search_queries(
            [failing, slow], EmbeddingCorpus.CONTROL
        )
    cached = get_mongodb()["test_query_vectors"].find_one(
        {"_id": f"test-embed|{hashlib.sha256(slow.encode()).hexdigest()}"}
    )
    assert cached is not None


def test_a_local_reranker_failure_is_counted_as_an_error() -> None:
    """Before: only the remote reranker counted its failures; a local model that would not load (the laptop)
    left tsg_ai_calls_total flat, so AiErrorRateHigh never fired there."""

    class WillNotLoad:
        def predict(self, _pairs: object) -> None:
            raise RuntimeError("model would not load")

    profile = RerankModelProfile(timeout_seconds=5)
    local = ai.RerankModel("test-local-rerank", profile, "", "")  # no base URL = the local model
    local._local_model = WillNotLoad()
    before = _ai_calls(AiTask.RERANK, "test-local-rerank", "error")
    with pytest.raises(RuntimeError):
        local.score_relevance("q", ["a"])
    assert _ai_calls(AiTask.RERANK, "test-local-rerank", "error") == before + 1


def test_the_vector_cache_ignores_a_duplicate_but_not_a_refused_write() -> None:
    """Before: every write error was swallowed, so a cache that stored nothing (a rejected document, a write
    concern not met) looked healthy and every text was paid for again on every call."""
    from pymongo.errors import BulkWriteError

    database = get_mongodb()
    database.drop_collection("test_vectors_duplicate")
    cache = VectorRepository(database["test_vectors_duplicate"])
    cache.save_vectors([{"_id": "key", "vector": b"vector"}])
    cache.save_vectors([{"_id": "key", "vector": b"vector"}])  # another worker stored it first: fine
    database.drop_collection("test_vectors_refused")
    database.create_collection("test_vectors_refused", validator={"$jsonSchema": {"required": ["never_set"]}})
    with pytest.raises(BulkWriteError):
        VectorRepository(database["test_vectors_refused"]).save_vectors([{"_id": "key", "vector": b"vector"}])


def test_a_timed_out_call_goes_to_the_fallback_model_without_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner, 2026-10-10: a call that timed out (the provider overloaded) is not asked again by us. Before, it
    was sent 3 more times, each waiting the full timeout (90-120 s): a worker held about 8 minutes per model,
    adding load to a provider that was already too slow."""
    requested: list[str] = []

    def first_model_times_out(**kwargs: object) -> SimpleNamespace:
        requested.append(str(kwargs["model"]))
        if kwargs["model"] == "openai/first":
            raise litellm.Timeout("no answer in time", model="openai/first", llm_provider="openai")
        return _json_response('{"relevant": true}')

    monkeypatch.setattr(litellm, "completion", first_model_times_out)
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    models = [("openai/first", JSON_CHAT), ("openai/fallback", PLAIN_CHAT)]
    chat = ai.ChatModel(models, "http://ai.invalid", "key", records)
    assert _ask(chat, AiTask.RELEVANCE_GATE) == {"relevant": True}
    assert requested == ["openai/first", "openai/fallback"]


def _replies(
    monkeypatch: pytest.MonkeyPatch, *contents: str, finish_reason: str = "stop"
) -> list[list[dict]]:
    """Fake chat answers, one per call in order; returns the messages each call was sent."""
    sent: list[list[dict]] = []
    answers = iter(contents)

    def answer(**kwargs: object) -> SimpleNamespace:
        sent.append(list(kwargs["messages"]))  # type: ignore[call-overload]
        message = SimpleNamespace(content=next(answers))
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason=finish_reason)], usage=None
        )

    monkeypatch.setattr(litellm, "completion", answer)
    return sent


def _needs_relevant(answer: dict) -> list[str]:
    return [] if isinstance(answer.get("relevant"), bool) else ["'relevant' must be true or false."]


def test_a_rejected_answer_is_asked_again_once_with_its_problems(monkeypatch: pytest.MonkeyPatch) -> None:
    """§9: one corrective re-ask, in the same conversation, with the exact re-ask message."""
    sent = _replies(monkeypatch, '{"relevant": "maybe"}', '{"relevant": true}')
    answer = _chat_model().ask_for_checked_json(AiTask.RELEVANCE_GATE, "system", "user", _needs_relevant)
    assert answer == {"relevant": True}
    assert sent[1][2:] == [
        {"role": "assistant", "content": '{"relevant": "maybe"}'},
        {
            "role": "user",
            "content": "Your previous reply was rejected:\n- 'relevant' must be true or false.\n"
            "Return the corrected JSON object only, in exactly the requested format.",
        },
    ]


def test_an_answer_still_wrong_after_the_re_ask_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _replies(monkeypatch, "not json", '{"relevant": "maybe"}')
    with pytest.raises(ai.UnreadableAiAnswer, match="still wrong after one re-ask"):
        _chat_model().ask_for_checked_json(AiTask.RELEVANCE_GATE, "system", "user", _needs_relevant)
    assert "- The reply was not one JSON object." in sent[1][-1]["content"]
    assert len(sent) == 2  # never a third call


def test_a_usable_first_answer_is_kept_when_the_re_ask_finds_the_ai_busy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The re-ask only improves a usable answer: an outage then keeps that answer, never fails the job. A
    first answer that is not usable still leaves the outage to the job's retry."""
    _no_waiting(monkeypatch)
    replies = iter(['{"relevant": true}'])

    def answer_once_then_busy(**_: object) -> SimpleNamespace:
        if (reply := next(replies, None)) is None:
            raise _busy()
        return _json_response(reply)

    monkeypatch.setattr(litellm, "completion", answer_once_then_busy)
    chat, faulted = _chat_model(), lambda _answer: ["a gap is missing"]
    with capture_logs() as logs:
        kept = chat.ask_for_checked_json(AiTask.RELEVANCE_GATE, "s", "u", _needs_relevant, faulted)
    assert kept == {"relevant": True}
    assert [entry["error_type"] for entry in logs if entry["event"] == "ai.first_answer_kept"] == [
        "Unavailable"
    ]
    replies = iter(['{"relevant": "maybe"}'])
    with pytest.raises(Unavailable) as raised:
        chat.ask_for_checked_json(AiTask.RELEVANCE_GATE, "s", "u", _needs_relevant, faulted)
    assert raised.value.reason == AiOutage.BUSY


def test_a_rejected_answer_too_long_to_quote_is_left_out_of_the_re_ask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v1 _reask: a batch fills up to 80% of the input limit; quoting a long rejected answer after it would
    make the re-ask too long to send, so only what was wrong is sent."""
    long_answer = '{"relevant": "' + "m" * JSON_CHAT.max_input_chars + '"}'
    sent = _replies(monkeypatch, long_answer, '{"relevant": true}')
    answer = _chat_model().ask_for_checked_json(AiTask.RELEVANCE_GATE, "system", "user", _needs_relevant)
    assert answer == {"relevant": True}
    assert [message["role"] for message in sent[1]] == ["system", "user", "user"]  # no assistant turn quoted


def test_a_re_ask_lists_at_most_20_problems_each_cut_short(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _replies(monkeypatch, "{}", '{"relevant": true}')
    many = [f"problem {n} " + "x" * 300 for n in range(30)]
    _chat_model().ask_for_checked_json(
        AiTask.RELEVANCE_GATE, "system", "user", lambda answer: [] if answer else many
    )
    lines = [line for line in sent[1][-1]["content"].splitlines() if line.startswith("- ")]
    assert len(lines) == AiLimits.REASK_MAX_PROBLEMS
    assert all(len(line) <= len("- ") + AiLimits.REASK_PROBLEM_CHARS for line in lines)


def test_a_cut_off_answer_or_a_too_long_prompt_is_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    """The caller sends less (e.g. halves the batch) instead of asking the same again."""
    sent = _replies(monkeypatch, '{"relevant": tr', finish_reason="length")
    with pytest.raises(ai.TruncatedAiAnswer, match="cut off"):
        _ask(_chat_model(), AiTask.RELEVANCE_GATE)
    too_long = "x" * (JSON_CHAT.max_input_chars + 1)
    with pytest.raises(ai.TruncatedAiAnswer, match="takes at most"):
        _ask(_chat_model(), AiTask.RELEVANCE_GATE, "system", too_long)
    assert len(sent) == 1  # the too-long prompt was never sent


def test_the_prompt_limit_is_the_smaller_models_so_either_can_answer() -> None:
    """UAT: kimi-k2.5 first, glm-5.3 as fallback, each with the gateway's own input limit (model info,
    2026-10-29: 114,688 and 262,144 tokens). Before, TSG assumed 262,144 and 1,000,000, so a prompt between
    the two was sent and refused whole."""
    uat = [(name, CHAT_MODEL_PROFILES[name]) for name in ("litellm_proxy/kimi-k2.5", "litellm_proxy/glm-5.3")]
    assert _chat_model(*uat).max_prompt_chars == 114_688 * 3
    assert _chat_model(uat[1]).max_prompt_chars == 262_144 * 3


def test_a_prompt_over_the_gateway_s_input_limit_is_refused_before_it_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prompt kimi-k2.5's gateway refuses (over 114,688 tokens) is never sent: the caller cuts it."""
    sent: list[object] = []
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: sent.append(kwargs))
    chat = _chat_model(("litellm_proxy/kimi-k2.5", CHAT_MODEL_PROFILES["litellm_proxy/kimi-k2.5"]))
    too_long = "x" * (114_688 * 3)  # the old limit took it: (262,144 - 12,288) x 3 characters
    with pytest.raises(ai.TruncatedAiAnswer, match="takes at most"):
        _ask(chat, AiTask.RELEVANCE_GATE, user_prompt=too_long)
    assert sent == []


def test_every_chat_task_asks_for_its_own_answer_room_never_the_model_s_whole() -> None:
    """LiteLLM reserves each request's answer room against the token budget while it runs. Before, the gate
    asked for 8,192 (largest answer 3,642) and four tasks for the model's whole 12,288, so TSG looked about 3x
    its real use (UAT 2026-10-28 10:20: 19,431 used, 50,274 counted). Each task's room is its own setting."""
    chat_tasks = set(AiTask) - {AiTask.EMBED, AiTask.RERANK}
    assert set(CHAT_MAX_OUTPUT_TOKENS) == chat_tasks
    assert all(256 <= room < 12_288 for room in CHAT_MAX_OUTPUT_TOKENS.values())
    assert CHAT_MAX_OUTPUT_TOKENS[AiTask.RELEVANCE_GATE] == TUNING.answer_tokens_relevance_gate


def test_a_call_record_names_the_run_and_the_request_it_served(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = uuid.uuid4().hex
    _replies(monkeypatch, f'{{"marker": "{marker}"}}')
    structlog.contextvars.bind_contextvars(record_id="run-7", request_id="req-9")
    try:
        _ask(_chat_model(), AiTask.RELEVANCE_GATE)
    finally:
        structlog.contextvars.unbind_contextvars("record_id", "request_id")
    record = get_mongodb()["test_ai_calls"].find_one({"response": f'{{"marker": "{marker}"}}'})
    assert (record["record_id"], record["request_id"]) == ("run-7", "req-9")


def test_the_local_reranker_scores_one_request_at_a_time() -> None:
    """G199 (live test 2026-10-11): one CPU prediction already uses every core; ten at once, a worker's
    threads, thrashed and none finished in 38 minutes. The local model takes one request at a time; the scores
    are unchanged."""
    running, most = [0], [0]
    guard = threading.Lock()

    class _Model:
        def predict(self, pairs: list[tuple[str, str]]) -> list[float]:
            with guard:
                running[0] += 1
                most[0] = max(most[0], running[0])
            time.sleep(0.05)
            with guard:
                running[0] -= 1
            return [0.5] * len(pairs)

    model = ai.RerankModel("test-rerank", RerankModelProfile(timeout_seconds=5), "", "")
    model._local_model = _Model()  # the local model, as loaded on first use
    scores: list[list[float]] = []
    threads = [
        threading.Thread(target=lambda: scores.append(model.score_relevance("q", ["a"]))) for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert most[0] == 1 and scores == [[50.0]] * 4


def test_a_job_that_lost_its_lease_never_calls_the_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    """G214: a cancelled job's next AI call is refused before it reaches the provider (no cost)."""
    called: list[object] = []
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: called.append(kwargs))
    with lease_lost_signal("cancelled-run") as lost:
        lost.set()
        with pytest.raises(LeaseLost):
            _ask(_chat_model(), AiTask.RELEVANCE_GATE)
    assert called == []


def test_at_most_cap_fallback_calls_run_at_once_and_the_first_model_is_never_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CII_<MODULE>_MAX_CONCURRENT_FALLBACK_CALLS: when kimi fails, glm (~77 s a call) would otherwise take
    ~230 calls at once at 180 requests a minute."""
    _no_waiting(monkeypatch)
    lock, in_flight, most = threading.Lock(), {"first": 0, "fallback": 0}, {"first": 0, "fallback": 0}
    failing = {"first"}

    def answer(**kwargs: object) -> SimpleNamespace:
        model = str(kwargs["model"])
        if model in failing:
            raise _overloaded()
        with lock:
            in_flight[model] += 1
            most[model] = max(most[model], in_flight[model])
        time.sleep(0.1)
        with lock:
            in_flight[model] -= 1
        return _json_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", answer)
    key = f"tsg:test_fallback_slots:{uuid.uuid4().hex}"
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    models = [("first", JSON_CHAT), ("fallback", PLAIN_CHAT)]
    capped = AiSlots(get_redis_client(), cap=1, wait_seconds=10, key=key)
    chat = ai.ChatModel(models, "http://ai.invalid", "key", records, fallback_slots=capped)
    answers: list[dict] = []

    def ask_four_at_once() -> None:
        callers = [
            threading.Thread(target=lambda: answers.append(_ask(chat, AiTask.GAP_FILL))) for _ in range(4)
        ]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join()

    ask_four_at_once()  # the first model down: the fallback answers, one call at a time
    failing.clear()
    ask_four_at_once()  # the first model up again: no cap
    get_redis_client().delete(key)
    assert answers == [{"ok": True}] * 8 and most["fallback"] == 1 and most["first"] > 1


def _timed_out() -> litellm.Timeout:
    return litellm.Timeout("no answer in time", model="first", llm_provider="openai")


def _overloaded() -> litellm.ServiceUnavailableError:
    return litellm.ServiceUnavailableError(message="overloaded", llm_provider="openai", model="first")


@pytest.mark.parametrize(("failure", "cools_down"), [(_timed_out, True), (_busy, True), (_overloaded, False)])
def test_a_model_that_timed_out_or_stayed_rate_limited_is_asked_last_until_it_answers(
    monkeypatch: pytest.MonkeyPatch, failure: Callable[[], Exception], cools_down: bool
) -> None:
    """Before: every call asked kimi first again, waiting out its timeout (120 s). A 429 left after its waits
    cools the model down too: the limit is that model's own, and the fallback's is not spent."""
    _no_waiting(monkeypatch)
    asked: list[str] = []
    failing = {"first": failure}

    def answer(**kwargs: object) -> SimpleNamespace:
        asked.append(str(kwargs["model"]))
        if fail := failing.get(str(kwargs["model"])):
            raise fail()
        return _json_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", answer)
    chat = _chat_model(("first", JSON_CHAT), ("fallback", PLAIN_CHAT))
    _ask(chat, AiTask.RELEVANCE_GATE)
    asked.clear()
    _ask(chat, AiTask.RELEVANCE_GATE)
    assert asked[0] == ("fallback" if cools_down else "first")
    failing.clear()
    failing["fallback"] = _overloaded
    _ask(chat, AiTask.RELEVANCE_GATE)  # the other one fails: the cooling one is still asked, and answers
    assert asked[-1] == "first"
    asked.clear()
    _ask(chat, AiTask.RELEVANCE_GATE)
    assert asked == ["first"]  # its answer ended its cool-down


def test_a_fallback_asked_first_takes_no_slot_wait_while_the_cooling_model_is_still_to_try(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: glm, first while kimi cooled down, waited up to 300 s for a slot; kimi answers in about 5 s."""
    _no_waiting(monkeypatch)
    asked: list[str] = []
    failing = {"first"}

    def answer(**kwargs: object) -> SimpleNamespace:
        asked.append(str(kwargs["model"]))
        if str(kwargs["model"]) in failing:
            raise _timed_out()
        return _json_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", answer)
    key = f"tsg:test_fallback_slots:{uuid.uuid4().hex}"
    fallback_slots = AiSlots(get_redis_client(), cap=1, wait_seconds=10, key=key)
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    models = [("first", JSON_CHAT), ("fallback", PLAIN_CHAT)]
    chat = ai.ChatModel(models, "http://ai.invalid", "key", records, fallback_slots=fallback_slots)
    _ask(chat, AiTask.RELEVANCE_GATE)  # the first model timed out: it cools down
    failing.clear()
    asked.clear()
    started = time.monotonic()
    try:
        with fallback_slots.hold_slot(AiTask.RELEVANCE_GATE):  # every fallback slot busy
            assert _ask(chat, AiTask.RELEVANCE_GATE) == {"ok": True}
    finally:
        get_redis_client().delete(key)
    assert asked == ["first"] and time.monotonic() - started < 5


def test_an_answer_cut_off_at_the_task_s_cap_is_asked_once_more_at_the_model_s_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caps were measured on dev's Kimi-K2.6 alone: another model (glm-5.3) may count more tokens."""
    sent: list[object] = []
    finish_reasons = iter(["length", "stop", "length", "length"])

    def answer(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs["max_tokens"])
        message = SimpleNamespace(content='{"ok": true}')
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason=next(finish_reasons))], usage=None
        )

    monkeypatch.setattr(litellm, "completion", answer)
    large = dataclasses.replace(JSON_CHAT, max_output_tokens=12_288)
    cap = CHAT_MAX_OUTPUT_TOKENS[AiTask.PLAN_CHECK]
    truncated = _ai_calls(AiTask.PLAN_CHECK, "test-chat", "truncated")
    assert _ask(_chat_model(("test-chat", large)), AiTask.PLAN_CHECK) == {"ok": True}
    with pytest.raises(ai.TruncatedAiAnswer, match="cut off"):  # cut off at the model's own limit too
        _ask(_chat_model(("test-chat", large)), AiTask.PLAN_CHECK)
    assert sent == [cap, 12_288, cap, 12_288]
    assert _ai_calls(AiTask.PLAN_CHECK, "test-chat", "truncated") == truncated + 3


def test_the_corrective_re_ask_after_an_answer_cut_off_at_the_cap_goes_at_the_model_s_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: the re-ask went at the task's cap again, to be cut off there first."""
    sent: list[object] = []
    finish_reasons = iter(["length", "stop", "stop"])

    def answer(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs["max_tokens"])
        message = SimpleNamespace(content='{"ok": true}')
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason=next(finish_reasons))], usage=None
        )

    monkeypatch.setattr(litellm, "completion", answer)
    large = dataclasses.replace(JSON_CHAT, max_output_tokens=12_288)
    problems = iter([["wrong"], []])
    chat = _chat_model(("test-chat", large))
    assert chat.ask_for_checked_json(AiTask.PLAN_CHECK, "s", "u", lambda _: next(problems)) == {"ok": True}
    assert sent == [CHAT_MAX_OUTPUT_TOKENS[AiTask.PLAN_CHECK], 12_288, 12_288]


def test_the_api_retries_a_429_as_any_busy_answer_and_a_worker_waits_it_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The API answers a caller: a 429's waits (up to 35 s) are a worker's alone. Every 429 is counted."""
    waits: list[float] = []
    monkeypatch.setattr(ai.common, "sleep_unless_lease_lost", waits.append)

    def rate_limited() -> None:
        raise _busy()

    def counted() -> float:
        return REGISTRY.get_sample_value("tsg_ai_rate_limited_total", {"model": "m"}) or 0.0

    before = counted()
    api = AiRequestRate(None, "m", per_minute=0, wait_seconds=0, waits_out_rate_limits=False)
    with pytest.raises(litellm.RateLimitError):
        ai.common.call_with_retries(
            rate_limited, api, UNLIMITED_AI_SLOTS, model="m", task=AiTask.RELEVANCE_GATE
        )
    assert waits == [0.5, 1, 2] and counted() == before + AiLimits.RETRIES + 1
    waits.clear()
    with pytest.raises(litellm.RateLimitError):  # a worker's limiter
        ai.common.call_with_retries(rate_limited, *_UNLIMITED, model="m", task=AiTask.RELEVANCE_GATE)
    assert len(waits) == len(AiLimits.RATE_LIMITED_WAITS_SECONDS) and min(waits) > 1
    for builder in ("create_all_indexes", "build_ai_gateways"):
        monkeypatch.setattr(container, builder, lambda *_: None)
    monkeypatch.setattr(container, "_waits_out_rate_limits", False)
    monkeypatch.setattr(container, "_ai_slot_wait_seconds", AiLimits.API_SLOT_WAIT_SECONDS)
    assert not container.ai_request_rate_for("m", 0)._waits_out_rate_limits  # the API's
    container.set_up_worker([])
    assert container.ai_request_rate_for("m", 0)._waits_out_rate_limits


def test_each_chat_request_waits_its_turn_at_the_limiter_of_the_model_it_goes_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """kimi-k2.5 and glm-5.3 each have their own requests-a-minute limit: a fallback request spends glm's.
    Every try states its prompt's estimated tokens, for a tokens-a-minute limit."""
    _no_waiting(monkeypatch)
    turns: list[str] = []
    sizes: list[int] = []

    class CountedTurns(AiRequestRate):
        def wait_for_turn(self, task: str, tokens: int = 0) -> float:
            turns.append(self._model)
            sizes.append(tokens)
            return 0.0

    def first_model_overloaded(**kwargs: object) -> SimpleNamespace:
        if kwargs["model"] == "first":
            raise _overloaded()
        return _json_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", first_model_overloaded)
    records = AiCallRepository(get_mongodb()["test_ai_calls"])
    models = [("first", JSON_CHAT), ("fallback", PLAIN_CHAT)]
    first, fallback = CountedTurns(None, "first", 0, 0), CountedTurns(None, "fallback", 0, 0)
    chat = ai.ChatModel(
        models, "http://ai.invalid", "key", records, request_rate=first, fallback_request_rate=fallback
    )
    assert _ask(chat, AiTask.RELEVANCE_GATE) == {"ok": True}
    assert turns == ["first"] * (AiLimits.RETRIES + 1) + ["fallback"]
    prompt = ai.chat_messages.build_conversation("system", "user")
    question = ai.chat_messages.count_prompt_chars(prompt) // AiLimits.PROMPT_CHARS_PER_TOKEN
    room = {
        name: ai.chat_messages.max_answer_tokens(profile, AiTask.RELEVANCE_GATE, False)
        for name, profile in models
    }
    # as LiteLLM counts against a token budget: the question and all the answer room asked for
    assert question > 0 and sizes == [question + room["first"]] * (len(turns) - 1) + [
        question + room["fallback"]
    ]


def test_each_ai_gateway_is_paced_by_its_own_model_s_requests_a_minute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: one limiter for the whole gateway, so embedding, rerank and glm requests spent kimi's."""
    _with_module_settings(monkeypatch)
    chat = container._chat_model_of(ChatModule.SCENARIO)
    embedding = container.get_embedding_model._build()
    rerank = container.get_rerank_model._build()
    rates = {  # by the model each request goes to
        **chat._request_rates,
        embedding._model: embedding._provider._request_rate,
        rerank._model: rerank._request_rate,
    }
    assert all(rate._model == model for model, rate in rates.items())  # its own model's Redis key
    assert {model: (rate._per_minute, rate._tokens_per_minute) for model, rate in rates.items()} == {
        KIMI: (11, 15),  # a module's tokens a minute pace its main chat model alone
        GLM: (12, 0),
        "litellm_proxy/qwen3-embedding-8b": (13, 0),
        "litellm_proxy/qwen3-reranker-8b": (14, 0),
    }


def test_each_module_s_chat_model_has_its_own_model_key_thinking_and_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner 2026-10-28: each module's CII_<MODULE>_CHAT_... lines alone, the same or a different model per
    module; no fallback model = no fallback limits. Each module's slots and request turns are its own Redis
    keys, two modules on one model included, so its 429s and limits never touch another module's."""
    _with_module_settings(monkeypatch)

    getters = {
        ChatModule.SCENARIO: container.get_scenario_chat_model,
        ChatModule.REMEDIATION: container.get_remediation_chat_model,
        ChatModule.SERVICE_MAPPER: container.get_service_mapper_chat_model,
    }

    def shown(module: ChatModule) -> tuple[object, ...]:
        chat = getters[module]._build()
        turns = {
            model: (r._per_minute, r._tokens_per_minute, r._key) for model, r in chat._request_rates.items()
        }
        connection = (chat._connection["api_base"], chat._connection["api_key"], sorted(chat._thinking_on))
        slots = [(pool._key, pool._cap) for pool in (chat._slots, chat._fallback_slots)]
        return [name for name, _ in chat._models], connection, turns, slots

    def turn(module: str, model: str) -> str:
        return AiLimits.REQUEST_RATE_KEY.format(model=f"{module}:{model}")

    def slots(module: str, cap: int, fallback_cap: int) -> list[tuple[str, int]]:
        return [
            (f"{AiLimits.SLOTS_KEY}:{module}", cap),
            (f"{AiLimits.FALLBACK_SLOTS_KEY}:{module}", fallback_cap),
        ]

    assert shown(ChatModule.SCENARIO) == (
        [KIMI, GLM],
        ("http://shared.invalid", "shared-key", []),
        {KIMI: (11, 15, turn("scenario", KIMI)), GLM: (12, 0, turn("scenario", GLM))},
        slots("scenario", 7, 2),
    )
    assert shown(ChatModule.REMEDIATION) == (  # its own key on its own gateway, glm thinking, no fallback
        [GLM],
        ("http://own.invalid", "own-key", [GLM]),
        {GLM: (21, 22, turn("remediation", GLM))},
        slots("remediation", 3, 0),
    )
    assert shown(ChatModule.SERVICE_MAPPER) == (  # threat scenarios' model and key, its own limits and keys
        [KIMI],
        ("http://shared.invalid", "shared-key", []),
        {KIMI: (31, 0, turn("service_mapper", KIMI))},
        slots("service_mapper", 6, 0),
    )


def test_each_job_asks_its_own_module_s_chat_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threat finding and scenario writing ask the scenario module's model, a remediation plan remediation's,
    the service mapper its own: a job wired to another module's would spend that module's model and limits."""
    for module in ChatModule:
        monkeypatch.setattr(container, f"get_{module}_chat_model", lambda module=module: f"{module} chat")
    jobs = {
        "scenario": container.get_plan_job._build()._threat_finder._chat,
        "scenario writing": container.get_scenario_write_job._build()._chat,
        "remediation": container.get_remediation_plan_job._build()._chat,
        "service_mapper": container.get_service_mapper_job._build()._chat,
    }
    assert jobs == {
        "scenario": "scenario chat",
        "scenario writing": "scenario chat",
        "remediation": "remediation chat",
        "service_mapper": "service_mapper chat",
    }


KIMI, GLM = "litellm_proxy/kimi-k2.5", "litellm_proxy/glm-5.3"


def _with_module_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threat scenarios and the service mapper on the same model, URL and key, each with its own limits;
    remediation on another model, URL and key. The service mapper's fallback limit counts for nothing: it has
    no fallback model."""
    settings = container.get_settings().model_copy(
        update={
            "embedding_model": "litellm_proxy/qwen3-embedding-8b",
            "rerank_model": "litellm_proxy/qwen3-reranker-8b",
            "rerank_base_url": "http://ai.invalid",
            "embedding_requests_per_minute": 13,
            "rerank_requests_per_minute": 14,
            "scenario_chat_base_url": "http://shared.invalid",
            "scenario_chat_api_key": SecretStr("shared-key"),
            "scenario_chat_model": KIMI,
            "scenario_chat_model_thinking": False,
            "scenario_chat_requests_per_minute": 11,
            "scenario_chat_tokens_per_minute": 15,
            "scenario_max_concurrent_ai_calls": 7,
            "scenario_chat_fallback_model": GLM,
            "scenario_chat_fallback_model_thinking": False,
            "scenario_chat_fallback_requests_per_minute": 12,
            "scenario_max_concurrent_fallback_calls": 2,
            "remediation_chat_base_url": "http://own.invalid",
            "remediation_chat_api_key": SecretStr("own-key"),
            "remediation_chat_model": GLM,
            "remediation_chat_model_thinking": True,
            "remediation_chat_requests_per_minute": 21,
            "remediation_chat_tokens_per_minute": 22,
            "remediation_max_concurrent_ai_calls": 3,
            "remediation_chat_fallback_model": "",
            "service_mapper_chat_base_url": "http://shared.invalid",
            "service_mapper_chat_api_key": SecretStr("shared-key"),
            "service_mapper_chat_model": KIMI,
            "service_mapper_chat_model_thinking": False,
            "service_mapper_chat_requests_per_minute": 31,
            "service_mapper_chat_tokens_per_minute": 0,
            "service_mapper_max_concurrent_ai_calls": 6,
            "service_mapper_chat_fallback_model": "",
            "service_mapper_max_concurrent_fallback_calls": 5,
        }
    )
    monkeypatch.setattr(container, "get_settings", lambda: settings)
    monkeypatch.setattr(container, "apply_proxy_once", lambda: None)
    monkeypatch.setattr(container, "get_module_ai_slots", container.get_module_ai_slots._build)


def test_a_batch_another_process_stored_meanwhile_is_not_sent_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every pod embeds a changed library at once: each sent every batch, though another had stored it."""
    texts = [f"stampede {uuid.uuid4().hex}" for _ in range(3)]
    theirs = np.array([0.0, 1.0], dtype=np.float32).tobytes()
    requested: list[list[str]] = []

    def embed_and_let_another_process_store_the_rest(**kwargs: object) -> SimpleNamespace:
        batch = list(kwargs["input"])  # type: ignore[call-overload]
        requested.append(batch)
        for text in set(texts) - set(batch):
            get_mongodb()["test_query_vectors"].update_one(
                {"_id": f"test-embed|{_sha(text)}"},
                {"$set": {"vector": theirs, "dimensions": 2}},
                upsert=True,
            )
        return SimpleNamespace(data=[{"index": i, "embedding": [1.0, 0.0]} for i in range(len(batch))])

    monkeypatch.setattr(litellm, "embedding", embed_and_let_another_process_store_the_rest)
    matrix = _embedding_model(2, batch_size=1).embed_search_queries(texts, EmbeddingCorpus.CONTROL)
    (sent,) = requested
    assert [list(row) for row in matrix] == [[1.0, 0.0] if [text] == sent else [0.0, 1.0] for text in texts]


def test_each_module_s_model_limits_replace_the_model_s_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner 2026-10-29: CII_<MODULE>_CHAT_MAX_INPUT_TOKENS, _MAX_OUTPUT_TOKENS and _TIMEOUT_SECONDS (and the
    backup's) set from the ConfigMap; a blank one keeps the model's own (app/ai/profiles.py)."""
    _with_module_settings(monkeypatch)
    settings = container.get_settings().model_copy(
        update={
            "scenario_chat_max_input_tokens": 50_000,
            "scenario_chat_timeout_seconds": 33,
            "scenario_chat_fallback_max_output_tokens": 2048,
        }
    )
    monkeypatch.setattr(container, "get_settings", lambda: settings)
    scenario = container.get_scenario_chat_model._build()
    profiles = dict(scenario._models)
    assert scenario.max_prompt_chars == 50_000 * AiLimits.PROMPT_CHARS_PER_TOKEN  # under glm's own 262,144
    assert (profiles[KIMI].timeout_seconds, profiles[KIMI].max_output_tokens) == (33, 12_288)
    assert (profiles[GLM].max_output_tokens, profiles[GLM].timeout_seconds) == (2048, 180)
    remediation = dict(container.get_remediation_chat_model._build()._models)
    assert remediation[GLM] == CHAT_MODEL_PROFILES[GLM]  # every line blank: the model's own
