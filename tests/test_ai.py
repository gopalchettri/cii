"""AI gateway logic with litellm faked: outage handling, JSON reading, call records, embedding cache."""

import hashlib
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import litellm
import numpy as np
import pytest
import structlog
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import ai
from app.ai.common import UnusableAiAnswer
from app.core.constants import AiLimits, AiTask, EmbeddingCorpus, ErrorCode
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.base import MongoRepository, VectorRepository
from app.models.ai.profiles import ChatModelProfile, EmbeddingModelProfile, RerankModelProfile

JSON_CHAT = ChatModelProfile(
    max_output_tokens=100, timeout_seconds=5, supports_json_mode=True, reasoning_effort="none"
)
PLAIN_CHAT = ChatModelProfile(
    max_output_tokens=50, timeout_seconds=9, supports_json_mode=False, reasoning_effort=None
)


def _chat_model(*models: tuple[str, ChatModelProfile]) -> ai.ChatModel:
    return ai.ChatModel(
        list(models) or [("test-chat", JSON_CHAT)],
        "http://ai.invalid",
        "key",
        AiCallRepository(get_mongodb()["test_ai_calls"]),
    )


def _json_response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))], usage=None)


def test_provider_outage_becomes_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_waiting(monkeypatch)

    def busy_provider(**_: object) -> None:
        raise litellm.RateLimitError(message="busy", llm_provider="openai", model="test-chat")

    monkeypatch.setattr(litellm, "completion", busy_provider)
    with capture_logs() as logs, pytest.raises(Unavailable):
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
    # S29 review (G125): the outage's kind is logged (a rate limit told from a timeout), never its text.
    outage = next(entry for entry in logs if entry["event"] == "ai.call_unavailable")
    assert (outage["error"], outage["status"], outage["model"]) == ("RateLimitError", 429, "test-chat")
    assert "busy" not in str(outage)


def test_fenced_json_answer_is_read_and_the_call_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = uuid.uuid4().hex  # finds its own record: "the newest" can be another test's (same millisecond)
    answer = SimpleNamespace(content=f'```json\n{{"relevant": true, "marker": "{marker}"}}\n```')
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=answer)],
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7),
    )
    monkeypatch.setattr(litellm, "completion", lambda **_: response)
    assert _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")["relevant"] is True
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
            assert _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, system_prompt, "batch") == {"ok": 1}
    assert calls == [1, 1]  # the retry asked the AI again
    records = list(get_mongodb()["test_ai_calls"].find({"task_id": task_id}))
    assert len(records) == 2 and all(len(record["prompt_hash"]) == 64 for record in records)
    assert "relevance gate" not in str(records)
    system, user = records[0]["prompt"]
    assert system["role"] == "system" and len(system["content_sha256"]) == 16
    assert user == {"role": "user", "content": "batch"}


def test_unreadable_answer_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm, "completion", lambda **_: _json_response("not json"))
    with pytest.raises(ai.UnreadableAiAnswer):
        _chat_model().ask_for_json(AiTask.WRITE_SCENARIO, "system", "user")


def test_fallback_model_answers_an_outage_with_its_own_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict] = []

    def first_model_busy(**kwargs: object) -> SimpleNamespace:
        sent.append(kwargs)
        if kwargs["model"] == "first":
            raise litellm.RateLimitError(message="busy", llm_provider="openai", model="first")
        return _json_response('{"ok": true}')

    _no_waiting(monkeypatch)
    monkeypatch.setattr(litellm, "completion", first_model_busy)
    answer = _chat_model(("first", JSON_CHAT), ("fallback", PLAIN_CHAT)).ask_for_json(
        AiTask.RELEVANCE_GATE, "system", "user"
    )
    *firsts, fallback = sent
    first = firsts[0]
    assert answer == {"ok": True}
    assert len(firsts) == AiLimits.RETRIES + 1  # the first model's own retries, then the fallback
    assert first["response_format"] == {"type": "json_object"} and first["reasoning_effort"] == "none"
    assert first["temperature"] == fallback["temperature"] == 0.0  # R-2: the task's, for either model
    # The fallback gets ITS limits and none of the options its profile says it does not accept.
    assert fallback["max_tokens"] == 50 and fallback["timeout"] == 9
    assert "response_format" not in fallback and "reasoning_effort" not in fallback


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
        chat.ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
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
            [uuid.uuid4().hex]
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
    first = _embedding_model(dimensions=2).embed_search_queries(["alpha", "beta", "alpha"])
    second = _embedding_model(dimensions=2).embed_search_queries(["beta", "alpha"])
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
        _embedding_model(dimensions=2).embed_search_queries(["gamma"])
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
        _embedding_model(dimensions=2).embed_search_queries(["delta", "epsilon"])


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
        _embedding_model(dimensions=2).embed_search_queries([f"zeta {vector}"])
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
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")


def _calls(outcome: str) -> float:
    labels = {"task": AiTask.WRITE_SCENARIO, "model": "test-chat", "outcome": outcome}
    return REGISTRY.get_sample_value("tsg_ai_calls_total", labels) or 0.0


def test_an_unreadable_answer_is_counted_once_as_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm, "completion", lambda **_: _json_response("not json"))
    ok_before, unreadable_before = _calls("ok"), _calls("unreadable")
    with pytest.raises(ai.UnreadableAiAnswer):
        _chat_model().ask_for_json(AiTask.WRITE_SCENARIO, "system", "user")
    assert (_calls("ok"), _calls("unreadable")) == (ok_before, unreadable_before + 1)


def test_a_refusal_or_a_reply_with_no_choices_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(**_: object) -> None:
        raise litellm.ContentPolicyViolationError(message="blocked", model="test-chat", llm_provider="openai")

    for reply in (refused, lambda **_: SimpleNamespace(choices=[], usage=None)):
        monkeypatch.setattr(litellm, "completion", reply)
        error_before, unreadable_before = _calls("error"), _calls("unreadable")
        with pytest.raises(ai.UnreadableAiAnswer, match="refused or malformed"):
            _chat_model().ask_for_json(AiTask.WRITE_SCENARIO, "system", "user")
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
    model.embed_search_queries([text])
    model.embed_search_queries([text])
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
    monkeypatch.setattr(ai.common.AiLimits, "RETRY_FIRST_WAIT_SECONDS", 0)


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
    ai.ChatModel(
        [("test-chat", JSON_CHAT)],
        "http://ai.invalid",
        "key",
        AiCallRepository(get_mongodb()["test_ai_calls"]),
        key_header,
    ).ask_for_json(AiTask.WRITE_SCENARIO, "s", "u")
    _embedding_model(2, key_header).embed_search_queries([f"header {uuid.uuid4().hex}"])
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
    _embedding_model(2, max_text_chars=40).embed_search_queries([head + "x" * 100])
    _embedding_model(2, max_text_chars=40).embed_search_queries(
        [head + "x" * 500]
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
    matrix = _embedding_model(2, batch_size=1, concurrency=3).embed_search_queries(texts)
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
            [uuid.uuid4().hex for _ in range(20)]
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
        _embedding_model(2).embed_search_queries([f"retry {uuid.uuid4().hex}"])
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
    _chat_model().ask_for_json(task, "system", "user")
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
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
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
        [f"short {uuid.uuid4().hex}", f"short {uuid.uuid4().hex}"]
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
        _embedding_model(2).embed_search_queries([f"never answered {uuid.uuid4().hex}"])
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
        lambda: _chat_model().ask_for_json(AiTask.WRITE_SCENARIO, "system", "user"),
        lambda: _embedding_model(2).embed_search_queries([f"refused {uuid.uuid4().hex}"]),
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
        _embedding_model(2, batch_size=1, concurrency=2).embed_search_queries([failing, slow])
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
    assert chat.ask_for_json(AiTask.RELEVANCE_GATE, "system", "user") == {"relevant": True}
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
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
    too_long = "x" * (JSON_CHAT.max_input_chars + 1)
    with pytest.raises(ai.TruncatedAiAnswer, match="takes at most"):
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", too_long)
    assert len(sent) == 1  # the too-long prompt was never sent


def test_a_call_record_names_the_run_and_the_request_it_served(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = uuid.uuid4().hex
    _replies(monkeypatch, f'{{"marker": "{marker}"}}')
    structlog.contextvars.bind_contextvars(record_id="run-7", request_id="req-9")
    try:
        _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
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
            _chat_model().ask_for_json(AiTask.RELEVANCE_GATE, "system", "user")
    assert called == []
