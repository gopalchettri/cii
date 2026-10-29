"""AI usage rows (tsg_ai_usage, owner 2026-10-29): one per AI attempt, failed and retried ones too, and one
per reused answer; each says who it served (module, API call, session, request, caller), in which part of the
work, and belongs to the ask it served. The API call that queues a job is saved on it; nothing ever deletes
the rows. Each test names the mutation it catches."""

import threading
import time
import uuid
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import structlog
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import ai
from app.ai.embeddings import _EmbeddingProvider
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS
from app.core.clock import utc_now
from app.core.constants import AiApi, AiLimits, AiTask, AiUsageCollection, Module, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, Unavailable
from app.core.lease_signal import start_thread_without_lease
from app.core.logging import job_origin_scope
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.admin.ai_usage_repository import AiUsageHourlyRepository, AiUsageRepository
from app.data_access.base import NeverDeletedRepository
from app.data_access.jobs.job_repository import JobLease, new_job
from app.domain.shared.ask_ai import ask_ai_and_check
from app.domain.shared.audit import origin_of_its_jobs
from app.models.ai.profiles import ChatModelProfile, EmbeddingModelProfile, RerankModelProfile

PROFILE = ChatModelProfile(
    max_output_tokens=100,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=20_100,
)
TEXTS = "test_ai_call_texts"


def _chat(*models: str) -> ai.ChatModel:
    names = models or ("test-chat",)
    return ai.ChatModel(
        [(name, PROFILE) for name in names],
        "http://ai.invalid",
        "key",
        AiCallRepository(get_mongodb()[TEXTS]),
    )


def _job(task: str = TaskName.FIND_THREATS, **extra: Any) -> dict[str, Any]:
    """A claimed job's log context, as run_leased_job and the claim's origin bind it."""
    return {
        "record_id": uuid.uuid4().hex,
        "epoch": 1,
        "task": task,
        "attempt": 1,
        "module": Module.THREAT_SCENARIOS,
        "request_id": uuid.uuid4().hex,
        "session_id": uuid.uuid4().hex,
        "api": AiApi.CREATE_SCENARIO,
        "client_id": "ui-client",
        "entity_id": 102,
        **extra,
    }


def _answer(content: str = '{"ok": 1}', tokens: tuple[int, int] = (11, 7), choices: bool = True) -> Any:
    usage = SimpleNamespace(prompt_tokens=tokens[0], completion_tokens=tokens[1])
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))] if choices else [], usage=usage
    )


def _ask(chat: ai.ChatModel, job: dict[str, Any], reuse: bool = False) -> Any:
    with structlog.contextvars.bound_contextvars(**job):
        return ask_ai_and_check(
            chat, AiTask.RELEVANCE_GATE, ("system", "user"), lambda a: (a, []), reuse_earlier_answer=reuse
        )


def _rows(request_id: str) -> list[dict[str, Any]]:
    rows = get_mongodb()[AiUsageCollection.USAGE].find({"request_id": request_id})
    return sorted(rows, key=lambda row: (row["created_at"], row.get("try_no", 1)))


def _counter(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0


def _no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AiLimits, "RETRY_FIRST_WAIT_SECONDS", 0)
    monkeypatch.setattr(AiLimits, "RATE_LIMITED_WAITS_SECONDS", (0, 0, 0, 0))


def test_an_answered_chat_call_writes_one_lean_row_saying_who_it_served(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: drop `api` (or `bucket`) from the row, or write the prompt into it."""
    monkeypatch.setattr(litellm, "completion", lambda **_: _answer())
    job = _job()
    _ask(_chat(), job)
    [row] = _rows(job["request_id"])
    who = ("module", "api", "session_id", "record_id", "epoch", "attempt", "client_id", "entity_id")
    assert {name: row[name] for name in who} == {name: job[name] for name in who}
    assert (row["bucket"], row["job_task"], row["task"], row["model"]) == (
        "threats",
        TaskName.FIND_THREATS,
        "relevance_gate",
        "test-chat",
    )
    assert (row["outcome"], row["try_no"], row["tokens_in"], row["tokens_out"]) == ("ok", 1, 11, 7)
    assert "prompt" not in row and "response" not in row  # lean: the text is kept in tsg_ai_call_texts
    assert get_mongodb()[TEXTS].find_one({"_id": row["_id"]})["response"] == '{"ok": 1}'  # same _id


def test_every_retried_attempt_is_a_row_of_the_same_ask_and_only_the_last_counts_in_ai_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each row's seconds are its own attempt's: the answer's never hold the failed tries before it (review
    2026-10-29: they did, so retried calls counted their time twice). Mutation: count a retried attempt in
    tsg_ai_calls_total (AiErrorRateHigh would misfire), drop the noting of failed attempts, or give the answer
    the caller's seconds."""
    _no_waiting(monkeypatch)
    replies = iter(
        [litellm.ServiceUnavailableError("busy", llm_provider="openai", model="m")] * 2 + [_answer()]
    )

    def flaky(**_: object) -> Any:
        reply = next(replies)
        if isinstance(reply, Exception):
            time.sleep(0.3)  # each busy answer takes a while; the good one comes at once
            raise reply
        return reply

    monkeypatch.setattr(litellm, "completion", flaky)
    calls = {"task": AiTask.RELEVANCE_GATE, "model": "test-chat"}
    before = (
        _counter("tsg_ai_calls_total", **calls, outcome="ok"),
        _counter("tsg_ai_calls_total", **calls, outcome="unavailable"),
    )
    job = _job()
    _ask(_chat(), job)
    rows = _rows(job["request_id"])
    assert [(row["try_no"], row["outcome"], row.get("reason")) for row in rows] == [
        (1, "unavailable", "ai_busy"),
        (2, "unavailable", "ai_busy"),
        (3, "ok", None),
    ]
    assert len({row["ask_id"] for row in rows}) == 1 and rows[0]["error_type"] == "ServiceUnavailableError"
    assert rows[0]["seconds"] >= 0.3 and rows[2]["seconds"] < 0.2  # the answer: its own attempt only
    text = get_mongodb()[TEXTS].find_one({"_id": rows[2]["_id"]})
    assert text["seconds"] == rows[2]["seconds"]  # fix-check 2026-10-29: the text row and usage row agree
    after = (
        _counter("tsg_ai_calls_total", **calls, outcome="ok"),
        _counter("tsg_ai_calls_total", **calls, outcome="unavailable"),
    )
    assert (after[0] - before[0], after[1] - before[1]) == (1, 0)


@pytest.mark.parametrize(
    ("reply", "raised", "expected"),
    [
        (
            litellm.Timeout("slow", model="m", llm_provider="openai"),
            Unavailable,
            ("unavailable", "ai_timed_out", "Timeout"),
        ),
        (
            litellm.AuthenticationError("bad key", llm_provider="openai", model="m"),
            JobFailed,
            ("error", None, "AuthenticationError"),
        ),
        (_answer(choices=False), ai.UnreadableAiAnswer, ("unreadable", "no_choices", None)),
    ],
)
def test_each_failure_is_one_row_with_its_outcome_and_reason(
    monkeypatch: pytest.MonkeyPatch, reply: Any, raised: type[Exception], expected: tuple
) -> None:
    """A timeout (never retried), a refused key and an answer with no choices. Mutation: classify a timeout
    as an error, or drop the no-choices reason."""

    def answer(**_: object) -> Any:
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(litellm, "completion", answer)
    job = _job()
    with pytest.raises(raised):
        _ask(_chat(), job)
    [row] = _rows(job["request_id"])
    assert (row["outcome"], row.get("reason"), row.get("error_type")) == expected


def test_a_fallback_answer_is_the_same_ask_as_the_primary_models_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: open an ask per model (call_with_retries' own) when an outer one is open."""

    def by_model(model: str, **_: object) -> Any:
        if model == "primary":
            raise litellm.Timeout("slow", model=model, llm_provider="openai")
        return _answer()

    monkeypatch.setattr(litellm, "completion", by_model)
    job = _job()
    _ask(_chat("primary", "backup"), job)
    rows = _rows(job["request_id"])
    assert [(row["model"], row["outcome"], row["try_no"]) for row in rows] == [
        ("primary", "unavailable", 1),
        ("backup", "ok", 2),
    ]
    assert rows[0]["ask_id"] == rows[1]["ask_id"]


def test_a_local_reranks_seconds_are_its_predicting_never_its_wait_for_a_turn() -> None:
    """Review 2026-10-29: the laptop's reranker timed from before its wait for a turn, so its usage row held
    another job's prediction too (a provider call's seconds are its own attempt's). Mutation: start the timer
    before the turns."""

    class SlowFirst:  # the first caller's prediction takes a while; the second's none
        def predict(self, pairs: list[tuple[str, str]]) -> list[float]:
            if pairs[0][0] == "first":
                time.sleep(0.4)
            return [0.5] * len(pairs)

    rerank = ai.RerankModel("test-local-rerank", RerankModelProfile(timeout_seconds=5), "", "")
    rerank._local_model = SlowFirst()
    first = threading.Thread(target=rerank._score_with_local_model, args=("first", ["a"]))
    first.start()
    time.sleep(0.1)  # the first holds the turn
    _, seconds = rerank._score_with_local_model("second", ["b"])  # waits ~0.3 s for it, predicts at once
    first.join()
    assert seconds < 0.2


def test_a_reused_answer_is_a_row_but_no_ai_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """It takes no try number, so an ask whose re-ask follows a reused answer counts that re-ask as its first
    attempt (review 2026-10-29). Mutation: count a reused answer in tsg_ai_calls_total, note no row for it, or
    number it as a try."""
    monkeypatch.setattr(litellm, "completion", lambda **_: _answer())
    chat, job = _chat(), _job()
    _ask(chat, job, reuse=True)
    before = _counter("tsg_ai_calls_total", task=AiTask.RELEVANCE_GATE, model="test-chat", outcome="ok")
    _ask(chat, job | {"attempt": 2}, reuse=True)  # the job's next delivery reads the answer back
    after = _counter("tsg_ai_calls_total", task=AiTask.RELEVANCE_GATE, model="test-chat", outcome="ok")
    found = [
        (row["outcome"], row.get("model"), row["attempt"], row.get("try_no"))
        for row in _rows(job["request_id"])
    ]
    assert found == [("ok", "test-chat", 1, 1), ("reused", "test-chat", 2, None)]
    assert after == before


def test_search_calls_are_counted_in_the_part_their_job_stage_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    """Controls are picked by embedding and reranking alone: a scenario's and a plan's both count as
    controls. Mutation: swap one stage's part in SEARCH_STAGE_BUCKETS."""
    monkeypatch.setattr(
        litellm, "embedding", lambda **_: SimpleNamespace(data=[{"index": 0, "embedding": [0.6, 0.8]}])
    )
    monkeypatch.setattr(
        litellm, "rerank", lambda **_: SimpleNamespace(results=[{"index": 0, "relevance_score": 0.5}])
    )
    profile = EmbeddingModelProfile(dimensions=2, batch_size=8, timeout_seconds=5, max_text_chars=100)
    embed = _EmbeddingProvider(
        "test-embed", profile, "http://ai.invalid", "key", "", UNLIMITED_AI_SLOTS, UNLIMITED_AI_REQUEST_RATE
    )
    rerank = ai.RerankModel("test-rerank", RerankModelProfile(timeout_seconds=5), "http://ai.invalid", "key")
    scenario, plan = (
        _job(TaskName.MAP_CONTROLS),
        _job(TaskName.WRITE_PLAN, module=Module.REMEDIATION, api=AiApi.CREATE_PLAN),
    )
    with structlog.contextvars.bound_contextvars(**scenario):
        embed.embed_batch(["scenario text"])
        rerank.score_relevance("scenario", ["control"])
    with structlog.contextvars.bound_contextvars(**plan):
        rerank.score_relevance("scenario", ["control"])
    found = [
        (row["task"], row["bucket"], row["outcome"])
        for row in _rows(scenario["request_id"]) + _rows(plan["request_id"])
    ]
    assert found == [("embed", "controls", "ok"), ("rerank", "controls", "ok"), ("rerank", "controls", "ok")]


def test_a_shared_threads_calls_are_no_requests_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """A library or evidence index build runs on a thread started from whichever job needed it first: its
    calls are counted as shared, never charged to that job's request. Mutation: drop the shared_work check."""
    monkeypatch.setattr(
        litellm, "embedding", lambda **_: SimpleNamespace(data=[{"index": 0, "embedding": [0.6, 0.8]}])
    )
    profile = EmbeddingModelProfile(dimensions=2, batch_size=8, timeout_seconds=5, max_text_chars=100)
    embed = _EmbeddingProvider(
        "test-embed", profile, "http://ai.invalid", "key", "", UNLIMITED_AI_SLOTS, UNLIMITED_AI_REQUEST_RATE
    )
    job, marker, done = _job(), uuid.uuid4().hex, threading.Event()

    def build() -> None:
        try:
            embed.embed_batch([marker])
        finally:
            done.set()

    with structlog.contextvars.bound_contextvars(**job):
        start_thread_without_lease(f"library-indexes-{marker}", build)
    assert done.wait(10)
    assert _rows(job["request_id"]) == []
    [row] = get_mongodb()[AiUsageCollection.USAGE].find({"job_task": f"library-indexes-{marker}"})
    assert (row["bucket"], "module" in row, "session_id" in row) == ("shared", False, False)


def test_the_api_call_that_queues_a_job_is_saved_on_it_and_bound_when_it_is_claimed() -> None:
    """The outer API call's name wins over a call it makes inside the same request, and ends with it (never
    left for the next call on the thread); the claim reads it back with the session (a plan's run, else the
    record itself). Mutation: drop `origin` from new_job, let the inner call win, or never reset it."""
    with (
        job_origin_scope(AiApi.CREATE_PLAN, "client-1", 7),
        job_origin_scope(AiApi.CREATE_SCENARIO, "client-2", 8),
    ):  # a hand-written plan's run, made inside it
        job = new_job(TaskName.WRITE_PLAN, 1, utc_now())
    assert job["origin"] == {"api": AiApi.CREATE_PLAN, "client_id": "client-1", "entity_id": 7}
    assert new_job(TaskName.WRITE_PLAN, 1, utc_now())["origin"] == {}  # the call ended: nothing left behind
    records = get_mongodb()["test_jobs"]
    plan = JobLease(records, "plan-1", 1, "task-1", 1, {"job": job, "session_id": "run-9"})
    run = JobLease(records, "run-9", 1, "task-2", 1, {"job": job})
    assert plan.origin == {
        "session_id": "run-9",
        "api": AiApi.CREATE_PLAN,
        "client_id": "client-1",
        "entity_id": 7,
    }
    assert run.origin["session_id"] == "run-9"


def test_a_service_method_names_its_jobs_only_while_it_runs() -> None:
    """The decorator on the seven AI-starting service methods: their jobs carry the API call and caller; a
    method one of them calls keeps the outer name. Mutation: let the inner method's name win."""

    class Service:
        @origin_of_its_jobs(AiApi.CREATE_PLAN)
        def plan(self, principal: Any) -> dict[str, Any]:
            return self.run(principal)

        @origin_of_its_jobs(AiApi.CREATE_SCENARIO)
        def run(self, principal: Any) -> dict[str, Any]:
            return new_job(TaskName.WRITE_PLAN, 1, utc_now())

    caller = SimpleNamespace(client_id="ui-client", entity_id=102, user_id="u")
    assert Service().plan(caller)["origin"] == {
        "api": AiApi.CREATE_PLAN,
        "client_id": "ui-client",
        "entity_id": 102,
    }
    assert Service().run(principal=caller)["origin"]["api"] == AiApi.CREATE_SCENARIO
    assert new_job(TaskName.WRITE_PLAN, 1, utc_now())["origin"] == {}


def test_no_usage_or_call_text_is_ever_expired_or_deleted() -> None:
    """Mutation: give one of them a ttl= again, or let delete through."""
    for repository in (AiUsageRepository(), AiUsageHourlyRepository(), AiCallRepository()):
        repository.create_indexes()
        expiring = [
            name
            for name, index in repository.collection.index_information().items()
            if "expireAfterSeconds" in index
        ]
        assert expiring == [], repository.collection.name
        with pytest.raises(PermissionError):
            repository.delete(_id="anything")
    with pytest.raises(TypeError):
        NeverDeletedRepository("test_kept", ttl=[("created_at", 60)])


def test_an_expiry_found_at_start_up_is_dropped_and_logged_as_an_error() -> None:
    """An expiry on a collection kept for good (someone's hand, an older release) would delete its rows, and
    an index of ours on the same field would clash with it and stop start-up: it is dropped first, loudly.
    Mutation: check after creating the indexes, or only log it."""
    collection = get_mongodb()[f"test_kept_{uuid.uuid4().hex}"]
    collection.create_index("created_at", expireAfterSeconds=60)
    with capture_logs() as logs:
        AiUsageRepository(collection).create_indexes()
    assert [
        (entry["event"], entry["log_level"]) for entry in logs if entry["event"] == "ai.usage_expiry_found"
    ] == [("ai.usage_expiry_found", "error")]
    indexes = collection.index_information()
    assert "created_at_1" in indexes and not [
        index for index in indexes.values() if "expireAfterSeconds" in index
    ]


def test_a_row_mongodb_does_not_take_is_logged_whole_and_never_fails_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: let the write error raise into the AI call."""

    def refused(*_: object) -> None:
        raise ConnectionError("mongodb down")

    monkeypatch.setattr(litellm, "completion", lambda **_: _answer())
    monkeypatch.setattr(AiUsageRepository, "create_rows", refused)
    before, job = _counter("tsg_ai_usage_spilled_total"), _job()
    with capture_logs() as logs:
        assert _ask(_chat(), job) == {"ok": 1}
    [spilled] = [entry for entry in logs if entry["event"] == "ai.usage_row_spilled"]
    assert (spilled["row"]["request_id"], spilled["row"]["outcome"]) == (job["request_id"], "ok")
    assert _counter("tsg_ai_usage_spilled_total") - before == 1
