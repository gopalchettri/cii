"""A search query is embedded after its model's query instruction (Qwen3-Embedding's "Instruct: ...\nQuery:");
library texts, and texts compared with their own kind, are embedded plain, so no stored vector changes."""

import ast
import hashlib
import pathlib
import uuid
from types import SimpleNamespace

import litellm
import pytest

from app import ai
from app.ai.profiles import EMBEDDING_MODEL_PROFILES
from app.core.constants import QUERY_TASKS, EmbeddingCorpus
from app.core.database import get_mongodb
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.base import VectorRepository
from app.domain.scenario.controls import control_query_instruction
from app.models.ai.profiles import EmbeddingModelProfile

QWEN = "litellm_proxy/qwen3-embedding-8b"
INSTRUCTION = "Instruct: {task}\nQuery:"
CONTROL_TASK = QUERY_TASKS[EmbeddingCorpus.CONTROL]
APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _sent_texts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every text sent to the provider, in order; each answers [3, 4]."""
    sent: list[str] = []

    def fake_embedding(**kwargs: object) -> SimpleNamespace:
        batch = list(kwargs["input"])  # type: ignore[call-overload]
        sent.extend(batch)
        return SimpleNamespace(data=[{"index": i, "embedding": [3.0, 4.0]} for i in range(len(batch))])

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    return sent


def _model(query_instruction: str | None = INSTRUCTION, max_text_chars: int = 1_000) -> ai.EmbeddingModel:
    profile = EmbeddingModelProfile(
        dimensions=2,
        batch_size=8,
        timeout_seconds=5,
        max_text_chars=max_text_chars,
        query_instruction=query_instruction,
    )
    return ai.EmbeddingModel(
        "test-embed",
        profile,
        "http://ai.invalid",
        "key",
        EmbeddingRepository(get_mongodb()["test_query_instruction_library"]),
        VectorRepository(get_mongodb()["test_query_vectors"]),
    )


def test_the_uat_model_takes_the_model_cards_query_format_and_the_laptop_model_none() -> None:
    """huggingface.co/Qwen/Qwen3-Embedding-8B: f'Instruct: {task_description}\\nQuery:{query}'."""
    assert EMBEDDING_MODEL_PROFILES[QWEN].query_as_sent("q", "T") == "Instruct: T\nQuery:q"
    assert EMBEDDING_MODEL_PROFILES["openai/text-embedding-3-large"].query_instruction is None


def test_only_a_query_is_sent_after_the_instruction_library_and_compared_texts_go_plain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_texts(monkeypatch)
    get_mongodb().drop_collection("test_query_instruction_library")
    text = f"phishing {uuid.uuid4().hex}"
    model = _model()
    model.embed_search_queries([text], EmbeddingCorpus.CONTROL)
    model.embed_library_texts(EmbeddingCorpus.CONTROL, [text], [{"table": "Control_Library", "id": 1}])
    model.embed_texts_to_compare([text])
    assert sent == [f"Instruct: {CONTROL_TASK}\nQuery:{text}", text, text]
    stored = get_mongodb()["test_query_instruction_library"].find_one({"text": text})
    assert stored is not None and stored["_id"] == f"test-embed|control|{_sha(text)}"  # key as before


def test_a_model_without_an_instruction_sends_and_keys_a_query_byte_for_byte_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_texts(monkeypatch)
    text = f"query {uuid.uuid4().hex}" + "x" * 100
    _model(query_instruction=None, max_text_chars=60).embed_search_queries([text], EmbeddingCorpus.THREAT)
    assert sent == [text[:60]]
    assert get_mongodb()["test_query_vectors"].find_one({"_id": f"test-embed|{_sha(text[:60])}"})


def test_the_cut_shortens_the_query_and_keeps_the_instruction_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent_texts(monkeypatch)
    instruction = f"Instruct: {CONTROL_TASK}\nQuery:"
    limit = len(instruction) + 10
    query = uuid.uuid4().hex + "x" * 200
    _model(max_text_chars=limit).embed_search_queries([query], EmbeddingCorpus.CONTROL)
    assert sent == [instruction + query[:10]] and len(sent[0]) == limit


def test_a_query_vector_is_keyed_on_the_text_sent_never_on_the_bare_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vector stored for the bare text (before the instruction, or by a comparison) never answers a query,
    and one query searched against two corpora is two texts sent."""
    sent = _sent_texts(monkeypatch)
    text = f"ransomware {uuid.uuid4().hex}"
    model = _model()
    model.embed_texts_to_compare([text])
    model.embed_search_queries([text], EmbeddingCorpus.CONTROL)
    model.embed_search_queries([text], EmbeddingCorpus.THREAT)
    model.embed_search_queries([text], EmbeddingCorpus.CONTROL)  # read from the store
    as_control = f"Instruct: {CONTROL_TASK}\nQuery:{text}"
    assert sent == [text, as_control, f"Instruct: {QUERY_TASKS[EmbeddingCorpus.THREAT]}\nQuery:{text}"]
    assert get_mongodb()["test_query_vectors"].find_one({"_id": f"test-embed|{_sha(as_control)}"})


def test_every_corpus_has_a_task_that_leaves_every_model_room_for_the_query() -> None:
    assert set(QUERY_TASKS) == set(EmbeddingCorpus)
    for profile in EMBEDDING_MODEL_PROFILES.values():
        for task in QUERY_TASKS.values():
            assert len(profile.instruction_for(task) or "") < profile.max_text_chars // 10


def test_a_stored_control_shortlist_is_keyed_on_the_instruction_the_gateway_sends() -> None:
    profile = EMBEDDING_MODEL_PROFILES[QWEN]
    instruction = control_query_instruction(SimpleNamespace(embedding_model=QWEN))  # type: ignore[arg-type]
    assert instruction is not None and profile.query_as_sent("q", CONTROL_TASK) == instruction + "q"
    laptop = SimpleNamespace(embedding_model="openai/text-embedding-3-large")
    assert control_query_instruction(laptop) is None  # type: ignore[arg-type]


# --- the convention: every search embeds its query through the query path

#: The only functions that embed library texts (the document path): the index builders.
DOCUMENT_EMBEDDERS = {
    "search/service.py:_index",
    "search/service_mapper.py:_for_catalog",
    "search/external_intelligence/evidence_index.py:build_index",
}
#: The only function that compares texts of one kind with each other (both sides plain).
TEXT_COMPARERS = {"domain/scenario/plan.py:merge_reworded_threats"}


def _functions() -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    return [
        (f"{source.relative_to(APP).as_posix()}:{node.name}", node)
        for source in sorted(APP.rglob("*.py"))
        if source.name != "embeddings.py" or source.parent.name != "ai"
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _calls(function: ast.AST, method: str, min_args: int = 0) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
        and len(node.args) >= min_args
        for node in ast.walk(function)
    )


def test_every_search_embeds_its_query_through_the_query_path() -> None:
    """A hybrid search (`index.search(query, vector, top_k, ...)`) embeds its query with
    embed_search_queries(texts, corpus); library texts are embedded only by the index builders and texts of
    one kind are compared only where listed: a search through either of those would lose the instruction."""
    functions = _functions()
    searches = {name for name, function in functions if _calls(function, "search", min_args=3)}
    assert searches, "no hybrid search found: the guard checks nothing"
    assert [n for n, f in functions if n in searches and not _calls(f, "embed_search_queries")] == []
    assert {n for n, f in functions if _calls(f, "embed_library_texts")} == DOCUMENT_EMBEDDERS
    assert {n for n, f in functions if _calls(f, "embed_texts_to_compare")} == TEXT_COMPARERS
    gateway = APP / "ai" / "embeddings.py"
    bypass = [s for s in APP.rglob("*.py") if s != gateway and "litellm.embedding(" in s.read_text("utf-8")]
    assert bypass == []  # nothing embeds around the gateway
