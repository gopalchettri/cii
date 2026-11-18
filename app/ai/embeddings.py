"""Embedding gateway: one L2-normalised vector per text, each text embedded once per model and stored with
what it is (app/data_access/admin/): library texts in tsg_embeddings, search queries in
tsg_query_vectors."""

import contextvars
import hashlib
import random
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from functools import partial
from typing import Any

import litellm
import numpy as np
import structlog

from app.ai import common
from app.ai import slots as ai_slots
from app.ai.attempts import call_with_retries, note_ai_usage, one_ask, search_tokens
from app.ai.common import IncompleteAiAnswer, UnusableAiAnswer, build_api_key_header, count_and_convert_ai_errors
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, EmbeddingModelProfile, find_model_profile
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core import metrics
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    QUERY_TASKS,
    AiOutcome,
    AiTask,
    Cache,
    Collection,
    EmbeddingCorpus,
    ErrorMessage,
    LogEvent,
)
from app.core.singletons import singleton
from app.crud.base import Record as Doc
from app.crud.base import VectorRepository
from app.crud.embeddings import EmbeddingRepository

log = structlog.get_logger(__name__)


class EmbeddingSizeMismatch(UnusableAiAnswer):
    """The model returned vectors of a different length than its profile says: every score would be wrong."""


class EmbeddingNotFinite(UnusableAiAnswer):
    """A vector with a NaN, an infinity or only zeros: it would score 0 or NaN against everything (G112)."""


class EmbeddingModel:
    """Vectors for library texts and search queries, each embedded once per model and stored."""

    def __init__(
        self,
        model: str,
        profile: EmbeddingModelProfile,
        base_url: str,
        api_key: str,
        library: EmbeddingRepository,
        queries: VectorRepository,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
        request_rate: AiRequestRate = UNLIMITED_AI_REQUEST_RATE,
    ):
        self._model, self._profile = model, profile
        # The vector space: model name plus revision, so an old vector is never compared with re-pointed weights.
        self._space = model if profile.revision == 1 else f"{model}@r{profile.revision}"
        self._library, self._queries = library, queries
        self._base_url, self._api_key = base_url, api_key
        self._key_header = build_api_key_header(key_header, api_key)
        self._slots, self._request_rate = slots, request_rate

    def embed_search_queries(self, texts: list[str], corpus: EmbeddingCorpus) -> np.ndarray:
        """One L2-normalised row per query, sent after the model's instruction for that search (QUERY_TASKS)."""
        task = QUERY_TASKS[corpus]
        return self._embed_kept_briefly([self._profile.query_as_sent(text, task) for text in texts])

    def embed_texts_to_compare(self, texts: list[str]) -> np.ndarray:
        """One row per text compared with texts of its own kind: sent plain, as library texts are."""
        return self._embed_kept_briefly(self._cut_to_model_limit(texts))

    def _embed_kept_briefly(self, texts: list[str]) -> np.ndarray:
        expires_at = utc_now() + timedelta(days=Cache.QUERY_VECTOR_DAYS)
        keys = [f"{self._space}|{_text_sha256(text)}" for text in texts]
        matrix, _ = self._load_stored_or_embed(
            texts, keys, self._queries, lambda _key, _text: {"expires_at": expires_at}
        )
        return matrix

    def embed_library_texts(self, corpus: EmbeddingCorpus, texts: list[str], sources: list[Doc]) -> np.ndarray:
        """One normalised row per text of the WHOLE corpus (`sources[i]`: its row); unused vectors are retired."""
        texts = self._cut_to_model_limit(texts)
        keys = [f"{self._space}|{corpus}|{_text_sha256(text)}" for text in texts]
        in_use: dict[str, list[Doc]] = {}
        for key, source in zip(keys, sources, strict=True):
            in_use.setdefault(key, []).append(source)
        matrix, stored = self._load_stored_or_embed(
            texts, keys, self._library, lambda key, text: {"corpus": corpus, "text": text, "sources": in_use[key]}
        )
        if retired := self._library.update_library_vector_corpus(corpus, in_use, stored):
            log.info(LogEvent.EMBEDDINGS_RETIRED, corpus=corpus, model=self._model, count=retired)
        return matrix

    def _cut_to_model_limit(self, texts: list[str]) -> list[str]:
        return [text[: self._profile.max_text_chars] for text in texts]

    def _load_stored_or_embed(
        self, texts: list[str], keys: list[str], store: VectorRepository, describe: Callable[[str, str], Doc]
    ) -> tuple[np.ndarray, dict[str, Doc]]:
        found = store.list(("vector", "dimensions", "sources", "retired_at"), ids=keys)
        stored = {doc["_id"]: doc for doc in found}
        dimensions = self._profile.dimensions
        vectors = {
            key: doc["vector"]
            for key, doc in stored.items()
            if _check_stored_vector_has_right_size(key, doc, dimensions)
        }
        key_of = dict(zip(texts, keys, strict=True))
        missing = [text for text, key in key_of.items() if key not in vectors]
        size = self._profile.batch_size
        batches = [missing[start : start + size] for start in range(0, len(missing), size)]
        random.shuffle(batches)
        embed = partial(self._embed_and_store, store, describe, key_of)
        for embedded in _in_parallel(batches, embed, self._profile.concurrency):
            vectors.update(embedded)
        if not keys:  # np.vstack refuses an empty list; an empty corpus is a valid (empty) answer
            return np.empty((0, dimensions), dtype=np.float32), stored
        matrix = np.vstack([np.frombuffer(vectors[key], dtype=np.float32) for key in keys])
        return matrix / np.clip(np.linalg.norm(matrix, axis=1, keepdims=True), 1e-12, None), stored

    def _embed_and_store(
        self, store: VectorRepository, describe: Callable[[str, str], Doc], key_of: dict[str, str], batch: list[str]
    ) -> dict[str, bytes]:
        keys = [key_of[text] for text in batch]
        dimensions = self._profile.dimensions
        try:
            found = {doc["_id"]: doc for doc in store.list(("vector", "dimensions"), ids=keys)}
        except Exception:  # noqa: BLE001 - ponytail: the batch is embedded, as without the re-read
            found = {}
        if all(key in found and _check_stored_vector_has_right_size(key, found[key], dimensions) for key in keys):
            return {key: found[key]["vector"] for key in keys}
        embedded = self.embed_batch(batch)
        made = {"model": self._model, "revision": self._profile.revision, "dimensions": dimensions}
        made["created_at"] = utc_now()
        documents = [
            describe(key, text) | made | {"_id": key, "text_hash": _text_sha256(text), "vector": vector}
            for key, text, vector in zip(keys, batch, embedded, strict=True)
        ]
        store.save_vectors(documents)
        return {document["_id"]: document["vector"] for document in documents}

    def embed_batch(self, batch: list[str]) -> list[bytes]:
        def ask() -> tuple[list[bytes], dict[str, int]]:
            # ponytail: no `dimensions` sent: the model answers at its own size, checked below
            response = litellm.embedding(
                model=self._model,
                input=batch,
                api_base=self._base_url,
                api_key=self._api_key,
                timeout=self._profile.timeout_seconds,
                **self._key_header,
            )
            vectors = _checked_vectors(response, batch, self._model, self._profile.dimensions)
            return vectors, search_tokens(response)

        with one_ask():  # its failed attempts and its answer: one ask's usage rows, written as it ends
            with count_and_convert_ai_errors(AiTask.EMBED, self._model):  # a slot per attempt
                (vectors, tokens), seconds = call_with_retries(
                    ask, self._request_rate, self._slots, model=self._model, task=AiTask.EMBED
                )
            note_ai_usage(AiTask.EMBED, self._model, AiOutcome.OK, seconds=seconds, **tokens)
        metrics.AI_CALLS.labels(AiTask.EMBED, self._model, AiOutcome.OK).inc()
        metrics.AI_SECONDS.labels(AiTask.EMBED, self._model).observe(seconds)
        return vectors


def _checked_vectors(response: Any, batch: list[str], model: str, dimensions: int) -> list[bytes]:
    rows = sorted(response.data, key=lambda item: item["index"])
    if [row["index"] for row in rows] != list(range(len(batch))):
        # A short answer or a repeated index would pair a text with another's vector, kept for good.
        raise IncompleteAiAnswer(
            ErrorMessage.AI_ANSWER_INCOMPLETE.format(task=AiTask.EMBED, model=model, expected=len(batch))
        )
    vectors = [np.asarray(row["embedding"], dtype=np.float32) for row in rows]
    wrong_sizes = {vector.size for vector in vectors} - {dimensions}
    if wrong_sizes:
        raise EmbeddingSizeMismatch(
            ErrorMessage.EMBEDDING_SIZE_MISMATCH.format(model=model, received=min(wrong_sizes), expected=dimensions)
        )
    if not all(np.isfinite(vector).all() and vector.any() for vector in vectors):
        raise EmbeddingNotFinite(ErrorMessage.EMBEDDING_NOT_FINITE.format(model=model))
    return [vector.tobytes() for vector in vectors]


def _in_parallel[Answer](
    batches: list[list[str]], request: Callable[[list[str]], Answer], concurrency: int
) -> Iterator[Answer]:
    if concurrency <= 1 or len(batches) <= 1:
        yield from map(request, batches)
        return
    pool = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="embed")
    try:  # each request in a copy of the caller's context: its log fields and its job's lease signal
        sent = [pool.submit(contextvars.copy_context().run, request, batch) for batch in batches]
        failure: BaseException | None = None
        for answer in as_completed(sent):
            if answer.cancelled():
                continue
            if answer.exception() is None:
                yield answer.result()
            elif failure is None:
                failure = answer.exception()
                for waiting in sent:
                    waiting.cancel()  # only batches not yet sent; those in flight still arrive
        if failure is not None:
            raise failure
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _check_stored_vector_has_right_size(key: str, doc: Doc, dimensions: int) -> bool:
    if doc.get("dimensions") == dimensions and len(doc["vector"]) == 4 * dimensions:
        return True
    log.warning(LogEvent.EMBEDDING_STORED_SIZE_WRONG, vector_id=key, stored=doc.get("dimensions"), expected=dimensions)
    return False


@singleton
def get_embedding_model() -> EmbeddingModel:
    common.apply_proxy_once()
    settings = get_settings()
    model = settings.embedding_model
    return EmbeddingModel(
        model,
        find_model_profile(EMBEDDING_MODEL_PROFILES, model),
        settings.embedding_base_url,
        settings.embedding_api_key.get_secret_value(),
        EmbeddingRepository(),
        VectorRepository(Collection.QUERY_VECTORS),  # tsg_query_vectors
        settings.ai_key_header,
        ai_slots.get_ai_slots(),
        ai_slots.ai_request_rate_for(model, settings.embedding_requests_per_minute),
    )
