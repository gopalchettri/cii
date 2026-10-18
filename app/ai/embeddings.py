"""Embedding gateway: one L2-normalised vector per text, each text embedded once per model and stored with
what it is (app/data_access/admin/repository.py): library texts in tsg_embeddings, search queries in
tsg_query_vectors."""

import contextvars
import hashlib
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

import litellm
import numpy as np
import structlog

from app.ai.common import (
    IncompleteAiAnswer,
    UnusableAiAnswer,
    apply_proxy_settings,
    build_api_key_header,
    call_with_retries,
    count_and_convert_ai_errors,
)
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_SLOTS, AiSlots, get_ai_slots, max_slot_hold_seconds
from app.core import metrics
from app.core.config import get_settings
from app.core.constants import AiOutcome, AiTask, Cache, EmbeddingCorpus, ErrorMessage, LogEvent
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.admin.repository import (
    LibraryVectorRepository,
    VectorRepository,
    library_vectors,
    query_vectors,
)
from app.data_access.base import Record as Doc
from app.models.ai import EmbeddingModelProfile

log = structlog.get_logger(__name__)


class EmbeddingSizeMismatch(UnusableAiAnswer):
    """The model returned vectors of a different length than its profile says: every score would be wrong."""


class EmbeddingNotFinite(UnusableAiAnswer):
    """A vector with a NaN, an infinity or only zeros: it would score 0 or NaN against everything, in silence,
    and the cache would keep it (G112)."""


class EmbeddingModel:
    """Vectors for library texts and search queries: each text embedded once per model and stored with what
    it is (app/data_access/admin/repository.py). _EmbeddingProvider makes the calls."""

    def __init__(
        self,
        model: str,
        profile: EmbeddingModelProfile,
        base_url: str,
        api_key: str,
        library: LibraryVectorRepository,
        queries: VectorRepository,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
    ):
        self._model = model
        self._profile = profile
        # The vector space: the model name, plus its revision once the provider has re-pointed the name to
        # other weights of the same size (EmbeddingModelProfile.revision), so an old vector is never compared
        # with a new one.
        self._space = model if profile.revision == 1 else f"{model}@r{profile.revision}"
        self._provider = _EmbeddingProvider(model, profile, base_url, api_key, key_header, slots)
        self._library = library
        self._queries = queries

    @traced("ai.embed_queries")
    def embed_search_queries(self, texts: list[str]) -> np.ndarray:
        """One L2-normalised float32 row per search query. Kept Cache.QUERY_VECTOR_DAYS; only the text's hash
        is stored, never the text."""
        expires_at = datetime.now(UTC) + timedelta(days=Cache.QUERY_VECTOR_DAYS)
        texts = self._cut_to_model_limit(texts)
        keys = [f"{self._space}|{_text_sha256(text)}" for text in texts]
        matrix, _ = self._load_stored_or_embed(
            texts, keys, self._queries, lambda _key, _text: {"expires_at": expires_at}
        )
        return matrix

    @traced("ai.embed_library_texts")
    def embed_library_texts(
        self, corpus: EmbeddingCorpus, texts: list[str], sources: list[Doc]
    ) -> np.ndarray:
        """One L2-normalised float32 row per library text. `texts` is the WHOLE corpus as the library holds
        it now and `sources[i]` the row `texts[i]` comes from (`{table, id, label}`): each stored vector lists
        the rows using it, and a vector of this corpus no row uses any more is retired (kept
        Cache.RETIRED_VECTOR_DAYS as the rows' history)."""
        texts = self._cut_to_model_limit(texts)
        keys = [f"{self._space}|{corpus}|{_text_sha256(text)}" for text in texts]
        in_use: dict[str, list[Doc]] = {}
        for key, source in zip(keys, sources, strict=True):
            in_use.setdefault(key, []).append(source)
        matrix, stored = self._load_stored_or_embed(
            texts,
            keys,
            self._library,
            lambda key, text: {"corpus": corpus, "text": text, "sources": in_use[key]},
        )
        if retired := self._library.update_library_vector_corpus(corpus, in_use, stored):
            log.info(LogEvent.EMBEDDINGS_RETIRED, corpus=corpus, model=self._model, count=retired)
        return matrix

    def _cut_to_model_limit(self, texts: list[str]) -> list[str]:
        """Cut to the model's input limit BEFORE the key: the key and the stored text name exactly what was
        embedded."""
        return [text[: self._profile.max_text_chars] for text in texts]

    def _load_stored_or_embed(
        self, texts: list[str], keys: list[str], store: VectorRepository, describe: Callable[[str, str], Doc]
    ) -> tuple[np.ndarray, dict[str, Doc]]:
        """The rows for `texts` and what was stored before. A text not stored yet (or stored at another size)
        is embedded once and stored with `describe(key, text)` plus the fields every vector has."""
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
        for batch, embedded in _embed_batches_in_parallel(
            batches, self._provider.embed_batch, self._profile.concurrency
        ):
            made = {
                "model": self._model,
                "revision": self._profile.revision,
                "dimensions": dimensions,
                "created_at": datetime.now(UTC),
            }
            documents = [
                describe(key_of[text], text)
                | made
                | {"_id": key_of[text], "text_hash": _text_sha256(text), "vector": vector}
                for text, vector in zip(batch, embedded, strict=True)
            ]
            vectors.update((document["_id"], document["vector"]) for document in documents)
            store.save_vectors(documents)  # each batch as soon as it arrives, even if a later one fails
        if not keys:  # np.vstack refuses an empty list; an empty corpus is a valid (empty) answer
            return np.empty((0, dimensions), dtype=np.float32), stored
        matrix = np.vstack([np.frombuffer(vectors[key], dtype=np.float32) for key in keys])
        return matrix / np.clip(np.linalg.norm(matrix, axis=1, keepdims=True), 1e-12, None), stored


class _EmbeddingProvider:
    """One embedding request per batch: retried (call_with_retries, the only retry: litellm's own are off),
    checked (one vector per text, each the profile's size) and counted in the AI metrics."""

    def __init__(  # noqa: PLR0913 — the provider's address, key and limiter: each one is needed
        self,
        model: str,
        profile: EmbeddingModelProfile,
        base_url: str,
        api_key: str,
        key_header: str,
        slots: AiSlots,
    ) -> None:
        self._model = model
        self._profile = profile
        self._base_url = base_url
        self._api_key = api_key
        self._key_header = build_api_key_header(key_header, api_key)
        self._slots = slots

    def embed_batch(self, batch: list[str]) -> list[bytes]:
        started = time.perf_counter()
        with (
            self._slots.hold_slot(max_slot_hold_seconds(self._profile.timeout_seconds)),
            count_and_convert_ai_errors(AiTask.EMBED, self._model),
        ):
            # A short answer is asked again too.
            vectors = call_with_retries(lambda: self._read_checked_vectors(self._call_provider(batch), batch))
        metrics.AI_CALLS.labels(AiTask.EMBED, self._model, AiOutcome.OK).inc()
        metrics.AI_SECONDS.labels(AiTask.EMBED, self._model).observe(time.perf_counter() - started)
        return vectors

    def _call_provider(self, batch: list[str]) -> Any:
        return litellm.embedding(
            model=self._model,
            input=batch,
            api_base=self._base_url,
            api_key=self._api_key,
            # ponytail: no `dimensions` sent — each model answers at its native size (as v1 did); the
            # profile's size is checked instead.
            timeout=self._profile.timeout_seconds,
            **self._key_header,
        )

    def _read_checked_vectors(self, response: Any, batch: list[str]) -> list[bytes]:
        """The answer's vectors in batch order, checked: one per text, each the profile's size, each finite
        and not all zeros."""
        rows = sorted(response.data, key=lambda item: item["index"])
        if [row["index"] for row in rows] != list(range(len(batch))):
            # A short answer or a repeated index would give a text another text's vector, and the cache
            # would keep that wrong pair for good.
            raise IncompleteAiAnswer(
                ErrorMessage.AI_ANSWER_INCOMPLETE.format(
                    task=AiTask.EMBED, model=self._model, expected=len(batch)
                )
            )
        vectors = [np.asarray(row["embedding"], dtype=np.float32) for row in rows]
        wrong_sizes = {vector.size for vector in vectors} - {self._profile.dimensions}
        if wrong_sizes:
            raise EmbeddingSizeMismatch(
                ErrorMessage.EMBEDDING_SIZE_MISMATCH.format(
                    model=self._model, received=min(wrong_sizes), expected=self._profile.dimensions
                )
            )
        if not all(np.isfinite(vector).all() and vector.any() for vector in vectors):
            raise EmbeddingNotFinite(ErrorMessage.EMBEDDING_NOT_FINITE.format(model=self._model))
        return [vector.tobytes() for vector in vectors]


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _check_stored_vector_has_right_size(key: str, doc: Doc, dimensions: int) -> bool:
    """A stored vector of another size (the provider changed the model behind the same name) would give wrong
    scores: it is embedded again and replaced."""
    if doc.get("dimensions") == dimensions and len(doc["vector"]) == 4 * dimensions:
        return True
    log.warning(
        LogEvent.EMBEDDING_STORED_SIZE_WRONG, key=key, stored=doc.get("dimensions"), expected=dimensions
    )
    return False


def _embed_batches_in_parallel(
    batches: list[list[str]], request: Callable[[list[str]], list[bytes]], concurrency: int
) -> Iterator[tuple[list[str], list[bytes]]]:
    """(batch, its vectors) as each answer arrives, with up to `concurrency` requests in flight: the library
    index build sends ~100 batches. After a failure no new batch is sent, but every answer already paid for is
    still handed back (and so stored) before the failure is raised."""
    if concurrency <= 1 or len(batches) <= 1:
        for batch in batches:
            yield batch, request(batch)
        return
    pool = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="embed")
    try:
        # Each request in a copy of the caller's context: its log fields (the run) and its job's lease signal
        # reach the pool's threads too.
        sent = {pool.submit(contextvars.copy_context().run, request, batch): batch for batch in batches}
        failure: BaseException | None = None
        for answer in as_completed(sent):
            if answer.cancelled():
                continue
            if answer.exception() is None:
                yield sent[answer], answer.result()
            elif failure is None:
                failure = answer.exception()
                for waiting in sent:
                    waiting.cancel()  # only batches not yet sent; those in flight still arrive
        if failure is not None:
            raise failure
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


@singleton
def get_embedding_model() -> EmbeddingModel:
    settings = get_settings()
    apply_proxy_settings(settings)
    return EmbeddingModel(
        settings.embedding_model,
        find_model_profile(EMBEDDING_MODEL_PROFILES, settings.embedding_model),
        settings.embedding_base_url,
        settings.embedding_api_key.get_secret_value(),
        library_vectors,
        query_vectors,
        settings.ai_key_header,
        get_ai_slots(),
    )
