"""Embedding gateway: one L2-normalised vector per text, each text embedded once per model and stored with
what it is (app/data_access/admin/): library texts in tsg_embeddings, search queries in
tsg_query_vectors."""

import hashlib
import random
from collections.abc import Callable
from datetime import timedelta
from functools import partial
from typing import Any

import litellm
import numpy as np
import structlog

from app.ai.common import (
    IncompleteAiAnswer,
    UnusableAiAnswer,
    build_api_key_header,
    call_with_retries,
    count_and_convert_ai_errors,
)
from app.ai.embedding_batches import embed_batches_in_parallel
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core import metrics
from app.core.clock import utc_now
from app.core.config import Settings
from app.core.constants import QUERY_TASKS, AiOutcome, AiTask, Cache, EmbeddingCorpus, ErrorMessage, LogEvent
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.base import Record as Doc
from app.data_access.base import VectorRepository
from app.models.ai.profiles import EmbeddingModelProfile

log = structlog.get_logger(__name__)


class EmbeddingSizeMismatch(UnusableAiAnswer):
    """The model returned vectors of a different length than its profile says: every score would be wrong."""


class EmbeddingNotFinite(UnusableAiAnswer):
    """A vector with a NaN, an infinity or only zeros: it would score 0 or NaN against everything, in silence,
    and the cache would keep it (G112)."""


class EmbeddingModel:
    """Vectors for library texts and search queries: each text embedded once per model and stored with what
    it is (app/data_access/admin/). _EmbeddingProvider makes the calls."""

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
        self._model = model
        self._profile = profile
        # The vector space: the model name, plus its revision once the provider has re-pointed the name to
        # other weights of the same size (EmbeddingModelProfile.revision), so an old vector is never compared
        # with a new one.
        self._space = model if profile.revision == 1 else f"{model}@r{profile.revision}"
        self._provider = _EmbeddingProvider(
            model, profile, base_url, api_key, key_header, slots, request_rate
        )
        self._library = library
        self._queries = queries

    def embed_search_queries(self, texts: list[str], corpus: EmbeddingCorpus) -> np.ndarray:
        """One L2-normalised float32 row per query searched against `corpus`, sent after the model's
        instruction for that search (QUERY_TASKS). Kept Cache.QUERY_VECTOR_DAYS; only the hash of the text
        sent is stored, never the text."""
        task = QUERY_TASKS[corpus]
        return self._embed_kept_briefly([self._profile.query_as_sent(text, task) for text in texts])

    def embed_texts_to_compare(self, texts: list[str]) -> np.ndarray:
        """One row per text compared with texts of its own kind, never searched against a corpus: sent plain,
        as library texts are. Kept as queries are."""
        return self._embed_kept_briefly(self._cut_to_model_limit(texts))

    def _embed_kept_briefly(self, texts: list[str]) -> np.ndarray:
        expires_at = utc_now() + timedelta(days=Cache.QUERY_VECTOR_DAYS)
        keys = [f"{self._space}|{_text_sha256(text)}" for text in texts]
        matrix, _ = self._load_stored_or_embed(
            texts, keys, self._queries, lambda _key, _text: {"expires_at": expires_at}
        )
        return matrix

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
        is embedded once and stored (_embed_and_store). The batches go out in a random order: processes that
        embed the same texts at once start on different batches."""
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
        for _, embedded in embed_batches_in_parallel(batches, embed, self._profile.concurrency):
            vectors.update(embedded)
        if not keys:  # np.vstack refuses an empty list; an empty corpus is a valid (empty) answer
            return np.empty((0, dimensions), dtype=np.float32), stored
        matrix = np.vstack([np.frombuffer(vectors[key], dtype=np.float32) for key in keys])
        return matrix / np.clip(np.linalg.norm(matrix, axis=1, keepdims=True), 1e-12, None), stored

    def _embed_and_store(
        self,
        store: VectorRepository,
        describe: Callable[[str, str], Doc],
        key_of: dict[str, str],
        batch: list[str],
    ) -> dict[str, bytes]:
        """The batch's vectors by key: embedded, then stored with `describe(key, text)` plus the fields every
        vector has, as soon as they arrive (even if a later batch fails). Read instead, with no request, when
        another process stored the whole batch since it was first read (every pod embeds a changed library at
        once); a failed re-read only costs the request it would save."""
        keys = [key_of[text] for text in batch]
        dimensions = self._profile.dimensions
        try:
            found = {doc["_id"]: doc for doc in store.list(("vector", "dimensions"), ids=keys)}
        except Exception:  # noqa: BLE001 - ponytail: the batch is embedded, as without the re-read
            found = {}
        if all(
            key in found and _check_stored_vector_has_right_size(key, found[key], dimensions) for key in keys
        ):
            return {key: found[key]["vector"] for key in keys}
        embedded = self._provider.embed_batch(batch)
        made = {
            "model": self._model,
            "revision": self._profile.revision,
            "dimensions": dimensions,
            "created_at": utc_now(),
        }
        documents = [
            describe(key, text) | made | {"_id": key, "text_hash": _text_sha256(text), "vector": vector}
            for key, text, vector in zip(keys, batch, embedded, strict=True)
        ]
        store.save_vectors(documents)
        return {document["_id"]: document["vector"] for document in documents}


class _EmbeddingProvider:
    """One embedding request per batch: retried, a short answer too (call_with_retries: litellm's are off),
    checked (one vector per text, each the profile's size) and counted in the AI metrics."""

    def __init__(  # noqa: PLR0913 — the provider's address, key and limiter: each one is needed
        self,
        model: str,
        profile: EmbeddingModelProfile,
        base_url: str,
        api_key: str,
        key_header: str,
        slots: AiSlots,
        request_rate: AiRequestRate,
    ) -> None:
        self._model = model
        self._profile = profile
        self._base_url = base_url
        self._api_key = api_key
        self._key_header = build_api_key_header(key_header, api_key)
        self._slots = slots
        self._request_rate = request_rate

    def embed_batch(self, batch: list[str]) -> list[bytes]:
        with count_and_convert_ai_errors(AiTask.EMBED, self._model):  # a slot per attempt: call_with_retries
            vectors, seconds = call_with_retries(
                lambda: self._read_checked_vectors(self._call_provider(batch), batch),
                self._request_rate,
                self._slots,
                model=self._model,
                task=AiTask.EMBED,
            )
        metrics.AI_CALLS.labels(AiTask.EMBED, self._model, AiOutcome.OK).inc()
        metrics.AI_SECONDS.labels(AiTask.EMBED, self._model).observe(seconds)
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
        LogEvent.EMBEDDING_STORED_SIZE_WRONG, vector_id=key, stored=doc.get("dimensions"), expected=dimensions
    )
    return False


def embedding_model_from(
    settings: Settings,
    library: EmbeddingRepository,
    queries: VectorRepository,
    slots: AiSlots,
    request_rate: AiRequestRate,
) -> EmbeddingModel:
    """The embedding model the settings name, with its vector stores and its limiters."""
    return EmbeddingModel(
        settings.embedding_model,
        find_model_profile(EMBEDDING_MODEL_PROFILES, settings.embedding_model),
        settings.embedding_base_url,
        settings.embedding_api_key.get_secret_value(),
        library,
        queries,
        settings.ai_key_header,
        slots,
        request_rate,
    )
