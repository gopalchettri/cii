"""The searchable corpus of the sources' current records, read in one streamed pass."""

import hashlib
import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future
from dataclasses import replace
from datetime import datetime
from typing import Any

import numpy as np
import structlog

from app.ai import EmbeddingModel, RerankModel
from app.ai.embeddings import get_embedding_model
from app.ai.rerank import get_rerank_model
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    EMBEDDING_SOURCE_TABLE,
    AiOutage,
    Dependency,
    EmbeddingCorpus,
    IntelDocId,
    IntelLimits,
    IntelMessage,
    IntelSource,
    LogEvent,
)
from app.core.exceptions import TEMPORARY_ERRORS, outage_reason
from app.core.lease_signal import start_thread_without_lease
from app.core.singletons import singleton
from app.crud.intel import get_intel_record_repository, get_intel_snapshot_repository
from app.schemas.intel_records import EvidenceCorpus, IntelHit, content_hash_of
from app.search.indexes import HybridIndex

_HIT_FIELDS = ("external_id", "kind", "title", "text", "url", "source", "asset_type", "data")
_MODULUS = 2**256


def build_corpus(docs: Iterable[dict[str, Any]], vector_space: str = "") -> EvidenceCorpus:
    """The corpus of these stored records."""
    hits: list[IntelHit] = []
    versions: dict[str, str] = {}
    digest_sum = 0
    for doc in docs:
        key = f"{doc['source']}|{doc['external_id']}|{doc['content_hash']}".encode()
        # a sum of digests: the same whatever order the records arrive in, and no list of keys to hold
        digest_sum = (digest_sum + int.from_bytes(hashlib.sha256(key).digest(), "big")) % _MODULUS
        versions[doc["source"]] = max(versions.get(doc["source"], ""), str(doc["source_version"]))
        # the record's own date and its fetch time travel with it, for the evidence's audit
        fetched = doc.get("fetched_at")
        fields: dict[str, Any] = {name: doc[name] for name in _HIT_FIELDS}
        fields |= {"modified": doc.get("modified"), "fetched_at": fetched.isoformat() if fetched else None}
        hits.append(IntelHit(**fields))
    if not hits:
        raise EvidenceIndexRefused(IntelMessage.SNAPSHOT_EMPTY)
    hits.sort(key=lambda hit: (hit.source, hit.external_id))
    checksum = content_hash_of(vector_space, len(hits), str(digest_sum))
    return EvidenceCorpus(tuple(hits), tuple(remove_indicators(hit.text) for hit in hits), checksum, versions)


_INDICATOR = re.compile(
    "|".join(
        [
            r"\b(?:https?|hxxps?|ftp)://\S+",
            r"\bwww\.\S+",
            r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            r"\b[a-f0-9]{32,128}\b",
        ]
    ),
    re.IGNORECASE,
)
_SPACES = re.compile(r"\s+")
_LABELS_TAIL = re.compile(r"\s*(?:Tactics|Platforms|Mitigations): .*$", re.DOTALL)


def remove_indicators(text: str) -> str:
    """The text without indicators, spaces collapsed."""
    return _SPACES.sub(" ", _INDICATOR.sub(" ", text)).strip()


def scoring_text(hit: IntelHit, titles: dict[tuple[IntelSource, str], str]) -> str:
    """What the reranker reads of a record."""
    text = _LABELS_TAIL.sub("", remove_indicators(hit.text).removeprefix(f"{hit.external_id} "))
    parent = titles.get((hit.source, hit.external_id.partition(".")[0])) if "." in hit.external_id else None
    return f"{parent}: {text}" if parent else text


def technique_titles(hits: Iterable[IntelHit]) -> dict[tuple[IntelSource, str], str]:
    """Each technique's title by (source, id)."""
    return {(hit.source, hit.external_id): hit.title for hit in hits}


class EvidenceIndexRefused(Exception):
    """No current record, or rows and vectors out of step."""

    def __init__(self, message: IntelMessage, **facts: object) -> None:
        super().__init__(message.format(**facts))
        self.no_data = message is IntelMessage.SNAPSHOT_EMPTY  # nothing imported yet (or all of it gone)


_EMPTY = EvidenceCorpus((), (), "")
#: The snapshot id of a corpus that settled empty: searched, and nothing found.
EMPTY_SNAPSHOT_ID = "empty"


class EvidenceIndex:
    """Built once, never changed afterwards."""

    def __init__(
        self,
        corpus: EvidenceCorpus,
        hybrid: HybridIndex | None,
        embeddings: EmbeddingModel,
        rerank: RerankModel,
        rerank_model: str = "",
        *,
        settled: bool = True,
        outage: AiOutage | None = None,
        outage_message: str = "",
    ) -> None:
        self.corpus = corpus  # the corpus the index was built from
        self._settled = settled  # False only for the placeholder served until the first build ends
        self.outage = outage  # the placeholder's: the AI outage that stopped the first build
        self.outage_message = outage_message  # that outage in its own words
        self._hybrid = hybrid
        self._embeddings = embeddings
        self._rerank = rerank
        self.rerank_model = rerank_model  # the model whose 0-100 scores the threshold is cut on
        self.built_at = utc_now()
        self._asset_types = np.array([hit.asset_type for hit in corpus.hits])
        self._titles = technique_titles(corpus.hits)

    @property
    def snapshot_id(self) -> str | None:
        """The same for the same corpus in every process, so a stored audit names one snapshot."""
        if self.corpus.hits:
            return self.corpus.checksum[:24]
        return EMPTY_SNAPSHOT_ID if self._settled else None

    @property
    def has_records(self) -> bool:
        """False when the corpus holds nothing to search."""
        return bool(self.corpus.hits)

    def find_candidates(self, searches: Sequence[tuple[str, frozenset[str]]], limit: int) -> list[list[IntelHit]]:
        """Per (search text, asset types): the `limit` nearest records of those types."""
        found: list[list[IntelHit]] = [[] for _ in searches]
        if self._hybrid is None or limit < 1:
            return found
        queries = [remove_indicators(text) for text, _ in searches]
        allowed = [np.isin(self._asset_types, list(types)) for _, types in searches]
        asked = [i for i, fits in enumerate(allowed) if fits.any() and queries[i]]
        if not asked:
            return found
        vectors = self._embeddings.embed_search_queries(
            [queries[i] for i in asked], EmbeddingCorpus.EXTERNAL_INTELLIGENCE
        )
        for position, vector in zip(asked, vectors, strict=True):
            hits = self._hybrid.search(queries[position], vector, limit, allowed[position])
            found[position] = [self.corpus.hits[hit.position] for hit in hits]
        return found

    def score_candidates(self, query: str, hits: Sequence[IntelHit]) -> list[IntelHit]:
        """`hits` scored 0-100 by the reranker against `query` (one call), best first."""
        if not hits:
            return []
        scores = self._rerank.score_relevance(
            remove_indicators(query), [scoring_text(hit, self._titles) for hit in hits]
        )
        scored = [replace(hit, score=score) for hit, score in zip(hits, scores, strict=True)]
        return sorted(scored, key=lambda hit: (-hit.score, hit.external_id))


def empty_index(
    embeddings: EmbeddingModel,
    rerank: RerankModel,
    rerank_model: str = "",
    *,
    settled: bool = False,
    outage: AiOutage | None = None,
    outage_message: str = "",
) -> EvidenceIndex:
    """An index with nothing to search."""
    return EvidenceIndex(
        _EMPTY, None, embeddings, rerank, rerank_model, settled=settled, outage=outage, outage_message=outage_message
    )


def build_index(
    corpus: EvidenceCorpus, embeddings: EmbeddingModel, rerank: RerankModel, rerank_model: str = ""
) -> EvidenceIndex:
    """The index of `corpus`, its texts embedded through the vector cache."""
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.EXTERNAL_INTELLIGENCE]
    sources = [{"table": table, "id": f"{hit.source}/{hit.external_id}", "label": hit.title} for hit in corpus.hits]
    texts = list(corpus.search_texts)
    vectors = embeddings.embed_library_texts(EmbeddingCorpus.EXTERNAL_INTELLIGENCE, texts, sources)
    if len(vectors) != len(texts):
        raise EvidenceIndexRefused(IntelMessage.SNAPSHOT_INCONSISTENT, rows=len(texts), vectors=len(vectors))
    hybrid = HybridIndex(texts, vectors)
    return EvidenceIndex(corpus, hybrid, embeddings, rerank, rerank_model)


log = structlog.get_logger(__name__)
RETRY_FIRST_SECONDS, RETRY_LONGEST_SECONDS = 30.0, 900.0  # a failed build's first and longest pause


class EvidenceIndexKeeper:
    """One process's evidence index."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._embeddings, self._rerank = get_embedding_model(), get_rerank_model()
        self._clock = clock
        self._index = empty_index(self._embeddings, self._rerank, get_settings().rerank_model, settled=False)
        self._lock = threading.Lock()  # guards the fields below; never held during a build or a read
        self._running: Future[EvidenceIndex] | None = None
        self._read_again = False  # a rebuild was asked for while one ran
        self._build_wanted = True  # the first build, or a failed one to try again
        self._failures = 0
        self._retry_at = self._check_at = 0.0  # when a failed build may retry; when to look at the pointer
        self._told_no_data = False  # "no data yet: run the import" is logged once per process, not per retry

    def peek_index(self) -> EvidenceIndex:
        """The index in use, starting nothing (health checks)."""
        return self._index

    def current_index(self) -> EvidenceIndex:
        """The index in use now, never waiting."""
        index, now = self._index, self._clock()
        if self._build_wanted and now >= self._retry_at:
            self._launch(read_again=False)
        elif not self._build_wanted:
            self._follow_active_snapshot(now)
        return index

    def rebuild_index(self) -> Future[EvidenceIndex]:
        """Start a rebuild in the background."""
        return self._launch(read_again=True)

    def _launch(self, *, read_again: bool) -> Future[EvidenceIndex]:
        with self._lock:
            if self._running is not None:
                self._read_again = self._read_again or read_again
                return self._running
            future: Future[EvidenceIndex] = Future()
            self._running = future
        try:
            start_thread_without_lease("evidence-index", self._run, future)
        except RuntimeError as exc:  # no thread to be had: never leave a build "running" for ever
            self._settle_failure(exc)
            future.set_exception(exc)
        return future

    def _run(self, future: Future[EvidenceIndex]) -> None:
        try:
            index = self._build_until_settled()
        except Exception as exc:  # handed to whoever waits; the index in use keeps serving
            self._settle_failure(exc)
            self._log_failure(exc)
            if self._index.snapshot_id is None:  # still the placeholder: it names the AI outage that stopped it
                outage = outage_reason(exc)
                words = str(exc) if outage else ""
                self._index = empty_index(
                    self._embeddings, self._rerank, self._index.rerank_model, outage=outage, outage_message=words
                )
            future.set_exception(exc)
        else:
            future.set_result(index)

    def _build_until_settled(self) -> EvidenceIndex:
        while True:
            index = self._build_and_swap()
            with self._lock:
                if not self._read_again:
                    self._running, self._build_wanted, self._failures = None, False, 0
                    self._told_no_data = False  # data came: should it all go, say so again
                    return index
                self._read_again = False

    def _log_failure(self, exc: Exception) -> None:
        if isinstance(exc, EvidenceIndexRefused) and exc.no_data:
            if not self._told_no_data:
                self._told_no_data = True
                log.warning(LogEvent.EXTERNAL_INTELLIGENCE_NO_DATA, action=IntelMessage.NO_DATA_YET.value)
            return
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED, error_type=type(exc).__name__)

    def _settle_failure(self, exc: Exception) -> None:
        with self._lock:
            self._running, self._read_again, self._build_wanted = None, False, True
            first_outage = self._index.snapshot_id is None and isinstance(exc, TEMPORARY_ERRORS)
            self._failures = 1 if first_outage else self._failures + 1
            pause = min(RETRY_FIRST_SECONDS * 2 ** (self._failures - 1), RETRY_LONGEST_SECONDS)
            self._retry_at = self._clock() + pause

    def _build_and_swap(self) -> EvidenceIndex:
        settings = get_settings()
        records = get_intel_record_repository().stream_current_intel_records()
        try:
            corpus = build_corpus(records, settings.embedding_model)
        except EvidenceIndexRefused:  # the sources hold nothing: a broken refresh, never an order to empty
            if self._index.snapshot_id is None:  # nothing imported yet: no evidence, not an outage
                self._index = empty_index(self._embeddings, self._rerank, settings.rerank_model, settled=True)
            raise
        current = self._index
        if corpus.checksum == current.corpus.checksum:
            return current
        index = build_index(corpus, self._embeddings, self._rerank, settings.rerank_model)
        publish_index(index)
        self._index = index  # the swap: readers see the old index or the new one, never a mix
        return index

    def _follow_active_snapshot(self, now: float) -> None:
        with self._lock:
            if now < self._check_at:
                return
            self._check_at = now + IntelLimits.SWITCH_CACHE_SECONDS
        try:
            start_thread_without_lease("evidence-check", self._rebuild_if_pointer_is_newer)
        except RuntimeError:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO)

    def _rebuild_if_pointer_is_newer(self) -> None:
        try:
            active = get_intel_snapshot_repository().get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
        except Exception:  # any failure of this read: keep serving, look again later
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO)
            return
        index = self._index
        built_at = active.get("built_at") if active else None
        newer = not isinstance(built_at, datetime) or built_at > index.built_at
        if active is not None and active.get("checksum") != index.corpus.checksum and newer:
            self._launch(read_again=False)


def publish_index(index: EvidenceIndex) -> None:
    """Store and activate the index's description (what the snapshot pointer carries)."""
    snapshots, settings = get_intel_snapshot_repository(), get_settings()
    active = snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
    if active is not None and active.get("checksum") == index.corpus.checksum:
        return
    snapshot_id = index.snapshot_id
    activated = snapshots.activate_intel_snapshot(
        {
            "snapshot_id": snapshot_id,
            "built_at": index.built_at,
            "source_versions": dict(index.corpus.source_versions),
            "counts": {"indexed": len(index.corpus.hits)},
            "checksum": index.corpus.checksum,
            "embedding_model": settings.embedding_model,  # a different model is a different index, never mixed
            "rerank_model": settings.rerank_model,
        }
    )
    event = (
        LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_ACTIVATED
        if activated
        else LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_SUPERSEDED
    )
    log.info(event, snapshot_id=snapshot_id, indexed=len(index.corpus.hits))


@singleton
def get_evidence_index_keeper() -> EvidenceIndexKeeper:
    return EvidenceIndexKeeper()
