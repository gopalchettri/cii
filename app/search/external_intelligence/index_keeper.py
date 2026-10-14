"""The evidence index in use: built in the background, swapped in whole, never lost to a failed build.

A request never waits for a build: until the first one is done the index is empty and finds nothing. A rebuild
reads the approved sources' current records, refuses an empty corpus, skips a corpus whose checksum is the one
in use, builds the new index off to the side, stores and activates its description and only then swaps it in
with one assignment. One rebuild runs at a time; a request made while one runs makes it read the records once
more when it ends, so a refresh that finished mid-build is never missed. A failed build keeps the old index
and is tried again after a growing pause. Every process holds its own index and follows the active snapshot
pointer (at most every IntelLimits.SWITCH_CACHE_SECONDS, in the background)."""

import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime

import structlog

from app.ai import EmbeddingModel, RerankModel, get_embedding_model, get_rerank_model
from app.core.config import get_settings
from app.core.constants import Dependency, IntelLimits, LogEvent
from app.core.database import get_mongodb
from app.core.singletons import singleton
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.search.external_intelligence.evidence_index import EvidenceIndex, build_index, empty_index
from app.search.external_intelligence.index_refused import EvidenceIndexRefused
from app.search.external_intelligence.intelligence_metrics import SNAPSHOT_AGE_SECONDS
from app.search.external_intelligence.snapshot_publisher import SnapshotPublisher

log = structlog.get_logger(__name__)
RETRY_FIRST_SECONDS, RETRY_LONGEST_SECONDS = 30.0, 900.0  # the pause after a failed build, doubled each time


class EvidenceIndexKeeper:
    def __init__(  # noqa: PLR0913 - the three stores, the two models, their names and a clock
        self,
        record_store: IntelRecordStore,
        snapshot_store: SnapshotPointerStore,
        feed_store: FeedStatusStore,
        embeddings: EmbeddingModel,
        rerank: RerankModel,
        embedding_model: str = "",
        rerank_model: str = "",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._records, self._snapshots, self._feeds = record_store, snapshot_store, feed_store
        self._embeddings, self._rerank = embeddings, rerank
        self._embedding_model, self._rerank_model = embedding_model, rerank_model
        self._builder = CorpusBuilder(embedding_model)
        self._publisher = SnapshotPublisher(snapshot_store, embedding_model, rerank_model)
        self._clock = clock
        self._index = empty_index(embeddings, rerank, rerank_model)
        self._lock = threading.Lock()  # guards the fields below; never held during a build or a read
        self._running: Future[EvidenceIndex] | None = None
        self._again = False
        self._wanted = True  # a build is wanted: the first one, or a failed one to try again
        self._failures = 0
        self._retry_at = 0.0
        self._check_at = 0.0

    def peek_index(self) -> EvidenceIndex:
        """The index in use, starting nothing (health checks)."""
        return self._index

    def current_index(self) -> EvidenceIndex:
        """The index in use now; never waits. Empty until the first build is done."""
        index, now = self._index, self._clock()
        if self._wanted and now >= self._retry_at:
            self._launch(again=False)
        elif not self._wanted:
            self._follow_active_snapshot(now)
        return index

    def rebuild_index(self) -> Future[EvidenceIndex]:
        """Starts a rebuild in the background (or joins the one running, which then reads the records once
        more); the future gives the index in use afterwards, or the error that kept the old one."""
        return self._launch(again=True)

    def snapshot_age_seconds(self) -> float:
        """NaN while there is no index: the gauge shows nothing rather than a made-up age."""
        index = self._index
        return (datetime.now(UTC) - index.built_at).total_seconds() if index.has_records else float("nan")

    def _launch(self, *, again: bool) -> Future[EvidenceIndex]:
        with self._lock:
            if self._running is not None:
                self._again = self._again or again
                return self._running
            future: Future[EvidenceIndex] = Future()
            self._running = future
        try:
            threading.Thread(target=self._run, args=(future,), name="evidence-index", daemon=True).start()
        except RuntimeError as exc:  # no thread to be had: never leave a build "running" for ever
            self._settle_failure()
            future.set_exception(exc)
        return future

    def _run(self, future: Future[EvidenceIndex]) -> None:
        try:
            index = self._build_until_settled()
        except Exception as exc:  # noqa: BLE001 - handed to whoever waits; the index in use keeps serving
            self._settle_failure()
            log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED, error=type(exc).__name__)
            future.set_exception(exc)
        else:
            future.set_result(index)

    def _build_until_settled(self) -> EvidenceIndex:
        while True:
            index = self._build_and_swap()
            with self._lock:
                if not self._again:
                    self._running, self._wanted, self._failures = None, False, 0
                    return index
                self._again = False

    def _settle_failure(self) -> None:
        with self._lock:
            self._running, self._again, self._wanted = None, False, True
            self._failures += 1
            pause = min(RETRY_FIRST_SECONDS * 2 ** (self._failures - 1), RETRY_LONGEST_SECONDS)
            self._retry_at = self._clock() + pause

    def _build_and_swap(self) -> EvidenceIndex:
        approved = self._feeds.list_approved_sources()
        try:
            corpus = self._builder.build_corpus(self._records.stream_current_records(approved))
        except EvidenceIndexRefused:
            if approved:  # sources are approved but hold nothing: a broken refresh, not an order to empty
                raise
            corpus = EvidenceCorpus((), (), "")  # every source revoked: nothing may stay searchable
        current = self._index
        if corpus.checksum == current.corpus.checksum:
            return current
        index = current.reuse_for(corpus) or self._build(corpus)
        self._publisher.publish_index(index)
        self._index = index  # the swap: readers see the old index or the new one, never a mix
        return index

    def _build(self, corpus: EvidenceCorpus) -> EvidenceIndex:
        if not corpus.hits:
            return empty_index(self._embeddings, self._rerank, self._rerank_model)
        return build_index(corpus, self._embeddings, self._rerank, self._rerank_model)

    def _follow_active_snapshot(self, now: float) -> None:
        with self._lock:
            if now < self._check_at:
                return
            self._check_at = now + IntelLimits.SWITCH_CACHE_SECONDS
        try:
            threading.Thread(
                target=self._rebuild_if_pointer_is_newer, name="evidence-check", daemon=True
            ).start()
        except RuntimeError:
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO)

    def _rebuild_if_pointer_is_newer(self) -> None:
        """One small read; a store outage leaves the index in use serving."""
        try:
            active = self._snapshots.read_active_snapshot()
        except Exception:  # noqa: BLE001 - any failure of this read: keep serving, look again later
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO)
            return
        index = self._index
        built_at = active.get("built_at") if active else None
        newer = not isinstance(built_at, datetime) or built_at > index.built_at
        if active is not None and active.get("checksum") != index.corpus.checksum and newer:
            self._launch(again=False)


@singleton
def get_evidence_index_keeper() -> EvidenceIndexKeeper:
    settings, db = get_settings(), get_mongodb()
    keeper = EvidenceIndexKeeper(
        IntelRecordStore(db),
        SnapshotPointerStore(db),
        FeedStatusStore(db),
        get_embedding_model(),
        get_rerank_model(),
        settings.embedding_model,
        settings.rerank_model,
    )
    SNAPSHOT_AGE_SECONDS.set_function(keeper.snapshot_age_seconds)
    return keeper
