"""The evidence index in use: built in the background, swapped in whole, never lost to a failed build, and
published as the active snapshot that every process follows."""

import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime

import structlog

from app.ai import EmbeddingModel, RerankModel
from app.ai.common import outage_reason
from app.core.constants import Dependency, IntelDocId, IntelLimits, IntelMessage, LogEvent
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.data_access.external_intelligence.intel_snapshot_repository import IntelSnapshotRepository
from app.models.external_intelligence.evidence_corpus import SnapshotDescription
from app.models.external_intelligence.source_health import sources_in_registry_order
from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import (
    EMPTY_SNAPSHOT_ID,
    EvidenceIndex,
    EvidenceIndexRefused,
    after_failed_build,
    build_index,
    empty_index,
)

log = structlog.get_logger(__name__)
RETRY_FIRST_SECONDS, RETRY_LONGEST_SECONDS = 30.0, 900.0  # the pause after a failed build, doubled each time


class EvidenceIndexKeeper:
    """One process's evidence index; a request never waits for a build, and one build runs at a time."""

    def __init__(
        self,
        record_store: IntelRecordRepository,
        snapshot_store: IntelSnapshotRepository,
        feed_store: IntelFeedRepository,
        embeddings: EmbeddingModel,
        rerank: RerankModel,
        embedding_model: str = "",
        rerank_model: str = "",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._records, self._snapshots, self._feeds = record_store, snapshot_store, feed_store
        self._embeddings, self._rerank = embeddings, rerank
        self._embedding_model, self._rerank_model = embedding_model, rerank_model
        self._clock = clock
        self._index = empty_index(embeddings, rerank, rerank_model, settled=False)
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
        """The index in use now, never waiting; starts a wanted build, or a look at the active snapshot."""
        index, now = self._index, self._clock()
        if self._build_wanted and now >= self._retry_at:
            self._launch(read_again=False)
        elif not self._build_wanted:
            self._follow_active_snapshot(now)
        return index

    def rebuild_index(self) -> Future[EvidenceIndex]:
        """Start a rebuild in the background; its future gives the index in use, or the error that kept it."""
        return self._launch(read_again=True)

    def snapshot_age_seconds(self) -> float:
        """Seconds since the index in use was built; NaN while there is none (the gauge shows nothing)."""
        index = self._index
        return (datetime.now(UTC) - index.built_at).total_seconds() if index.has_records else float("nan")

    def _launch(self, *, read_again: bool) -> Future[EvidenceIndex]:
        """Start the build thread, or join the build running (asking it to read again when `read_again`)."""
        with self._lock:
            if self._running is not None:
                self._read_again = self._read_again or read_again
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
        """The build thread: build until settled and hand the index, or the error, to whoever waits."""
        try:
            index = self._build_until_settled()
        except Exception as exc:  # handed to whoever waits; the index in use keeps serving
            self._settle_failure()
            self._log_failure(exc)
            self._index = after_failed_build(self._index, outage_reason(exc))
            future.set_exception(exc)
        else:
            future.set_result(index)

    def _build_until_settled(self) -> EvidenceIndex:
        """Build and swap, again while a rebuild was asked for meanwhile (a refresh that ended mid-build)."""
        while True:
            index = self._build_and_swap()
            with self._lock:
                if not self._read_again:
                    self._running, self._build_wanted, self._failures = None, False, 0
                    self._told_no_data = False  # data came: should it all go, say so again
                    return index
                self._read_again = False

    def _log_failure(self, exc: Exception) -> None:
        """Log a failed build; with nothing imported yet, one line per process names the import to run."""
        if isinstance(exc, EvidenceIndexRefused) and exc.no_data:
            if not self._told_no_data:
                self._told_no_data = True
                log.warning(LogEvent.EXTERNAL_INTELLIGENCE_NO_DATA, action=IntelMessage.NO_DATA_YET.value)
            return
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED, error=type(exc).__name__)

    def _settle_failure(self) -> None:
        """End a failed build: the build is wanted again after a pause that doubles per failure."""
        with self._lock:
            self._running, self._read_again, self._build_wanted = None, False, True
            self._failures += 1
            pause = min(RETRY_FIRST_SECONDS * 2 ** (self._failures - 1), RETRY_LONGEST_SECONDS)
            self._retry_at = self._clock() + pause

    def _build_and_swap(self) -> EvidenceIndex:
        """Build the approved records' index aside (unless in use already), publish it and swap it in."""
        approved = sources_in_registry_order(self._feeds.list(["_id"], sources=True, approved=True))
        empty = empty_index(self._embeddings, self._rerank, self._rerank_model, settled=True)
        try:
            corpus = build_corpus(self._records.stream_current_intel_records(approved), self._embedding_model)
        except EvidenceIndexRefused:
            if approved:  # sources are approved but hold nothing: a broken refresh, not an order to empty
                if self._index.snapshot_id is None:  # nothing imported yet: no evidence, not an outage
                    self._index = empty
                raise
            corpus = empty.corpus  # every source revoked: nothing may stay searchable
        current = self._index
        if corpus.checksum == current.corpus.checksum and current.snapshot_id is not None:
            return current  # never the placeholder: it stands for no build, not for an empty corpus
        index = current.reuse_for(corpus) if corpus.hits else empty
        index = index or build_index(corpus, self._embeddings, self._rerank, self._rerank_model)
        publish_index(self._snapshots, index, self._embedding_model, self._rerank_model)
        self._index = index  # the swap: readers see the old index or the new one, never a mix
        return index

    def _follow_active_snapshot(self, now: float) -> None:
        """At most every SWITCH_CACHE_SECONDS, look at the active snapshot from a background thread."""
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
        """Start a build when the active snapshot is a newer corpus; an outage keeps the index serving."""
        try:
            active = self._snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
        except Exception:  # any failure of this read: keep serving, look again later
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO)
            return
        index = self._index
        built_at = active.get("built_at") if active else None
        newer = not isinstance(built_at, datetime) or built_at > index.built_at
        if active is not None and active.get("checksum") != index.corpus.checksum and newer:
            self._launch(read_again=False)


def publish_index(
    snapshots: IntelSnapshotRepository, index: EvidenceIndex, embedding_model: str, rerank_model: str
) -> None:
    """Store and activate the index's description, unless another process already published this corpus. An
    empty index is published too, so other processes drop what was revoked; the store never moves the pointer
    to an older build."""
    active = snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
    if active is not None and active.get("checksum") == index.corpus.checksum:
        return
    description = SnapshotDescription(
        index.snapshot_id or EMPTY_SNAPSHOT_ID,
        index.built_at,
        index.source_versions,
        index.corpus.counts(),
        index.corpus.checksum,
        embedding_model,
        rerank_model,
    )
    snapshots.save({**description.as_doc(), "_id": description.snapshot_id})
    activated = snapshots.activate_intel_snapshot(description.snapshot_id)
    event = (
        LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_ACTIVATED
        if activated
        else LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_SUPERSEDED
    )
    log.info(event, snapshot_id=description.snapshot_id, indexed=len(index.corpus.hits))
