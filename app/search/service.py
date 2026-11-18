"""The library's search snapshots: one per library version, built on first use and after every change."""

import threading
import time
from concurrent.futures import Future
from typing import Any

import structlog

from app.ai import EmbeddingModel
from app.ai.embeddings import get_embedding_model
from app.core.constants import EMBEDDING_SOURCE_TABLE, Cache, EmbeddingCorpus, LogEvent
from app.core.lease_signal import start_thread_without_lease, wait_while_leased
from app.core.singletons import singleton
from app.schemas.library import LoadedLibraries
from app.search.indexes import HybridIndex
from app.search.library_cache import LibraryCache, get_library_cache
from app.search.snapshot import LibrarySnapshot, describe_control, threat_types_of

log = structlog.get_logger(__name__)


#: One corpus's last build: its texts and sources, and the index made from them.
_Corpus = tuple[list[str], list[dict[str, Any]], HybridIndex]


class LibrarySearch:
    """The current library's snapshot: one build per library version, shared by every caller."""

    def __init__(self, library: LibraryCache, embeddings: EmbeddingModel) -> None:
        self._library, self._embeddings = library, embeddings
        self._lock = threading.Lock()  # guards the three fields below; never held during a build
        self._current: LibrarySnapshot | None = None
        self._building: tuple[LoadedLibraries, Future[LibrarySnapshot]] | None = None
        self._retry_at = 0.0
        self._corpora: dict[EmbeddingCorpus, _Corpus] = {}

    def snapshot(self, *, wait: bool = False) -> LibrarySnapshot:
        """The current library's snapshot, else the older one while it builds; `wait=True` waits for its own."""
        library = self._library.get_loaded_libraries()
        current = self._current
        if current is not None and current.library is library:
            return current
        with self._lock:
            current, building = self._current, self._building
            if current is not None and current.library is library:  # built while this caller waited
                return current
            builds_it = (building is None or building[0] is not library) and (
                current is None or wait or time.monotonic() >= self._retry_at
            )
            if builds_it:
                building = self._building = (library, Future())
        # The build is every waiter's: under no caller's lease, so one job's cancel never fails the others.
        if builds_it and building is not None:
            start_thread_without_lease("library-indexes", self._build_and_share, *building)
        if current is not None and not wait:
            return current
        assert building is not None
        return wait_while_leased(building[1])  # a waiter's own cancel ends its wait, not the build

    def _build_and_share(self, library: LoadedLibraries, outcome: Future[LibrarySnapshot]) -> None:
        try:
            snapshot = self._build(library)
        except BaseException as exc:  # noqa: BLE001 — an interrupt too: no waiting caller waits for ever
            if isinstance(exc, Exception):
                self._retry_at = time.monotonic() + Cache.LIBRARY_STAMP_EVERY_SECONDS
                log.warning(LogEvent.LIBRARY_INDEXES_BUILD_FAILED, message=str(exc), exc_info=True)
            self._forget_build(outcome)
            outcome.set_exception(exc)  # raised by every caller's wait
        else:
            # Kept only while it is still the current library: a slow build of an older version must never
            # replace a newer snapshot (its callers still get the snapshot they asked for).
            if library is self._library.get_loaded_libraries():
                self._current = snapshot
            self._forget_build(outcome)
            outcome.set_result(snapshot)

    def _forget_build(self, outcome: Future[LibrarySnapshot]) -> None:
        with self._lock:
            if self._building is not None and self._building[1] is outcome:
                self._building = None

    def _build(self, library: LoadedLibraries) -> LibrarySnapshot:
        threats, actors = library.threat_library.threats, library.threat_library.actors
        controls, threat_types = library.control_library, threat_types_of(library.threat_library)
        # v1's texts, so v1 and v2 rank alike, each with its source's (id, label)
        entries = {
            EmbeddingCorpus.THREAT: [(f"{row.type_name}: {row.name}", row.catalogue_id, row.name) for row in threats],
            EmbeddingCorpus.CONTROL: [(describe_control(row), row.control_id, row.code) for row in controls],
            EmbeddingCorpus.THREAT_ACTOR: [(row.name, row.actor_id, row.name) for row in actors],
            EmbeddingCorpus.THREAT_TYPE: [(row.name, row.type_id, row.name) for row in threat_types],
        }
        indexes = {corpus: self._index(corpus, rows) for corpus, rows in entries.items()}
        log.info(LogEvent.LIBRARY_INDEXES_BUILT)
        return LibrarySnapshot(library, self._embeddings, indexes, threat_types)

    def _index(self, corpus: EmbeddingCorpus, entries: list[tuple[str, int, str]]) -> HybridIndex:
        texts = [text for text, _, _ in entries]
        table = EMBEDDING_SOURCE_TABLE[corpus]
        sources = [{"table": table, "id": row_id, "label": label} for _, row_id, label in entries]
        previous = self._corpora.get(corpus)
        if previous is not None and previous[0] == texts and previous[1] == sources:
            return previous[2]
        index = HybridIndex(texts, self._embeddings.embed_library_texts(corpus, texts, sources))
        self._corpora[corpus] = (texts, sources, index)
        return index


@singleton
def get_library_search() -> LibrarySearch:
    return LibrarySearch(get_library_cache(), get_embedding_model())
