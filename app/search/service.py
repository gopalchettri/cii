"""The library's search snapshots: one per library version, built on first use and after every library change,
shared by every caller (app/search/snapshot.py holds a snapshot and its searches)."""

import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future
from typing import Any

import structlog

from app.ai import EmbeddingModel
from app.core.constants import EMBEDDING_SOURCE_TABLE, Cache, EmbeddingCorpus, LogEvent
from app.models.library.library import (
    LibraryActor,
    LibraryControl,
    LibraryThreat,
    LibraryThreatType,
    LoadedLibraries,
)
from app.search.indexes import HybridIndex
from app.search.library_cache import LibraryCache
from app.search.snapshot import LibrarySnapshot, threat_types_of
from app.search.texts import describe_actor, describe_control, describe_threat, describe_threat_type

log = structlog.get_logger(__name__)


class LibrarySearch:
    """Hands out the current library's snapshot. A run takes one and does all its searches on it."""

    def __init__(self, library: LibraryCache, embeddings: EmbeddingModel) -> None:
        self._snapshots = _SnapshotKeeper(library, _SnapshotBuilder(embeddings).build)

    def snapshot(self, *, wait: bool = False) -> LibrarySnapshot:
        """The current library's snapshot; while a newer one builds, the older one (no search waits).
        `wait=True` (the maintenance job) waits for the current library's own snapshot."""
        return self._snapshots.get(wait=wait)


#: One corpus's last build: its texts and rows, and the index made from them.
_Corpus = tuple[list[str], list[dict[str, Any]], HybridIndex]


class _SnapshotKeeper:
    """The current library's snapshot: built on first use and after every library change, one build per
    library version shared by every caller.

    While a newer library is being built, searches keep using the older snapshot: no search waits for a
    rebuild, and a failed rebuild (logged) is tried again Cache.LIBRARY_STAMP_EVERY_SECONDS later while the
    older snapshot keeps serving. Only when there is no snapshot yet do callers wait for the first build,
    sharing its outcome, the snapshot or its error."""

    def __init__(self, library: LibraryCache, build: Callable[[LoadedLibraries], LibrarySnapshot]) -> None:
        self._library = library
        self._build = build
        self._lock = threading.Lock()  # guards the three fields below; never held during a build
        self._current: LibrarySnapshot | None = None
        self._building: tuple[LoadedLibraries, Future[LibrarySnapshot]] | None = None
        self._retry_at = 0.0

    def get(self, *, wait: bool) -> LibrarySnapshot:
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
        if current is not None and not wait:
            if builds_it and building is not None:
                threading.Thread(
                    target=self._build_and_share, args=building, name="library-indexes", daemon=True
                ).start()
            return current
        assert building is not None
        if builds_it:
            self._build_and_share(*building)
        return building[1].result()

    def _build_and_share(self, library: LoadedLibraries, outcome: Future[LibrarySnapshot]) -> None:
        try:
            snapshot = self._build(library)
        except BaseException as exc:  # noqa: BLE001 — handed to every waiting caller, raised by result()
            outcome.set_exception(exc)
            if not isinstance(exc, Exception):
                # An interrupt still ends this thread; its waiting callers got it instead of waiting for ever.
                raise
            self._retry_at = time.monotonic() + Cache.LIBRARY_STAMP_EVERY_SECONDS
            log.warning(LogEvent.LIBRARY_INDEXES_BUILD_FAILED, error=str(exc), exc_info=True)
        else:
            # Kept only while it is still the current library: a slow build of an older version must never
            # replace a newer snapshot (its callers still get the snapshot they asked for).
            if library is self._library.get_loaded_libraries():
                self._current = snapshot
            outcome.set_result(snapshot)
        finally:
            with self._lock:
                if self._building is not None and self._building[1] is outcome:
                    self._building = None


class _SnapshotBuilder:
    """Builds one library version's snapshot, corpus by corpus. A corpus whose texts and rows did not
    change keeps its index: no MongoDB read, no AI call (an edit to one table rebuilds one corpus)."""

    def __init__(self, embeddings: EmbeddingModel) -> None:
        self._embeddings = embeddings
        self._corpora: dict[EmbeddingCorpus, _Corpus] = {}

    def build(self, library: LoadedLibraries) -> LibrarySnapshot:
        threats, actors = library.threat_library.threats, library.threat_library.actors
        controls, threat_types = library.control_library, threat_types_of(library.threat_library)
        indexes = {
            EmbeddingCorpus.THREAT: self._index(
                EmbeddingCorpus.THREAT, threats, describe_threat, _identify_threat
            ),
            EmbeddingCorpus.CONTROL: self._index(
                EmbeddingCorpus.CONTROL, controls, describe_control, _identify_control
            ),
            EmbeddingCorpus.THREAT_ACTOR: self._index(
                EmbeddingCorpus.THREAT_ACTOR, actors, describe_actor, _identify_actor
            ),
            EmbeddingCorpus.THREAT_TYPE: self._index(
                EmbeddingCorpus.THREAT_TYPE, threat_types, describe_threat_type, _identify_type
            ),
        }
        counts = {"threats": len(threats), "controls": len(controls), "actors": len(actors)}
        log.info(LogEvent.LIBRARY_INDEXES_BUILT, **counts, threat_types=len(threat_types))
        return LibrarySnapshot(library, self._embeddings, indexes, threat_types)

    def _index[Row](
        self,
        corpus: EmbeddingCorpus,
        rows: Sequence[Row],
        describe: Callable[[Row], str],
        identify: Callable[[Row], tuple[int, str]],
    ) -> HybridIndex:
        """One corpus embedded (each vector stored with the rows it comes from) and indexed; the previous
        index again when the corpus's texts and rows are unchanged (an edit to one table rebuilds one)."""
        texts = [describe(row) for row in rows]
        table = EMBEDDING_SOURCE_TABLE[corpus]
        sources = [{"table": table, "id": row_id, "label": label} for row_id, label in map(identify, rows)]
        previous = self._corpora.get(corpus)
        if previous is not None and previous[0] == texts and previous[1] == sources:
            return previous[2]
        vectors = self._embeddings.embed_library_texts(corpus, texts, sources)
        index = HybridIndex(texts, vectors)
        self._corpora[corpus] = (texts, sources, index)
        return index


def _identify_threat(threat: LibraryThreat) -> tuple[int, str]:
    return threat.catalogue_id, threat.name


def _identify_control(control: LibraryControl) -> tuple[int, str]:
    return control.control_id, control.code


def _identify_actor(actor: LibraryActor) -> tuple[int, str]:
    return actor.actor_id, actor.name


def _identify_type(threat_type: LibraryThreatType) -> tuple[int, str]:
    return threat_type.type_id, threat_type.name
