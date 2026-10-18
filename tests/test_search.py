"""Library search gives v1's ranking (BM25 + vectors + rank fusion), with scopes and exact names."""

import math
import random
import threading
import time
from collections import Counter
from collections.abc import Callable
from types import SimpleNamespace

import numpy as np
import pytest

from app.core.constants import ErrorMessage, StrideCategory
from app.core.exceptions import Unavailable
from app.models.library.library import (
    LibraryActor,
    LibraryControl,
    LibraryThreat,
    LibraryThreatType,
    ThreatLibrary,
)
from app.search.indexes import HybridIndex, KeywordIndex, fuse_by_rank, tokenize
from app.search.service import LibrarySearch
from tests.fakes import FakeEmbeddings


def v1_bm25_scores(query_tokens: list[str], docs_tokens: list[list[str]]) -> list[float]:
    """v1's pipeline/hybrid_search.bm25_scores, copied verbatim as the reference."""
    k1, b = 1.5, 0.75
    n_docs = len(docs_tokens)
    avgdl = sum(len(d) for d in docs_tokens) / n_docs
    df: Counter[str] = Counter()
    for d in docs_tokens:
        df.update(set(d))
    scores = []
    for d in docs_tokens:
        tf, dl, s = Counter(d), len(d), 0.0
        for t in query_tokens:
            f = tf.get(t)
            if f:
                idf = math.log(1.0 + (n_docs - df[t] + 0.5) / (df[t] + 0.5))
                s += idf * (f * (k1 + 1.0)) / (f + k1 * (1.0 - b + b * dl / avgdl))
        scores.append(s)
    return scores


def test_keyword_scores_equal_v1_on_random_corpora() -> None:
    words = ["ransomware", "phishing", "scada", "plc", "backup", "s7-1500", "insider", "ddos", "the", "of"]
    generator = random.Random(7)  # noqa: S311 — reproducible test data, not security
    for _ in range(25):
        texts = [" ".join(generator.choices(words, k=generator.randint(1, 9))) for _ in range(30)]
        query = " ".join(generator.choices(words, k=4))
        expected = v1_bm25_scores(tokenize(query), [tokenize(text) for text in texts])
        assert np.allclose(KeywordIndex(texts).score(query), expected)


def test_rank_fusion_equals_v1() -> None:
    rankings = [[3, 1, 2], [1, 4]]
    v1 = {3: 1 / 61, 1: 1 / 62 + 1 / 61, 2: 1 / 63, 4: 1 / 62}
    assert fuse_by_rank(rankings) == sorted(v1.items(), key=lambda item: (-item[1], item[0]))


def _unit(*values: float) -> np.ndarray:
    vector = np.array(values, dtype=np.float32)
    return vector / np.linalg.norm(vector)


def test_a_rare_exact_word_is_found_even_when_the_vectors_miss_it() -> None:
    texts = ["Siemens S7-1500 firmware tampering", "Generic malware infection", "Phishing email"]
    vectors = np.vstack([_unit(0, 1), _unit(1, 0), _unit(1, 0.1)])  # the vector leg prefers the other two
    hits = HybridIndex(texts, vectors).search("S7-1500 attack", _unit(1, 0), top_k=3)
    assert 0 in [hit.position for hit in hits]


def test_an_exact_name_comes_first_and_a_scope_applies_before_the_cut() -> None:
    texts = ["Ransomware", "Ransomware on backups", "Ransomware via phishing"]
    vectors = np.vstack([_unit(0, 1), _unit(1, 0), _unit(1, 0)])
    index = HybridIndex(texts, vectors)
    assert index.search("ransomware!", _unit(1, 0), top_k=3)[0].position == 0
    only_last = np.array([False, False, True])
    assert [hit.position for hit in index.search("ransomware", _unit(1, 0), 1, only_last)] == [2]


def test_threats_are_searched_within_their_category_and_controls_and_actors_in_full() -> None:
    def threat(catalogue_id: int, name: str, category: StrideCategory) -> LibraryThreat:
        return LibraryThreat(catalogue_id, name, 1, "Malware", (category,), ())

    threats = (
        threat(1, "Ransomware encrypts backup servers", StrideCategory.TAMPERING),
        threat(2, "Ransomware exfiltrates data", StrideCategory.INFORMATION_DISCLOSURE),
        threat(3, "Insider deletes logs", StrideCategory.REPUDIATION),
    )
    actors = (LibraryActor(1, "Ransomware gang"), LibraryActor(2, "Malicious insider"))
    controls = (
        LibraryControl(1, "C-1", None, None, "Offline backup", "Keep an offline backup copy"),
        LibraryControl(2, "C-2", None, None, "Phishing training", None),
    )
    library = SimpleNamespace(threat_library=ThreatLibrary(threats, actors), control_library=controls)
    embeddings = FakeEmbeddings()
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), embeddings)  # type: ignore[arg-type]

    (tampering,) = search.snapshot().find_threats([("ransomware attack", StrideCategory.TAMPERING)], top_k=5)
    assert [found.catalogue_id for found, _ in tampering] == [1]  # the disclosure one is out of scope
    (controls_found,) = search.snapshot().find_controls(["ransomware hit the backup"], top_k=1)
    assert controls_found[0][0].code == "C-1"
    (actors_found,) = search.snapshot().find_actors(["insider threat"], top_k=1)
    assert actors_found[0][0].name == "Malicious insider"
    (types_found,) = search.snapshot().find_threat_types(["malware"], top_k=1)
    assert types_found[0][0] == LibraryThreatType(1, "Malware")  # one type, though three threats use it
    assert search.snapshot() is search.snapshot()  # built once per library version
    # Each corpus is embedded on its own, with the rows it comes from; then the four search queries.
    assert embeddings.calls == ["threat", "control", "threat_actor", "threat_type"] + ["query"] * 4
    assert embeddings.sources["control"][0] == {"table": "Control_Library", "id": 1, "label": "C-1"}


def test_the_vector_leg_keeps_only_close_rows_when_any_are_close_else_the_best_anyway() -> None:
    index = HybridIndex(
        ["alpha", "beta", "gamma"], np.vstack([_unit(1, 0, 0), _unit(0, 1, 0), _unit(0, 0, 1)])
    )
    close = index.search("unrelated words", _unit(1, 0.2, 0), top_k=3)
    assert [hit.position for hit in close] == [0]  # cosine 0.98 passes the 0.60 floor; 0.20 does not
    nothing_close = index.search("unrelated words", _unit(0.5, 0.4, -1), top_k=3)
    assert [hit.position for hit in nothing_close] == [
        0,
        1,
    ]  # none reaches 0.60 (0.42, 0.34): best ones count


def _library(control_name: str) -> SimpleNamespace:
    control = LibraryControl(1, "C-1", None, None, control_name, None)
    return SimpleNamespace(threat_library=ThreatLibrary((), ()), control_library=(control,))


def test_callers_during_a_build_share_its_failure_instead_of_repeating_it() -> None:
    """Before: each caller waiting on the lock repeated the failing build in turn, so with the AI provider
    down the fifth caller waited five timeouts."""
    builds: list[int] = []
    release = threading.Event()

    class ProviderDown:
        def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
            builds.append(1)
            release.wait(5)
            raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    library = _library("Offline backup")
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), ProviderDown())  # type: ignore[arg-type]
    failures: list[Exception] = []

    def call() -> None:
        try:
            search.snapshot()
        except Unavailable as exc:
            failures.append(exc)

    threads = [threading.Thread(target=call) for _ in range(5)]
    for thread in threads:
        thread.start()
    time.sleep(0.3)  # every caller is now waiting on the one build
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(builds) == 1 and len(failures) == 5
    with pytest.raises(Unavailable):
        search.snapshot()  # a later call is a new attempt
    assert len(builds) == 2


def test_an_interrupted_build_still_answers_the_callers_waiting_on_it() -> None:
    """Before: only an Exception was handed to the waiting callers. An interrupt (KeyboardInterrupt,
    SystemExit) ended the building thread and left every caller waiting on its build blocked for ever."""

    class Interrupted(BaseException):
        pass

    started, release = threading.Event(), threading.Event()

    class Interrupting:
        def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
            started.set()
            release.wait(5)
            raise Interrupted

    library = _library("Offline backup")
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), Interrupting())  # type: ignore[arg-type]
    outcomes: list[str] = []

    def call() -> None:
        try:
            search.snapshot()
        except Interrupted:
            outcomes.append("interrupted")

    builder = threading.Thread(target=call, daemon=True)
    builder.start()
    assert started.wait(5)
    waiter = threading.Thread(target=call, daemon=True)  # daemon: a regression must not hang pytest's exit
    waiter.start()
    time.sleep(0.2)  # the second caller now waits on the first one's build
    release.set()
    builder.join(5)
    waiter.join(5)
    assert not waiter.is_alive() and outcomes == ["interrupted", "interrupted"]


def test_a_slow_build_of_an_older_library_never_replaces_the_newer_one() -> None:
    """Before: a caller that saw the old library rebuilt it after the new one was built and installed it over
    the newer indexes."""
    old, new = _library("Old backup"), _library("New backup")
    current = [old]
    old_build_started, release_old = threading.Event(), threading.Event()

    class SlowForOld(FakeEmbeddings):
        def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
            if "Old backup: " in texts:
                old_build_started.set()
                release_old.wait(5)
            return super().embed_library_texts(corpus, texts, sources)

    embeddings = SlowForOld()
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: current[0]), embeddings)  # type: ignore[arg-type]
    got_old: list[object] = []
    slow = threading.Thread(target=lambda: got_old.append(search.snapshot()))
    slow.start()
    assert old_build_started.wait(5)
    current[0] = new
    assert search.snapshot().library is new
    release_old.set()
    slow.join(5)
    assert got_old[0].library is old  # type: ignore[attr-defined]  # its caller still got what it asked for
    assert search.snapshot().library is new
    assert (
        embeddings.calls.count("control") == 2
    )  # old and new built once each: the newer were never replaced


def _until(condition: Callable[[], bool], seconds: float = 5) -> bool:
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.01)
    return condition()


def _library_with(control_name: str) -> SimpleNamespace:
    control = LibraryControl(1, "C-1", None, None, control_name, None)
    threat_library = ThreatLibrary((), (LibraryActor(1, "Ransomware gang"),))
    return SimpleNamespace(threat_library=threat_library, control_library=(control,))


def test_a_rebuild_never_makes_a_search_wait_and_only_a_changed_corpus_is_embedded_again() -> None:
    """Before: after any library edit every search in every process waited for the whole rebuild (all four
    corpora read and embedded again), and a rebuild that kept failing failed every search."""
    old, new = _library_with("Old backup"), _library_with("New backup")
    current, release = [old], threading.Event()

    class SlowForNew(FakeEmbeddings):
        def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
            if "New backup: " in texts:
                release.wait(5)
            return super().embed_library_texts(corpus, texts, sources)

    embeddings = SlowForNew()
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: current[0]), embeddings)  # type: ignore[arg-type]
    assert search.snapshot().library is old
    current[0] = new
    started = time.monotonic()
    assert search.snapshot().library is old  # the older snapshot answers at once while the new one builds
    assert time.monotonic() - started < 1
    release.set()
    assert _until(lambda: search.snapshot().library is new)
    assert embeddings.calls.count("control") == 2 and embeddings.calls.count("threat_actor") == 1


def test_a_failed_rebuild_keeps_the_older_snapshot_and_is_tried_again_later() -> None:
    old, new = _library_with("Old backup"), _library_with("New backup")
    current, attempts = [old], []

    class DownForNew(FakeEmbeddings):
        def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
            if "New backup: " in texts:
                attempts.append(1)
                raise Unavailable(ErrorMessage.AI_UNREACHABLE)
            return super().embed_library_texts(corpus, texts, sources)

    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: current[0]), DownForNew())  # type: ignore[arg-type]
    search.snapshot()
    current[0] = new
    assert search.snapshot().library is old
    assert _until(lambda: attempts == [1] and search._snapshots._building is None)
    assert search.snapshot().library is old and attempts == [1]  # no new attempt within the pause
    search._snapshots._retry_at = 0.0  # the pause is over
    search.snapshot()
    assert _until(lambda: attempts == [1, 1])
    with pytest.raises(Unavailable):
        search.snapshot(wait=True)  # the maintenance job waits, so it fails and is counted
