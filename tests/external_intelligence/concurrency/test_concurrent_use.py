"""Many users at once: no cross-talk between requests, results equal to serial runs, the rerank gate never
exceeded, a rebuild during searches keeps serving the old index, the switch consistent during flips."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.config import get_settings
from app.core.constants import AssetType
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import RerankGate
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.external_intelligence.switch import ExternalIntelligenceSwitch
from tests.external_intelligence.evidence_fakes import (
    ALL_SOURCES,
    CountingRerank,
    MemoryFeeds,
    MemoryPointer,
    MemoryRecords,
    ScoredBy,
    TextEmbeddings,
    request_of,
    technique_doc,
    vulnerability_doc,
)
from tests.external_intelligence.switch.test_switch import MemoryFlags

USERS, BATCHES = 8, 6
WORDS = ("ransomware", "phishing", "backup", "insider", "flood")


def _docs() -> list[dict]:
    docs = [technique_doc(f"T{n}", "IT", f"{WORDS[n % 5]} technique number {n}") for n in range(1, 21)]
    return docs + [technique_doc(f"T{n}", "OT", f"{WORDS[n % 5]} ot technique {n}") for n in range(21, 31)]


def _keeper(docs, rerank=None):
    keeper = EvidenceIndexKeeper(
        MemoryRecords(docs), MemoryPointer(), MemoryFeeds(), TextEmbeddings(), rerank or ScoredBy(), "m", "r"
    )
    keeper.rebuild_index().result(10)
    return keeper


def _requests(user: int) -> list:
    word = WORDS[user % 5]
    types = {"OT", AssetType.IT_OT} if user % 2 else {"IT", AssetType.IT_OT}
    return [request_of(f"Threat: {word} number {user} part {part}", types) for part in range(4)]


def _shape(results) -> list[tuple]:
    return [(tuple(e.ref for e in r.evidence), r.search.query, r.search.asset_types) for r in results]


def test_many_users_get_exactly_what_a_serial_run_gives_and_never_each_others_evidence() -> None:
    keeper = _keeper(_docs())
    finder = EvidenceFinder(keeper.current_index, 1.0, gate=RerankGate(3))
    serial = {
        user: _shape(finder.find_evidence(_requests(user), stale=False, approved=ALL_SOURCES)[0])
        for user in range(USERS)
    }

    def work(user: int) -> list:
        return [
            _shape(finder.find_evidence(_requests(user), stale=False, approved=ALL_SOURCES)[0])
            for _ in range(BATCHES)
        ]

    with ThreadPoolExecutor(USERS) as pool:
        concurrent = list(pool.map(work, range(USERS)))
    for user, runs in enumerate(concurrent):
        assert all(run == serial[user] for run in runs)
        numbers = {int(ref[1:]) for run in runs for refs, _, _ in run for ref in refs}
        assert numbers and all((number > 20) == (user % 2 == 1) for number in numbers)  # only its own types
        assert all(
            query.endswith(tuple(f"number {user} part {p}" for p in range(4)))
            for run in runs
            for _, query, _ in run
        )


def test_the_gate_is_never_exceeded_by_many_batches_at_once() -> None:
    rerank = CountingRerank(0.01)
    keeper = _keeper(_docs(), rerank)
    finder = EvidenceFinder(keeper.current_index, 1.0, gate=RerankGate(3))
    with ThreadPoolExecutor(USERS) as pool:
        list(
            pool.map(
                lambda user: finder.find_evidence(_requests(user), stale=False, approved=ALL_SOURCES),
                range(USERS * 2),
            )
        )
    assert 1 <= rerank.most <= 3


def test_a_rebuild_during_searches_keeps_serving_whole_indexes_and_swaps_at_once() -> None:
    gate, started = threading.Event(), threading.Event()

    class SlowEmbeddings(TextEmbeddings):
        def embed_library_texts(self, corpus, texts, sources):
            if self.library_texts:  # the second build waits
                started.set()
                gate.wait(10)
            return super().embed_library_texts(corpus, texts, sources)

    docs = _docs()
    records = MemoryRecords(docs)
    keeper = EvidenceIndexKeeper(
        records, MemoryPointer(), MemoryFeeds(), SlowEmbeddings(), ScoredBy(), "m", "r"
    )
    old = keeper.rebuild_index().result(10)
    finder = EvidenceFinder(keeper.current_index, 1.0, gate=RerankGate(3))
    records.docs.append(vulnerability_doc("CVE-9", "V", "P"))
    rebuilding = keeper.rebuild_index()
    assert started.wait(5)
    seen: list[str | None] = []

    def search(_: int) -> None:
        (result,), summary = finder.find_evidence(
            [request_of("Threat: ransomware number 1")], stale=False, approved=ALL_SOURCES
        )
        seen.append(summary.snapshot_id)
        assert result.search.snapshot_id == summary.snapshot_id

    with ThreadPoolExecutor(6) as pool:
        list(pool.map(search, range(30)))
    assert set(seen) == {old.snapshot_id} and keeper.current_index() is old  # the old index kept serving
    gate.set()
    new = rebuilding.result(10)
    assert new is not old and keeper.current_index() is new
    finder.find_evidence([request_of()], stale=False, approved=ALL_SOURCES)


def test_switch_flips_during_load_stay_consistent_and_end_where_the_last_flip_left_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    flags = MemoryFlags()
    switch = ExternalIntelligenceSwitch(flags)
    stop = threading.Event()
    seen: list[bool] = []

    def read() -> None:
        while not stop.is_set():
            seen.append(switch.is_on())

    readers = [threading.Thread(target=read) for _ in range(6)]
    for reader in readers:
        reader.start()
    for flip in range(10):
        switch.change_runtime_flag(flip % 2 == 0, "admin")
    switch.change_runtime_flag(False, "admin")
    stop.set()
    for reader in readers:
        reader.join()
    assert seen and all(isinstance(value, bool) for value in seen)
    assert not switch.is_on() and flags.stored[0] is False
