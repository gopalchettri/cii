"""Many users at once: no cross-talk between requests, results equal to serial runs, the rerank gate never
exceeded, a rebuild during searches keeps serving the old index, the switch consistent during flips."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.config import get_settings
from app.core.constants import AssetType
from app.domain.intel import evidence, index
from app.domain.intel.evidence import RerankGate
from app.domain.intel.index import EvidenceIndexKeeper
from app.domain.intel.switch import IntelligenceSwitch
from tests.external_intelligence.evidence_fakes import (
    CountingRerank,
    MemoryPointer,
    MemoryRecords,
    ScoredBy,
    TextEmbeddings,
    request_of,
    technique_doc,
    use_index,
)
from tests.external_intelligence.switch.test_switch import MemoryFlags

USERS, BATCHES = 8, 6
WORDS = ("ransomware", "phishing", "backup", "insider", "flood")


def _docs() -> list[dict]:
    docs = [technique_doc(f"T{n}", "IT", f"{WORDS[n % 5]} technique number {n}") for n in range(1, 21)]
    return docs + [technique_doc(f"T{n}", "OT", f"{WORDS[n % 5]} ot technique {n}") for n in range(21, 31)]


def _search_through_keeper(monkeypatch: pytest.MonkeyPatch, docs, rerank=None) -> None:
    """evidence.find_evidence searches a keeper's index of `docs`, built first, behind a gate of 3 places."""
    records, pointer, embeddings = MemoryRecords(docs), MemoryPointer(), TextEmbeddings()
    monkeypatch.setattr(index, "get_intel_record_repository", lambda: records)
    monkeypatch.setattr(index, "get_intel_snapshot_repository", lambda: pointer)
    monkeypatch.setattr(index, "get_embedding_model", lambda: embeddings)
    monkeypatch.setattr(index, "get_rerank_model", lambda: rerank or ScoredBy())
    monkeypatch.setattr(get_settings(), "embedding_model", "m")
    monkeypatch.setattr(get_settings(), "rerank_model", "r")
    keeper = EvidenceIndexKeeper()
    keeper.rebuild_index().result(10)
    use_index(monkeypatch, keeper.current_index, gate=RerankGate(3))


def _requests(user: int) -> list:
    word = WORDS[user % 5]
    types = {"OT", AssetType.IT_OT} if user % 2 else {"IT", AssetType.IT_OT}
    return [request_of(f"Threat: {word} number {user} part {part}", types) for part in range(4)]


def _shape(results) -> list[tuple]:
    return [(tuple(e.ref for e in r.evidence), r.search.query, r.search.asset_types) for r in results]


def test_many_users_get_exactly_what_a_serial_run_gives_and_never_each_others_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _search_through_keeper(monkeypatch, _docs())
    serial = {user: _shape(evidence.find_evidence(_requests(user))) for user in range(USERS)}

    def work(user: int) -> list:
        return [_shape(evidence.find_evidence(_requests(user))) for _ in range(BATCHES)]

    with ThreadPoolExecutor(USERS) as pool:
        concurrent = list(pool.map(work, range(USERS)))
    for user, runs in enumerate(concurrent):
        assert all(run == serial[user] for run in runs)
        numbers = {int(ref[1:]) for run in runs for refs, _, _ in run for ref in refs}
        assert numbers and all((number > 20) == (user % 2 == 1) for number in numbers)  # only its own types
        assert all(
            query.endswith(tuple(f"number {user} part {p}" for p in range(4))) for run in runs for _, query, _ in run
        )


def test_the_gate_is_never_exceeded_by_many_batches_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    rerank = CountingRerank(0.01)
    _search_through_keeper(monkeypatch, _docs(), rerank)
    with ThreadPoolExecutor(USERS) as pool:
        list(pool.map(lambda user: evidence.find_evidence(_requests(user)), range(USERS * 2)))
    assert 1 <= rerank.most <= 3


def test_switch_flips_during_load_stay_consistent_and_end_where_the_last_flip_left_them() -> None:
    flags = MemoryFlags()
    switch = IntelligenceSwitch(flags, env_enabled=lambda: True)  # type: ignore[arg-type]
    stop = threading.Event()
    seen: list[bool] = []

    def read() -> None:
        while not stop.is_set():
            seen.append(switch.is_on())

    readers = [threading.Thread(target=read) for _ in range(6)]
    for reader in readers:
        reader.start()
    for flip in range(10):
        switch.save(flip % 2 == 0, "admin")
    switch.save(False, "admin")
    stop.set()
    for reader in readers:
        reader.join()
    assert seen and all(isinstance(value, bool) for value in seen)
    assert not switch.is_on() and flags.stored[0] is False
