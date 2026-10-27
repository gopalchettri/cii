"""The rerank gate: bounded, released on errors, ends with the caller's deadline, safe beside the AI
slots for a remote-like model (slot limited) and a local-like one (no limit); the laptop's one-at-a-time model
is waited for, never given up on while it answers (G218)."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from typing import Any

import pytest

from app import container
from app.core.constants import AiOutage, EvidenceSearchFailure, RerankGateLimits
from app.core.exceptions import LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import RerankGate, rerank_gate_for
from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import build_index
from tests.external_intelligence.evidence_fakes import (
    ALL_SOURCES,
    CountingRerank,
    TextEmbeddings,
    request_of,
    technique_doc,
)


class RemoteLikeRerank(CountingRerank):
    """Takes a slot inside the call, as RerankModel's remote path does (after the gate)."""

    def __init__(self, slots: threading.BoundedSemaphore, **kwargs) -> None:
        super().__init__(**kwargs)
        self.slots = slots

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self.slots:
            return super().score_relevance(query, documents)


def _finder(rerank, gate: RerankGate) -> EvidenceFinder:
    index = build_index(build_corpus([technique_doc("T1")]), TextEmbeddings(), rerank)
    return EvidenceFinder(lambda: index, 1.0, gate=gate, candidates=6, kept_per_threat=3)


def _batch(finder: EvidenceFinder, size: int = 12) -> None:
    results, _ = finder.find_evidence(
        [request_of(f"Threat: ransomware {n}") for n in range(size)], stale=False, approved=ALL_SOURCES
    )
    assert all(result.evidence for result in results)


def test_the_process_gate_is_one_small_constant_shared_by_every_caller() -> None:
    finder = container.get_evidence_finder()  # every caller shares the one finder, so its one gate
    assert finder is container.get_evidence_finder() and RerankGateLimits.RERANKS_AT_ONCE <= 6


@pytest.mark.parametrize("size", [1, 2, 3])
def test_a_local_like_model_never_runs_more_reranks_than_the_gate_allows_across_batches(size: int) -> None:
    rerank = CountingRerank()
    finder = _finder(rerank, RerankGate(size))
    with ThreadPoolExecutor(6) as pool:
        for future in [pool.submit(_batch, finder) for _ in range(6)]:
            future.result(30)
    assert 1 <= rerank.most <= size


def test_a_remote_like_model_with_fewer_slots_than_gate_places_finishes_without_deadlock() -> None:
    slots = threading.BoundedSemaphore(1)
    rerank = RemoteLikeRerank(slots)
    finder = _finder(rerank, RerankGate(3))
    with ThreadPoolExecutor(4) as pool:
        for future in [pool.submit(_batch, finder, 8) for _ in range(4)]:
            future.result(30)
    assert rerank.most == 1


def test_a_failing_rerank_releases_its_place() -> None:
    gate = RerankGate(1)

    class Broken(CountingRerank):
        def score_relevance(self, query, documents):
            raise Unavailable("down")

    finder = _finder(Broken(), gate)
    for _ in range(3):  # a leaked place would make the second batch wait for it
        results, _ = finder.find_evidence([request_of()], stale=False, approved=ALL_SOURCES)
        assert results[0].search.failure is not None
    with gate.hold_place():
        pass


def test_a_wait_for_the_gate_ends_at_its_limit_as_unavailable() -> None:
    gate = RerankGate(1, wait_seconds=0.2)
    held, release = threading.Event(), threading.Event()

    def hold() -> None:
        with gate.hold_place():
            held.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(5)
    started = time.monotonic()
    with pytest.raises(Unavailable) as busy, gate.hold_place():
        pass
    assert time.monotonic() - started < 5 and busy.value.reason == AiOutage.BUSY  # the UI is told "busy"
    release.set()
    holder.join()


class OneAtATimeRerank(CountingRerank):
    """Answers one call at a time, as the laptop's CPU model does behind its lock (G199)."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.turn = threading.Lock()

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self.turn:
            return super().score_relevance(query, documents)


class GiveUpCountingGate(RerankGate):
    """Counts the waits that gave up: a test's model keeps its places until they have (no clock race)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gave_up = threading.Semaphore(0)

    def _wait_for_place(self) -> None:
        try:
            super()._wait_for_place()
        except Unavailable:
            self.gave_up.release()
            raise


class BusyUntilGivenUp(OneAtATimeRerank):
    """The model's first answer comes only once `expected` waiters have given up: the places stay taken
    however late a loaded machine starts a thread (a fixed 0.2 s answer let the last thread find one free)."""

    def __init__(self, gate: GiveUpCountingGate, expected: int, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.gate, self.expected = gate, expected

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self.turn:
            while self.expected:
                assert self.gate.gave_up.acquire(timeout=10), "a waiter never gave up"
                self.expected -= 1
            return CountingRerank.score_relevance(self, query, documents)


def _failures(gate: GiveUpCountingGate, giving_up: int = 0) -> list[EvidenceSearchFailure]:
    """Run 0a84b002's next set in small: 6 threats at once, a model answering one at a time."""
    finder = _finder(BusyUntilGivenUp(gate, giving_up, hold_seconds=0.02), gate)
    results, _ = finder.find_evidence(
        [request_of(f"Threat: ransomware {n}") for n in range(6)], stale=False, approved=ALL_SOURCES
    )
    return [result.search.failure for result in results if result.search.failure is not None]


def test_the_laptop_model_is_waited_for_so_every_threat_of_a_set_gets_its_evidence() -> None:
    """G218: 4 places and a fixed wait shorter than the queue left 2 threats of each 6 without evidence while
    the model was still answering (live: a 60 s wait, 106 s for the first answer); the laptop's gate waits."""
    fixed = GiveUpCountingGate(4, wait_seconds=0.05)
    assert _failures(fixed, giving_up=2) == [EvidenceSearchFailure.UNAVAILABLE] * 2
    laptop = GiveUpCountingGate(RerankGateLimits.LOCAL_RERANKS_AT_ONCE, wait_seconds=None)
    assert rerank_gate_for("")._wait_seconds is None and _failures(laptop) == []


def _hold(gate: RerankGate) -> tuple[threading.Thread, threading.Event]:
    """A place held by another caller until the returned event is set; returns once it is held."""
    held, release = threading.Event(), threading.Event()

    def hold() -> None:
        with gate.hold_place():
            held.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(5)
    return holder, release


def test_a_laptop_gate_waiter_keeps_waiting_past_many_checks_and_gets_its_place() -> None:
    gate = RerankGate(1, wait_seconds=None, check_every=0.02)
    holder, release = _hold(gate)
    threading.Timer(0.3, release.set).start()
    started = time.monotonic()
    with gate.hold_place():
        assert time.monotonic() - started >= 0.2  # 10 checks and more: it never gave up on a moving queue
    holder.join()


def test_a_cancelled_job_stops_waiting_for_the_gate_within_one_check() -> None:
    gate = RerankGate(1, wait_seconds=None, check_every=0.02)
    holder, release = _hold(gate)
    with lease_lost_signal("cancelled-run") as lost:
        threading.Timer(0.1, lost.set).start()
        started = time.monotonic()
        with pytest.raises(LeaseLost), gate.hold_place():
            pass
    assert time.monotonic() - started < 1
    release.set()
    holder.join()


def test_both_gates_wait_until_a_place_frees_or_the_lease_is_lost_and_the_proxy_gate_has_six() -> None:
    local, remote = rerank_gate_for(""), rerank_gate_for("http://proxy.invalid")
    assert local._wait_seconds is None and remote._wait_seconds is None
    for gate, places in ((local, 1), (remote, RerankGateLimits.RERANKS_AT_ONCE)):
        with ExitStack() as stack:
            for _ in range(places):
                stack.enter_context(gate.hold_place())
            assert not gate._places.acquire(timeout=0)  # noqa: SLF001 — every place is taken
