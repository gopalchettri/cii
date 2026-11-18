"""The rerank gate: bounded, released on errors, ends with the caller's deadline, safe beside the AI
slots for a remote-like model (slot limited) and a local-like one (no limit); the laptop's one-at-a-time model
is waited for, never given up on while it answers (G218)."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

import pytest

from app.core.constants import RerankGateLimits
from app.core.exceptions import LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal
from app.domain.intel import evidence
from app.domain.intel.evidence import RerankGate, get_rerank_gate, rerank_gate_for
from app.domain.intel.index import build_corpus, build_index
from tests.external_intelligence.evidence_fakes import (
    CountingRerank,
    TextEmbeddings,
    request_of,
    technique_doc,
    use_index,
)


class RemoteLikeRerank(CountingRerank):
    """Takes a slot inside the call, as RerankModel's remote path does (after the gate)."""

    def __init__(self, slots: threading.BoundedSemaphore, **kwargs) -> None:
        super().__init__(**kwargs)
        self.slots = slots

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self.slots:
            return super().score_relevance(query, documents)


def _finder(monkeypatch: pytest.MonkeyPatch, rerank, gate: RerankGate) -> None:
    index = build_index(build_corpus([technique_doc("T1")]), TextEmbeddings(), rerank)
    use_index(monkeypatch, index, gate=gate)


def _batch(size: int = 12) -> None:
    requests = [request_of(f"Threat: ransomware {n}") for n in range(size)]
    results = evidence.find_evidence(requests)
    assert all(result.evidence for result in results)


def test_the_process_gate_is_one_constant_shared_by_every_caller() -> None:
    gate = get_rerank_gate()  # every caller shares the one gate
    assert gate is get_rerank_gate() and 1 <= RerankGateLimits.RERANKS_AT_ONCE <= 64


@pytest.mark.parametrize("size", [1, 2, 3])
def test_a_local_like_model_never_runs_more_reranks_than_the_gate_allows_across_batches(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    rerank = CountingRerank()
    _finder(monkeypatch, rerank, RerankGate(size))
    with ThreadPoolExecutor(6) as pool:
        for future in [pool.submit(_batch) for _ in range(6)]:
            future.result(30)
    assert 1 <= rerank.most <= size


def test_a_remote_like_model_with_fewer_slots_than_gate_places_finishes_without_deadlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slots = threading.BoundedSemaphore(1)
    rerank = RemoteLikeRerank(slots)
    _finder(monkeypatch, rerank, RerankGate(3))
    with ThreadPoolExecutor(4) as pool:
        for future in [pool.submit(_batch, 8) for _ in range(4)]:
            future.result(30)
    assert rerank.most == 1


def test_a_failing_rerank_releases_its_place(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = RerankGate(1)

    class Broken(CountingRerank):
        def score_relevance(self, query, documents):
            raise Unavailable("down")

    _finder(monkeypatch, Broken(), gate)
    for _ in range(3):  # a leaked place would make the second batch wait for it
        results = evidence.find_evidence([request_of()])
        assert results[0].search.failure is not None
    with gate.hold_place():
        pass


class OneAtATimeRerank(CountingRerank):
    """Answers one call at a time, as the laptop's CPU model does behind its lock (G199)."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.turn = threading.Lock()

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self.turn:
            return super().score_relevance(query, documents)


def test_the_laptop_model_is_waited_for_so_every_threat_of_a_set_gets_its_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G218: a fixed wait shorter than the queue left threats without evidence while the model was still
    answering; the laptop's gate waits."""
    _finder(monkeypatch, OneAtATimeRerank(hold_seconds=0.02), rerank_gate_for(""))
    requests = [request_of(f"Threat: ransomware {n}") for n in range(6)]
    results = evidence.find_evidence(requests)
    assert [result.search.failure for result in results if result.search.failure is not None] == []


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
    gate = RerankGate(1, check_every=0.02)
    holder, release = _hold(gate)
    threading.Timer(0.3, release.set).start()
    started = time.monotonic()
    with gate.hold_place():
        assert time.monotonic() - started >= 0.2  # 10 checks and more: it never gave up on a moving queue
    holder.join()


def test_a_cancelled_job_stops_waiting_for_the_gate_within_one_check() -> None:
    gate = RerankGate(1, check_every=0.02)
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
    for gate, places in ((local, 1), (remote, RerankGateLimits.RERANKS_AT_ONCE)):
        with ExitStack() as stack:
            for _ in range(places):
                stack.enter_context(gate.hold_place())
            assert not gate._places.acquire(timeout=0)  # noqa: SLF001 — every place is taken
