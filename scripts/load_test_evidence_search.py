r"""Latency and throughput of the evidence search under many users at once, with fake models (no network,
no AI, no database). Prints one row per number of users: batches per second, the median and 95th
percentile batch time, and the most reranks that ran at the same moment (the gate keeps it within its size).

From the project folder:
.venv\Scripts\python scripts\load_test_evidence_search.py [rerank_ms] [gate_size]"""

from __future__ import annotations

import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.core.constants import RerankGateLimits  # noqa: E402
from app.domain.external_intelligence.evidence_finder import EvidenceFinder  # noqa: E402
from app.domain.external_intelligence.rerank_gate import RerankGate  # noqa: E402
from app.search.external_intelligence.corpus_builder import build_corpus  # noqa: E402
from app.search.external_intelligence.evidence_index import build_index  # noqa: E402
from tests.external_intelligence.evidence_fakes import (  # noqa: E402
    ALL_SOURCES,
    CountingRerank,
    TextEmbeddings,
    request_of,
    technique_doc,
)

WORDS = ("ransomware", "phishing", "backup", "insider", "flood")
USERS = (1, 4, 8, 16)
BATCHES_PER_USER, REQUESTS_PER_BATCH = 5, 6


def make_finder(rerank_seconds: float, gate_size: int) -> tuple[EvidenceFinder, CountingRerank]:
    docs = [technique_doc(f"T{n}", "IT", f"{WORDS[n % 5]} technique {n}") for n in range(1, 400)]
    rerank = CountingRerank(rerank_seconds)
    corpus = build_corpus(docs)
    index = build_index(corpus, TextEmbeddings(), rerank)  # type: ignore[arg-type]  # fakes stand in: no AI
    return EvidenceFinder(lambda: index, 1.0, gate=RerankGate(gate_size), candidates=30), rerank


def one_batch(finder: EvidenceFinder, user: int) -> float:
    word = WORDS[user % 5]
    requests = [request_of(f"Threat: {word} {user} {part}", {"IT"}) for part in range(REQUESTS_PER_BATCH)]
    started = time.perf_counter()
    finder.find_evidence(requests, stale=False, approved=ALL_SOURCES)
    return time.perf_counter() - started


def run_users(finder: EvidenceFinder, users: int) -> tuple[list[float], float]:
    started = time.perf_counter()
    with ThreadPoolExecutor(users) as pool:
        futures = [
            pool.submit(one_batch, finder, user) for user in range(users) for _ in range(BATCHES_PER_USER)
        ]
        times = [future.result() for future in futures]
    return times, time.perf_counter() - started


def main() -> None:
    rerank_seconds = float(sys.argv[1]) / 1000 if len(sys.argv) > 1 else 0.02
    gate_size = int(sys.argv[2]) if len(sys.argv) > 2 else RerankGateLimits.RERANKS_AT_ONCE
    print(f"{'users':>5} {'batches/s':>10} {'p50 s':>8} {'p95 s':>8} {'max reranks at once':>20}")
    for users in USERS:
        finder, rerank = make_finder(rerank_seconds, gate_size)
        times, total = run_users(finder, users)
        p95 = statistics.quantiles(times, n=20)[-1] if len(times) > 1 else times[0]
        median, rate = statistics.median(times), len(times) / total
        print(f"{users:>5} {rate:>10.1f} {median:>8.3f} {p95:>8.3f} {rerank.most:>20}")


if __name__ == "__main__":
    main()
