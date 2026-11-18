"""Stand-ins for the evidence search, refresh and switch tests: record documents, in-memory stores,
models that count their concurrent callers. No MongoDB, no network, no AI model."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from app.core.config import get_settings
from app.core.constants import AssetType, FeedStatus, IntelKind, IntelSource
from app.domain.intel import evidence
from app.domain.intel.evidence import RerankGate
from app.domain.intel.index import EvidenceIndex
from app.schemas.intel_records import EvidenceRequest, FetchResult, IntelRecord, SanitisedText, SourceHealth
from tests.fakes import FakeEmbeddings, FakeRerankModel

NOW = datetime(2026, 10, 12, tzinfo=UTC)
ALL_SOURCES = list(IntelSource)


def technique_doc(ref: str, asset_type: str = "IT", text: str = "ransomware encrypts files", **data: Any) -> dict:
    source = IntelSource.ATTACK_ICS if asset_type == "OT" else IntelSource.ATTACK_ENTERPRISE
    full = f"{ref} Technique {ref}. {text} Tactics: impact."
    record = IntelRecord(
        source, ref, IntelKind.TECHNIQUE, asset_type, f"Technique {ref}", full, f"https://x/{ref}", "r1", data=data
    )
    return record.as_doc(NOW)


def request_of(text: str = "Threat: Ransomware encrypts backup servers", types: set[str] | None = None):
    return EvidenceRequest(text, frozenset(types or {"IT", AssetType.IT_OT}))


def use_index(
    monkeypatch: pytest.MonkeyPatch,
    index: EvidenceIndex | Callable[[], EvidenceIndex],
    threshold: float = 1.0,
    candidates: int = 6,
    kept: int = 3,
    gate: RerankGate | None = None,
) -> None:
    """evidence.find_evidence searches `index` (or the index its provider gives) with these settings and gate;
    the rerank score cache starts empty."""
    provider = index if callable(index) else (lambda: index)
    one_gate = gate or RerankGate(2)
    monkeypatch.setattr(evidence, "get_evidence_index_keeper", lambda: SimpleNamespace(current_index=provider))
    monkeypatch.setattr(evidence, "get_rerank_gate", lambda: one_gate)
    settings = get_settings()
    monkeypatch.setattr(settings, "evidence_similarity_threshold", threshold)
    monkeypatch.setattr(settings, "evidence_candidates", candidates)
    monkeypatch.setattr(settings, "evidence_kept_per_threat", kept)
    evidence._scored.clear()  # noqa: SLF001


class ScoredBy(FakeRerankModel):
    """Scores a document by the first table key its text holds; `default` for any other."""

    def __init__(self, table: dict[str, float] | None = None, default: float = 90.0) -> None:
        super().__init__()
        self.table, self.default = table or {}, default

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.calls.append((query, documents))
        return [next((s for key, s in self.table.items() if key in doc), self.default) for doc in documents]


class CountingRerank(ScoredBy):
    """Counts how many calls run at the same moment (the gate must keep it down)."""

    def __init__(self, hold_seconds: float = 0.02, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.hold, self.running, self.most = hold_seconds, 0, 0
        self._lock = threading.Lock()

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        with self._lock:
            self.running += 1
            self.most = max(self.most, self.running)
        try:
            time.sleep(self.hold)
            return [90.0 for _ in documents]
        finally:
            with self._lock:
                self.running -= 1


class TextEmbeddings(FakeEmbeddings):
    """Also keeps the texts it was asked to embed, and counts calls per kind."""

    def __init__(self) -> None:
        super().__init__()
        self.library_texts: list[str] = []
        self.query_texts: list[str] = []
        self.fail = False
        self.lock = threading.Lock()

    def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
        if self.fail:
            raise RuntimeError("down")
        self.library_texts = list(texts)
        return super().embed_library_texts(corpus, texts, sources)

    def embed_search_queries(self, texts: list[str], corpus: str) -> np.ndarray:
        with self.lock:
            self.query_texts += texts
        return super().embed_search_queries(texts, corpus)


class FlaggingSanitiser:
    """Flags any text holding IGNORE (a stand-in for group A's injection patterns)."""

    def sanitise(self, text: str, max_chars: int) -> SanitisedText:
        return SanitisedText(text[:max_chars], unsafe="IGNORE" in text.upper(), reason="flagged")


class MemoryRecords:
    def __init__(self, docs: list[dict] | None = None) -> None:
        self.docs = docs or []
        self.saved: list[Sequence[IntelRecord]] = []
        self.retired: list[tuple[str, set[str]]] = []
        self.counts = 0

    def stream_current_intel_records(self) -> Iterator[dict]:
        return iter(self.docs)

    def save_intel_records(self, records: Sequence[IntelRecord], fetched_at: datetime) -> int:
        self.saved.append(records)
        return len(records)

    def retire_intel_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime | None = None
    ) -> int:
        self.retired.append((source, seen_ids))
        return 0

    def list(self, fields: Any = None, **where: Any) -> list[dict]:
        return [doc for doc in self.docs if doc["source"] == where.get("source")]

    def count(self, **where: Any) -> int:
        return len(self.saved)


class MemoryPointer:
    def __init__(self) -> None:
        self.saved: list[dict] = []
        self.active: dict | None = None

    def activate_intel_snapshot(self, description: dict) -> bool:
        self.saved.append(description)
        self.active = description
        return True

    def get(self, fields: Any = None, **where: Any) -> dict | None:
        return self.active


class MemoryFeeds:
    """tsg_external_feed_status in memory, answering the base verbs the services ask with; `sources`: the
    ones it holds (every one unless given)."""

    def __init__(self, sources: list[IntelSource] | None = None) -> None:
        self.sources = list(ALL_SOURCES if sources is None else sources)
        self.health: dict[IntelSource, SourceHealth] = {}
        self.claimed: dict[IntelSource, str] = {}  # source -> claim token
        self.successes: list[tuple] = []
        self.failures: list[tuple[IntelSource, str]] = []
        self.claims_made = 0
        self.lock = threading.Lock()

    def create_missing_intel_feeds(self) -> None:
        for source in self.sources:
            self.health.setdefault(source, SourceHealth(source))

    def _doc(self, source: IntelSource) -> dict:
        return {**self.health[source].as_doc(), "_id": source}

    def get(self, fields: Any = None, **where: Any) -> dict | None:
        return self._doc(where["_id"]) if where["_id"] in self.health else None

    def list(self, fields: Any = None, **where: Any) -> list[dict]:
        return [self._doc(source) for source in self.health]

    def claim_intel_feed_refresh(self, source: IntelSource, now: datetime, stale_before: datetime) -> str | None:
        with self.lock:
            self.claims_made += 1
            if source in self.claimed:
                return None
            self.claimed[source] = f"token-{self.claims_made}"
            return self.claimed[source]

    def release_intel_feed_refresh(self, source: IntelSource, claim: str, outcome: dict | None = None) -> bool:
        if self.claimed.get(source) != claim:
            return False
        del self.claimed[source]
        if outcome and outcome["status"] == FeedStatus.OK:
            self._record_success(source, outcome)
        elif outcome:
            self._record_failure(source, outcome)
        return True

    def _record_success(self, source: IntelSource, done: dict) -> None:
        now, records = done["last_success_at"], done["records"]
        checkpoint, version = done["checkpoint"], done["source_version"]
        self.successes.append((source, checkpoint, version, records))
        self.health[source] = SourceHealth(source, FeedStatus.OK, checkpoint, version, records, now, now)

    def _record_failure(self, source: IntelSource, failed: dict) -> None:
        self.failures.append((source, failed["last_error"]))
        previous = self.health.get(source) or SourceHealth(source)
        self.health[source] = SourceHealth(
            source, FeedStatus.FAILED, previous.checkpoint, previous.source_version, previous.records,
            failed["last_attempt_at"], previous.last_success_at, failed["last_error"],
        )  # fmt: skip


class StubFetcher:
    """Gives `result` (or raises it, when it is an exception); None: nothing new."""

    def __init__(self, source: IntelSource, result: FetchResult | BaseException | None) -> None:
        self.source_id, self.result, self.calls = source, result, 0
        self.checkpoints: list[str | None] = []

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        self.calls += 1
        self.checkpoints.append(checkpoint)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class MemoryKeeper:
    """What the refresher and health need of the index keeper."""

    def __init__(self, fail: bool | Exception = False) -> None:
        self.rebuilds, self.fail = 0, fail  # an exception: the rebuild fails with it; True: RuntimeError

    def rebuild_index(self):
        from concurrent.futures import Future

        self.rebuilds += 1
        future: Future = Future()
        if self.fail:
            future.set_exception(self.fail if isinstance(self.fail, Exception) else RuntimeError("down"))
        else:
            future.set_result(None)
        return future

    def peek_index(self):
        from app.domain.intel.index import empty_index

        return empty_index(FakeEmbeddings(), ScoredBy())  # type: ignore[arg-type]
