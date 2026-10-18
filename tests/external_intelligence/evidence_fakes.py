"""Stand-ins for the evidence search, refresh and switch tests: record documents, in-memory stores,
models that count their concurrent callers. No MongoDB, no network, no AI model."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from typing import Any

import numpy as np

from app.core.constants import AssetType, FeedStatus, IntelKind, IntelSource
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    RecordedProduct,
    RecordedProducts,
)
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, SaveCounts
from app.models.external_intelligence.sanitised_text import SanitisedText
from app.models.external_intelligence.source_health import (
    SourceHealth,
    source_health_in_registry_order,
    sources_in_registry_order,
)
from tests.fakes import FakeEmbeddings, FakeRerankModel

NOW = datetime(2026, 10, 12, tzinfo=UTC)
ALL_SOURCES = list(IntelSource)


def technique_doc(
    ref: str, asset_type: str = "IT", text: str = "ransomware encrypts files", **data: Any
) -> dict:
    source = IntelSource.ATTACK_ICS if asset_type == "OT" else IntelSource.ATTACK_ENTERPRISE
    full = f"{ref} Technique {ref}. {text} Tactics: impact."
    record = IntelRecord(
        source,
        ref,
        IntelKind.TECHNIQUE,
        asset_type,
        f"Technique {ref}",
        full,
        f"https://x/{ref}",
        "r1",
        data=data,
    )
    return record.as_doc(NOW)


def vulnerability_doc(cve: str, vendor: str, product: str, **data: Any) -> dict:
    data = {"cve": cve, "vendor": vendor, "product": product, "date_added": "2024-03-01"} | data
    text = f"{cve} ransomware flaw. {vendor} {product}."
    record = IntelRecord(
        IntelSource.CISA_KEV,
        cve,
        IntelKind.VULNERABILITY,
        "IT",
        cve,
        text,
        f"https://x/{cve}",
        "v1",
        data=data,
    )
    return record.as_doc(NOW)


def advisory_doc(ident: str, *entries: Any, **data: Any) -> dict:
    data = {"advisory_id": ident, "vendor": "Siemens", "cves": [], "affected": list(entries)} | data
    text = f"{ident} advisory. Ransomware encrypts files."
    record = IntelRecord(
        IntelSource.CISA_ICS,
        ident,
        IntelKind.ADVISORY,
        "OT",
        ident,
        text,
        f"https://x/{ident}",
        "a1",
        data=data,
    )
    return record.as_doc(NOW)


def epss_doc(cve: str, epss: float = 0.5) -> dict:
    data = {"cve": cve, "epss": epss, "percentile": 0.9}
    record = IntelRecord(
        IntelSource.FIRST_EPSS, cve, IntelKind.EXPLOIT_SCORE, "IT", cve, "score", "u", "d", data=data
    )
    return record.as_doc(NOW)


def detail_doc(cve: str, **data: Any) -> dict:
    full = {"cve": cve, "cvss": 9.8, "severity": "CRITICAL", "cwes": [], "affected": [{"vendor": "V"}]} | data
    record = IntelRecord(
        IntelSource.NIST_NVD, cve, IntelKind.VULNERABILITY_DETAIL, "IT", cve, "detail", "u", "n1", data=full
    )
    return record.as_doc(NOW)


def request_of(
    text: str = "Threat: Ransomware encrypts backup servers", types: set[str] | None = None, **product: Any
):
    rows = (RecordedProduct(**{k: tuple(v) for k, v in product.items()}),) if product else ()
    return EvidenceRequest(text, frozenset(types or {"IT", AssetType.IT_OT}), RecordedProducts(rows))


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

    def embed_search_queries(self, texts: list[str]) -> np.ndarray:
        with self.lock:
            self.query_texts += texts
        return super().embed_search_queries(texts)


class FlaggingSanitiser:
    """Flags any text holding IGNORE (a stand-in for group A's injection patterns)."""

    def sanitise(self, text: str, max_chars: int) -> SanitisedText:
        return SanitisedText(text[:max_chars], unsafe="IGNORE" in text.upper(), reason="flagged")


class MemoryRecords:
    def __init__(self, docs: list[dict] | None = None) -> None:
        self.docs = docs or []
        self.saved: list[tuple[Sequence[IntelRecord], int]] = []
        self.retired: list[tuple[str, set[str]]] = []
        self.purged: list[str] = []
        self.counts = 0

    def stream_current_intel_records(self, sources: Sequence[IntelSource]) -> Iterator[dict]:
        return iter([doc for doc in self.docs if doc["source"] in sources])

    def save_intel_records(
        self, records: Sequence[IntelRecord], rejected: Sequence[Any], fetched_at: datetime
    ) -> SaveCounts:
        self.saved.append((records, len(rejected)))
        return SaveCounts(len(records), 0, len(rejected))

    def retire_intel_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime | None = None
    ) -> int:
        self.retired.append((source, seen_ids))
        return 0

    def list(self, fields: Any = None, **where: Any) -> list[dict]:
        return [doc for doc in self.docs if doc["source"] == where.get("source")]

    def count(self, **where: Any) -> int:
        return len(self.saved)

    def delete(self, **where: Any) -> int:
        source = where["source"]
        self.purged.append(source)
        self.docs = [doc for doc in self.docs if doc["source"] != source]
        return 1


class MemoryPointer:
    def __init__(self) -> None:
        self.saved: list[dict] = []
        self.active: dict | None = None

    def save(self, record: dict, only_if: Any = None) -> bool:
        self.saved.append({name: value for name, value in record.items() if name != "_id"})
        return True

    def activate_intel_snapshot(self, snapshot_id: str) -> bool:
        self.active = next(d for d in self.saved if d["snapshot_id"] == snapshot_id)
        return True

    def get(self, fields: Any = None, **where: Any) -> dict | None:
        return self.active


class MemoryFeeds:
    """tsg_external_feed_status in memory, answering the base verbs the services ask with."""

    def __init__(self, approved: list[IntelSource] | None = None) -> None:
        self.approved = list(ALL_SOURCES if approved is None else approved)
        self.health: dict[IntelSource, SourceHealth] = {}
        self.more: set[IntelSource] = set()
        self.claimed: dict[IntelSource, str] = {}  # source -> claim token
        self.successes: list[tuple] = []
        self.failures: list[tuple[IntelSource, str]] = []
        self.claims_made = 0
        self.lock = threading.Lock()

    def create_missing_intel_feeds(self) -> None:
        for source in self.approved:
            self.health.setdefault(source, SourceHealth(source))

    def set_source_approved(self, source: IntelSource, approved: bool) -> None:
        if approved and source not in self.approved:
            self.approved.append(source)
        if not approved and source in self.approved:
            self.approved.remove(source)

    def _doc(self, source: IntelSource) -> dict:
        doc = self.health[source].as_doc()
        return {
            **doc,
            "_id": source,
            "approved": source in self.approved,
            "more_pending": source in self.more,
        }

    def get(self, fields: Any = None, **where: Any) -> dict | None:
        return self._doc(where["_id"]) if where["_id"] in self.health else None

    def list(self, fields: Any = None, **where: Any) -> list[dict]:
        if where.get("approved"):
            return [{"_id": source} for source in self.approved]
        return [self._doc(source) for source in self.health]

    def list_approved_sources(self) -> list[IntelSource]:
        return sources_in_registry_order(self.list(approved=True))

    def list_source_health(self) -> list[SourceHealth]:
        return source_health_in_registry_order(self.list())

    def count(self, **where: Any) -> int:
        source = where["_id"]
        if where.get("more_pending"):
            return int(source in self.more)
        return int(source in self.approved)

    def claim_intel_feed_refresh(
        self, source: IntelSource, now: datetime, stale_before: datetime
    ) -> str | None:
        with self.lock:
            self.claims_made += 1
            if source in self.claimed or source not in self.approved:
                return None
            self.claimed[source] = f"token-{self.claims_made}"
            return self.claimed[source]

    def release_intel_feed_refresh(
        self, source: IntelSource, claim: str, outcome: dict | None = None
    ) -> bool:
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
        self.successes.append((source, checkpoint, version, done["more_pending"], records))
        self.health[source] = SourceHealth(source, FeedStatus.OK, checkpoint, version, records, now, now)

    def _record_failure(self, source: IntelSource, failed: dict) -> None:
        self.failures.append((source, failed["last_error"]))
        previous = self.health.get(source) or SourceHealth(source)
        self.health[source] = SourceHealth(
            source, FeedStatus.FAILED, previous.checkpoint, previous.source_version, previous.records,
            failed["last_attempt_at"], previous.last_success_at, failed["last_error"],
        )  # fmt: skip


class MemoryCatalogue:
    def __init__(self, fetchers: dict) -> None:
        self._fetchers = fetchers

    def fetchers(self) -> dict:
        return self._fetchers


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
    """What the refresher, health and purge need of the index keeper."""

    def __init__(self, fail: bool = False) -> None:
        self.rebuilds, self.fail = 0, fail

    def rebuild_index(self):
        from concurrent.futures import Future

        self.rebuilds += 1
        future: Future = Future()
        if self.fail:
            future.set_exception(RuntimeError("down"))
        else:
            future.set_result(None)
        return future

    def peek_index(self):
        from app.search.external_intelligence.evidence_index import empty_index

        return empty_index(FakeEmbeddings(), ScoredBy())  # type: ignore[arg-type]
