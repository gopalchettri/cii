"""Health (freshness per source, snapshot, switch) and the purge of a revoked source."""

from datetime import datetime, timedelta

import pytest

from app.core.constants import Collection, EmbeddingCorpus, FeedStatus, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.intel_vector_purge import IntelVectorPurge
from app.models.external_intelligence.source_health import SourceHealth
from app.models.external_intelligence.switch_state import SwitchState
from app.services.external_intelligence.health import HealthReporter
from app.services.external_intelligence.purge_revoked_source import RevokedSourcePurger
from app.worker.external_intelligence import intel_access
from app.worker.external_intelligence.intel_access import IntelAccess
from tests.external_intelligence.evidence_fakes import (
    NOW,
    MemoryFeeds,
    MemoryKeeper,
    MemoryPointer,
    MemoryRecords,
)
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds

KEV, EPSS, NVD = IntelSource.CISA_KEV, IntelSource.FIRST_EPSS, IntelSource.NIST_NVD


class FixedSwitch:
    def state(self) -> SwitchState:
        return SwitchState(True, False, NOW, "admin")


def _reporter(feeds: MemoryFeeds, pointer: MemoryPointer) -> HealthReporter:
    return HealthReporter(feeds, pointer, FixedSwitch(), MemoryKeeper())  # type: ignore[arg-type]


def _fresh(source: IntelSource, hours: float) -> SourceHealth:
    return SourceHealth(source, FeedStatus.OK, "c", "v", 5, NOW, NOW - timedelta(hours=hours))


def test_health_shows_each_source_the_snapshot_the_switch_and_whether_anything_is_stale() -> None:
    feeds, pointer = MemoryFeeds([KEV, EPSS]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 1)}
    pointer.active = {"snapshot_id": "snap-1", "checksum": "c"}
    report = _reporter(feeds, pointer).describe_health(NOW)
    assert (report.snapshot_id, report.stale, len(report.sources)) == ("snap-1", False, 2)
    assert report.switch.runtime_enabled is False and report.as_doc()["switch"]["effective"] is False
    feeds.health[EPSS] = _fresh(EPSS, IntelLimits.STALE_AFTER_HOURS + 1)
    assert _reporter(feeds, pointer).describe_health(NOW).stale


def test_a_never_run_source_is_pending_not_stale_while_the_others_are_fresh() -> None:
    """The live run: five sources refreshed, NVD's first pass (hours) not yet. That is no staleness."""
    feeds, pointer = MemoryFeeds([KEV, EPSS, NVD]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 2), NVD: SourceHealth(NVD)}
    report = _reporter(feeds, pointer).describe_health(NOW)
    assert not report.stale and report.pending_sources == (NVD,) and not report.no_data
    assert report.as_doc()["pending_sources"] == ["nist_nvd"]


def test_a_source_with_data_older_than_the_limit_is_stale_even_beside_a_pending_one() -> None:
    feeds, pointer = MemoryFeeds([KEV, NVD]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, IntelLimits.STALE_AFTER_HOURS + 1), NVD: SourceHealth(NVD)}
    report = _reporter(feeds, pointer).describe_health(NOW)
    assert report.stale and report.pending_sources == (NVD,)


def test_when_no_source_ever_succeeded_there_is_no_data_and_nothing_is_stale() -> None:
    feeds, pointer = MemoryFeeds([KEV, EPSS]), MemoryPointer()
    feeds.health = {KEV: SourceHealth(KEV), EPSS: SourceHealth(EPSS, FeedStatus.FAILED, last_attempt_at=NOW)}
    report = _reporter(feeds, pointer).describe_health(NOW)
    assert report.no_data and not report.stale and report.snapshot_id is None  # no pointer, empty index
    assert set(report.pending_sources) == {KEV, EPSS}


def test_a_revoked_source_counts_neither_as_stale_nor_as_pending() -> None:
    feeds, pointer = MemoryFeeds([KEV]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 1000), NVD: SourceHealth(NVD)}
    report = _reporter(feeds, pointer).describe_health(NOW)
    assert not report.stale and report.pending_sources == () and not report.no_data


def test_the_worker_search_flag_follows_the_same_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    feeds = MemoryFeeds([KEV, NVD])
    feeds.health = {KEV: _fresh(KEV, 1), NVD: SourceHealth(NVD)}
    monkeypatch.setattr(intel_access, "FeedStatusStore", lambda _db: feeds)
    monkeypatch.setattr(intel_access, "get_mongodb", lambda: None)
    monkeypatch.setattr(intel_access, "datetime", _FixedClock)
    assert IntelAccess()._feeds_are_stale() is False  # noqa: SLF001
    feeds.health[KEV] = _fresh(KEV, IntelLimits.STALE_AFTER_HOURS + 1)
    assert IntelAccess()._feeds_are_stale() is True  # noqa: SLF001


class _FixedClock:
    @staticmethod
    def now(_tz: object = None) -> datetime:
        return NOW


class MemoryVectors:
    def __init__(self) -> None:
        self.purged: list[IntelSource] = []

    def purge_source_vectors(self, source: IntelSource) -> int:
        self.purged.append(source)
        return 1


def test_a_revoked_source_is_unapproved_first_then_its_records_and_vectors_go_and_the_index_is_rebuilt() -> (
    None
):
    feeds, records, keeper, vectors = (
        ClaimFeeds([KEV, EPSS]),
        MemoryRecords(),
        MemoryKeeper(),
        MemoryVectors(),
    )
    order: list[str] = []
    original = records.purge_source
    records.purge_source = lambda s: (order.append(f"records approved={KEV in feeds.approved}"), original(s))[
        1
    ]  # type: ignore[method-assign]
    purger = RevokedSourcePurger(records, feeds, keeper, vectors)  # type: ignore[arg-type]
    assert purger.revoke_and_purge(KEV) == 1
    assert order == ["records approved=False"] and vectors.purged == [KEV] and keeper.rebuilds == 1
    assert feeds.approved == [EPSS]


def test_a_failed_rebuild_does_not_undo_the_purge() -> None:
    feeds, records, vectors = ClaimFeeds([KEV]), MemoryRecords(), MemoryVectors()
    purger = RevokedSourcePurger(records, feeds, MemoryKeeper(fail=True), vectors)  # type: ignore[arg-type]
    assert purger.revoke_and_purge(KEV) == 1 and records.purged == [KEV]


def test_cached_vectors_of_a_revoked_source_are_deleted_but_a_shared_vector_stays() -> None:
    db = get_mongodb()
    vectors = db[Collection.EMBEDDINGS]
    corpus = EmbeddingCorpus.EXTERNAL_INTELLIGENCE
    mine = {"_id": "t|mine", "corpus": corpus, "sources": [{"id": "cisa_kev/CVE-1"}], "text": "x"}
    shared = {
        "_id": "t|shared",
        "corpus": corpus,
        "sources": [{"id": "cisa_kev/CVE-2"}, {"id": "first_epss/CVE-2"}],
    }
    other = {"_id": "t|other", "corpus": corpus, "sources": [{"id": "first_epss/CVE-3"}]}
    library = {"_id": "t|library", "corpus": "controls", "sources": [{"id": "cisa_kev/CVE-1"}]}
    vectors.delete_many({"_id": {"$in": [d["_id"] for d in (mine, shared, other, library)]}})
    vectors.insert_many([mine, shared, other, library])
    try:
        assert IntelVectorPurge(db).purge_source_vectors(KEV) == 1
        left = {doc["_id"] for doc in vectors.find({"_id": {"$regex": "^t\\|"}})}
        assert left == {"t|shared", "t|other", "t|library"}
    finally:
        vectors.delete_many({"_id": {"$regex": "^t\\|"}})
