"""The source registry against the real MongoDB: seed, atomic claims (also under threads), health."""

import dataclasses
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from structlog.testing import capture_logs

from app.core.constants import Collection, FeedStatus, IntelDocId, IntelKind, IntelLimits, IntelSource, LogEvent
from app.core.database import get_mongodb
from app.crud.intel import IntelFeedRepository, get_intel_feed_repository, get_intel_schedule_repository
from app.domain.intel import refresh
from app.schemas.intel_records import (
    FetchResult,
    IntelRecord,
    SourceHealth,
    refresh_failure_fields,
    refresh_success_fields,
    source_health_in_registry_order,
)
from tests.external_intelligence.evidence_fakes import MemoryKeeper, StubFetcher

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.ATTACK_ENTERPRISE
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


@pytest.fixture
def feeds() -> IntelFeedRepository:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    store = get_intel_feed_repository()
    store.create_missing_intel_feeds()
    return store


def test_the_seed_adds_every_source_never_run(feeds: IntelFeedRepository) -> None:
    health = source_health_in_registry_order(feeds.list(sources=True))
    assert [h.source for h in health] == list(IntelSource)
    assert all(h.status == FeedStatus.NEVER_RUN and h.checkpoint is None and h.records == 0 for h in health)


def test_the_seed_only_adds_and_never_resets_a_source(feeds: IntelFeedRepository) -> None:
    claim = feeds.claim_intel_feed_refresh(IntelSource.ATTACK_ICS, NOW, NOW - STALE)
    feeds.release_intel_feed_refresh(IntelSource.ATTACK_ICS, claim, refresh_success_fields("cp", "v", NOW, records=3))
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_one({"_id": SOURCE})
    feeds.create_missing_intel_feeds()
    assert SourceHealth.from_doc(feeds.get(_id=IntelSource.ATTACK_ICS)).checkpoint == "cp"  # not reset
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).status == FeedStatus.NEVER_RUN  # added again


def test_the_switch_document_in_the_same_collection_is_not_a_source(feeds: IntelFeedRepository) -> None:
    feeds.save({"_id": IntelDocId.SWITCH, "enabled": False, "changed_by": "admin", "changed_at": NOW})
    assert len(source_health_in_registry_order(feeds.list(sources=True))) == len(IntelSource)
    assert get_mongodb()[Collection.EXTERNAL_FEED_STATUS].count_documents({"_id": IntelDocId.SWITCH}) == 1


def _claim(feeds: IntelFeedRepository, now: datetime = NOW) -> str:
    token = feeds.claim_intel_feed_refresh(SOURCE, now, now - STALE)
    assert token
    return token


def test_a_source_is_claimed_once_until_it_is_released(feeds: IntelFeedRepository) -> None:
    token = _claim(feeds)
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE) is None
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).claimed_at is not None
    assert feeds.release_intel_feed_refresh(SOURCE, token, refresh_success_fields("cp1", "v1", NOW, records=5)) is True
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)  # released by success


def test_a_failure_releases_the_claim_and_keeps_the_last_good_checkpoint(feeds: IntelFeedRepository) -> None:
    feeds.release_intel_feed_refresh(SOURCE, _claim(feeds), refresh_success_fields("cp1", "v1", NOW, records=5))
    assert (
        feeds.release_intel_feed_refresh(
            SOURCE, _claim(feeds), refresh_failure_fields("boom" * 400, NOW + timedelta(hours=1))
        )
        is True
    )
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.checkpoint, health.claimed_at) == (FeedStatus.FAILED, "cp1", None)
    assert health.last_success_at == NOW and len(health.last_error) == 500
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)


def test_a_claim_of_a_dead_worker_is_taken_over_but_a_live_one_is_not(feeds: IntelFeedRepository) -> None:
    first = _claim(feeds)
    soon = NOW + STALE / 2
    assert feeds.claim_intel_feed_refresh(SOURCE, soon, soon - STALE) is None
    later = NOW + STALE + timedelta(seconds=1)
    second = _claim(feeds, later)
    assert second != first


def test_a_dead_worker_waking_late_cannot_release_the_newer_claim(feeds: IntelFeedRepository) -> None:
    old = _claim(feeds)
    new = _claim(feeds, NOW + STALE + timedelta(seconds=1))
    assert feeds.release_intel_feed_refresh(SOURCE, old, refresh_success_fields("stale", "v", NOW, records=1)) is False
    assert feeds.release_intel_feed_refresh(SOURCE, old, refresh_failure_fields("late", NOW)) is False
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.checkpoint, health.last_error) == (FeedStatus.NEVER_RUN, None, None)
    assert health.claimed_at is not None  # still held by the newer claim
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW + STALE, NOW) is None
    assert feeds.release_intel_feed_refresh(SOURCE, new, refresh_success_fields("cp", "v", NOW, records=2)) is True
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).checkpoint == "cp"


def test_a_released_token_cannot_be_used_twice(feeds: IntelFeedRepository) -> None:
    token = _claim(feeds)
    assert feeds.release_intel_feed_refresh(SOURCE, token, refresh_failure_fields("x", NOW)) is True
    assert feeds.release_intel_feed_refresh(SOURCE, token, refresh_success_fields("cp", "v", NOW, records=1)) is False
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).status == FeedStatus.FAILED


def test_many_workers_racing_for_one_source_give_exactly_one_token(feeds: IntelFeedRepository) -> None:
    def claim(_: int) -> str | None:
        return get_intel_feed_repository().claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(claim, range(64)))
    assert len([token for token in results if token]) == 1


def test_success_records_the_checkpoint_version_and_count(feeds: IntelFeedRepository) -> None:
    feeds.release_intel_feed_refresh(SOURCE, _claim(feeds), refresh_success_fields("cp", "ver", NOW, records=7))
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.checkpoint, health.source_version, health.records) == (FeedStatus.OK, "cp", "ver", 7)
    assert health.last_success_at == NOW and health.last_error is None
    assert SourceHealth.from_doc(feeds.get(_id=IntelSource.ATTACK_ICS)).status == FeedStatus.NEVER_RUN


def _import(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """One real import of every source (each giving one technique); the log lines it wrote."""
    record = IntelRecord(IntelSource.ATTACK_ENTERPRISE, "T1", IntelKind.TECHNIQUE, "IT", "t", "x", "https://x", "v")
    found = {s: FetchResult((dataclasses.replace(record, source=s),), (), "v", "v") for s in IntelSource}
    monkeypatch.setattr(refresh, "MitreAttackSource", lambda source: StubFetcher(source, found[source]))
    monkeypatch.setattr(refresh, "get_evidence_index_keeper", MemoryKeeper)
    monkeypatch.setattr(refresh, "apply_proxy_once", lambda: None)
    with capture_logs() as logs:
        refresh.refresh_all_sources(NOW)
    return [line for line in logs if line["event"] == LogEvent.EXTERNAL_INTELLIGENCE_REMOVED_SOURCES_DELETED]


def test_an_import_deletes_what_a_removed_source_left_and_keeps_the_rest(
    feeds: IntelFeedRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = get_mongodb()
    db[Collection.INTEL].delete_many({})
    feeds.save({"_id": IntelDocId.SWITCH, "enabled": True, "changed_by": "admin", "changed_at": NOW})
    get_intel_schedule_repository().create_missing_schedule({"enabled": True})
    db[Collection.EXTERNAL_FEED_STATUS].insert_one({"_id": "cisa_kev", "source": "cisa_kev", "status": "ok"})
    db[Collection.EXTERNAL_FEED_STATUS].insert_one({"_id": "a_newer_source", "source": "a_newer_source"})
    db[Collection.INTEL].insert_many([{"source": "cisa_kev", "external_id": f"CVE-{n}"} for n in range(3)])
    db[Collection.INTEL].insert_one({"source": "a_newer_source", "external_id": "N1"})  # a newer version's source
    first = _import(monkeypatch)
    assert [(line["records"], line["status_documents"]) for line in first] == [(3, 1)]
    kept = {doc["_id"] for doc in db[Collection.EXTERNAL_FEED_STATUS].find({}, {"_id": 1})}
    assert kept == {*IntelSource, IntelDocId.SWITCH, IntelDocId.SCHEDULE, "a_newer_source"}
    assert feeds.get(_id=IntelDocId.SWITCH)["enabled"] is True
    assert sorted(db[Collection.INTEL].distinct("source")) == sorted([*IntelSource, "a_newer_source"])
    assert _import(monkeypatch) == []  # nothing left to delete: no line
