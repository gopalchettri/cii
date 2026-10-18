"""The source registry against the real MongoDB: seed, approval, atomic claims (also under threads),
health."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, FeedStatus, IntelDocId, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.repository import (
    IntelFeedRepository,
    intel_feeds,
)
from app.models.external_intelligence.source_health import (
    SourceHealth,
    refresh_failure_fields,
    refresh_success_fields,
    source_health_in_registry_order,
    sources_in_registry_order,
)

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.CISA_KEV
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


@pytest.fixture
def feeds() -> IntelFeedRepository:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    store = intel_feeds
    store.create_missing_intel_feeds()
    return store


def test_the_seed_adds_every_source_approved_and_never_run(feeds: IntelFeedRepository) -> None:
    assert sources_in_registry_order(feeds.list(["_id"], sources=True, approved=True)) == list(IntelSource)
    health = source_health_in_registry_order(feeds.list(sources=True))
    assert [h.source for h in health] == list(IntelSource)
    assert all(h.status == FeedStatus.NEVER_RUN and h.checkpoint is None and h.records == 0 for h in health)
    assert bool(feeds.count(_id=SOURCE, more_pending=True)) is False


def test_the_seed_never_undoes_an_operators_revocation_and_only_adds(feeds: IntelFeedRepository) -> None:
    feeds.update_intel_feed_approval(SOURCE, False)
    claim = feeds.claim_intel_feed_refresh(IntelSource.NIST_NVD, NOW, NOW - STALE)
    feeds.release_intel_feed_refresh(
        IntelSource.NIST_NVD, claim, refresh_success_fields("cp", "v", NOW, more=False, records=3)
    )
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_one({"_id": IntelSource.FIRST_EPSS})
    feeds.create_missing_intel_feeds()
    assert not bool(feeds.count(_id=SOURCE, approved=True)) and bool(
        feeds.count(_id=IntelSource.FIRST_EPSS, approved=True)
    )
    assert SourceHealth.from_doc(feeds.get(_id=IntelSource.NIST_NVD)).checkpoint == "cp"  # not reset
    assert SOURCE not in sources_in_registry_order(feeds.list(["_id"], sources=True, approved=True))


def test_a_revocation_before_the_seed_is_kept() -> None:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    store = intel_feeds
    store.update_intel_feed_approval(SOURCE, False)
    store.create_missing_intel_feeds()
    assert not bool(store.count(_id=SOURCE, approved=True)) and len(
        source_health_in_registry_order(store.list(sources=True))
    ) == len(IntelSource)


def test_the_switch_document_in_the_same_collection_is_not_a_source(feeds: IntelFeedRepository) -> None:
    intel_feeds.save({"_id": IntelDocId.SWITCH, "enabled": False, "changed_by": "admin", "changed_at": NOW})
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
    assert (
        feeds.release_intel_feed_refresh(
            SOURCE, token, refresh_success_fields("cp1", "v1", NOW, more=True, records=5)
        )
        is True
    )
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)  # released by success


def test_a_failure_releases_the_claim_and_keeps_the_last_good_checkpoint(feeds: IntelFeedRepository) -> None:
    feeds.release_intel_feed_refresh(
        SOURCE, _claim(feeds), refresh_success_fields("cp1", "v1", NOW, more=False, records=5)
    )
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
    assert (
        feeds.release_intel_feed_refresh(
            SOURCE, old, refresh_success_fields("stale", "v", NOW, more=False, records=1)
        )
        is False
    )
    assert feeds.release_intel_feed_refresh(SOURCE, old, refresh_failure_fields("late", NOW)) is False
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.checkpoint, health.last_error) == (FeedStatus.NEVER_RUN, None, None)
    assert health.claimed_at is not None  # still held by the newer claim
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW + STALE, NOW) is None
    assert (
        feeds.release_intel_feed_refresh(
            SOURCE, new, refresh_success_fields("cp", "v", NOW, more=False, records=2)
        )
        is True
    )
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).checkpoint == "cp"


def test_a_released_token_cannot_be_used_twice(feeds: IntelFeedRepository) -> None:
    token = _claim(feeds)
    assert feeds.release_intel_feed_refresh(SOURCE, token, refresh_failure_fields("x", NOW)) is True
    assert (
        feeds.release_intel_feed_refresh(
            SOURCE, token, refresh_success_fields("cp", "v", NOW, more=False, records=1)
        )
        is False
    )
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).status == FeedStatus.FAILED


def test_a_revoked_source_cannot_be_claimed(feeds: IntelFeedRepository) -> None:
    feeds.update_intel_feed_approval(SOURCE, False)
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE) is None
    feeds.update_intel_feed_approval(SOURCE, True)
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)


def test_many_workers_racing_for_one_source_give_exactly_one_token(feeds: IntelFeedRepository) -> None:
    def claim(_: int) -> str | None:
        return intel_feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(claim, range(64)))
    assert len([token for token in results if token]) == 1


def test_success_records_the_checkpoint_version_count_and_more(feeds: IntelFeedRepository) -> None:
    feeds.release_intel_feed_refresh(
        SOURCE, _claim(feeds), refresh_success_fields("cp", "ver", NOW, more=True, records=7)
    )
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.checkpoint, health.source_version, health.records) == (
        FeedStatus.OK,
        "cp",
        "ver",
        7,
    )
    assert (
        health.last_success_at == NOW
        and health.last_error is None
        and bool(feeds.count(_id=SOURCE, more_pending=True))
    )
    assert SourceHealth.from_doc(feeds.get(_id=IntelSource.CISA_ICS)).status == FeedStatus.NEVER_RUN
