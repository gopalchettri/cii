"""The source registry against the real MongoDB: seed, approval, atomic claims (also under threads),
health."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, FeedStatus, IntelDocId, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.switch_flag_store import SwitchFlagStore

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.CISA_KEV
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


@pytest.fixture
def feeds() -> FeedStatusStore:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    store = FeedStatusStore(db)
    store.seed_sources()
    return store


def test_the_seed_adds_every_source_approved_and_never_run(feeds: FeedStatusStore) -> None:
    assert feeds.list_approved_sources() == list(IntelSource)
    health = feeds.read_all_source_health()
    assert [h.source for h in health] == list(IntelSource)
    assert all(h.status == FeedStatus.NEVER_RUN and h.checkpoint is None and h.records == 0 for h in health)
    assert feeds.is_more_pending(SOURCE) is False


def test_the_seed_never_undoes_an_operators_revocation_and_only_adds(feeds: FeedStatusStore) -> None:
    feeds.revoke_source(SOURCE)
    claim = feeds.claim_source_for_refresh(IntelSource.NIST_NVD, NOW, NOW - STALE)
    feeds.record_refresh_success(IntelSource.NIST_NVD, claim, "cp", "v", NOW, more=False, records=3)
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_one({"_id": IntelSource.FIRST_EPSS})
    feeds.seed_sources()
    assert not feeds.is_source_approved(SOURCE) and feeds.is_source_approved(IntelSource.FIRST_EPSS)
    assert feeds.read_source_health(IntelSource.NIST_NVD).checkpoint == "cp"  # not reset
    assert SOURCE not in feeds.list_approved_sources()


def test_a_revocation_before_the_seed_is_kept() -> None:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    store = FeedStatusStore(db)
    store.revoke_source(SOURCE)
    store.seed_sources()
    assert not store.is_source_approved(SOURCE) and len(store.read_all_source_health()) == len(IntelSource)


def test_the_switch_document_in_the_same_collection_is_not_a_source(feeds: FeedStatusStore) -> None:
    SwitchFlagStore(get_mongodb()).write_runtime_flag(False, "admin", NOW)
    assert len(feeds.read_all_source_health()) == len(IntelSource)
    assert get_mongodb()[Collection.EXTERNAL_FEED_STATUS].count_documents({"_id": IntelDocId.SWITCH}) == 1


def _claim(feeds: FeedStatusStore, now: datetime = NOW) -> str:
    token = feeds.claim_source_for_refresh(SOURCE, now, now - STALE)
    assert token
    return token


def test_a_source_is_claimed_once_until_it_is_released(feeds: FeedStatusStore) -> None:
    token = _claim(feeds)
    assert feeds.claim_source_for_refresh(SOURCE, NOW, NOW - STALE) is None
    assert feeds.read_source_health(SOURCE).claimed_at is not None
    assert feeds.record_refresh_success(SOURCE, token, "cp1", "v1", NOW, more=True, records=5) is True
    assert feeds.claim_source_for_refresh(SOURCE, NOW, NOW - STALE)  # released by success


def test_a_failure_releases_the_claim_and_keeps_the_last_good_checkpoint(feeds: FeedStatusStore) -> None:
    feeds.record_refresh_success(SOURCE, _claim(feeds), "cp1", "v1", NOW, more=False, records=5)
    assert feeds.record_refresh_failure(SOURCE, _claim(feeds), "boom" * 400, NOW + timedelta(hours=1)) is True
    health = feeds.read_source_health(SOURCE)
    assert (health.status, health.checkpoint, health.claimed_at) == (FeedStatus.FAILED, "cp1", None)
    assert health.last_success_at == NOW and len(health.last_error) == 500
    assert feeds.claim_source_for_refresh(SOURCE, NOW, NOW - STALE)


def test_a_claim_of_a_dead_worker_is_taken_over_but_a_live_one_is_not(feeds: FeedStatusStore) -> None:
    first = _claim(feeds)
    soon = NOW + STALE / 2
    assert feeds.claim_source_for_refresh(SOURCE, soon, soon - STALE) is None
    later = NOW + STALE + timedelta(seconds=1)
    second = _claim(feeds, later)
    assert second != first


def test_a_dead_worker_waking_late_cannot_release_the_newer_claim(feeds: FeedStatusStore) -> None:
    old = _claim(feeds)
    new = _claim(feeds, NOW + STALE + timedelta(seconds=1))
    assert feeds.record_refresh_success(SOURCE, old, "stale", "v", NOW, more=False, records=1) is False
    assert feeds.record_refresh_failure(SOURCE, old, "late", NOW) is False
    health = feeds.read_source_health(SOURCE)
    assert (health.status, health.checkpoint, health.last_error) == (FeedStatus.NEVER_RUN, None, None)
    assert health.claimed_at is not None  # still held by the newer claim
    assert feeds.claim_source_for_refresh(SOURCE, NOW + STALE, NOW) is None
    assert feeds.record_refresh_success(SOURCE, new, "cp", "v", NOW, more=False, records=2) is True
    assert feeds.read_source_health(SOURCE).checkpoint == "cp"


def test_a_released_token_cannot_be_used_twice(feeds: FeedStatusStore) -> None:
    token = _claim(feeds)
    assert feeds.record_refresh_failure(SOURCE, token, "x", NOW) is True
    assert feeds.record_refresh_success(SOURCE, token, "cp", "v", NOW, more=False, records=1) is False
    assert feeds.read_source_health(SOURCE).status == FeedStatus.FAILED


def test_a_revoked_source_cannot_be_claimed(feeds: FeedStatusStore) -> None:
    feeds.revoke_source(SOURCE)
    assert feeds.claim_source_for_refresh(SOURCE, NOW, NOW - STALE) is None
    feeds.approve_source(SOURCE)
    assert feeds.claim_source_for_refresh(SOURCE, NOW, NOW - STALE)


def test_many_workers_racing_for_one_source_give_exactly_one_token(feeds: FeedStatusStore) -> None:
    def claim(_: int) -> str | None:
        return FeedStatusStore(get_mongodb()).claim_source_for_refresh(SOURCE, NOW, NOW - STALE)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(claim, range(64)))
    assert len([token for token in results if token]) == 1


def test_success_records_the_checkpoint_version_count_and_more(feeds: FeedStatusStore) -> None:
    feeds.record_refresh_success(SOURCE, _claim(feeds), "cp", "ver", NOW, more=True, records=7)
    health = feeds.read_source_health(SOURCE)
    assert (health.status, health.checkpoint, health.source_version, health.records) == (
        FeedStatus.OK,
        "cp",
        "ver",
        7,
    )
    assert health.last_success_at == NOW and health.last_error is None and feeds.is_more_pending(SOURCE)
    assert feeds.read_source_health(IntelSource.CISA_ICS).status == FeedStatus.NEVER_RUN
