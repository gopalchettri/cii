"""The claim is a fence against the real MongoDB: a heartbeat that keeps a long run alive, and a takeover
that shuts the old worker out of every write."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, FeedStatus, IntelKind, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.crud.intel import (
    IntelFeedRepository,
    IntelRecordRepository,
    get_intel_feed_repository,
    get_intel_record_repository,
)
from app.domain.intel.refresh import ClaimLost, write_fetch_result
from app.schemas.intel_records import FetchResult, IntelRecord, SourceHealth

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.ATTACK_ENTERPRISE
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


@pytest.fixture
def stores() -> tuple[IntelFeedRepository, IntelRecordRepository]:
    db = get_mongodb()
    for name in (Collection.EXTERNAL_FEED_STATUS, Collection.INTEL):
        db[name].delete_many({})
    feeds, records = get_intel_feed_repository(), get_intel_record_repository()
    records.create_indexes()
    feeds.create_missing_intel_feeds()
    return feeds, records


def _result(version: str, count: int = 5) -> FetchResult:
    records = tuple(
        IntelRecord(SOURCE, f"T{n}", IntelKind.TECHNIQUE, "IT", "t", f"{version} {n}", "https://x", version)
        for n in range(count)
    )
    return FetchResult(records, (), version, version)


def _owner(feeds: IntelFeedRepository, token: str):
    return lambda: feeds.renew_intel_feed_refresh(SOURCE, token, datetime.now(UTC))


def test_the_heartbeat_keeps_a_long_run_from_being_taken_over(stores) -> None:
    feeds, _ = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    renewed = NOW + STALE * 0.9  # the run is nearly as old as the limit and renews
    assert feeds.renew_intel_feed_refresh(SOURCE, token, renewed) is True
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).claimed_at == renewed
    later = NOW + STALE * 1.5  # older than the limit counted from the start, not from the heartbeat
    assert feeds.claim_intel_feed_refresh(SOURCE, later, later - STALE) is None


def test_a_taken_over_claim_cannot_be_renewed_and_the_new_owner_can(stores) -> None:
    feeds, _ = stores
    old = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    later = NOW + STALE + timedelta(seconds=1)
    new = feeds.claim_intel_feed_refresh(SOURCE, later, later - STALE)
    assert (
        new
        and not feeds.renew_intel_feed_refresh(SOURCE, old, later)
        and feeds.renew_intel_feed_refresh(SOURCE, new, later)
    )


def test_two_workers_racing_a_takeover_never_both_write(stores) -> None:
    feeds, records = stores
    old = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    later = datetime.now(UTC) + STALE  # the old claim is stale for both racers

    def take_over(_: int) -> str | None:
        return get_intel_feed_repository().claim_intel_feed_refresh(SOURCE, later, later - STALE)

    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = [token for token in pool.map(take_over, range(16)) if token]
    assert len(tokens) == 1
    with pytest.raises(ClaimLost):  # the old worker wakes up: its first write is refused
        write_fetch_result(records, SOURCE, _result("old"), NOW, _owner(feeds, old))
    assert records.count(sources=[SOURCE], current=True) == 0
    write_fetch_result(records, SOURCE, _result("new"), NOW, _owner(feeds, tokens[0]))
    assert {doc["source_version"] for doc in records.stream_current_intel_records()} == {"new"}


def test_a_worker_that_loses_the_claim_between_batches_stops_there(stores) -> None:
    feeds, records = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    many = _result("v1", IntelLimits.BATCH_SIZE * 2 + 1)
    asked: list[int] = []

    def still_ours() -> bool:
        asked.append(1)
        if len(asked) == 2:  # taken over after the first batch
            later = datetime.now(UTC) + STALE
            feeds.claim_intel_feed_refresh(SOURCE, later, later - STALE)
        return feeds.renew_intel_feed_refresh(SOURCE, token, datetime.now(UTC))

    with pytest.raises(ClaimLost):
        write_fetch_result(records, SOURCE, many, NOW, still_ours)
    assert records.count(sources=[SOURCE], current=True) == IntelLimits.BATCH_SIZE  # one batch, no more


def test_release_gives_the_claim_back_and_changes_nothing_else(stores) -> None:
    feeds, _ = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    assert feeds.release_intel_feed_refresh(SOURCE, "not-mine") is False
    assert feeds.release_intel_feed_refresh(SOURCE, token) is True
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.status, health.claimed_at, health.last_error) == (FeedStatus.NEVER_RUN, None, None)
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
