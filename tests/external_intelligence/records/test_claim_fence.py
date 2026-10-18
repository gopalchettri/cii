"""The claim is a fence against the real MongoDB: a heartbeat that keeps a long run alive, a takeover that
shuts the old worker out of every write, a revoke that does the same, and the reset that makes a re-approved
source load everything again."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, FeedStatus, IntelKind, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.repository import (
    IntelFeedRepository,
    IntelRecordRepository,
    intel_feeds,
    intel_records,
)
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord
from app.models.external_intelligence.source_health import (
    SourceHealth,
    refresh_success_fields,
)
from app.services.external_intelligence.record_batch_writer import (
    ClaimLost,
    write_fetch_result,
)

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.CISA_KEV
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


@pytest.fixture
def stores() -> tuple[IntelFeedRepository, IntelRecordRepository]:
    db = get_mongodb()
    for name in (Collection.EXTERNAL_FEED_STATUS, Collection.INTEL):
        db[name].delete_many({})
    feeds, records = intel_feeds, intel_records
    records.create_indexes()
    feeds.create_missing_intel_feeds()
    return feeds, records


def _result(version: str, count: int = 5) -> FetchResult:
    records = tuple(
        IntelRecord(
            SOURCE, f"CVE-{n}", IntelKind.VULNERABILITY, "IT", "t", f"{version} {n}", "https://x", version
        )
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


def test_a_revoked_source_refuses_the_heartbeat_of_a_run_in_flight(stores) -> None:
    feeds, _ = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    feeds.update_intel_feed_approval(SOURCE, False)
    assert feeds.renew_intel_feed_refresh(SOURCE, token, NOW) is False
    assert (
        SourceHealth.from_doc(feeds.get(_id=SOURCE)).claimed_at is None
    )  # the claim ended, nothing was renewed


def test_a_revoke_then_a_re_approve_still_shuts_the_run_in_flight_out(stores) -> None:
    """Before: the claim survived both, so the old run renewed it again and wrote on over the purge."""
    feeds, _ = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    feeds.update_intel_feed_approval(SOURCE, False)
    feeds.update_intel_feed_approval(SOURCE, True)
    assert feeds.renew_intel_feed_refresh(SOURCE, token, NOW) is False
    assert not feeds.release_intel_feed_refresh(
        SOURCE, token, refresh_success_fields("cp", "v", NOW, more=False, records=1)
    )
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)  # a new run may start at once


def test_two_workers_racing_a_takeover_never_both_write(stores) -> None:
    feeds, records = stores
    old = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    later = datetime.now(UTC) + STALE  # the old claim is stale for both racers

    def take_over(_: int) -> str | None:
        return intel_feeds.claim_intel_feed_refresh(SOURCE, later, later - STALE)

    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = [token for token in pool.map(take_over, range(16)) if token]
    assert len(tokens) == 1
    with pytest.raises(ClaimLost):  # the old worker wakes up: its first write is refused
        write_fetch_result(records, SOURCE, _result("old"), NOW, _owner(feeds, old))
    assert records.count(sources=[SOURCE], current=True) == 0
    write_fetch_result(records, SOURCE, _result("new"), NOW, _owner(feeds, tokens[0]))
    assert {doc["source_version"] for doc in records.stream_current_intel_records([SOURCE])} == {"new"}


def test_a_worker_that_loses_the_claim_between_batches_stops_there(stores) -> None:
    feeds, records = stores
    token = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    many = _result("v1", IntelLimits.BATCH_SIZE * 2 + 1)
    asked: list[int] = []

    def still_ours() -> bool:
        asked.append(1)
        if len(asked) == 2:  # lost after the first batch
            feeds.update_intel_feed_approval(SOURCE, False)
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


def test_a_revoked_source_starts_from_a_blank_health_when_it_is_approved_again(stores) -> None:
    feeds, _ = stores
    feeds.release_intel_feed_refresh(
        SOURCE,
        feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE),
        refresh_success_fields("cp", "v", NOW, more=True, records=9),
    )
    feeds.update_intel_feed_approval(SOURCE, False)
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert (health.checkpoint, health.records, health.last_success_at) == (None, 0, None)
    assert not bool(feeds.count(_id=SOURCE, approved=True)) and not bool(
        feeds.count(_id=SOURCE, more_pending=True)
    )
    feeds.update_intel_feed_approval(SOURCE, True)
    assert bool(feeds.count(_id=SOURCE, approved=True)) and feeds.claim_intel_feed_refresh(
        SOURCE, NOW, NOW - STALE
    )


def test_revoking_without_creating_changes_only_what_exists() -> None:
    db = get_mongodb()
    db[Collection.EXTERNAL_FEED_STATUS].drop()
    feeds = intel_feeds
    feeds.update_intel_feed_approval(SOURCE, False, create=False)
    assert Collection.EXTERNAL_FEED_STATUS not in db.list_collection_names()
    feeds.create_missing_intel_feeds()
    feeds.update_intel_feed_approval(SOURCE, False, create=False)
    assert not bool(feeds.count(_id=SOURCE, approved=True))
