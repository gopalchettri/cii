"""A worker killed in the middle of a refresh: the re-run reaches the same final state, with no duplicates,
and the checkpoint moved only after the records were stored."""

from datetime import UTC, datetime, timedelta

import pytest

from app import container
from app.core.constants import Collection, IntelKind, IntelLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord
from app.models.external_intelligence.source_health import (
    SourceHealth,
    refresh_success_fields,
)

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)
SOURCE = IntelSource.CISA_KEV
STALE = timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


class Killed(Exception):
    pass


def _result() -> FetchResult:
    records = tuple(
        IntelRecord(
            SOURCE,
            f"CVE-2024-{n:04d}",
            IntelKind.VULNERABILITY,
            "IT",
            "t",
            f"text {n}",
            "https://x.test",
            "v2",
        )
        for n in range(40)
    )
    return FetchResult(records, (), "v2", "v2")


@pytest.fixture
def stores() -> tuple[IntelRecordRepository, IntelFeedRepository]:
    db = get_mongodb()
    for name in (Collection.INTEL, Collection.EXTERNAL_FEED_STATUS):
        db[name].delete_many({})
    records, feeds = container.get_intel_record_repository(), container.get_intel_feed_repository()
    records.create_indexes()
    feeds.create_missing_intel_feeds()
    claim = feeds.claim_intel_feed_refresh(SOURCE, NOW - timedelta(days=1), NOW - timedelta(days=2))
    feeds.release_intel_feed_refresh(
        SOURCE, claim, refresh_success_fields("v1", "v1", NOW - timedelta(days=1), more=False, records=0)
    )
    return records, feeds


def _run(
    records: IntelRecordRepository, feeds: IntelFeedRepository, now: datetime, kill_after: int | None = None
) -> bool:
    """The order a refresher must follow: claim, fetch, store in order, and only then move the checkpoint."""
    claim = feeds.claim_intel_feed_refresh(SOURCE, now, now - STALE)
    if claim is None:
        return False
    result = _result()
    try:
        for start in range(0, len(result.records), 10):
            if kill_after is not None and start >= kill_after:
                raise Killed
            records.save_intel_records(result.records[start : start + 10], [], now)
        count = len(result.records)
        feeds.release_intel_feed_refresh(
            SOURCE,
            claim,
            refresh_success_fields(result.checkpoint, result.source_version, now, more=False, records=count),
        )
    except Killed:
        pass  # the process is gone: no failure is recorded and the claim is left behind
    return True


def _state() -> list[dict]:
    docs = get_mongodb()[Collection.INTEL].find({}, {"_id": 0, "fetched_at": 0})
    return sorted(docs, key=lambda doc: doc["external_id"])


def test_a_batch_half_stored_then_rerun_gives_the_state_of_one_clean_run(stores) -> None:
    records, feeds = stores
    _run(records, feeds, NOW)
    clean = _state()
    get_mongodb()[Collection.INTEL].delete_many({})
    claim = feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)
    feeds.release_intel_feed_refresh(
        SOURCE, claim, refresh_success_fields("v1", "v1", NOW, more=False, records=0)
    )

    day2 = NOW + timedelta(days=1)
    _run(records, feeds, day2, kill_after=20)
    assert 0 < len(_state()) < 40  # half stored
    health = SourceHealth.from_doc(feeds.get(_id=SOURCE))
    assert health.checkpoint == "v1" and health.claimed_at is not None  # the checkpoint did not move

    assert _run(records, feeds, day2 + STALE + timedelta(minutes=1))  # the dead worker's claim is taken over
    assert _state() == clean and len({doc["external_id"] for doc in _state()}) == 40
    assert SourceHealth.from_doc(feeds.get(_id=SOURCE)).checkpoint == "v2"


def test_a_second_trigger_while_a_refresh_runs_does_not_start_another(stores) -> None:
    records, feeds = stores
    assert feeds.claim_intel_feed_refresh(SOURCE, NOW, NOW - STALE)  # the first trigger
    assert _run(records, feeds, NOW + timedelta(seconds=5)) is False  # the double trigger gets False
    assert _state() == []
