"""A refresh that must stop writing: a claim taken over mid-run, a feed cut short. A worker that lost its
claim writes no more, and a truncated feed keeps the last good data."""

import pytest

from app.core.constants import IntelKind, IntelLimits, IntelMessage, IntelSource
from app.schemas.intel_records import FetchResult, IntelRecord, RefreshResult
from tests.external_intelligence.evidence_fakes import NOW, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords, use_refresh_parts

ENT = IntelSource.ATTACK_ENTERPRISE
BATCHES = 3


def result(count: int, *, prefix: str = "T") -> FetchResult:
    records = tuple(
        IntelRecord(ENT, f"{prefix}-{n}", IntelKind.TECHNIQUE, "IT", "t", f"{n} t", "https://x", "v1")
        for n in range(count)
    )
    return FetchResult(records, (), "v1", "v1")


def build(monkeypatch: pytest.MonkeyPatch, fetched: FetchResult, current: int = 0):
    feeds, records = ClaimFeeds([ENT]), CurrentRecords([f"T-{n}" for n in range(current)])
    fetchers = {ENT: StubFetcher(ENT, fetched)}
    run = use_refresh_parts(monkeypatch, fetchers, records=records, feeds=feeds, keeper=MemoryKeeper())
    return run, feeds, records


def three_batches() -> FetchResult:
    return result(IntelLimits.BATCH_SIZE * (BATCHES - 1) + 5)


def test_the_claim_is_renewed_before_every_batch_and_before_the_retirement(monkeypatch: pytest.MonkeyPatch) -> None:
    run, feeds, records = build(monkeypatch, three_batches())
    run.refresh_all_sources(NOW)
    assert feeds.renewals == BATCHES + 1


def test_a_worker_that_lost_its_claim_mid_run_writes_nothing_more_and_changes_no_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, feeds, records = build(monkeypatch, three_batches())
    records.after_save = lambda saved: feeds.claimed.update({ENT: "the-new-owner"}) if saved == 1 else None
    summary = run.refresh_all_sources(NOW)
    assert summary.sources[0].result == RefreshResult.CLAIM_LOST and summary.failed == ()
    assert len(records.saved) == 1 and records.retired == []
    assert feeds.successes == [] and feeds.failures == []  # the new owner's claim and status are untouched
    assert feeds.claimed == {ENT: "the-new-owner"}


def test_a_claim_taken_over_during_the_download_means_nothing_is_written(monkeypatch: pytest.MonkeyPatch) -> None:
    feeds, records = ClaimFeeds([ENT]), CurrentRecords()

    class TakenOver(StubFetcher):
        def download_changes(self, checkpoint):
            feeds.claimed[ENT] = "the-new-owner"
            return super().download_changes(checkpoint)

    fetchers = {ENT: TakenOver(ENT, result(3))}
    run = use_refresh_parts(monkeypatch, fetchers, records=records, feeds=feeds, keeper=MemoryKeeper())
    assert run.refresh_all_sources(NOW).sources[0].result == RefreshResult.CLAIM_LOST
    assert records.saved == []


def test_a_feed_cut_short_is_a_failed_fetch_that_stores_and_retires_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    run, feeds, records = build(monkeypatch, result(5), current=1500)
    summary = run.refresh_all_sources(NOW)
    assert summary.failed == (ENT,) and records.saved == [] and records.retired == []
    expected = IntelMessage.CUT_SHORT.format(source=ENT, kept=5, current=1500)
    assert feeds.failures == [(ENT, expected)] and feeds.successes == []


@pytest.mark.parametrize(("delivered", "refused"), [(1350, False), (750, False), (749, True), (0, True)])
def test_the_retire_rule_lets_a_real_shrink_pass_and_stops_a_collapse(
    delivered: int, refused: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = 1500
    assert IntelLimits.MIN_RETIRE_RATIO * current == 750
    fetched = result(delivered) if delivered else result(1, prefix="OTHER")  # the first ids of the current ones
    run, feeds, records = build(monkeypatch, fetched, current)
    summary = run.refresh_all_sources(NOW)
    assert (summary.failed == (ENT,)) is refused
    assert bool(records.retired) is not refused


def test_the_first_load_is_not_judged_by_the_ratio(monkeypatch: pytest.MonkeyPatch) -> None:
    first, feeds, records = build(monkeypatch, result(5))  # nothing current yet
    assert first.refresh_all_sources(NOW).failed == ()
