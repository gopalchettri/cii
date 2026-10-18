"""A refresh that must stop writing: a revoke between its batches, a claim taken over mid-run, a feed cut
short. Nothing of a revoked source is left, a worker that lost its claim writes no more, and a truncated
feed keeps the last good data."""

import pytest

from app.core.constants import IntelKind, IntelLimits, IntelOperationsLimits, IntelSource
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord
from app.models.external_intelligence.refresh_summary import RefreshResult
from app.services.external_intelligence.record_batch_writer import RefreshMessage
from app.services.external_intelligence.refresh_sources import SourceRefresher
from tests.external_intelligence.evidence_fakes import NOW, MemoryCatalogue, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords

KEV = IntelSource.CISA_KEV
BATCHES = 3


def result(count: int, *, prefix: str = "CVE", **flags: bool) -> FetchResult:
    records = tuple(
        IntelRecord(KEV, f"{prefix}-{n}", IntelKind.VULNERABILITY, "IT", "t", f"{n} t", "https://x", "v1")
        for n in range(count)
    )
    return FetchResult(records, (), "v1", "v1", **flags)


def build(fetched: FetchResult, current: int = 0):
    feeds, records = ClaimFeeds([KEV]), CurrentRecords([f"CVE-{n}" for n in range(current)])
    run = SourceRefresher(
        MemoryCatalogue({KEV: StubFetcher(KEV, fetched)}),
        records,
        feeds,
        MemoryKeeper(),  # type: ignore[arg-type]
    )
    return run, feeds, records


def three_batches() -> FetchResult:
    return result(IntelLimits.BATCH_SIZE * (BATCHES - 1) + 5)


def test_a_revoke_between_two_batches_stops_the_refresh_and_leaves_no_record_of_the_source() -> None:
    run, feeds, records = build(three_batches())
    records.after_save = lambda saved: feeds.revoke_source(KEV) if saved == 1 else None
    summary = run.refresh_due_sources(NOW)
    assert summary.sources[0].result == RefreshResult.CLAIM_LOST
    assert len(records.saved) == 1  # the second batch was refused: the claim does not hold a revoked source
    assert records.purged == [KEV] and feeds.successes == [] and records.retired == []


def test_a_revoke_during_the_last_batch_is_purged_by_the_refresh_itself() -> None:
    run, feeds, records = build(three_batches())
    records.after_save = lambda saved: feeds.revoke_source(KEV) if saved == BATCHES else None
    summary = run.refresh_due_sources(NOW)
    assert len(records.saved) == BATCHES and records.purged == [KEV]  # all written, then deleted again
    assert summary.sources[0].result == RefreshResult.CLAIM_LOST and feeds.successes == []


def test_a_revoke_after_the_last_write_is_purged_and_the_run_is_recorded_as_revoked() -> None:
    run, feeds, records = build(three_batches())
    records.after_retire = lambda: feeds.revoke_source(KEV)
    summary = run.refresh_due_sources(NOW)
    assert records.purged == [KEV] and feeds.successes == [] and summary.failed == (KEV,)
    assert "revoked" in summary.sources[0].error


def test_an_approved_source_is_never_purged_by_its_own_refresh() -> None:
    run, feeds, records = build(three_batches())
    run.refresh_due_sources(NOW)
    assert records.purged == [] and len(feeds.successes) == 1


def test_the_claim_is_renewed_before_every_batch_and_before_the_retirement() -> None:
    run, feeds, records = build(three_batches())
    run.refresh_due_sources(NOW)
    assert feeds.renewals == BATCHES + 1


def test_a_worker_that_lost_its_claim_mid_run_writes_nothing_more_and_changes_no_status() -> None:
    run, feeds, records = build(three_batches())
    records.after_save = lambda saved: feeds.claimed.update({KEV: "the-new-owner"}) if saved == 1 else None
    summary = run.refresh_due_sources(NOW)
    assert summary.sources[0].result == RefreshResult.CLAIM_LOST and summary.failed == ()
    assert len(records.saved) == 1 and records.retired == []
    assert feeds.successes == [] and feeds.failures == []  # the new owner's claim and status are untouched
    assert feeds.claimed == {KEV: "the-new-owner"}


def test_a_claim_taken_over_during_the_download_means_nothing_is_written() -> None:
    feeds, records = ClaimFeeds([KEV]), CurrentRecords()

    class TakenOver(StubFetcher):
        def download_changes(self, checkpoint):
            feeds.claimed[KEV] = "the-new-owner"
            return super().download_changes(checkpoint)

    run = SourceRefresher(MemoryCatalogue({KEV: TakenOver(KEV, result(3))}), records, feeds, MemoryKeeper())  # type: ignore[arg-type]
    assert run.refresh_due_sources(NOW).sources[0].result == RefreshResult.CLAIM_LOST
    assert records.saved == []


def test_a_feed_cut_short_is_a_failed_fetch_that_stores_and_retires_nothing() -> None:
    run, feeds, records = build(result(5), current=1500)
    summary = run.refresh_due_sources(NOW)
    assert summary.failed == (KEV,) and records.saved == [] and records.retired == []
    expected = RefreshMessage.CUT_SHORT.format(source=KEV, kept=5, current=1500)
    assert feeds.failures == [(KEV, expected)] and feeds.successes == []


@pytest.mark.parametrize(("delivered", "refused"), [(1350, False), (750, False), (749, True), (0, True)])
def test_the_retire_rule_lets_a_real_shrink_pass_and_stops_a_collapse(delivered: int, refused: bool) -> None:
    current = 1500
    assert IntelOperationsLimits.MIN_RETIRE_RATIO * current == 750
    fetched = (
        result(delivered) if delivered else result(1, prefix="OTHER")
    )  # the first ids of the current ones
    run, feeds, records = build(fetched, current)
    summary = run.refresh_due_sources(NOW)
    assert (summary.failed == (KEV,)) is refused
    assert bool(records.retired) is not refused


def test_the_first_load_and_a_partial_pass_are_not_judged_by_the_ratio() -> None:
    first, feeds, records = build(result(5))  # nothing current yet
    assert first.refresh_due_sources(NOW).failed == ()
    partial, feeds, records = build(result(5, partial=True), current=1500)
    assert partial.refresh_due_sources(NOW).failed == () and records.retired == []
