"""Refreshing the sources: due-ness, single flight, checkpoint safety, retirement, a failure's claim."""

import dataclasses
from datetime import timedelta

import pytest

from app import container
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    REFRESH_AFTER_HOURS,
    AiOutage,
    IntelKind,
    IntelLimits,
    IntelMessage,
    IntelSource,
)
from app.core.exceptions import IntelFetchFailed, Unavailable
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord
from app.models.external_intelligence.refresh_summary import RefreshResult
from app.models.external_intelligence.source_health import (
    SourceHealth,
)
from app.search.external_intelligence.evidence_index import EvidenceIndexRefused
from app.worker.external_intelligence.refresh_sources import SourceRefresher
from tests.external_intelligence.evidence_fakes import NOW, MemoryCatalogue, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords

KEV, EPSS = IntelSource.CISA_KEV, IntelSource.FIRST_EPSS


def result(*ids: str, version: str = "v1", **flags: bool) -> FetchResult:
    records = tuple(
        IntelRecord(KEV, i, IntelKind.VULNERABILITY, "IT", i, f"{i} t", "https://x", version) for i in ids
    )
    return FetchResult(records, (), version, version, **flags)


def refresher(fetchers: dict, approved=None, keeper=None):
    feeds, records = ClaimFeeds(approved), CurrentRecords()
    keeper = keeper or MemoryKeeper()
    audit = container.get_audit_repository()
    run = SourceRefresher(MemoryCatalogue(fetchers), records, feeds, keeper, audit)  # type: ignore[arg-type]
    return run, feeds, records, keeper


def test_a_first_refresh_stores_in_batches_moves_the_checkpoint_and_rebuilds_the_index() -> None:
    many = result(*(f"CVE-{n}" for n in range(IntelLimits.BATCH_SIZE + 5)))
    run, feeds, records, keeper = refresher({KEV: StubFetcher(KEV, many)}, [KEV])
    summary = run.refresh_due_sources(NOW)
    assert [len(batch) for batch, _ in records.saved] == [IntelLimits.BATCH_SIZE, 5]
    assert records.retired[0][0] == KEV and len(records.retired[0][1]) == IntelLimits.BATCH_SIZE + 5
    assert feeds.successes[0][:3] == (KEV, "v1", "v1") and feeds.claimed == {}
    assert (summary.new_versions, summary.index_rebuilt, keeper.rebuilds) == (
        IntelLimits.BATCH_SIZE + 5,
        True,
        1,
    )


def test_only_approved_sources_that_are_due_are_fetched() -> None:
    kev, epss = StubFetcher(KEV, result("A")), StubFetcher(EPSS, result("B", version="d"))
    run, feeds, *_ = refresher({KEV: kev, EPSS: epss}, [KEV])
    run.refresh_due_sources(NOW)
    assert (kev.calls, epss.calls) == (1, 0)  # EPSS is not approved
    again = run.refresh_due_sources(NOW + timedelta(hours=1))
    assert kev.calls == 1 and again.sources[0].result == RefreshResult.SKIPPED
    run.refresh_due_sources(NOW + timedelta(hours=REFRESH_AFTER_HOURS[KEV] + 1))
    assert kev.calls == 2
    revoked, *_ = refresher({KEV: StubFetcher(KEV, result("A"))}, [])
    assert revoked.refresh_due_sources(NOW).sources == ()


def test_a_failed_fetch_keeps_the_checkpoint_frees_the_claim_and_gives_a_people_readable_reason() -> None:
    run, feeds, records, _ = refresher({KEV: StubFetcher(KEV, result("A"))}, [KEV])
    run.refresh_due_sources(NOW)
    run, feeds2, records2, _ = refresher({KEV: StubFetcher(KEV, RuntimeError("password=hunter2"))}, [KEV])
    feeds2.health = feeds.health
    summary = run.refresh_due_sources(NOW + timedelta(days=2))
    assert summary.failed == (KEV,) and feeds2.claimed == {}
    ((_, reason),) = feeds2.failures
    assert "RuntimeError" in reason and "hunter2" not in reason
    assert feeds2.health[KEV].checkpoint == "v1" and records2.saved == []  # the last good data stays


def test_a_source_error_message_is_recorded_as_the_enum_text() -> None:
    error = IntelFetchFailed(IntelMessage.REFUSED, url="https://x", status=503)
    run, feeds, *_ = refresher({KEV: StubFetcher(KEV, error)}, [KEV])
    run.refresh_due_sources(NOW)
    assert feeds.failures == [(KEV, "https://x answered with status 503.")]


def test_an_empty_result_is_a_failure_that_retires_nothing_and_never_moves_the_checkpoint() -> None:
    empty = FetchResult((), (), "v3", "v3")
    run, feeds, records, _ = refresher({KEV: StubFetcher(KEV, empty)}, [KEV])
    summary = run.refresh_due_sources(NOW)
    assert summary.failed == (KEV,) and records.retired == [] and feeds.successes == []
    assert feeds.failures[0][1] == IntelMessage.BAD_FORMAT.format(source=KEV)


def test_a_partial_result_retires_nothing_and_marks_more_for_a_hot_recheck() -> None:
    capped = result("A", partial=True, more=True)
    run, feeds, records, _ = refresher({KEV: StubFetcher(KEV, capped)}, [KEV])
    run.refresh_due_sources(NOW)
    assert records.retired == [] and feeds.successes[0][3] is True
    feeds.more.add(KEV)
    run.refresh_due_sources(NOW + timedelta(hours=1))  # not due by age, but more is pending
    assert len(records.saved) == 2


def test_rejected_records_are_stored_even_with_an_empty_partial_pass() -> None:
    rejected = (RejectedRecord(KEV, "X", "bad", "h"),)
    partial = FetchResult((), rejected, "v1", "v1", partial=True)
    run, feeds, records, _ = refresher({KEV: StubFetcher(KEV, partial)}, [KEV])
    run.refresh_due_sources(NOW)
    assert records.saved == [((), 1)]


def test_nothing_new_counts_as_fresh_without_storing() -> None:
    first = StubFetcher(KEV, result("A"))
    run, feeds, records, _ = refresher({KEV: first}, [KEV])
    run.refresh_due_sources(NOW)
    first.result = None
    summary = run.refresh_due_sources(NOW + timedelta(days=2))
    assert summary.sources[0].result == RefreshResult.UNCHANGED and len(records.saved) == 1
    assert first.checkpoints[-1] == "v1" and feeds.successes[-1][1] == "v1"


def test_nothing_to_ask_for_on_a_first_run_is_a_no_op_not_a_failure() -> None:
    """EPSS, NVD and ICS wait for KEV's CVEs: until then each hourly check changes nothing."""
    run, feeds, records, _ = refresher({EPSS: StubFetcher(EPSS, None)}, [EPSS])
    feeds.create_missing_intel_feeds()
    summary = run.refresh_due_sources(NOW)
    assert summary.sources[0].result == RefreshResult.SKIPPED and summary.failed == ()
    assert feeds.failures == [] and feeds.successes == [] and feeds.claimed == {}  # claim back, nothing else
    assert feeds.health[EPSS] == SourceHealth(EPSS) and records.saved == []
    assert run.refresh_due_sources(NOW + timedelta(hours=1)).failed == ()  # and it asks again next time


def test_one_failing_source_never_stops_the_others() -> None:
    fetchers = {KEV: StubFetcher(KEV, RuntimeError("x")), EPSS: StubFetcher(EPSS, result("A", version="d"))}
    run, feeds, *_ = refresher(fetchers, [KEV, EPSS])
    summary = run.refresh_due_sources(NOW)
    assert [s.result for s in summary.sources] == [RefreshResult.FAILED, RefreshResult.REFRESHED]


def test_a_source_revoked_while_it_downloaded_stores_nothing_and_frees_its_claim() -> None:
    class Revoking(StubFetcher):
        def download_changes(self, checkpoint):
            feeds.set_source_approved(KEV, False)
            return super().download_changes(checkpoint)

    run, feeds, records, _ = refresher({KEV: Revoking(KEV, result("A"))}, [KEV])
    summary = run.refresh_due_sources(NOW)
    assert records.saved == [] and feeds.claimed == {} and feeds.successes == []
    assert summary.sources[0].result == RefreshResult.FAILED and "revoked" in summary.sources[0].error


def test_refresh_one_source_ignores_due_but_not_a_live_claim_or_a_missing_fetcher() -> None:
    fetcher = StubFetcher(KEV, result("A"))
    run, feeds, records, _ = refresher({KEV: fetcher}, [KEV])
    run.refresh_due_sources(NOW)
    assert (
        run.refresh_one_source(KEV, NOW + timedelta(minutes=1)).sources[0].result == RefreshResult.REFRESHED
    )
    feeds.claimed[KEV] = "other"  # another worker holds it
    assert run.refresh_one_source(KEV, NOW).sources[0].result == RefreshResult.SKIPPED
    assert run.refresh_one_source(IntelSource.NIST_NVD, NOW).sources[0].result == RefreshResult.SKIPPED


def test_a_stop_signal_gives_the_claim_back_before_it_propagates() -> None:
    run, feeds, *_ = refresher({KEV: StubFetcher(KEV, KeyboardInterrupt())}, [KEV])
    with pytest.raises(KeyboardInterrupt):
        run.refresh_due_sources(NOW)
    assert feeds.claimed == {} and feeds.failures


def test_a_failed_index_rebuild_does_not_fail_the_refresh() -> None:
    run, feeds, *_ = refresher({KEV: StubFetcher(KEV, result("A"))}, [KEV], MemoryKeeper(fail=True))
    summary = run.refresh_due_sources(NOW)
    assert summary.index_rebuilt is False and summary.sources[0].result == RefreshResult.REFRESHED
    assert summary.index_error == {"code": "internal_error", "message": "RuntimeError"}  # no driver text


def test_a_rebuild_refused_for_want_of_data_is_told_with_its_own_message() -> None:
    """Nothing current to index (a first import that failed): a known state, never an internal error."""
    refused = EvidenceIndexRefused(IntelMessage.SNAPSHOT_EMPTY)
    run, *_ = refresher({KEV: StubFetcher(KEV, result("A"))}, [KEV], MemoryKeeper(fail=refused))
    assert run.refresh_due_sources(NOW).index_error == {"code": "conflict", "message": str(refused)}


def test_an_index_rebuild_the_ai_stopped_is_told_with_its_outage() -> None:
    """Owner 2026-10-20: the refresh job then says the AI was down, not that all went well."""
    down = Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN)
    run, *_ = refresher({KEV: StubFetcher(KEV, result("A"))}, [KEV], MemoryKeeper(fail=down))
    summary = run.refresh_due_sources(NOW)
    assert summary.index_error == {
        "code": "unavailable",
        "message": AI_OUTAGE_MESSAGES[AiOutage.DOWN],
        "reason": AiOutage.DOWN,
    }


def test_two_refreshes_of_one_source_at_once_run_it_once() -> None:
    import threading

    gate, started = threading.Event(), threading.Event()

    class Slow(StubFetcher):
        def download_changes(self, checkpoint):
            started.set()
            gate.wait(5)
            return super().download_changes(checkpoint)

    fetcher = Slow(KEV, result("A"))
    run, feeds, records, _ = refresher({KEV: fetcher}, [KEV])
    first = threading.Thread(target=run.refresh_due_sources, args=(NOW,))
    first.start()
    assert started.wait(5)
    second = run.refresh_due_sources(NOW)
    gate.set()
    first.join()
    assert (
        second.sources[0].result == RefreshResult.SKIPPED and fetcher.calls == 1 and len(records.saved) == 1
    )


def test_a_checkpoint_without_its_version_is_downloaded_in_full_and_saved_whole_again() -> None:
    """G217: a stored checkpoint whose version was lost was trusted anyway, and recording "nothing new" then
    needed the missing version. They are always saved together: a row missing either downloads in full."""
    first = StubFetcher(KEV, result("A"))
    run, feeds, records, _ = refresher({KEV: first}, [KEV])
    run.refresh_due_sources(NOW)
    feeds.health[KEV] = dataclasses.replace(feeds.health[KEV], source_version=None)  # a damaged row
    first.result = result("A", "B", version="v2")
    run.refresh_due_sources(NOW + timedelta(days=2))
    assert first.checkpoints[-1] is None  # not trusted: asked from the start
    assert feeds.successes[-1][1:3] == ("v2", "v2") and feeds.health[KEV].source_version == "v2"
