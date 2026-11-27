"""Refreshing the sources: every one, single flight, checkpoint safety, retirement, a failure's claim."""

import dataclasses
from datetime import timedelta

import pytest

from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, IntelKind, IntelLimits, IntelMessage, IntelSource
from app.core.exceptions import IntelFetchFailed, Unavailable
from app.domain.intel.index import EvidenceIndexRefused
from app.schemas.intel_records import FetchResult, IntelRecord, RefreshResult
from tests.external_intelligence.evidence_fakes import NOW, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords, use_refresh_parts

ENT, ICS = IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS
LATER = NOW + timedelta(days=8)  # the next scheduled import


def result(*ids: str, version: str = "v1") -> FetchResult:
    records = tuple(IntelRecord(ENT, i, IntelKind.TECHNIQUE, "IT", i, f"{i} t", "https://x", version) for i in ids)
    return FetchResult(records, (), version, version)


def refresher(monkeypatch: pytest.MonkeyPatch, fetchers: dict, sources=None, keeper=None):
    feeds, records = ClaimFeeds(sources), CurrentRecords()
    keeper = keeper or MemoryKeeper()
    run = use_refresh_parts(monkeypatch, fetchers, records=records, feeds=feeds, keeper=keeper)
    return run, feeds, records, keeper


def test_a_first_refresh_stores_in_batches_moves_the_checkpoint_and_rebuilds_the_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    many = result(*(f"T{n}" for n in range(IntelLimits.BATCH_SIZE + 5)))
    run, feeds, records, keeper = refresher(monkeypatch, {ENT: StubFetcher(ENT, many)}, [ENT])
    summary = run.refresh_all_sources(NOW)
    assert [len(batch) for batch in records.saved] == [IntelLimits.BATCH_SIZE, 5]
    assert records.retired[0][0] == ENT and len(records.retired[0][1]) == IntelLimits.BATCH_SIZE + 5
    assert feeds.successes[0][:3] == (ENT, "v1", "v1") and feeds.claimed == {}
    stored = sum(item.new_versions for item in summary.sources)
    assert (stored, summary.index_rebuilt, keeper.rebuilds) == (IntelLimits.BATCH_SIZE + 5, True, 1)


def test_every_source_is_fetched_and_every_run_asks_each_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """The saved schedule decides when a run starts; a run asks every source, giving it the stored
    checkpoint, so an unchanged file is not downloaded again."""
    ent, ics = StubFetcher(ENT, result("A")), StubFetcher(ICS, result("B", version="d"))
    run, feeds, *_ = refresher(monkeypatch, {ENT: ent, ICS: ics})
    run.refresh_all_sources(NOW)
    assert (ent.calls, ics.calls) == (1, 1)
    again = run.refresh_all_sources(NOW + timedelta(hours=1))
    assert (ent.checkpoints, ics.checkpoints) == ([None, "v1"], [None, "d"])
    assert [item.result for item in again.sources] == [RefreshResult.REFRESHED] * 2


def test_a_failed_fetch_keeps_the_checkpoint_frees_the_claim_and_gives_a_people_readable_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, feeds, records, _ = refresher(monkeypatch, {ENT: StubFetcher(ENT, result("A"))}, [ENT])
    run.refresh_all_sources(NOW)
    run, feeds2, records2, _ = refresher(monkeypatch, {ENT: StubFetcher(ENT, RuntimeError("password=hunter2"))}, [ENT])
    feeds2.health = feeds.health
    summary = run.refresh_all_sources(LATER)
    assert summary.failed == (ENT,) and feeds2.claimed == {}
    ((_, reason),) = feeds2.failures
    assert "RuntimeError" in reason and "hunter2" not in reason
    assert feeds2.health[ENT].checkpoint == "v1" and records2.saved == []  # the last good data stays


def test_a_source_error_message_is_recorded_as_the_enum_text(monkeypatch: pytest.MonkeyPatch) -> None:
    error = IntelFetchFailed(IntelMessage.REFUSED, url="https://x", status=503)
    run, feeds, *_ = refresher(monkeypatch, {ENT: StubFetcher(ENT, error)}, [ENT])
    run.refresh_all_sources(NOW)
    assert feeds.failures == [(ENT, "https://x answered with status 503.")]


def test_an_empty_result_is_a_failure_that_retires_nothing_and_never_moves_the_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = FetchResult((), (), "v3", "v3")
    run, feeds, records, _ = refresher(monkeypatch, {ENT: StubFetcher(ENT, empty)}, [ENT])
    summary = run.refresh_all_sources(NOW)
    assert summary.failed == (ENT,) and records.retired == [] and feeds.successes == []
    assert feeds.failures[0][1] == IntelMessage.BAD_FORMAT.format(source=ENT)


def test_nothing_new_counts_as_fresh_without_storing(monkeypatch: pytest.MonkeyPatch) -> None:
    first = StubFetcher(ENT, result("A"))
    run, feeds, records, _ = refresher(monkeypatch, {ENT: first}, [ENT])
    run.refresh_all_sources(NOW)
    first.result = None
    summary = run.refresh_all_sources(LATER)
    assert summary.sources[0].result == RefreshResult.UNCHANGED and len(records.saved) == 1
    assert first.checkpoints[-1] == "v1" and feeds.successes[-1][1] == "v1"


def test_only_an_import_that_changes_the_data_moves_last_new_data(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner 2026-11-25: "Last success" moved on every check, so a check that found nothing new looked like
    new data. A first import and a real change move last_new_data_at; nothing new, or a full download of the
    same content (an untrusted checkpoint), leaves it as it was while last_success_at moves."""
    first = StubFetcher(ENT, result("A"))
    run, feeds, *_ = refresher(monkeypatch, {ENT: first}, [ENT])
    assert run.refresh_all_sources(NOW).sources[0].new_data is True
    assert feeds.health[ENT].last_new_data_at == NOW
    first.result = None  # MITRE: not modified
    unchanged = run.refresh_all_sources(LATER).sources[0]
    assert (unchanged.result, unchanged.new_data) == (RefreshResult.UNCHANGED, False)
    assert (feeds.health[ENT].last_success_at, feeds.health[ENT].last_new_data_at) == (LATER, NOW)
    first.result = result("A")  # the same content again, downloaded in full
    later = LATER + timedelta(days=1)
    same = run.refresh_all_sources(later).sources[0]
    assert (same.result, same.new_data, feeds.health[ENT].last_new_data_at) == (RefreshResult.REFRESHED, False, NOW)
    first.result = result("A", "B", version="v2")  # a new release
    newest = later + timedelta(days=1)
    assert run.refresh_all_sources(newest).sources[0].new_data is True
    assert feeds.health[ENT].last_new_data_at == newest


def test_one_failing_source_never_stops_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    fetchers = {ENT: StubFetcher(ENT, RuntimeError("x")), ICS: StubFetcher(ICS, result("A", version="d"))}
    run, feeds, *_ = refresher(monkeypatch, fetchers, [ENT, ICS])
    summary = run.refresh_all_sources(NOW)
    assert [s.result for s in summary.sources] == [RefreshResult.FAILED, RefreshResult.REFRESHED]


def test_refresh_one_source_respects_a_live_claim_and_skips_a_source_with_no_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = StubFetcher(ENT, result("A"))
    run, feeds, records, _ = refresher(monkeypatch, {ENT: fetcher}, [ENT])
    run.refresh_all_sources(NOW)
    assert run.refresh_one_source(ENT, NOW + timedelta(minutes=1)).sources[0].result == RefreshResult.REFRESHED
    feeds.claimed[ENT] = "other"  # another worker holds it
    assert run.refresh_one_source(ENT, NOW).sources[0].result == RefreshResult.SKIPPED
    assert run.refresh_one_source(IntelSource.ATTACK_ICS, NOW).sources[0].result == RefreshResult.SKIPPED


def test_a_stop_signal_gives_the_claim_back_before_it_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    run, feeds, *_ = refresher(monkeypatch, {ENT: StubFetcher(ENT, KeyboardInterrupt())}, [ENT])
    with pytest.raises(KeyboardInterrupt):
        run.refresh_all_sources(NOW)
    assert feeds.claimed == {} and feeds.failures


def test_a_failed_index_rebuild_does_not_fail_the_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    run, feeds, *_ = refresher(monkeypatch, {ENT: StubFetcher(ENT, result("A"))}, [ENT], MemoryKeeper(fail=True))
    summary = run.refresh_all_sources(NOW)
    assert summary.index_rebuilt is False and summary.sources[0].result == RefreshResult.REFRESHED
    assert summary.index_error == {"code": "internal_error", "message": "RuntimeError"}  # no driver text


def test_a_rebuild_refused_for_want_of_data_is_told_with_its_own_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing current to index (a first import that failed): a known state, never an internal error."""
    refused = EvidenceIndexRefused(IntelMessage.SNAPSHOT_EMPTY)
    run, *_ = refresher(monkeypatch, {ENT: StubFetcher(ENT, result("A"))}, [ENT], MemoryKeeper(fail=refused))
    assert run.refresh_all_sources(NOW).index_error == {"code": "conflict", "message": str(refused)}


def test_an_index_rebuild_the_ai_stopped_is_told_with_its_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner 2026-10-20: the refresh job then says the AI was down, not that all went well."""
    down = Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN)
    run, *_ = refresher(monkeypatch, {ENT: StubFetcher(ENT, result("A"))}, [ENT], MemoryKeeper(fail=down))
    summary = run.refresh_all_sources(NOW)
    assert summary.index_error == {
        "code": "unavailable",
        "message": AI_OUTAGE_MESSAGES[AiOutage.DOWN],
        "reason": AiOutage.DOWN,
    }


def test_two_refreshes_of_one_source_at_once_run_it_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    gate, started = threading.Event(), threading.Event()

    class Slow(StubFetcher):
        def download_changes(self, checkpoint):
            started.set()
            gate.wait(5)
            return super().download_changes(checkpoint)

    fetcher = Slow(ENT, result("A"))
    run, feeds, records, _ = refresher(monkeypatch, {ENT: fetcher}, [ENT])
    first = threading.Thread(target=run.refresh_all_sources, args=(NOW,))
    first.start()
    assert started.wait(5)
    second = run.refresh_all_sources(NOW)
    gate.set()
    first.join()
    assert second.sources[0].result == RefreshResult.SKIPPED and fetcher.calls == 1 and len(records.saved) == 1


def test_a_checkpoint_without_its_version_is_downloaded_in_full_and_saved_whole_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G217: a stored checkpoint whose version was lost was trusted anyway, and recording "nothing new" then
    needed the missing version. They are always saved together: a row missing either downloads in full."""
    first = StubFetcher(ENT, result("A"))
    run, feeds, records, _ = refresher(monkeypatch, {ENT: first}, [ENT])
    run.refresh_all_sources(NOW)
    feeds.health[ENT] = dataclasses.replace(feeds.health[ENT], source_version=None)  # a damaged row
    first.result = result("A", "B", version="v2")
    run.refresh_all_sources(LATER)
    assert first.checkpoints[-1] is None  # not trusted: asked from the start
    assert feeds.successes[-1][1:3] == ("v2", "v2") and feeds.health[ENT].source_version == "v2"


def test_a_cancelled_import_stops_before_its_next_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST /v1/admin/jobs/{job_id}/cancel: the source being imported finishes, the next is never fetched."""
    ent, ics = StubFetcher(ENT, result("A")), StubFetcher(ICS, result("B", version="d"))
    run, *_ = refresher(monkeypatch, {ENT: ent, ICS: ics}, [ENT, ICS])
    answers = iter([True, False])  # still active before Enterprise, cancelled before ICS
    run.refresh_all_sources(NOW, keep_going=lambda: next(answers))
    assert (ent.calls, ics.calls) == (1, 0)
