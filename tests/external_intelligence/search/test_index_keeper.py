"""The keeper: background single-flight rebuild, atomic swap, old index kept on failure, back-off,
empty-corpus refusal, following a newer pointer, a revoked source leaving every process."""

import threading
from datetime import timedelta

import pytest
from structlog.testing import capture_logs

from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, IntelLimits, IntelSource, LogEvent
from app.core.exceptions import Unavailable
from app.search.external_intelligence.evidence_index import EMPTY_SNAPSHOT_ID, EvidenceIndexRefused
from app.search.external_intelligence.index_keeper import (
    RETRY_FIRST_SECONDS,
    EvidenceIndexKeeper,
)
from tests.external_intelligence.evidence_fakes import (
    NOW,
    MemoryFeeds,
    MemoryPointer,
    MemoryRecords,
    ScoredBy,
    TextEmbeddings,
    technique_doc,
    vulnerability_doc,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _keeper(docs, embeddings=None, feeds=None, pointer=None, clock=None, model="m1"):
    records, pointer = MemoryRecords(docs), pointer or MemoryPointer()
    embeddings = embeddings or TextEmbeddings()
    keeper = EvidenceIndexKeeper(
        records, pointer, feeds or MemoryFeeds(), embeddings, ScoredBy(), model, "r1", clock or Clock()
    )
    return keeper, records, pointer, embeddings


def _wait_for_index(keeper: EvidenceIndexKeeper) -> None:
    keeper.rebuild_index().result(10)


def test_a_request_never_waits_and_gets_the_empty_index_until_the_first_build() -> None:
    gate, started = threading.Event(), threading.Event()

    class Slow(TextEmbeddings):
        def embed_library_texts(self, corpus, texts, sources):
            started.set()
            gate.wait(10)
            return super().embed_library_texts(corpus, texts, sources)

    keeper, *_ = _keeper([technique_doc("T1")], Slow())
    assert not keeper.current_index().has_records  # starts the build, returns at once
    assert started.wait(5) and not keeper.current_index().has_records
    gate.set()
    keeper.rebuild_index().result(10)
    assert keeper.current_index().has_records


def test_the_build_is_published_once_and_an_unchanged_corpus_is_not_embedded_again() -> None:
    keeper, records, pointer, embeddings = _keeper([technique_doc("T1")])
    first = keeper.rebuild_index().result(10)
    assert keeper.rebuild_index().result(10) is first  # same checksum: nothing built or saved
    assert (embeddings.calls.count("external_intelligence"), len(pointer.saved)) == (1, 1)
    assert pointer.active["snapshot_id"] == first.snapshot_id and pointer.active["embedding_model"] == "m1"
    assert pointer.active["rerank_model"] == "r1" and pointer.active["counts"]["indexed"] == 1


def test_a_failed_build_keeps_the_old_index_then_tries_again_after_a_growing_pause() -> None:
    clock = Clock()
    keeper, records, pointer, embeddings = _keeper([technique_doc("T1")], clock=clock)
    first = keeper.rebuild_index().result(10)
    records.docs.append(technique_doc("T2"))
    embeddings.fail = True
    with pytest.raises(RuntimeError):
        keeper.rebuild_index().result(10)
    assert keeper.current_index() is first and len(pointer.saved) == 1  # old index and pointer stay
    embeddings.fail = False
    keeper.current_index()  # inside the pause: no new attempt
    assert len(pointer.saved) == 1
    clock.now += RETRY_FIRST_SECONDS + 1
    keeper.current_index()  # due: tries again in the background
    keeper.rebuild_index().result(10)
    assert keeper.current_index() is not first and len(pointer.saved) == 2


def test_a_first_build_the_ai_stopped_leaves_writes_waiting_for_that_outage() -> None:
    """Owner 2026-10-20: until a first build ends, writes wait for a snapshot; when the AI stopped it, the
    placeholder names which AI outage, so the wait is told as that outage. The next build clears it."""

    class Down(TextEmbeddings):
        def __init__(self) -> None:
            super().__init__()
            self.down = True

        def embed_library_texts(self, corpus, texts, sources):
            if self.down:
                raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN)
            return super().embed_library_texts(corpus, texts, sources)

    clock, embeddings = Clock(), Down()
    keeper, *_ = _keeper([technique_doc("T1")], embeddings, clock=clock)
    with pytest.raises(Unavailable):
        keeper.rebuild_index().result(10)
    waiting = keeper.current_index()
    assert waiting.snapshot_id is None and waiting.outage == AiOutage.DOWN
    embeddings.down = False
    clock.now += RETRY_FIRST_SECONDS + 1
    keeper.rebuild_index().result(10)
    assert keeper.current_index().snapshot_id is not None and keeper.current_index().outage is None


def test_the_pause_doubles_with_each_failure() -> None:
    clock = Clock()
    keeper, _, _, embeddings = _keeper([technique_doc("T1")], clock=clock)
    embeddings.fail = True
    for failures in (1, 2):
        with pytest.raises(RuntimeError):
            keeper.rebuild_index().result(10)
        assert keeper._retry_at == clock.now + RETRY_FIRST_SECONDS * 2 ** (failures - 1)  # noqa: SLF001


def test_sources_approved_but_empty_keep_the_old_index_and_all_revoked_empties_it_everywhere() -> None:
    feeds = MemoryFeeds()
    keeper, records, pointer, _ = _keeper([technique_doc("T1")], feeds=feeds)
    first = keeper.rebuild_index().result(10)
    records.docs.clear()
    with pytest.raises(Exception, match="snapshot was not built"):
        keeper.rebuild_index().result(10)
    assert keeper.current_index() is first
    feeds.approved.clear()  # every source revoked: nothing may stay searchable
    empty = keeper.rebuild_index().result(10)
    assert not empty.has_records and pointer.active["counts"]["indexed"] == 0
    other, *_ = _keeper([technique_doc("T1")], pointer=pointer)  # another process, still holding the old data
    assert pointer.active["checksum"] == empty.corpus.checksum != first.corpus.checksum


def test_an_empty_corpus_settles_as_the_empty_snapshot_and_only_a_pending_first_build_names_none() -> None:
    keeper, _, pointer, _ = _keeper([])
    assert keeper.peek_index().snapshot_id is None  # the first build is pending: a write waits
    with pytest.raises(EvidenceIndexRefused):
        keeper.rebuild_index().result(10)
    assert keeper.peek_index().snapshot_id == EMPTY_SNAPSHOT_ID and pointer.active is None  # nothing imported
    revoked, _, pointer, _ = _keeper([technique_doc("T1")], feeds=MemoryFeeds([]))  # every source revoked
    settled = revoked.rebuild_index().result(10)
    assert settled.snapshot_id == EMPTY_SNAPSHOT_ID == pointer.active["snapshot_id"]


def test_two_rebuilds_asked_at_once_share_one_build_and_a_request_during_it_reads_once_more() -> None:
    gate, started = threading.Event(), threading.Event()

    class Slow(TextEmbeddings):
        def embed_library_texts(self, corpus, texts, sources):
            started.set()
            gate.wait(10)
            return super().embed_library_texts(corpus, texts, sources)

    keeper, records, _, embeddings = _keeper([technique_doc("T1")], Slow())
    one = keeper.rebuild_index()
    assert started.wait(5)
    two = keeper.rebuild_index()  # asked while the first runs
    records.docs.append(vulnerability_doc("CVE-1", "V", "P"))  # arrives mid-build
    gate.set()
    assert one is two and one.result(10) is two.result(10)
    assert keeper.current_index().corpus.counts()["indexed"] == 2  # the second read saw it


def test_a_process_follows_a_newer_active_pointer_built_elsewhere() -> None:
    clock = Clock()
    pointer = MemoryPointer()
    keeper, records, _, _ = _keeper([technique_doc("T1")], pointer=pointer, clock=clock)
    first = keeper.rebuild_index().result(10)
    other, orecords, _, _ = _keeper([technique_doc("T1"), technique_doc("T2")], pointer=pointer)
    newer = other.rebuild_index().result(10)  # another process published a different corpus
    records.docs.append(technique_doc("T2"))
    pointer.active["built_at"] = first.built_at + timedelta(seconds=5)
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    assert keeper.current_index() is first  # the check runs in the background
    deadline = threading.Event()
    for _ in range(200):  # wait for the background rebuild
        if keeper.current_index().corpus.checksum == newer.corpus.checksum:
            break
        deadline.wait(0.05)
    assert keeper.current_index().corpus.checksum == newer.corpus.checksum


def test_the_pointer_is_looked_at_once_per_period_however_many_requests() -> None:
    clock = Clock()
    pointer = MemoryPointer()
    keeper, *_ = _keeper([technique_doc("T1")], pointer=pointer, clock=clock)
    keeper.rebuild_index().result(10)
    reads = []
    original = pointer.get
    pointer.get = lambda *fields, **where: (reads.append(1), original(*fields, **where))[1]  # type: ignore[method-assign]
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    for _ in range(50):
        keeper.current_index()
    threading.Event().wait(0.3)
    assert len(reads) == 1


def test_a_changed_embedding_model_is_a_different_index() -> None:
    one, *_ = _keeper([technique_doc("T1")], model="m1")
    two, *_ = _keeper([technique_doc("T1")], model="m2")
    assert one.rebuild_index().result(10).corpus.checksum != two.rebuild_index().result(10).corpus.checksum


def test_only_approved_sources_are_read_and_the_age_gauge_is_nan_until_built() -> None:
    feeds = MemoryFeeds([IntelSource.CISA_KEV])
    keeper, *_ = _keeper([vulnerability_doc("CVE-1", "V", "P"), technique_doc("T1")], feeds=feeds)
    assert keeper.snapshot_age_seconds() != keeper.snapshot_age_seconds()  # NaN
    index = keeper.rebuild_index().result(10)
    assert [hit.external_id for hit in index.corpus.hits] == ["CVE-1"] and keeper.snapshot_age_seconds() >= 0
    assert NOW


def test_nothing_imported_yet_says_once_which_api_to_run_then_retries_quietly() -> None:
    """Owner, 2026-10-15: on but empty, the log names the import to run once per process (not one failure
    per retry); data coming and going again says it again; any other failure is logged each time."""
    keeper, records, _, embeddings = _keeper([])

    def failures(times: int) -> list[str]:
        with capture_logs() as logs:
            for _ in range(times):
                with pytest.raises(EvidenceIndexRefused):
                    keeper.rebuild_index().result(10)
        return [log["event"] for log in logs]

    assert failures(3) == [LogEvent.EXTERNAL_INTELLIGENCE_NO_DATA]
    with capture_logs() as told, pytest.raises(EvidenceIndexRefused):
        keeper.rebuild_index().result(10)
    assert told == []
    records.docs.append(technique_doc("T1"))
    keeper.rebuild_index().result(10)
    records.docs.clear()
    with capture_logs() as again, pytest.raises(EvidenceIndexRefused):
        keeper.rebuild_index().result(10)
    assert [log["event"] for log in again] == [LogEvent.EXTERNAL_INTELLIGENCE_NO_DATA]
    assert "POST /v1/tsg/intel/refresh" in again[0]["action"]
    records.docs.append(technique_doc("T2"))
    embeddings.fail = True
    with capture_logs() as broken:
        for _ in range(2):
            with pytest.raises(RuntimeError):
                keeper.rebuild_index().result(10)
    assert [log["event"] for log in broken] == [LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED] * 2
