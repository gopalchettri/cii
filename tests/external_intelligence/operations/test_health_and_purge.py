"""Health (each source, pending sources, snapshot, switch) and the purge of a revoked source."""

from datetime import timedelta

import pytest

from app import container
from app.core.config import get_settings
from app.core.constants import Collection, EmbeddingCorpus, FeedStatus, IntelSource
from app.core.database import get_mongodb
from app.models.external_intelligence.source_health import (
    SourceHealth,
)
from app.models.external_intelligence.switch_state import SwitchState
from tests.external_intelligence.evidence_fakes import (
    NOW,
    MemoryFeeds,
    MemoryKeeper,
    MemoryPointer,
    MemoryRecords,
)
from tests.external_intelligence.fakes import intelligence_service
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds

KEV, EPSS, NVD = IntelSource.CISA_KEV, IntelSource.FIRST_EPSS, IntelSource.NIST_NVD


class FixedSwitch:
    def state(self) -> SwitchState:
        return SwitchState(True, False, NOW, "admin")


@pytest.fixture(autouse=True)
def env_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env master switch on."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)


def _health(feeds: MemoryFeeds, pointer: MemoryPointer) -> dict:
    keeper = MemoryKeeper()
    service = intelligence_service(switch=FixedSwitch(), feeds=feeds, snapshots=pointer, index_keeper=keeper)
    return service.get_intelligence_health()


def _fresh(source: IntelSource, hours: float) -> SourceHealth:
    return SourceHealth(source, FeedStatus.OK, "c", "v", 5, NOW, NOW - timedelta(hours=hours))


def test_health_shows_each_source_the_snapshot_and_the_switch() -> None:
    feeds, pointer = MemoryFeeds([KEV, EPSS]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 1000)}
    pointer.active = {"snapshot_id": "snap-1", "checksum": "c"}
    report = _health(feeds, pointer)
    assert (report["snapshot_id"], len(report["sources"])) == ("snap-1", 2)
    assert report["switch"]["runtime_enabled"] is False and report["switch"]["effective"] is False


def test_a_never_run_source_is_pending_while_the_others_have_data() -> None:
    """The live run: five sources refreshed, NVD's first pass (hours) not yet."""
    feeds, pointer = MemoryFeeds([KEV, EPSS, NVD]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 2), NVD: SourceHealth(NVD)}
    report = _health(feeds, pointer)
    assert report["pending_sources"] == ["nist_nvd"] and not report["no_data"]


def test_when_no_source_ever_succeeded_there_is_no_data() -> None:
    feeds, pointer = MemoryFeeds([KEV, EPSS]), MemoryPointer()
    feeds.health = {KEV: SourceHealth(KEV), EPSS: SourceHealth(EPSS, FeedStatus.FAILED, last_attempt_at=NOW)}
    report = _health(feeds, pointer)
    # no pointer, empty index
    assert report["no_data"] and report["snapshot_id"] is None
    assert set(report["pending_sources"]) == {KEV, EPSS}


def test_a_revoked_source_does_not_count_as_pending() -> None:
    feeds, pointer = MemoryFeeds([KEV]), MemoryPointer()
    feeds.health = {KEV: _fresh(KEV, 1), EPSS: _fresh(EPSS, 1000), NVD: SourceHealth(NVD)}
    report = _health(feeds, pointer)
    assert report["pending_sources"] == [] and not report["no_data"]


class MemoryVectors:
    def __init__(self) -> None:
        self.purged: list[IntelSource] = []

    def delete_vectors_used_only_by(self, source: IntelSource) -> int:
        self.purged.append(source)
        return 1


def test_a_revoked_source_is_unapproved_first_then_its_records_and_vectors_go_and_the_index_is_rebuilt() -> (
    None
):
    feeds, records, keeper, vectors = (
        ClaimFeeds([KEV, EPSS]),
        MemoryRecords(),
        MemoryKeeper(),
        MemoryVectors(),
    )
    order: list[str] = []
    original = records.delete
    records.delete = lambda **where: (  # type: ignore[method-assign]
        order.append(f"records approved={KEV in feeds.approved}"),
        original(**where),
    )[1]
    parts = {"feeds": feeds, "records": records, "vectors": vectors, "index_keeper": keeper}
    service = intelligence_service(switch=FixedSwitch(), **parts)
    assert service.revoke_intelligence_source(KEV, "op")["records_purged"] == 1
    assert order == ["records approved=False"] and vectors.purged == [KEV] and keeper.rebuilds == 1
    assert feeds.approved == [EPSS]


def test_a_failed_rebuild_does_not_undo_the_purge() -> None:
    feeds, records, vectors = ClaimFeeds([KEV]), MemoryRecords(), MemoryVectors()
    keeper = MemoryKeeper(fail=True)
    parts = {"feeds": feeds, "records": records, "vectors": vectors, "index_keeper": keeper}
    service = intelligence_service(switch=FixedSwitch(), **parts)
    assert service.revoke_intelligence_source(KEV, "op")["records_purged"] == 1 and records.purged == [KEV]


def test_cached_vectors_of_a_revoked_source_are_deleted_but_a_shared_vector_stays() -> None:
    db = get_mongodb()
    vectors = db[Collection.EMBEDDINGS]
    corpus = EmbeddingCorpus.EXTERNAL_INTELLIGENCE
    mine = {"_id": "t|mine", "corpus": corpus, "sources": [{"id": "cisa_kev/CVE-1"}], "text": "x"}
    shared = {
        "_id": "t|shared",
        "corpus": corpus,
        "sources": [{"id": "cisa_kev/CVE-2"}, {"id": "first_epss/CVE-2"}],
    }
    other = {"_id": "t|other", "corpus": corpus, "sources": [{"id": "first_epss/CVE-3"}]}
    library = {"_id": "t|library", "corpus": "controls", "sources": [{"id": "cisa_kev/CVE-1"}]}
    vectors.delete_many({"_id": {"$in": [d["_id"] for d in (mine, shared, other, library)]}})
    vectors.insert_many([mine, shared, other, library])
    try:
        assert container.get_embedding_repository().delete_vectors_used_only_by(KEV) == 1
        left = {doc["_id"] for doc in vectors.find({"_id": {"$regex": "^t\\|"}})}
        assert left == {"t|shared", "t|other", "t|library"}
    finally:
        vectors.delete_many({"_id": {"$regex": "^t\\|"}})
