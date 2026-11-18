"""The active-snapshot pointer: one read, atomic, and never moved to an older build."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, IntelDocId, SnapshotState
from app.core.database import get_mongodb
from app.crud.intel import IntelSnapshotRepository, get_intel_snapshot_repository

T0 = datetime(2026, 10, 12, 8, tzinfo=UTC)


@pytest.fixture
def snapshots() -> IntelSnapshotRepository:
    db = get_mongodb()
    db[Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS].delete_many({})
    store = get_intel_snapshot_repository()
    store.create_indexes()
    return store


def _describe(name: str, built_at: datetime) -> dict:
    return {
        "snapshot_id": name,
        "built_at": built_at,
        "source_versions": {"mitre_attack_enterprise": "1"},
        "checksum": f"sum-{name}",
    }


def test_the_pointer_is_the_only_document_written(snapshots: IntelSnapshotRepository) -> None:
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT) is None
    assert snapshots.activate_intel_snapshot(_describe("s1", T0)) is True
    stored = list(get_mongodb()[Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS].find({}))
    assert [doc["_id"] for doc in stored] == [IntelDocId.ACTIVE_SNAPSHOT] and stored[0]["schema_version"] == 1


def test_the_pointer_carries_the_whole_description_in_one_read(snapshots: IntelSnapshotRepository) -> None:
    assert snapshots.activate_intel_snapshot(_describe("s1", T0)) is True
    active = snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
    assert (active["snapshot_id"], active["checksum"]) == ("s1", "sum-s1")
    assert active["source_versions"] == {"mitre_attack_enterprise": "1"} and active["built_at"] == T0
    assert active["state"] == SnapshotState.ACTIVE and "_id" not in active


def test_a_newer_snapshot_replaces_it(snapshots: IntelSnapshotRepository) -> None:
    assert snapshots.activate_intel_snapshot(_describe("s1", T0))
    assert snapshots.activate_intel_snapshot(_describe("s2", T0 + timedelta(hours=1)))
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "s2"


def test_the_pointer_never_moves_back_to_an_older_build(snapshots: IntelSnapshotRepository) -> None:
    new, old = _describe("new", T0 + timedelta(hours=2)), _describe("old", T0)
    assert snapshots.activate_intel_snapshot(new) is True
    assert snapshots.activate_intel_snapshot(old) is False
    assert snapshots.activate_intel_snapshot(new) is False  # not newer than itself either
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "new"


def test_builders_racing_leave_the_newest_active(snapshots: IntelSnapshotRepository) -> None:
    def activate(n: int) -> bool:
        description = _describe(f"s{n}", T0 + timedelta(minutes=n))
        return get_intel_snapshot_repository().activate_intel_snapshot(description)

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(activate, range(12)))
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "s11"
