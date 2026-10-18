"""The active-snapshot pointer: one read, atomic, and never moved to an older build."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app import container
from app.core.constants import Collection, IntelDocId, SnapshotState
from app.core.database import get_mongodb
from app.data_access.external_intelligence.intel_snapshot_repository import IntelSnapshotRepository

T0 = datetime(2026, 10, 12, 8, tzinfo=UTC)


@pytest.fixture
def snapshots() -> IntelSnapshotRepository:
    db = get_mongodb()
    db[Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS].delete_many({})
    store = container.get_intel_snapshot_repository()
    store.create_indexes()
    return store


def _describe(store: IntelSnapshotRepository, name: str, built_at: datetime) -> None:
    store.save(
        {
            "_id": name,
            "snapshot_id": name,
            "built_at": built_at,
            "source_versions": {"cisa_kev": "1"},
            "checksum": f"sum-{name}",
            "state": SnapshotState.BUILDING,
        }
    )


def _states() -> dict[str, str]:
    return {d["_id"]: d["state"] for d in get_mongodb()[Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS].find({})}


def test_nothing_is_active_until_a_snapshot_is_activated(snapshots: IntelSnapshotRepository) -> None:
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT) is None
    _describe(snapshots, "s1", T0)
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT) is None
    assert snapshots.activate_intel_snapshot("missing") is False


def test_the_pointer_carries_the_whole_description_in_one_read(snapshots: IntelSnapshotRepository) -> None:
    _describe(snapshots, "s1", T0)
    assert snapshots.activate_intel_snapshot("s1") is True
    active = snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
    assert (active["snapshot_id"], active["checksum"]) == ("s1", "sum-s1")
    assert active["source_versions"] == {"cisa_kev": "1"} and active["built_at"] == T0
    assert active["state"] == SnapshotState.ACTIVE and "_id" not in active


def test_a_newer_snapshot_replaces_it_and_the_older_one_is_superseded(
    snapshots: IntelSnapshotRepository,
) -> None:
    _describe(snapshots, "s1", T0)
    _describe(snapshots, "s2", T0 + timedelta(hours=1))
    assert snapshots.activate_intel_snapshot("s1") and snapshots.activate_intel_snapshot("s2")
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "s2"
    assert (_states()["s1"], _states()["s2"]) == (SnapshotState.SUPERSEDED, SnapshotState.ACTIVE)


def test_the_pointer_never_moves_back_to_an_older_build(snapshots: IntelSnapshotRepository) -> None:
    _describe(snapshots, "new", T0 + timedelta(hours=2))
    _describe(snapshots, "old", T0)
    assert snapshots.activate_intel_snapshot("new") is True
    assert snapshots.activate_intel_snapshot("old") is False
    assert snapshots.activate_intel_snapshot("new") is False  # not newer than itself either
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "new"
    assert _states()["old"] == SnapshotState.BUILDING


def test_builders_racing_leave_the_newest_active(snapshots: IntelSnapshotRepository) -> None:
    for n in range(12):
        _describe(snapshots, f"s{n}", T0 + timedelta(minutes=n))

    def activate(n: int) -> bool:
        return container.get_intel_snapshot_repository().activate_intel_snapshot(f"s{n}")

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(activate, range(12)))
    assert snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)["snapshot_id"] == "s11"
