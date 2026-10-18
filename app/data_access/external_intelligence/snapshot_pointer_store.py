"""tsg_external_intelligence_snapshots: one document per built snapshot and one `active` pointer, replaced in
one write, so a reader sees the old snapshot or the new one, never half of each."""

from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection, IntelDocId, SnapshotState, StoreLimits

Doc = dict[str, Any]


class SnapshotPointerStore:
    """Snapshot description: {snapshot_id, built_at, source_versions, counts, checksum, ...}. Finished
    descriptions are kept (tiny, one per changed refresh)."""

    def __init__(self, db: Database) -> None:
        self._snapshots = db[Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS]

    def ensure_indexes(self) -> None:
        """The snapshots by state and age."""
        self._snapshots.create_index([("state", 1), ("built_at", -1)], name="by_state_and_age")

    def save_snapshot_description(self, description: Doc) -> None:
        """A built snapshot's description, saved under its id."""
        snapshot_id = description["snapshot_id"]
        self._snapshots.replace_one({"_id": snapshot_id}, {**description, "_id": snapshot_id}, upsert=True)

    def activate_snapshot(self, snapshot_id: str) -> bool:
        """Makes a saved snapshot the active one in one write. False (nothing changed) when it was not saved
        or one built at the same time or later is already active: two builders racing never move the pointer
        back to the older build."""
        doc = self._snapshots.find_one({"_id": snapshot_id})
        if doc is None:
            return False
        pointer = {**doc, "_id": IntelDocId.ACTIVE_SNAPSHOT, "state": SnapshotState.ACTIVE}
        pointer["activated_at"] = datetime.now(UTC)
        if not self._move_pointer(pointer, doc["built_at"]):
            return False
        self._snapshots.update_one({"_id": snapshot_id}, {"$set": {"state": SnapshotState.ACTIVE}})
        older = {"_id": {"$nin": [snapshot_id, IntelDocId.ACTIVE_SNAPSHOT]}, "state": SnapshotState.ACTIVE}
        self._snapshots.update_many(older, {"$set": {"state": SnapshotState.SUPERSEDED}})
        return True

    def _move_pointer(self, pointer: Doc, built_at: datetime) -> bool:
        """The pointer replaced while the active one is older; False when a newer one holds it."""
        newer_than_active = {"_id": IntelDocId.ACTIVE_SNAPSHOT, "built_at": {"$lt": built_at}}
        for _ in range(StoreLimits.ACTIVATION_TRIES):
            try:
                self._snapshots.replace_one(newer_than_active, pointer, upsert=True)
                return True
            except DuplicateKeyError:  # the pointer exists and is not older, or just appeared
                continue
        return False

    def read_active_snapshot(self) -> Doc | None:
        """The active snapshot's description; None before the first activation."""
        return self._snapshots.find_one({"_id": IntelDocId.ACTIVE_SNAPSHOT}, {"_id": 0})
