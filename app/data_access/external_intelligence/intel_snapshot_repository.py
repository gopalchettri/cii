"""tsg_external_intelligence_snapshots in MongoDB: one description per built snapshot and the `active`
pointer that every process follows."""

from datetime import datetime
from typing import Any

from pymongo.collection import Collection as MongoCollection
from pymongo.errors import DuplicateKeyError

from app.core.clock import utc_now
from app.core.constants import Collection, IntelDocId, SnapshotState, StoreLimits
from app.data_access.base import MongoRepository

Record = dict[str, Any]


class IntelSnapshotRepository(MongoRepository):
    """tsg_external_intelligence_snapshots: one description per built snapshot and the `active` pointer."""

    def __init__(
        self, collection: str | MongoCollection = Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS
    ) -> None:
        """The snapshot collection with its index and the description field list."""
        super().__init__(
            collection,
            indexes=({"keys": [("state", 1), ("built_at", -1)], "name": "by_state_and_age"},),
            field_lists={"description": {"_id": 0}},
            schema_version=1,
        )

    def activate_intel_snapshot(self, snapshot_id: str) -> bool:
        """Makes a saved snapshot of tsg_external_intelligence_snapshots active in one write; False when it
        was not saved or one built at the same time or later is active (the pointer never moves back)."""
        doc = self.get(_id=snapshot_id)
        if doc is None:
            return False
        pointer = {**doc, "_id": IntelDocId.ACTIVE_SNAPSHOT, "state": SnapshotState.ACTIVE}
        pointer["activated_at"] = utc_now()
        if not self._replace_older_pointer(pointer, doc["built_at"]):
            return False
        self.update({"state": SnapshotState.ACTIVE}, _id=snapshot_id)
        older = {"_id": {"$nin": [snapshot_id, IntelDocId.ACTIVE_SNAPSHOT]}, "state": SnapshotState.ACTIVE}
        self.collection.update_many(older, {"$set": {"state": SnapshotState.SUPERSEDED}})
        return True

    def _replace_older_pointer(self, pointer: Record, built_at: datetime) -> bool:
        """The pointer replaced while the active one is older; False when a newer one holds it."""
        older_than_this = {"_id": IntelDocId.ACTIVE_SNAPSHOT, "built_at": {"$lt": built_at}}
        for _ in range(StoreLimits.ACTIVATION_TRIES):
            try:
                self.collection.replace_one(older_than_this, pointer, upsert=True)
                return True
            except DuplicateKeyError:  # the pointer exists and is not older, or just appeared
                continue
        return False
