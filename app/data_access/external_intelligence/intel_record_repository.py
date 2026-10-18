"""tsg_intel in MongoDB: one document per version of a source record; `current` marks today's version."""

from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta
from typing import Any

from pymongo import ASCENDING, UpdateMany, UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, IntelLimits, IntelOperationsLimits, IntelSource, IntelState
from app.data_access.base import MongoRepository
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, SaveCounts

Record = dict[str, Any]
_RECORD_KEY = ("source", "external_id", "content_hash")
_RETIRED_VERSION_SECONDS = int(timedelta(days=IntelOperationsLimits.RETIRED_VERSION_DAYS).total_seconds())


class IntelRecordRepository(MongoRepository):
    """tsg_intel: `current` marks today's version of a record; a rejected record is stored quarantined."""

    def __init__(self, collection: str | MongoCollection = Collection.INTEL) -> None:
        """The intel record collection with its indexes, retired-version expiry and named conditions."""
        super().__init__(
            collection,
            indexes=(
                {
                    "keys": [(name, ASCENDING) for name in _RECORD_KEY],
                    "unique": True,
                    "name": "one_per_version",
                },
                # Every read of the current records (snapshot build, KEV ids, retire, purge) filters on these.
                {
                    "keys": [("source", ASCENDING), ("state", ASCENDING), ("current", ASCENDING)],
                    "name": "current_by_source",
                },
            ),
            ttl=(("retired_at", _RETIRED_VERSION_SECONDS),),
            conditions={
                "current": {"state": IntelState.VALID, "current": True},
                "sources": lambda sources: {"source": {"$in": list(sources)}},
                "external_ids": lambda ids: {"external_id": {"$in": list(ids)}},
            },
            schema_version=1,
        )

    def save_intel_records(
        self, records: Sequence[IntelRecord], rejected: Sequence[RejectedRecord], fetched_at: datetime
    ) -> SaveCounts:
        """Writes a batch to tsg_intel in order, in bulk: each record becomes (or stays) current and its older
        versions stop being current, the new one written first so a reader never sees none. Saving the same
        batch again changes nothing, so a worker killed before its checkpoint simply reads it again."""
        operations: list[UpdateOne | UpdateMany] = []
        for record in records:
            doc = record.as_doc(fetched_at)
            key = {name: doc[name] for name in _RECORD_KEY}
            back = {"$set": {"current": True}, "$unset": {"retired_at": ""}, "$setOnInsert": doc}
            operations.append(UpdateOne(key, back, upsert=True))
            older = {"source": doc["source"], "external_id": doc["external_id"], "current": True}
            older["content_hash"] = {"$ne": doc["content_hash"]}
            operations.append(UpdateMany(older, {"$set": {"current": False, "retired_at": fetched_at}}))
        created = self._write_in_order(operations)
        refused = [
            UpdateOne({name: doc[name] for name in _RECORD_KEY}, {"$setOnInsert": doc}, upsert=True)
            for doc in (bad.as_doc(fetched_at) for bad in rejected)
        ]
        # A rejected record seen before is not stored again, so it is not counted as new either.
        return SaveCounts(created, len(records) - created, self._write_in_order(refused))

    def _write_in_order(self, operations: Sequence[UpdateOne | UpdateMany]) -> int:
        """Runs `operations` in order; how many documents it created."""
        return self.collection.bulk_write(operations, ordered=True).upserted_count if operations else 0

    def retire_intel_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime
    ) -> int:
        """Stops the current records of `source` in tsg_intel that its COMPLETE fetch `seen_ids` no longer has
        (kept as history, out of every snapshot); an empty `seen_ids` is a broken feed and retires nothing."""
        listed = self.list(["external_id"], source=source, current=True) if seen_ids else []
        gone = {doc["external_id"] for doc in listed} - seen_ids
        if not gone:
            return 0
        retired = {"current": False, "retired_at": retired_at}
        return self.update(retired, many=True, source=source, current=True, external_ids=gone)

    def stream_current_intel_records(self, sources: Sequence[IntelSource]) -> Iterator[Record]:
        """Every valid current record of `sources` in tsg_intel, streamed in batches (never all held)."""
        cursor = self.collection.find(
            self.filter({"sources": sources, "current": True}), {"_id": 0, "state": 0, "current": 0}
        )
        yield from cursor.batch_size(IntelLimits.BATCH_SIZE)
