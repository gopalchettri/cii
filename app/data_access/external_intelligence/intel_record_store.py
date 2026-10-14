"""tsg_intel: the normalised intelligence records, the only code that reads or writes them.

One document per version of a source record, keyed by (source, external_id, content_hash); `current` marks
the version the source says today. A record the source did not change is not written again; a changed one
becomes a new version and the older one stays (traceable) but stops being current, stamped `retired_at`: a TTL
index deletes it IntelOperationsLimits.RETIRED_VERSION_DAYS later, so a score that changes daily cannot grow
the collection for ever. A rejected record is stored with `state=quarantined` and its reason, never current,
so it cannot reach an index."""

from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta
from typing import Any

from pymongo import ASCENDING, UpdateMany, UpdateOne
from pymongo.database import Database

from app.core.constants import Collection, IntelLimits, IntelOperationsLimits, IntelSource, IntelState
from app.core.database import expire_documents_after
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, SaveCounts

Doc = dict[str, Any]
_KEY = ("source", "external_id", "content_hash")
_STORED_ONLY = {"_id": 0, "state": 0, "current": 0}


class IntelRecordStore:
    def __init__(self, db: Database) -> None:
        self._records = db[Collection.INTEL]

    def ensure_indexes(self) -> None:
        self._records.create_index([(key, ASCENDING) for key in _KEY], unique=True, name="one_per_version")
        # Every read of the current records (snapshot build, KEV ids, retire, purge) filters on these three.
        self._records.create_index(
            [("source", ASCENDING), ("state", ASCENDING), ("current", ASCENDING)], name="current_by_source"
        )
        expire_documents_after(
            self._records,
            "retired_at",
            int(timedelta(days=IntelOperationsLimits.RETIRED_VERSION_DAYS).total_seconds()),
        )

    def save_batch(
        self, records: Sequence[IntelRecord], rejected: Sequence[RejectedRecord], fetched_at: datetime
    ) -> SaveCounts:
        """Writes a batch in order, in bulk: each record becomes (or stays) the current version and its older
        versions stop being current. Saving the same batch again changes nothing, which is what makes a worker
        killed between this write and the checkpoint safe: the batch is simply read again. Within one record
        the new version is written before the older one is switched off, so a reader never sees none."""
        operations: list[UpdateOne | UpdateMany] = []
        for record in records:
            doc = record.as_doc(fetched_at)
            key = {name: doc[name] for name in _KEY}
            back = {"$set": {"current": True}, "$unset": {"retired_at": ""}, "$setOnInsert": doc}
            operations.append(UpdateOne(key, back, upsert=True))
            older = {"source": doc["source"], "external_id": doc["external_id"], "current": True}
            older["content_hash"] = {"$ne": doc["content_hash"]}
            operations.append(UpdateMany(older, {"$set": {"current": False, "retired_at": fetched_at}}))
        created = self._write(operations)
        refused = [
            UpdateOne({name: doc[name] for name in _KEY}, {"$setOnInsert": doc}, upsert=True)
            for doc in (bad.as_doc(fetched_at) for bad in rejected)
        ]
        # A rejected record seen before is not stored again, so it is not counted as new either.
        return SaveCounts(created, len(records) - created, self._write(refused))

    def _write(self, operations: Sequence[UpdateOne | UpdateMany]) -> int:
        """Runs `operations` in order; how many documents it created."""
        return self._records.bulk_write(operations, ordered=True).upserted_count if operations else 0

    def retire_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime
    ) -> int:
        """Stops `source`'s current records that its latest COMPLETE fetch no longer contains (a vulnerability
        removed, a technique deprecated): they stay stored as history but leave every future snapshot. The
        caller never asks after a partial result, and an empty `seen_ids` retires nothing (an empty answer is
        a broken feed, not a feed with no records). The retired versions carry `retired_at`."""
        gone = self.list_current_external_ids(source) - seen_ids if seen_ids else set()
        if not gone:
            return 0
        query = {**self._current([source]), "external_id": {"$in": list(gone)}}
        return self._records.update_many(
            query, {"$set": {"current": False, "retired_at": retired_at}}
        ).modified_count

    def stream_current_records(self, sources: Sequence[IntelSource]) -> Iterator[Doc]:
        """Every valid current record of `sources`, streamed in batches: a snapshot build never holds the
        collection twice."""
        cursor = self._records.find(self._current(sources), _STORED_ONLY)
        yield from cursor.batch_size(IntelLimits.BATCH_SIZE)

    def count_current_records(self, sources: Sequence[IntelSource]) -> int:
        return self._records.count_documents(self._current(sources))

    def list_current_external_ids(self, source: IntelSource) -> set[str]:
        cursor = self._records.find(self._current([source]), {"_id": 0, "external_id": 1})
        return {doc["external_id"] for doc in cursor.batch_size(IntelLimits.BATCH_SIZE)}

    def purge_source(self, source: IntelSource) -> int:
        """Deletes every version and rejection of `source` (its terms were revoked); how many documents."""
        return self._records.delete_many({"source": source}).deleted_count

    @staticmethod
    def _current(sources: Sequence[IntelSource]) -> Doc:
        return {"source": {"$in": list(sources)}, "state": IntelState.VALID, "current": True}
