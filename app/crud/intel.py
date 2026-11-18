"""tsg_external_feed_status in MongoDB: one document per source."""

from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from pymongo import ASCENDING, ReturnDocument, UpdateMany, UpdateOne
from pymongo.collection import Collection as MongoCollection
from pymongo.errors import DuplicateKeyError

from app.core.clock import utc_now
from app.core.constants import (
    REMOVED_INTEL_SOURCES,
    Collection,
    IntelDocId,
    IntelLimits,
    IntelSource,
    IntelState,
    SnapshotState,
)
from app.core.singletons import singleton
from app.crud.base import MongoRepository, bulk_write
from app.schemas.intel_records import IntelRecord, SourceHealth

Record = dict[str, Any]
ALL_SOURCES = [source.value for source in IntelSource]
_RELEASED = {"claimed_at": None, "claim_token": None}


class IntelFeedRepository(MongoRepository):
    """tsg_external_feed_status: the source registry, its refresh claims and checkpoints."""

    def __init__(self, collection: str | MongoCollection = Collection.EXTERNAL_FEED_STATUS) -> None:
        """The feed status collection with its named conditions."""
        super().__init__(
            collection,
            conditions={
                "sources": {"_id": {"$in": ALL_SOURCES}},  # every source document, never the switch document
                "claim_free_or_older_than": lambda before: {
                    "$or": [{"claimed_at": None}, {"claimed_at": {"$lt": before}}]
                },
            },
            schema_version=1,
        )

    def create_missing_intel_feeds(self) -> None:
        """Adds each missing source of tsg_external_feed_status."""
        self.bulk_write_skipping_duplicates(
            [
                UpdateOne({"_id": source}, {"$setOnInsert": SourceHealth(source).as_doc()}, upsert=True)
                for source in IntelSource
            ],
            ordered=False,
        )

    def claim_intel_feed_refresh(self, source: IntelSource, now: datetime, stale_before: datetime) -> str | None:
        """Claims the refresh of an unclaimed (or stale-claimed) source in tsg_external_feed_status."""
        token = uuid4().hex
        claim = {"claimed_at": now, "claim_token": token, "last_attempt_at": now}
        matched = self.update(claim, _id=source, claim_free_or_older_than=stale_before)
        return token if matched == 1 else None

    def renew_intel_feed_refresh(self, source: IntelSource, claim: str, now: datetime) -> bool:
        """Renews the claim in tsg_external_feed_status while `claim` holds it."""
        return self.update({"claimed_at": now}, _id=source, claim_token=claim) == 1

    def release_intel_feed_refresh(
        self, source: IntelSource, claim: str, outcome: Mapping[str, Any] | None = None
    ) -> bool:
        """Releases the claim in tsg_external_feed_status, recording `outcome`."""
        return self.update({**(outcome or {}), **_RELEASED}, _id=source, claim_token=claim) == 1


_RECORD_KEY = ("source", "external_id", "content_hash")
_RETIRED_VERSION_SECONDS = int(timedelta(days=IntelLimits.RETIRED_VERSION_DAYS).total_seconds())


class IntelRecordRepository(MongoRepository):
    """tsg_intel: `current` marks today's version of a record."""

    def __init__(self, collection: str | MongoCollection = Collection.INTEL) -> None:
        """The intel record collection with its indexes."""
        super().__init__(
            collection,
            indexes=(
                {"keys": [(name, ASCENDING) for name in _RECORD_KEY], "unique": True, "name": "one_per_version"},
                # Every read of the current records (snapshot build, retire) filters on these.
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

    def save_intel_records(self, records: Sequence[IntelRecord], fetched_at: datetime) -> int:
        """Writes a batch to tsg_intel in order, in bulk; answers how many new versions it made."""
        operations: list[UpdateOne | UpdateMany] = []
        for record in records:
            doc = record.as_doc(fetched_at)
            key = {name: doc[name] for name in _RECORD_KEY}
            back = {"$set": {"current": True}, "$unset": {"retired_at": ""}, "$setOnInsert": doc}
            operations.append(UpdateOne(key, back, upsert=True))
            older = {"source": doc["source"], "external_id": doc["external_id"], "current": True}
            older["content_hash"] = {"$ne": doc["content_hash"]}
            operations.append(UpdateMany(older, {"$set": {"current": False, "retired_at": fetched_at}}))
        return bulk_write(self.collection, operations, ordered=True).upserted_count if operations else 0

    def retire_intel_records_missing_from(self, source: IntelSource, seen_ids: set[str], retired_at: datetime) -> int:
        """Stops the current records of `source` in tsg_intel missing from its COMPLETE fetch `seen_ids`."""
        listed = self.list(["external_id"], source=source, current=True) if seen_ids else []
        gone = {doc["external_id"] for doc in listed} - seen_ids
        if not gone:
            return 0
        retired = {"current": False, "retired_at": retired_at}
        return self.update(retired, many=True, source=source, current=True, external_ids=gone)

    def stream_current_intel_records(self) -> Iterator[Record]:
        """Every valid current record of the sources in tsg_intel, streamed in batches."""
        cursor = self.collection.find(
            self.filter({"sources": ALL_SOURCES, "current": True}), {"_id": 0, "state": 0, "current": 0}
        )
        yield from cursor.batch_size(IntelLimits.BATCH_SIZE)


class IntelSnapshotRepository(MongoRepository):
    """tsg_external_intelligence_snapshots."""

    def __init__(self, collection: str | MongoCollection = Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS) -> None:
        """The snapshot collection with its index and the description field list."""
        super().__init__(
            collection,
            indexes=({"keys": [("state", 1), ("built_at", -1)], "name": "by_state_and_age"},),
            field_lists={"description": {"_id": 0}},
            schema_version=1,
        )

    def activate_intel_snapshot(self, description: Record) -> bool:
        """Makes `description` the active pointer in one write, unless the pointer holds a build as new."""
        active = {"_id": IntelDocId.ACTIVE_SNAPSHOT, "state": SnapshotState.ACTIVE, "activated_at": utc_now()}
        pointer = description | self._stamp | active
        older_than_this = {"_id": IntelDocId.ACTIVE_SNAPSHOT, "built_at": {"$lt": description["built_at"]}}
        for _ in range(2):  # a first activation racing another one can lose its insert once
            try:
                self.collection.replace_one(older_than_this, pointer, upsert=True)
                return True
            except DuplicateKeyError:  # the pointer exists and is not older, or just appeared
                continue
        return False


#: What a scheduled run is claimed on: a claim wins only while the document still holds each as it was read.
_SCHEDULE_CLAIM_KEYS = ("enabled", "frequency", "day_of_week", "time", "timezone", "next_run_at")
_SCHEDULE_FIELDS = dict.fromkeys((*_SCHEDULE_CLAIM_KEYS, "last_run_at", "updated_at"), 1) | {"_id": 0}


class IntelScheduleRepository(MongoRepository):
    """tsg_external_feed_status: the one schedule document, beside the sources and the switch."""

    def __init__(self, collection: str | MongoCollection = Collection.EXTERNAL_FEED_STATUS) -> None:
        """The feed status collection; every read and write is by the schedule's _id."""
        super().__init__(collection, field_lists={"schedule": _SCHEDULE_FIELDS}, schema_version=1)

    def get_schedule(self) -> Record | None:
        """The saved schedule (one read by _id), or None while none is saved."""
        return self.get("schedule", _id=IntelDocId.SCHEDULE)

    def create_missing_schedule(self, default: Record) -> Record:
        """Stores `default` unless a schedule is already saved; answers the stored one either way."""
        return self._upsert_schedule({"$setOnInsert": default | self._stamp})

    def save_schedule(self, values: Record) -> Record:
        """Writes the admin's schedule over the saved one, keeping its last run, and answers it."""
        return self._upsert_schedule({"$set": values, "$setOnInsert": {"last_run_at": None} | self._stamp})

    def update_unchanged_schedule(self, seen: Record, changes: Record) -> bool:
        """Sets `changes` in one compare-and-set: only while the schedule still holds what `seen` read."""
        unchanged = {"_id": IntelDocId.SCHEDULE} | {key: seen.get(key) for key in _SCHEDULE_CLAIM_KEYS}
        return self.collection.update_one(unchanged, {"$set": changes}).modified_count == 1

    def _upsert_schedule(self, update: Record) -> Record:
        stored: Record | None = self.collection.find_one_and_update(
            {"_id": IntelDocId.SCHEDULE},
            update,
            upsert=True,
            projection=_SCHEDULE_FIELDS,
            return_document=ReturnDocument.AFTER,
        )
        assert stored is not None  # an upsert always leaves the document
        return stored


@singleton
def get_intel_feed_repository() -> IntelFeedRepository:
    return IntelFeedRepository()


@singleton
def get_intel_record_repository() -> IntelRecordRepository:
    return IntelRecordRepository()


@singleton
def get_intel_snapshot_repository() -> IntelSnapshotRepository:
    return IntelSnapshotRepository()


@singleton
def get_intel_schedule_repository() -> IntelScheduleRepository:
    return IntelScheduleRepository()


def delete_removed_sources() -> dict[str, int]:
    """Deletes the records and status documents of the removed feeds; how many of each went."""
    removed = {"$in": list(REMOVED_INTEL_SOURCES)}  # by the source-first indexes of tsg_intel, by _id in the status
    return {
        "records": get_intel_record_repository().delete(source=removed),
        "status_documents": get_intel_feed_repository().delete(_id=removed),
    }
