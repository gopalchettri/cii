"""External intelligence in MongoDB: the feed status (one document per source plus the switch document), the
intel records (one document per version of a source record) and the snapshot descriptions with their
`active` pointer. Plain reads and writes go through the base verbs; only the real rules are named here."""

import re
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pymongo import ASCENDING, UpdateMany, UpdateOne
from pymongo.errors import DuplicateKeyError

from app.core.constants import (
    Collection,
    EmbeddingCorpus,
    IntelDocId,
    IntelLimits,
    IntelOperationsLimits,
    IntelSource,
    IntelState,
    IntelUrl,
    SnapshotState,
    StoreLimits,
)
from app.data_access.base import MongoRepository
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, SaveCounts
from app.models.external_intelligence.source_health import SourceHealth

Record = dict[str, Any]
ALL_SOURCES = [source.value for source in IntelSource]
_RECORD_KEY = ("source", "external_id", "content_hash")
#: Where each source's terms are published: kept beside the registry for whoever audits an approval.
_TERMS: dict[IntelSource, str] = {
    IntelSource.CISA_KEV: IntelUrl.TERMS_KEV,
    IntelSource.FIRST_EPSS: IntelUrl.TERMS_EPSS,
    IntelSource.ATTACK_ENTERPRISE: IntelUrl.TERMS_ATTACK,
    IntelSource.ATTACK_ICS: IntelUrl.TERMS_ATTACK,
    IntelSource.CISA_ICS: IntelUrl.TERMS_CISA,
    IntelSource.NIST_NVD: IntelUrl.TERMS_NVD,
}
_RELEASED = {"claimed_at": None, "claim_token": None}


def _blank_health(source: IntelSource) -> Record:
    """A source's health before any run, without its id and claim: no checkpoint, no count, no error."""
    blank = SourceHealth(source).as_doc()
    health = {name: value for name, value in blank.items() if name not in ("source", "claimed_at")}
    return {**health, "more_pending": False}


class IntelFeedRepository(MongoRepository):
    """tsg_external_feed_status: the source registry, its refresh claims and checkpoints."""

    def create_missing_intel_feeds(self) -> None:
        """Adds each missing source of tsg_external_feed_status, approved; a revoked source stays revoked."""
        self.bulk_write_skipping_duplicates(
            [
                UpdateOne(
                    {"_id": source},
                    {
                        "$setOnInsert": {
                            **SourceHealth(source).as_doc(),
                            "terms_url": _TERMS[source],
                            "more_pending": False,
                            "approved": True,
                        }
                    },
                    upsert=True,
                )
                for source in IntelSource
            ],
            ordered=False,
        )

    def claim_intel_feed_refresh(
        self, source: IntelSource, now: datetime, stale_before: datetime
    ) -> str | None:
        """Claims the refresh of an approved, unclaimed (or stale-claimed) source in tsg_external_feed_status;
        the claim's new token, or None. A stale claim taken over gets a new token, fencing the dead worker."""
        token = uuid4().hex
        claim = {"claimed_at": now, "claim_token": token, "last_attempt_at": now}
        matched = self.update(claim, _id=source, approved=True, claim_free_or_older_than=stale_before)
        return token if matched == 1 else None

    def renew_intel_feed_refresh(self, source: IntelSource, claim: str, now: datetime) -> bool:
        """Renews the claim in tsg_external_feed_status while `claim` holds it and the source is approved."""
        return self.update({"claimed_at": now}, _id=source, claim_token=claim, approved=True) == 1

    def release_intel_feed_refresh(
        self, source: IntelSource, claim: str, outcome: Mapping[str, Any] | None = None
    ) -> bool:
        """Releases the claim in tsg_external_feed_status, recording `outcome` (a success's checkpoint or a
        failure's error), only while `claim` still holds it; False when it was taken over."""
        return self.update({**(outcome or {}), **_RELEASED}, _id=source, claim_token=claim) == 1

    def update_intel_feed_approval(self, source: IntelSource, approved: bool, *, create: bool = True) -> None:
        """Sets `approved` on a source of tsg_external_feed_status with a blank health and no claim (a refresh
        in flight loses it); `create=False` changes only an existing source document."""
        changes = {"approved": approved, **_blank_health(source), **_RELEASED}
        setting = {"$set": changes, "$setOnInsert": {"terms_url": _TERMS[source]}}
        self.collection.update_one({"_id": source}, setting, upsert=create)


class IntelRecordRepository(MongoRepository):
    """tsg_intel: `current` marks today's version of a record; a rejected record is stored quarantined."""

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


class IntelSnapshotRepository(MongoRepository):
    """tsg_external_intelligence_snapshots: one description per built snapshot and the `active` pointer."""

    def activate_intel_snapshot(self, snapshot_id: str) -> bool:
        """Makes a saved snapshot of tsg_external_intelligence_snapshots active in one write; False when it
        was not saved or one built at the same time or later is active (the pointer never moves back)."""
        doc = self.get(_id=snapshot_id)
        if doc is None:
            return False
        pointer = {**doc, "_id": IntelDocId.ACTIVE_SNAPSHOT, "state": SnapshotState.ACTIVE}
        pointer["activated_at"] = datetime.now(UTC)
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


def _vectors_used_only_by(source: IntelSource) -> Record:
    """The cached vectors of external intelligence texts that only `source`'s records use."""
    own = re.compile(f"^{re.escape(source)}/")
    return {
        "corpus": EmbeddingCorpus.EXTERNAL_INTELLIGENCE,
        "sources.id": own,
        "sources": {"$not": {"$elemMatch": {"id": {"$not": own}}}},
    }


intel_feeds = IntelFeedRepository(
    Collection.EXTERNAL_FEED_STATUS,
    conditions={
        "sources": {"_id": {"$in": ALL_SOURCES}},  # every source document, never the switch document
        "claim_free_or_older_than": lambda before: {
            "$or": [{"claimed_at": None}, {"claimed_at": {"$lt": before}}]
        },
    },
    schema_version=1,
)
intel_records = IntelRecordRepository(
    Collection.INTEL,
    indexes=(
        {"keys": [(name, ASCENDING) for name in _RECORD_KEY], "unique": True, "name": "one_per_version"},
        # Every read of the current records (snapshot build, KEV ids, retire, purge) filters on these three.
        {
            "keys": [("source", ASCENDING), ("state", ASCENDING), ("current", ASCENDING)],
            "name": "current_by_source",
        },
    ),
    ttl=(("retired_at", int(timedelta(days=IntelOperationsLimits.RETIRED_VERSION_DAYS).total_seconds())),),
    conditions={
        "current": {"state": IntelState.VALID, "current": True},
        "sources": lambda sources: {"source": {"$in": list(sources)}},
        "external_ids": lambda ids: {"external_id": {"$in": list(ids)}},
    },
    schema_version=1,
)
intel_snapshots = IntelSnapshotRepository(
    Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS,
    indexes=({"keys": [("state", 1), ("built_at", -1)], "name": "by_state_and_age"},),
    field_lists={"description": {"_id": 0}},
    schema_version=1,
)
#: tsg_embeddings as external intelligence purges it (its indexes belong to the embeddings repository).
intel_vectors = MongoRepository(
    Collection.EMBEDDINGS, conditions={"used_only_by_source": _vectors_used_only_by}, schema_version=1
)
