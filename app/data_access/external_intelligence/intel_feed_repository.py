"""tsg_external_feed_status in MongoDB: one document per source (the registry, its refresh claims and
checkpoints) plus the switch document. Plain reads and writes go through the base verbs."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import uuid4

from pymongo import UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection, IntelSource
from app.data_access.base import MongoRepository
from app.models.external_intelligence.source_health import SourceHealth, sources_in_registry_order

Record = dict[str, Any]
ALL_SOURCES = [source.value for source in IntelSource]
_RELEASED = {"claimed_at": None, "claim_token": None}


def _blank_health(source: IntelSource) -> Record:
    """A source's health before any run, without its id and claim: no checkpoint, no count, no error."""
    blank = SourceHealth(source).as_doc()
    health = {name: value for name, value in blank.items() if name not in ("source", "claimed_at")}
    return {**health, "more_pending": False}


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
        """Adds each missing source of tsg_external_feed_status, approved; a revoked source stays revoked."""
        self.bulk_write_skipping_duplicates(
            [
                UpdateOne(
                    {"_id": source},
                    {
                        "$setOnInsert": {
                            **SourceHealth(source).as_doc(),
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

    def list_approved_sources(self) -> list[IntelSource]:
        """The sources Legal still allows, in registry order."""
        return sources_in_registry_order(self.list(["_id"], sources=True, approved=True))

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
        self.collection.update_one({"_id": source}, {"$set": changes}, upsert=create)
