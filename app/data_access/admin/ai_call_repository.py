"""tsg_ai_calls: one record per AI call, kept AiLimits.CALL_RECORD_DAYS."""

from datetime import timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.constants import AiLimits, Collection, Timeouts
from app.data_access.base import MongoRepository, Record

_DAY_SECONDS = int(timedelta(days=1).total_seconds())


class AiCallRepository(MongoRepository):
    """tsg_ai_calls: every write bounded by Timeouts.RECORD_WRITE_SECONDS (the answer is in hand)."""

    def __init__(self, collection: str | MongoCollection = Collection.AI_CALLS) -> None:
        """tsg_ai_calls with its job index and its expiry."""
        super().__init__(
            collection,
            indexes=[{"keys": [("task_id", 1), ("prompt_hash", 1)]}],  # find one job's AI calls
            ttl=[("created_at", AiLimits.CALL_RECORD_DAYS * _DAY_SECONDS)],
            schema_version=1,
        )

    def create(self, record: Record) -> Any:
        """Inserts one tsg_ai_calls record within Timeouts.RECORD_WRITE_SECONDS."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            return super().create(record)
