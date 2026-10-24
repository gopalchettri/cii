"""tsg_ai_calls: one record per AI call, kept AiLimits.CALL_RECORD_DAYS."""

from datetime import timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.constants import AiLimits, AiOutcome, Collection, Timeouts
from app.data_access.base import MongoRepository, Record

_DAY_SECONDS = int(timedelta(days=1).total_seconds())


class AiCallRepository(MongoRepository):
    """tsg_ai_calls: every write bounded by Timeouts.RECORD_WRITE_SECONDS (the answer is in hand)."""

    def __init__(self, collection: str | MongoCollection = Collection.AI_CALLS) -> None:
        """tsg_ai_calls with its job index and its expiry."""
        super().__init__(
            collection,
            # find one job's AI calls, whichever delivery made them
            indexes=[{"keys": [("record_id", 1), ("epoch", 1), ("job_task", 1), ("prompt_hash", 1)]}],
            ttl=[("created_at", AiLimits.CALL_RECORD_DAYS * _DAY_SECONDS)],
            schema_version=1,
        )

    def create(self, record: Record) -> Any:
        """Inserts one tsg_ai_calls record within Timeouts.RECORD_WRITE_SECONDS."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            return super().create(record)

    def find_ok_response(self, job: dict[str, Any], prompt_hash: str) -> str | None:
        """The response of the job's newest ok call with this conversation (`job`: its record_id, epoch and
        job_task), read in RECORD_WRITE_SECONDS."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            found = self.list(  # newest first; _id breaks a same-millisecond tie in insertion order
                ("response",),
                ("-created_at", "-_id"),
                limit=1,
                **job,
                prompt_hash=prompt_hash,
                outcome=AiOutcome.OK,
            )
        return found[0]["response"] if found else None
