"""tsg_ai_call_texts: the prompt and answer of every answered chat call, kept for good (owner 2026-10-29); its
usage row in tsg_ai_usage has the same _id."""

from datetime import datetime, timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import PREVIOUS_AI_CALL_TEXTS, AiOutcome, AiUsageLimits, Collection, Timeouts
from app.data_access.base import NeverDeletedRepository, Record

_DAY = timedelta(days=1)


class AiCallRepository(NeverDeletedRepository):
    """tsg_ai_call_texts: every write bounded by Timeouts.RECORD_WRITE_SECONDS (the answer is in hand). A new
    name, not tsg_ai_calls: an older release re-creates its 14-day expiry there, never here."""

    def __init__(self, collection: str | MongoCollection = Collection.AI_CALLS) -> None:
        """tsg_ai_call_texts with its job index."""
        super().__init__(
            collection,
            indexes=[
                # find one job's AI calls, whichever delivery made them
                {"keys": [("record_id", 1), ("epoch", 1), ("job_task", 1), ("prompt_hash", 1)]},
                # find any run's newest answer to one conversation (threat finding's reuse across runs)
                {"keys": [("prompt_hash", 1), ("created_at", -1)]},
            ],
            schema_version=1,
        )

    def create(self, record: Record) -> Any:
        """Inserts one tsg_ai_call_texts record within Timeouts.RECORD_WRITE_SECONDS."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            return super().create(record)

    def copy_records_from(self, source: str) -> int:
        """Copies every record of the `source` collection in, a day at a time, each within COPY_DAY_SECONDS
        (one copy of it all would outlast the client's 30 s wait); one already here is kept as it is, so it is
        safe to run again. How many records this collection then holds."""
        old = self.collection.database[source]
        merge = {
            "into": self.collection.name,
            "on": "_id",
            "whenMatched": "keepExisting",
            "whenNotMatched": "insert",
        }
        dated = {"created_at": {"$type": "date"}}
        oldest = old.find_one(dated, {"created_at": 1}, sort=[("created_at", 1)])
        day, end = (oldest["created_at"] if oldest else utc_now()), utc_now() + _DAY
        batches: list[Record] = [{"created_at": {"$not": {"$type": "date"}}}]  # untimed records: one batch
        while day < end:
            batches.append({"created_at": {"$gte": day, "$lt": day + _DAY}})
            day += _DAY
        for batch in batches:
            with pymongo.timeout(AiUsageLimits.COPY_DAY_SECONDS):
                old.aggregate([{"$match": batch}, {"$merge": merge}])
        return self.collection.estimated_document_count()

    def find_ok_response(self, job: dict[str, Any], prompt_hash: str) -> tuple[str, str] | None:
        """(response, model) of the job's newest ok call with this conversation (`job`: its record_id, epoch
        and job_task), read in RECORD_WRITE_SECONDS."""
        conversation = {**job, "prompt_hash": prompt_hash, "outcome": AiOutcome.OK}
        newest = {"projection": {"response": 1, "model": 1}, "sort": [("created_at", -1), ("_id", -1)]}
        # ponytail: the previous release's collection too, for a job re-sent across the first rollout; drop
        # this read 14 days after the release (its records expire by then).
        previous = self.collection.database[PREVIOUS_AI_CALL_TEXTS]
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            found = self.collection.find_one(conversation, **newest) or previous.find_one(
                conversation, **newest
            )
        return (found["response"], found.get("model", "")) if found else None

    def find_recent_ok_response(
        self, task: str, prompt_hash: str, models: list[tuple[str, bool]], since: datetime
    ) -> tuple[str, str] | None:
        """(response, model) of any run's newest ok `task` call with this conversation, answered by one of
        `models` (name, thinking on) at or after `since`, read in RECORD_WRITE_SECONDS."""
        answered_by = [{"model": name, "thinking": on} for name, on in models]
        conversation = {
            "prompt_hash": prompt_hash,
            "task": task,
            "outcome": AiOutcome.OK,
            "$or": answered_by,
            "created_at": {"$gte": since},
        }
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            found = self.collection.find_one(
                conversation, projection={"response": 1, "model": 1}, sort=[("created_at", -1), ("_id", -1)]
            )
        return (found["response"], found["model"]) if found else None
