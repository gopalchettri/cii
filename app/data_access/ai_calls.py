"""tsg_ai_calls: one record per chat call (prompt, answer, tokens, seconds), deleted
AiLimits.CALL_RECORD_DAYS after its created_at."""

from datetime import timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.constants import AiOutcome, Timeouts
from app.core.database import expire_documents_after


class AiCallRecords:
    def __init__(self, collection: MongoCollection) -> None:
        self._records = collection

    def keep_for_days(self, days: int) -> None:
        """Records are deleted `days` after their created_at (a TTL index; a changed retention updates it)."""
        expire_documents_after(self._records, "created_at", int(timedelta(days=days).total_seconds()))

    def index_for_retries(self) -> None:
        """G244: a retried job finds the answer it already got by its task id and exact prompt."""
        self._records.create_index([("task_id", 1), ("prompt_hash", 1)])

    def find_usable_reply(self, task_id: str, prompt_hash: str) -> str | None:
        """The newest usable ("ok") reply job `task_id` got for the prompt with `prompt_hash`: one indexed
        read, bounded like the write."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            found = self._records.find_one(
                {"task_id": task_id, "prompt_hash": prompt_hash, "outcome": AiOutcome.OK},
                {"response": 1},
                sort=[("created_at", -1)],
            )
        return found["response"] if found else None

    def insert(self, record: dict[str, Any]) -> None:
        # Bounded like the audit write: the answer is already in hand, so a slow MongoDB must not hold it for
        # the 30 s socket timeout (the caller logs a failed record and carries on).
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            self._records.insert_one(record)
