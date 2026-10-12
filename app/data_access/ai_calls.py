"""tsg_ai_calls: one record per chat call (prompt, answer, tokens, seconds), deleted
AiLimits.CALL_RECORD_DAYS after its created_at."""

from datetime import timedelta
from typing import Any

import pymongo
from pymongo.collection import Collection as MongoCollection

from app.core.constants import Timeouts
from app.core.database import expire_documents_after


class AiCallRecords:
    def __init__(self, collection: MongoCollection) -> None:
        self._records = collection

    def keep_for_days(self, days: int) -> None:
        """Records are deleted `days` after their created_at (a TTL index; a changed retention updates it)."""
        expire_documents_after(self._records, "created_at", int(timedelta(days=days).total_seconds()))

    def insert(self, record: dict[str, Any]) -> None:
        # Bounded like the audit write: the answer is already in hand, so a slow MongoDB must not hold it for
        # the 30 s socket timeout (the caller logs a failed record and carries on).
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            self._records.insert_one(record)
