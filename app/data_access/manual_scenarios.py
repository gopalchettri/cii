"""A hand-written scenario's run and scenario (BLUEPRINT M11 R2 step 6; BUILD_PLAN S55), each saved by an
upsert on its key-derived id: a retry after a crash lands on the same documents and changes nothing."""

from typing import Any

from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection, RunClash


class ManualRecords:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]
        self._scenarios = db[Collection.SCENARIOS]

    def save(self, run: dict[str, Any], scenario: dict[str, Any]) -> RunClash | None:
        """None once both exist; IDEMPOTENCY_KEY when another run took the key meanwhile (its unique
        index)."""
        try:
            _insert_once(self._sessions, run)
        except DuplicateKeyError:
            return RunClash.IDEMPOTENCY_KEY
        _insert_once(self._scenarios, scenario)
        return None


def _insert_once(records: MongoCollection, record: dict[str, Any]) -> None:
    fields = {key: value for key, value in record.items() if key != "_id"}
    records.update_one({"_id": record["_id"]}, {"$setOnInsert": fields}, upsert=True)
