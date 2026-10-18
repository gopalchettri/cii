"""A hand-written scenario's run and scenario, each saved by an upsert on its key-derived id: a retry after a
crash lands on the same documents and changes nothing."""

from typing import Any

from pymongo import ReturnDocument
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
        index) or a request with this key and another body saved its run first (nothing is saved)."""
        try:
            stored = _insert_once(self._sessions, run)
        except DuplicateKeyError:
            return RunClash.IDEMPOTENCY_KEY
        if stored.get("request_hash") != run["request_hash"]:
            return RunClash.IDEMPOTENCY_KEY
        _insert_once(self._scenarios, scenario)
        return None

    def complete(self, scenario_id: str, changes: dict[str, Any]) -> None:
        """What its plan job found (attackers, library ids) saved and `pending` removed, in one write."""
        self._scenarios.update_one({"_id": scenario_id}, {"$set": changes, "$unset": {"pending": ""}})


def _insert_once(records: MongoCollection, record: dict[str, Any]) -> dict[str, Any]:
    """Insert `record` unless its id exists already; the record as stored."""
    fields = {key: value for key, value in record.items() if key != "_id"}
    return records.find_one_and_update(
        {"_id": record["_id"]}, {"$setOnInsert": fields}, upsert=True, return_document=ReturnDocument.AFTER
    )
