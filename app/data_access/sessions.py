"""tsg_sessions: one document per run. Its job fields are written by app/data_access/job_records.py; this
module reads a run's status, inserts runs and finds them by key.

Two unique indexes make the run rules race-free without a lock: one active run per asset, and one run per
Idempotency-Key per entity."""

from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection, RunClash, SessionMessage
from app.core.database import get_mongodb
from app.core.exceptions import NotFound
from app.models.scenarios import SessionStatus

#: What a replay reads of the run that first took an Idempotency-Key.
_REPLAY_FIELDS = {**SessionStatus.RECORD_FIELDS, "kind": 1, "request_hash": 1}
_WRITING_FIELDS = {
    "entity_id": 1,
    "asset_id": 1,
    "context": 1,
    "job.batch": 1,
    "job.set": 1,
    "last_action.started_at": 1,
    "last_action.kind": 1,  # a next set's end is shown on the status (last_next_set)
    **{f"plan.{part}": 1 for part in ("threats", "paths", "not_assessed", "frozen_at")},
}


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def ensure_indexes(self) -> None:
        self._sessions.create_index(
            [("entity_id", 1), ("asset_id", 1)], unique=True, partialFilterExpression={"active": True}
        )
        self._sessions.create_index(
            [("entity_id", 1), ("idempotency_key", 1)],
            unique=True,
            partialFilterExpression={"idempotency_key": {"$exists": True}},
        )
        self._sessions.create_index([("entity_id", 1), ("created_at", -1)])
        # The job list (G214): an entity's runs queued or running, and (a partial index: few runs) its runs
        # whose controls are still being matched; each oldest first.
        self._sessions.create_index([("entity_id", 1), ("status", 1), ("created_at", 1)])
        self._sessions.create_index(
            [("entity_id", 1), ("created_at", 1)],
            name="controls_waiting_by_entity",
            partialFilterExpression={"counts.controls_waiting": {"$gt": 0}},
        )

    def find_status(self, session_id: str) -> SessionStatus | None:
        """A run's status; reads only the fields the status body shows, never the plan or the context."""
        record = self._sessions.find_one({"_id": session_id}, SessionStatus.RECORD_FIELDS)
        return None if record is None else SessionStatus.from_record(record)

    def find_by_idempotency_key(self, entity_id: int, key: str) -> dict[str, Any] | None:
        return self._sessions.find_one({"entity_id": entity_id, "idempotency_key": key}, _REPLAY_FIELDS)

    def find_context(self, session_id: str) -> dict[str, Any]:
        """The run's frozen asset context (the threat-finding job's input); NotFound (404) for a run that does
        not exist, or was deleted while a plan request or a job read it (G214)."""
        found = self._sessions.find_one({"_id": session_id}, {"context": 1})
        if found is None:
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
        return found["context"]

    def find_for_writing(self, session_id: str) -> dict[str, Any]:
        """What the write job reads of its run: the frozen context, the plan's threats and paths and the
        batch; never the plan's category records (the biggest part). KeyError for an unknown run."""
        found = self._sessions.find_one({"_id": session_id}, _WRITING_FIELDS)
        if found is None:
            raise KeyError(session_id)
        return found

    def find_active_run_id(self, entity_id: int, asset_id: int) -> str | None:
        found = self._sessions.find_one(
            {"entity_id": entity_id, "asset_id": asset_id, "active": True}, {"_id": 1}
        )
        return None if found is None else found["_id"]

    def insert_run(self, record: dict[str, Any]) -> RunClash | None:
        """None when inserted; else which unique rule refused it."""
        try:
            self._sessions.insert_one(record)
        except DuplicateKeyError as exc:
            refused_key = (exc.details or {}).get("keyPattern", {})
            return RunClash.ACTIVE_RUN if "asset_id" in refused_key else RunClash.IDEMPOTENCY_KEY
        return None


def find_session_status(session_id: str) -> SessionStatus | None:
    """The status of a run, for the live-update stream and its checks."""
    return SessionRepository(get_mongodb()).find_status(session_id)
