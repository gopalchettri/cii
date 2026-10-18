"""tsg_sessions: one document per run. Its start, its reads, a next set's or regenerate's new write job, and
the asset context the run is built from."""

import json
from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import (
    Collection,
    RunActionKind,
    RunActionOutcome,
    RunClash,
    SessionMessage,
    Status,
    Step,
    StoredProcedure,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.core.exceptions import NotFound
from app.data_access.job_control import DELETING_MARK, is_being_deleted
from app.data_access.job_records import new_job
from app.models.asset_context import AssetContextRows
from app.models.scenario.views import (
    COVERAGE_FIELDS,
    SessionStatus,
    StartRunRequest,
    run_coverage,
    running_action,
)

#: What a replay reads of the run that first took an Idempotency-Key.
_REPLAY_FIELDS = {**SessionStatus.RECORD_FIELDS, "kind": 1, "request_hash": 1}
_WRITING_FIELDS = {
    "entity_id": 1,
    "asset_id": 1,
    "context": 1,
    "job.batch": 1,
    "job.set": 1,
    "last_action.started_at": 1,
    "last_action.kind": 1,
    **{f"plan.{part}": 1 for part in ("threats", "paths", "not_assessed", "frozen_at")},
}
_ACTION_FIELDS = {"entity_id": 1, "asset_id": 1, "status": 1, "step": 1, "job.epoch": 1}
#: What a new next set or regenerate clears: the last set's times and a cancel's mark.
_CLEARED_BY_A_NEW_ACTION = {
    "finished_at": "",
    "timings.scenarios_s": "",
    "timings.controls_s": "",
    "cancelled": "",
}


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def ensure_indexes(self) -> None:
        """One active run per asset and one run per Idempotency-Key, race-free; the job list's two reads."""
        self._sessions.create_index(
            [("entity_id", 1), ("asset_id", 1)], unique=True, partialFilterExpression={"active": True}
        )
        self._sessions.create_index(
            [("entity_id", 1), ("idempotency_key", 1)],
            unique=True,
            partialFilterExpression={"idempotency_key": {"$exists": True}},
        )
        self._sessions.create_index([("entity_id", 1), ("status", 1), ("created_at", 1)])
        self._sessions.create_index(
            [("entity_id", 1), ("created_at", 1)],
            name="controls_waiting_by_entity",
            partialFilterExpression={"counts.controls_waiting": {"$gt": 0}},
        )

    def find_by_idempotency_key(self, entity_id: int, key: str) -> dict[str, Any] | None:
        """The run that took this Idempotency-Key, as a replay reads it."""
        return self._sessions.find_one({"entity_id": entity_id, "idempotency_key": key}, _REPLAY_FIELDS)

    def find_context(self, session_id: str) -> dict[str, Any]:
        """The run's frozen asset context; NotFound for a run that does not exist (or was deleted)."""
        found = self._sessions.find_one({"_id": session_id}, {"context": 1})
        if found is None:
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
        return found["context"]

    def find_for_writing(self, session_id: str) -> dict[str, Any]:
        """What the write job reads of its run: context, plan threats and paths, batch. KeyError: unknown."""
        found = self._sessions.find_one({"_id": session_id}, _WRITING_FIELDS)
        if found is None:
            raise KeyError(session_id)
        return found

    def find_active_run_id(self, entity_id: int, asset_id: int) -> str | None:
        """The id of the asset's active run, if any."""
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


def find_run_coverage(session_id: str) -> dict[str, Any] | None:
    """The run's coverage worked out from its plan; None before a plan exists or for an unknown run."""
    record = get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id}, COVERAGE_FIELDS)
    return None if record is None else run_coverage(record)


def find_session_status(session_id: str) -> SessionStatus | None:
    """A run's status, read with only the fields the status shows; None for an unknown run."""
    record = get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id}, SessionStatus.RECORD_FIELDS)
    return None if record is None else SessionStatus.from_record(record)


class RunActionRecords:
    """A finished run given a new write job (next set, regenerate) in one conditional update, so of two clicks
    exactly one wins; and one threat of its frozen plan, for promotion."""

    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def find_for_action(self, session_id: str, with_paths: bool) -> dict[str, Any]:
        """The run's state and job epoch, and with_paths its plan's paths. NotFound for a run that does not
        exist (or was deleted since the caller read it)."""
        fields = _ACTION_FIELDS | ({"plan.paths": 1} if with_paths else {})
        found = self._sessions.find_one({"_id": session_id}, fields)
        if found is None:
            raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
        return found

    def queue_again(
        self,
        run: dict[str, Any],
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> RunClash | None:
        """A new write job for `batch` (epoch + 1) and, for a next set, the set it asked for, only while the
        run is as read: finished in step scenarios at the same epoch and not being deleted. None when queued;
        CHANGED or DELETING when the run moved on; ACTIVE_RUN when another run of the asset is active."""
        still_as_read = {
            "_id": run["_id"],
            "entity_id": run["entity_id"],
            "job.epoch": run["job"]["epoch"],
            "status": {"$in": [Status.DONE, Status.FAILED, Status.CANCELLED]},
            "step": Step.SCENARIOS,
            DELETING_MARK: {"$exists": False},
        }
        epoch, now = run["job"]["epoch"] + 1, datetime.now(UTC)
        queued = {
            "status": Status.QUEUED,
            "active": True,
            "job": new_job(TaskName.WRITE_SCENARIOS, epoch, now, batch=batch, set=asked),
            "last_action": running_action(kind, now),
            **_running_summary(kind, batch, asked, epoch),
            "updated_at": now,
        }
        try:
            written = self._sessions.update_one(
                still_as_read, {"$set": queued, "$unset": _CLEARED_BY_A_NEW_ACTION}
            )
        except DuplicateKeyError:
            return RunClash.ACTIVE_RUN
        if written.matched_count:
            return None
        return RunClash.DELETING if is_being_deleted(self._sessions, run["_id"]) else RunClash.CHANGED

    def find_plan_threat(self, session_id: str, threat_key: str) -> dict[str, Any] | None:
        """One threat of the run's frozen plan, by key, read alone (the positional projection)."""
        found = self._sessions.find_one(
            {"_id": session_id, "plan.threats.key": threat_key}, {"plan.threats.$": 1}
        )
        threats = ((found or {}).get("plan") or {}).get("threats") or []
        return threats[0] if threats else None


def _running_summary(
    kind: RunActionKind, batch: list[dict[str, Any]], asked: list[str] | None, epoch: int
) -> dict[str, Any]:
    """The status's summary of this action from its first moment, so it never shows the one before; its
    finish write fills in what it delivered. `requested` and `epoch` are written here only."""
    running = {"outcome": RunActionOutcome.RUNNING}
    if kind == RunActionKind.NEXT_SET:
        summary = {"requested": len(asked or []), "delivered": None, "reason": None, "remaining": None}
        return {"last_next_set": running | summary | {"epoch": epoch}}
    return {"last_regen": running | {"requested": len(batch), "replaced": None, "epoch": epoch}}


class AssetContextRepository:
    """One tsg_GetAssetContext call proves the entity owns the asset and reads every fact a run uses."""

    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def read(self, entity_id: int, request: StartRunRequest) -> AssetContextRows:
        """The procedure reads the sub-sector when sent, else the sector, with its parent."""
        asset, services, sector, systems, options = self._procedures.execute_procedure(
            StoredProcedure.GET_ASSET_CONTEXT,
            EntityID=entity_id,
            AssetID=request.asset_id,
            SystemIDs=json.dumps(request.supporting_system_ids),
            ServiceID=request.service_id,
            SectorID=request.sector_id,
            SubsectorID=request.subsector_id,
        )
        return AssetContextRows(
            asset=asset[0] if asset else None,
            services=services,
            sector=sector[0] if sector else None,
            systems=systems,
            options=options,
        )
