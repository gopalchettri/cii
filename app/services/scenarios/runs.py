"""Starting a run: one SQL call proves ownership and freezes the asset's
facts, one insert queues the whole job, and the threat-finding job is sent. Next set and regenerate join here
with review."""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    RunActionKind,
    RunClash,
    RunKind,
    SessionMessage,
    Status,
    Step,
    TaskName,
)
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.asset_context import AssetContextRepository
from app.data_access.sessions import SessionRepository
from app.models.api_clients import Principal
from app.models.asset_context import FrozenContext
from app.models.scenarios import SessionStatus, StartRunRequest, running_action
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.external_intelligence.data_check import refuse_without_intel_data
from app.services.scenarios.context import freeze_context
from app.worker.celery_app import send_job

#: Every count a status shows, zero until the scenarios exist (BLUEPRINT M09 S12 keeps them).
_ZERO_COUNTS = dict.fromkeys(
    (
        "planned",
        "written",
        "remaining",
        "failed",
        "abandoned",
        "accepted",
        "rejected",
        "pending",
        "controls_waiting",
        "controls_failed",
    ),
    0,
)


class RunService:
    def __init__(self, asset_contexts: AssetContextRepository, sessions: SessionRepository) -> None:
        self._asset_contexts = asset_contexts
        self._sessions = sessions

    @traced("run.start")
    def start(
        self, principal: Principal, request: StartRunRequest, idempotency_key: str | None
    ) -> tuple[SessionStatus, bool]:
        """(the run's status, True when it was created now; False for a replay of the same
        Idempotency-Key)."""
        if idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
            return replayed, False
        refuse_without_intel_data()  # on but nothing imported: refused now, never a run that can only fail
        rows = self._asset_contexts.read(
            principal.entity_id,
            request.asset_id,
            request.supporting_system_ids,
            request.service_id,
            request.sector_id,
            request.subsector_id,
        )
        context = freeze_context(request, rows)
        record = new_run_record(principal, request, idempotency_key, context)
        clash = self._sessions.insert_run(record)
        if clash is RunClash.ACTIVE_RUN:
            active_id = self._sessions.find_active_run_id(principal.entity_id, request.asset_id)
            message = SessionMessage.ACTIVE_SESSION_EXISTS.format(asset_id=request.asset_id)
            raise Conflict(
                message, reason=ConflictReason.ACTIVE_SESSION_EXISTS, details={"active_session_id": active_id}
            )
        if (
            clash is RunClash.IDEMPOTENCY_KEY
        ):  # a parallel start with the same key won: this one is its replay
            assert idempotency_key is not None
            replayed = self._replay(principal, request, idempotency_key)
            assert replayed is not None  # the key is taken, so its run exists
            return replayed, False
        self._announce(principal, record, context)
        return SessionStatus.from_record(record), True

    def _replay(self, principal: Principal, request: StartRunRequest, key: str) -> SessionStatus | None:
        """The run that already took this key: its status when it is the same request; 409 when the key named
        another request (another asset, other systems or context: G111) or a hand-written run (one key space
        per entity)."""
        earlier = self._sessions.find_by_idempotency_key(principal.entity_id, key)
        if earlier is None:
            return None
        other_request = earlier.get("request_hash", request_fingerprint(request)) != request_fingerprint(
            request
        )
        if earlier.get("kind") == RunKind.MANUAL or earlier["asset_id"] != request.asset_id or other_request:
            raise Conflict(
                SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT
            )
        return SessionStatus.from_record(earlier)

    @staticmethod
    def _announce(principal: Principal, record: dict[str, Any], context: FrozenContext) -> None:
        """After the insert: the job is sent (a failed send is re-sent by the reaper), counted and audited."""
        send_job(TaskName.FIND_THREATS, record["_id"], record["job"]["epoch"])
        metrics.RUNS.labels(RunKind.GENERATED).inc()
        record_audit(
            AuditAction.RUN_STARTED,
            caller_actor(principal),
            audit_target(AuditTarget.SESSION, record["_id"]),
            after={
                "asset_id": record["asset_id"],
                "supporting_system_ids": record["request"]["supporting_system_ids"],
            },
            details={"missing_facts": context.missing_facts},
        )


def request_fingerprint(request: StartRunRequest) -> str:
    """The request's SHA-256 over its canonical JSON (systems as a set): what a replayed Idempotency-Key must
    match to return the earlier run (spec v4.0 §6.1 #1)."""
    canonical = request.model_dump(mode="json") | {
        "supporting_system_ids": sorted(request.supporting_system_ids)
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def new_run_record(
    principal: Principal, request: StartRunRequest, idempotency_key: str | None, context: FrozenContext
) -> dict[str, Any]:
    """A queued run with its whole job: the claim takes a queued job only when job.due_at has come, and the
    reaper finds a lost one by it, so a job without due_at would never be picked up."""
    now = datetime.now(UTC)
    record: dict[str, Any] = {
        "_id": uuid.uuid4().hex,
        "kind": RunKind.GENERATED,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,  # the calling system: stored, never shown, never used to refuse
        "asset_id": request.asset_id,
        "request": request.model_dump(exclude={"asset_id"}),
        "request_hash": request_fingerprint(request),
        "context": context.to_record(),
        "status": Status.QUEUED,
        "step": Step.THREATS,
        "active": True,
        "plan_note": None,
        "last_action": running_action(RunActionKind.START, now),
        "counts": dict(_ZERO_COUNTS),
        "job": {
            "task": TaskName.FIND_THREATS,
            "epoch": 1,
            "task_id": None,
            "attempts": 0,
            "due_at": now,
            "error": None,
        },
        "created_at": now,
        "updated_at": now,
    }
    if idempotency_key:
        record["idempotency_key"] = idempotency_key
    return record


@singleton
def get_run_service() -> RunService:
    return RunService(AssetContextRepository(get_stored_procedure_client()), SessionRepository(get_mongodb()))
