"""Requesting a plan for an accepted generated scenario: the
scenario checked (404, 403, 409 not accepted), one plan per scenario (409 plan_already_exists, checked
before any control is mapped), its controls topped up when missing , the register resolved
against the library, version 1's snapshot frozen, one insert, the plan job sent. A hand-written scenario
comes with S55."""

import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    RemediationMessage,
    RunKind,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.core.redaction import REDACTED
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.remediations import RemediationRepository
from app.models.api_clients import Principal
from app.models.remediation import PlanStarted
from app.models.remediation_requests import PlanRequest, RegisterData
from app.realtime.publisher import publish_remediation_status
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.remediation.snapshots import SnapshotMaker, get_snapshot_maker
from app.worker.celery_app import send_job


class PlanRequestService:
    def __init__(self, plans: RemediationRepository, snapshots: SnapshotMaker) -> None:
        self._plans, self._snapshots = plans, snapshots

    @traced("remediation.request")
    def request(self, principal: Principal, body: PlanRequest) -> PlanStarted:
        """A generated scenario's plan (a hand-written one: app/services/remediation/manual.py)."""
        assert body.session_id is not None and body.scenario_id is not None  # PlanRequest: is_manual=false
        scenario = self._accepted_scenario(principal, body.session_id, body.scenario_id)
        return self.plan_scenario(principal, body, scenario)

    def plan_scenario(
        self, principal: Principal, register: RegisterData, scenario: dict[str, Any]
    ) -> PlanStarted:
        """R1 steps 3-8 for an accepted scenario, generated or hand-written: one plan per scenario (checked
        before any control is mapped), the snapshot, one insert, the job sent."""
        if (existing := self._plans.find_for_scenario(scenario["_id"])) is not None:
            raise _plan_exists(scenario["_id"], existing.remediation_id)
        record = new_plan_record(principal, register, scenario, self._snapshots.make(register, scenario))
        if not self._plans.insert(record):  # a request made at the same moment won
            winner = self._plans.find_for_scenario(scenario["_id"])
            raise _plan_exists(scenario["_id"], winner.remediation_id if winner else None)
        if self._plans.find_scenario(scenario["_id"]) is None:  # its run was deleted meanwhile (G214)
            self._plans.remove(record["_id"])
            raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario["_id"]))
        _announce(principal, record)
        return PlanStarted(
            remediation_id=record["_id"],
            session_id=record["session_id"],
            scenario_id=record["scenario_id"],
            version=1,
            status=Status.QUEUED,
            is_manual=record["source"] == RunKind.MANUAL,
        )

    def _accepted_scenario(self, principal: Principal, session_id: str, scenario_id: str) -> dict[str, Any]:
        """404 unknown or in another run (v1: "scenario not found in this session"), 403 another entity's, 409
        not accepted."""
        scenario = self._plans.find_scenario(scenario_id)
        if scenario is None:
            raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id))
        if scenario["session_id"] != session_id:
            message = RemediationMessage.SCENARIO_NOT_IN_SESSION.format(
                scenario_id=scenario_id, session_id=session_id
            )
            raise NotFound(message)
        if scenario["entity_id"] != principal.entity_id:
            raise Forbidden(RemediationMessage.SCENARIO_OTHER_ENTITY.format(scenario_id=scenario_id))
        if not still_accepted(scenario):
            message = RemediationMessage.SCENARIO_NOT_ACCEPTED.format(scenario_id=scenario_id)
            raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
        return scenario


def still_accepted(scenario: dict[str, Any] | None) -> bool:
    """Only an accepted, written scenario is planned; once un-accepted its plan is read-only (G-J)."""
    return (
        scenario is not None
        and scenario["status"] == ScenarioStatus.DONE
        and scenario["decision"] == Decision.ACCEPTED
    )


def new_plan_record(
    principal: Principal, register: RegisterData, scenario: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    """A queued plan with version 1 and its whole job (BLUEPRINT §12.2): the claim takes a queued job only
    when job.due_at has come, and `decision_seq` starts at 0 (a decision filters on it: a missing one never
    matches)."""
    now = datetime.now(UTC)
    content = scenario.get("content") or {}
    return {
        "_id": uuid.uuid4().hex,
        "scenario_id": scenario["_id"],
        "session_id": scenario["session_id"],
        "entity_id": principal.entity_id,
        "asset_id": scenario["asset_id"],
        "source": scenario["source"],
        "title": content.get("title") or (content.get("threat") or {}).get("name"),
        "register": register.register(),
        "versions": [new_version(1, principal, snapshot, now)],
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "risk_level": register.risk_level,
        "status": Status.QUEUED,
        "active": True,
        "job": {
            "task": TaskName.WRITE_PLAN,
            "epoch": 1,
            "task_id": None,
            "attempts": 0,
            "due_at": now,
            "error": None,
        },
        "created_at": now,
        "updated_at": now,
    }


def new_version(number: int, principal: Principal, snapshot: dict[str, Any], now: datetime) -> dict[str, Any]:
    """One version as requested: its snapshot, no plan yet, undecided; who asked, from which system."""
    return {
        "version": number,
        "status": Status.QUEUED,
        "snapshot": snapshot,
        "plan": None,
        "warnings": [],
        "prompt_version": None,
        "error": None,
        "decision": Decision.PENDING,
        "decided_by": None,
        "decided_by_client": None,
        "decided_at": None,
        "review_comment": None,
        "requested_by": principal.user_id,
        "requested_by_client": principal.client_id,
        "requested_at": now,
        "completed_at": None,
    }


def _announce(principal: Principal, record: dict[str, Any]) -> None:
    """After the insert: the job is sent (a failed send is re-sent by the reaper), audited with the risk owner
    masked (a person), and watchers told."""
    send_job(TaskName.WRITE_PLAN, record["_id"], record["job"]["epoch"])
    register = dict(record["register"])
    if register.get("risk_owner"):
        register["risk_owner"] = REDACTED
    record_audit(
        AuditAction.PLAN_REQUESTED,
        caller_actor(principal),
        audit_target(AuditTarget.REMEDIATION, record["_id"]),
        after={"scenario_id": record["scenario_id"], "version": 1, "register": register},
    )
    publish_remediation_status(record["_id"])


def _plan_exists(scenario_id: str, remediation_id: str | None) -> Conflict:
    message = RemediationMessage.PLAN_EXISTS.format(scenario_id=scenario_id, remediation_id=remediation_id)
    return Conflict(
        message, reason=ConflictReason.PLAN_ALREADY_EXISTS, details={"remediation_id": remediation_id}
    )


@singleton
def get_plan_request_service() -> PlanRequestService:
    db = get_mongodb()
    return PlanRequestService(RemediationRepository(db), get_snapshot_maker())
