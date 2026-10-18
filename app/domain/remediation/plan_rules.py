"""What may be done to a remediation plan (BLUEPRINT M11): which scenario gets a plan, who may read or change
one, when a new version may be made (at most the configured number in total), and the records a
request writes. Pure: the services read and write; these decide, or raise the answer."""

import uuid
from datetime import datetime
from typing import Any

from app.core.constants import (
    ConflictReason,
    Decision,
    JobControlMessage,
    RemediationMessage,
    ScenarioStatus,
    SessionMessage,
    Status,
)
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.models.admin.api_clients import Principal
from app.models.remediation.plan import RemediationStatus
from app.models.remediation.requests import RegisterData

#: The latest version's statuses a new version may follow; one queued or running is resumed on purpose (G214).
_REGENERABLE = (Status.DONE, Status.FAILED, Status.CANCELLED)


def still_accepted(scenario: dict[str, Any] | None) -> bool:
    """Only an accepted, written scenario is planned; once un-accepted its plan is read-only (G-J)."""
    return (
        scenario is not None
        and scenario["status"] == ScenarioStatus.DONE
        and scenario["decision"] == Decision.ACCEPTED
    )


def check_plannable_scenario(
    scenario: dict[str, Any] | None, session_id: str, scenario_id: str, entity_id: int
) -> dict[str, Any]:
    """The scenario a plan is requested for: 404 unknown or in another run (v1: "scenario not found in this
    session"), 403 another entity's, 409 not accepted."""
    if scenario is None:
        raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario_id))
    if scenario["session_id"] != session_id:
        raise NotFound(
            RemediationMessage.SCENARIO_NOT_IN_SESSION.format(scenario_id=scenario_id, session_id=session_id)
        )
    if scenario["entity_id"] != entity_id:
        raise Forbidden(RemediationMessage.SCENARIO_OTHER_ENTITY.format(scenario_id=scenario_id))
    if not still_accepted(scenario):
        message = RemediationMessage.SCENARIO_NOT_ACCEPTED.format(scenario_id=scenario_id)
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
    return scenario


def check_plan_owner(read: dict[str, Any] | None, entity_id: int, remediation_id: str) -> dict[str, Any]:
    """The plan a regenerate or a decision changes: 404 unknown, 403 another entity's."""
    if read is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    if read["entity_id"] != entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=remediation_id))
    return read


def check_plan_changeable(scenario: dict[str, Any] | None, read: dict[str, Any]) -> None:
    """A plan whose scenario is no longer accepted stays readable but takes no change (G-J)."""
    if not still_accepted(scenario):
        message = RemediationMessage.PLAN_READ_ONLY.format(scenario_id=read["scenario_id"])
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)


def check_regenerable(read: dict[str, Any], remediation_id: str, max_version_count: int) -> int:
    """The new version's number: 409 while the latest is still being written, or when the plan already has
    `max_version_count` versions (REGENERATIONS_MAX_VERSION_COUNT)."""
    latest = read["job"]["epoch"]
    if read["status"] not in _REGENERABLE:
        raise version_in_progress(remediation_id, latest)
    if latest >= max_version_count:
        message = RemediationMessage.VERSION_LIMIT_REACHED.format(
            remediation_id=remediation_id, max_versions=max_version_count
        )
        raise Conflict(message, reason=ConflictReason.VERSION_LIMIT_REACHED)
    return latest + 1


def version_in_progress(remediation_id: str, version: int) -> Conflict:
    """409 generation_in_progress: the latest version is still being written."""
    message = RemediationMessage.VERSION_IN_PROGRESS.format(version=version, remediation_id=remediation_id)
    return Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)


def plan_exists(scenario_id: str, remediation_id: str | None) -> Conflict:
    """409 plan_already_exists: one plan per scenario, regenerated instead."""
    message = RemediationMessage.PLAN_EXISTS.format(scenario_id=scenario_id, remediation_id=remediation_id)
    return Conflict(
        message, reason=ConflictReason.PLAN_ALREADY_EXISTS, details={"remediation_id": remediation_id}
    )


def run_being_deleted(session_id: str) -> Conflict:
    """409 run_being_deleted, as a next set answers: the plan's run is being deleted."""
    message = JobControlMessage.BEING_DELETED.format(session_id=session_id)
    return Conflict(message, reason=ConflictReason.RUN_BEING_DELETED)


def check_own_entity(entity_id: int, caller_entity_id: int) -> None:
    """An entity's plans are listed for that entity's callers only (403)."""
    if entity_id != caller_entity_id:
        raise Forbidden(SessionMessage.ENTITY_MISMATCH)


def check_plan_of_scenario(
    status: RemediationStatus | None, entity_id: int, session_id: str, scenario_id: str
) -> RemediationStatus:
    """The scenario's plan: 404 none or not in this run, 403 another entity's."""
    if status is None or status.session_id != session_id:
        message = RemediationMessage.PLAN_NOT_REQUESTED.format(scenario_id=scenario_id, session_id=session_id)
        raise NotFound(message)
    if status.entity_id != entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=status.remediation_id))
    return status


def new_plan_record(  # noqa: PLR0913 — one record, whole
    principal: Principal,
    register: RegisterData,
    scenario: dict[str, Any],
    snapshot: dict[str, Any],
    job: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """A queued plan with version 1 and its whole job (BLUEPRINT §12.2): the claim takes a queued job only
    when job.due_at has come, and `decision_seq` starts at 0 (a decision filters on it: a missing one never
    matches)."""
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
        "job": job,
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
