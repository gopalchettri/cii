"""What may be done to a remediation plan and the records a request or a decision writes; pure, no IO."""

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.core.constants import (
    ConflictReason,
    Decision,
    ErrorCode,
    ErrorMessage,
    RemediationMessage,
    ScenarioStatus,
    SessionMessage,
    Status,
)
from app.core.exceptions import Conflict, Forbidden, Invalid, NotFound
from app.models.admin.api_clients import Principal
from app.models.library.library import LibraryControl
from app.models.remediation.plan import RemediationStatus, version_status


def still_accepted(scenario: dict[str, Any] | None) -> bool:
    """Whether the scenario is written and accepted: only then is it planned or its plan changed."""
    return (
        scenario is not None
        and scenario["status"] == ScenarioStatus.DONE
        and scenario["decision"] == Decision.ACCEPTED
    )


def check_plannable_scenario(
    scenario: dict[str, Any] | None, session_id: str, scenario_id: str, entity_id: int
) -> dict[str, Any]:
    """The scenario a plan is requested for: 404 unknown or in another run, 403 another entity's, 409 not
    accepted."""
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


def check_plan_changeable(
    scenario: dict[str, Any] | None, read: dict[str, Any] | None, entity_id: int, remediation_id: str
) -> dict[str, Any]:
    """The plan a regenerate or a decision changes: 404 unknown, 403 another entity's, 409 read-only."""
    if read is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    if read["entity_id"] != entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=remediation_id))
    if not still_accepted(scenario):
        message = RemediationMessage.PLAN_READ_ONLY.format(scenario_id=read["scenario_id"])
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
    return read


def check_regenerable(read: dict[str, Any], remediation_id: str, max_version_count: int) -> int:
    """The new version's number: 409 while the latest is being written or the version limit is reached."""
    latest = read["job"]["epoch"]
    if read["status"] not in (Status.DONE, Status.FAILED, Status.CANCELLED):
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


def check_own_entity(entity_id: int, caller_entity_id: int) -> None:
    """403 unless the entity is the caller's own."""
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


def check_control_library(library: Sequence[LibraryControl]) -> None:
    """409 while the control library is empty: no control could ever be kept."""
    if not library:
        raise Conflict(ErrorMessage.CONTROL_LIBRARY_EMPTY, reason=ErrorCode.CONTROL_LIBRARY_EMPTY)


def check_register_systems(register: dict[str, Any], system_ids: Sequence[int]) -> None:
    """422 naming each existing control's supporting_system_ids entry that is not a system of the asset."""
    known = set(system_ids)
    errors = [
        {
            "field": f"body.existing_controls[{position}].supporting_system_ids",
            "message": RemediationMessage.SYSTEM_NOT_OF_ASSET.format(
                system_id=system_id, known=", ".join(map(str, system_ids))
            ),
        }
        for position, entry in enumerate(register.get("existing_controls") or [])
        for system_id in entry.get("supporting_system_ids") or []
        if system_id not in known
    ]
    if errors:
        raise Invalid(RemediationMessage.REGISTER_SYSTEMS_INVALID, errors=errors)


def new_plan_record(
    principal: Principal,
    register: dict[str, Any],
    scenario: dict[str, Any],
    job: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """A queued plan with version 1, its whole job and decision_seq 0."""
    content = scenario.get("content") or {}
    return {
        "_id": uuid.uuid4().hex,
        "scenario_id": scenario["_id"],
        "session_id": scenario["session_id"],
        "entity_id": principal.entity_id,
        "asset_id": scenario["asset_id"],
        "source": scenario["source"],
        "title": content.get("title") or (content.get("threat") or {}).get("name"),
        "register": register,
        "versions": [new_version(1, principal, now)],
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "risk_level": register["risk_level"],
        "status": Status.QUEUED,
        "active": True,
        "job": job,
        "created_at": now,
        "updated_at": now,
    }


def new_version(number: int, principal: Principal, now: datetime) -> dict[str, Any]:
    """One version as requested: no snapshot or plan yet, undecided, with who asked from which client."""
    return {
        "version": number,
        "status": Status.QUEUED,
        "snapshot": None,
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


def newest_done_version(read: dict[str, Any]) -> int | None:
    """The highest version number whose status is done, or None."""
    return max(
        (item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE),
        default=None,
    )


def decidable_version(read: dict[str, Any], asked: int | None, remediation_id: str) -> int:
    """The version to decide (asked, else the newest done): 409 none done, 404 unknown, 409 not done."""
    version = asked if asked is not None else newest_done_version(read)
    if version is None:
        message = RemediationMessage.NO_DONE_VERSION.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    item = next((item for item in read["versions"] if item["version"] == version), None)
    if item is None:
        message = RemediationMessage.VERSION_NOT_FOUND.format(remediation_id=remediation_id, version=version)
        raise NotFound(message, reason=ConflictReason.VERSION_NOT_FOUND)
    if (status := version_status(read, item)) != Status.DONE:
        message = RemediationMessage.NOT_COMPLETE.format(
            version=version, remediation_id=remediation_id, status=status
        )
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    return version


def decision_change(
    read: dict[str, Any],
    version: int,
    decision: Decision,
    decided_by: dict[str, str],
    comment: str | None,
    now: datetime,
) -> dict[str, Any] | None:
    """The one change a decision makes as plain values, or None for a repeat; at most one version accepted."""
    decisions = {item["version"]: item["decision"] for item in read["versions"]}
    accepted = read.get("accepted_version")
    repeat = accepted == version if decision == Decision.ACCEPTED else decisions[version] == Decision.REJECTED
    if repeat:
        return None
    decisions[version] = decision
    back_to_pending = None
    if decision == Decision.ACCEPTED:
        if accepted is not None:
            back_to_pending = accepted
            decisions[accepted] = Decision.PENDING
        accepted = version
    elif accepted == version:
        accepted = None
    done = {item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE}
    if accepted is not None:
        record_decision = Decision.ACCEPTED
    elif any(decisions[v] == Decision.PENDING for v in done | {read["job"]["epoch"]}):
        record_decision = Decision.PENDING  # the latest or a done version still waits
    else:
        record_decision = Decision.REJECTED
    return {
        "version": version,
        "decision": decision,
        "stamp": {**decided_by, "decided_at": now, "review_comment": comment},
        "back_to_pending": back_to_pending,
        "accepted_version": accepted,
        "record_decision": record_decision,
    }
