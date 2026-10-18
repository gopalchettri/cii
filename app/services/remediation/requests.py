"""Requesting a plan for an accepted generated scenario: the scenario checked (404, 403, 409 not accepted),
one plan per scenario (409 plan_already_exists), the register resolved against the library and stored as
version 1's pending snapshot (its plan job maps missing controls and completes it), one insert, its run
checked for a delete after the insert (409 run_being_deleted), the plan job sent."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import AuditAction, AuditTarget, RemediationMessage, RunKind, Status, TaskName
from app.core.exceptions import DuplicateRecord, NotFound
from app.core.redaction import REDACTED
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.jobs.repository import new_job
from app.data_access.remediation.repository import (
    PLANNED_SCENARIO_FIELDS,
    is_plan_run_being_deleted,
    remediation_plans,
)
from app.data_access.scenario.repository import scenarios
from app.domain.remediation.plan_rules import (
    check_plannable_scenario,
    new_plan_record,
    plan_exists,
    run_being_deleted,
)
from app.models.api_clients import Principal
from app.models.remediation import PlanStarted
from app.models.remediation_requests import PlanRequest, RegisterData
from app.realtime.publisher import publish_remediation_status
from app.services.audit import audit_target, caller_actor
from app.services.remediation.queries import get_remediation_status_of_scenario
from app.services.remediation.snapshots import SnapshotMaker, get_snapshot_maker
from app.worker.celery_app import send_job


class PlanRequestService:
    def __init__(self, snapshots: SnapshotMaker) -> None:
        self._snapshots = snapshots

    def request(self, principal: Principal, body: PlanRequest) -> PlanStarted:
        """A generated scenario's plan (a hand-written one: app/services/remediation/manual.py)."""
        assert body.session_id is not None and body.scenario_id is not None  # PlanRequest: is_manual=false
        scenario = scenarios.get(fields=PLANNED_SCENARIO_FIELDS, _id=body.scenario_id)
        checked = check_plannable_scenario(scenario, body.session_id, body.scenario_id, principal.entity_id)
        return self.plan_scenario(principal, body, checked)

    def plan_scenario(
        self, principal: Principal, register: RegisterData, scenario: dict[str, Any]
    ) -> PlanStarted:
        """R1 steps 3-8 for an accepted scenario, generated or hand-written: one plan per scenario, the
        pending snapshot, one insert, the job sent."""
        if (existing := get_remediation_status_of_scenario(scenario["_id"])) is not None:
            raise plan_exists(scenario["_id"], existing.remediation_id)
        snapshot, now = self._snapshots.make(register, scenario), datetime.now(UTC)
        job = new_job(TaskName.WRITE_PLAN, 1, now)
        record = new_plan_record(principal, register, scenario, snapshot, job, now)
        try:
            remediation_plans.create(record)
        except DuplicateRecord:  # a request made at the same moment won
            winner = get_remediation_status_of_scenario(scenario["_id"])
            raise plan_exists(scenario["_id"], winner.remediation_id if winner else None) from None
        if not scenarios.count(_id=scenario["_id"]):  # its run was deleted meanwhile: no plan outlives it
            remediation_plans.delete(_id=record["_id"])
            raise NotFound(RemediationMessage.SCENARIO_NOT_FOUND.format(scenario_id=scenario["_id"]))
        # Checked after the insert: either this sees the delete's mark or the delete's check for work sees it.
        if is_plan_run_being_deleted(record["session_id"]):
            remediation_plans.delete(_id=record["_id"])
            raise run_being_deleted(record["session_id"])
        _announce(principal, record)
        return PlanStarted(
            remediation_id=record["_id"],
            session_id=record["session_id"],
            scenario_id=record["scenario_id"],
            version=1,
            status=Status.QUEUED,
            is_manual=record["source"] == RunKind.MANUAL,
        )


def _announce(principal: Principal, record: dict[str, Any]) -> None:
    """After the insert: the job is sent (a failed send is re-sent by the reaper), audited with the risk owner
    masked (a person), and watchers told."""
    send_job(TaskName.WRITE_PLAN, record["_id"], record["job"]["epoch"])
    register = dict(record["register"])
    if register.get("risk_owner"):
        register["risk_owner"] = REDACTED
    audit_records.create_audit_record(
        AuditAction.PLAN_REQUESTED,
        caller_actor(principal),
        audit_target(AuditTarget.REMEDIATION, record["_id"]),
        after={"scenario_id": record["scenario_id"], "version": 1, "register": register},
    )
    publish_remediation_status(record["_id"])


@singleton
def get_plan_request_service() -> PlanRequestService:
    return PlanRequestService(get_snapshot_maker())
