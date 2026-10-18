"""Reading remediation plans: a scenario's plan (status and result), an entity's or a run's plans, and the
status a live-update stream reads. Each is one projected read (+ the scenario for a result, + one count for a
list), the caller's entity checked (404 unknown, 403 another entity's)."""

from typing import Any

import structlog

from app.core.constants import Decision, Dependency, LogEvent, RemediationMessage, Status
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, NotFound
from app.core.singletons import singleton
from app.data_access.remediation.repository import remediation_plans
from app.data_access.scenario.repository import scenarios
from app.domain.remediation.plan_rules import check_own_entity, check_plan_of_scenario
from app.models.api_clients import Principal
from app.models.remediation import RemediationStatus
from app.models.remediation_views import RemediationList, RemediationResult, RemediationSummary

log = structlog.get_logger(__name__)


#: What a result shows of the planned scenario.
_SCENARIO_SUMMARY_FIELDS = ("content", "controls.items")


class RemediationQueries:
    def result(
        self, principal: Principal, session_id: str, scenario_id: str, include_history: bool
    ) -> RemediationResult:
        """The scenario's plan as shown, with the scenario it treats; 404/403 as every plan route."""
        record = remediation_plans.get(fields="result", scenario_id=scenario_id)
        status = None if record is None else RemediationStatus.from_record(record)
        check_plan_of_scenario(status, principal.entity_id, session_id, scenario_id)
        assert record is not None  # check_plan_of_scenario refused a missing plan
        scenario = scenarios.get(fields=_SCENARIO_SUMMARY_FIELDS, _id=scenario_id)
        return RemediationResult.from_records(record, scenario, include_history)

    def entity_plans(  # noqa: PLR0913 — the list's filters, each its own query parameter
        self,
        principal: Principal,
        entity_id: int,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The entity's plans (the entity in the path must be the caller's, else 403), newest first."""
        check_own_entity(entity_id, principal.entity_id)
        return self.run_plans(entity_id, None, status, decision, risk_level, offset, limit)

    def run_plans(  # noqa: PLR0913 — the list's filters, each its own query parameter
        self,
        entity_id: int,
        session_id: str | None,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The entity's plans (of one run when `session_id` is given), newest first, filtered by every filter
        given. The caller's run is checked by the route (valid_session)."""
        given = {"session_id": session_id, "status": status, "decision": decision, "risk_level": risk_level}
        where: dict[str, Any] = {key: value for key, value in given.items() if value is not None}
        where["entity_id"] = entity_id  # each filter with the newest-first sort is one index scan
        records = remediation_plans.list(
            fields="summary", sort="-created_at", skip=offset, limit=limit, **where
        )
        total = remediation_plans.count(**where)
        return RemediationList(
            items=[RemediationSummary.from_record(record) for record in records], total=total
        )


def find_plan_for_caller(session_id: str, scenario_id: str, entity_id: int) -> RemediationStatus:
    """The plan of a scenario in a run, as every `.../treatment-plan` route reads it first: 404 when the
    scenario has no plan or is not in this run, 403 another entity's."""
    status = get_remediation_status_of_scenario(scenario_id)
    return check_plan_of_scenario(status, entity_id, session_id, scenario_id)


def read_current_remediation_status(remediation_id: str) -> dict[str, Any] | None:
    """The plan's status body read now; None when MongoDB cannot say (the next published change follows
    anyway); NotFound once the plan is gone (deleted with its run, G214)."""
    try:
        status = get_remediation_status(remediation_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    if status is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    return status.model_dump(mode="json")


def get_remediation_status(remediation_id: str) -> RemediationStatus | None:
    """Reads a remediation plan's status from tsg_remediations (never a snapshot or a plan), if it exists."""
    record = remediation_plans.get(fields="status", _id=remediation_id)
    return None if record is None else RemediationStatus.from_record(record)


def get_remediation_status_of_scenario(scenario_id: str) -> RemediationStatus | None:
    """Reads the scenario's remediation plan status from tsg_remediations (id-only gate read), if any."""
    record = remediation_plans.get(fields="status", scenario_id=scenario_id)
    return None if record is None else RemediationStatus.from_record(record)


@singleton
def get_remediation_queries() -> RemediationQueries:
    """The process's plan reads."""
    return RemediationQueries()
