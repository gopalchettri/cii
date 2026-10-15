"""Reading remediation plans: a scenario's plan (status and result), an entity's or a run's plans, and the
status a live-update stream reads. Each is one projected read (+ the scenario for a result, + one count for a
list), the caller's entity checked (404 unknown, 403 another entity's)."""

from typing import Any

import structlog

from app.core.constants import Decision, Dependency, LogEvent, RemediationMessage, SessionMessage, Status
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Forbidden, NotFound
from app.core.singletons import singleton
from app.data_access.remediation_reads import RemediationReads
from app.models.api_clients import Principal
from app.models.remediation import RemediationStatus
from app.models.remediation_views import RemediationList, RemediationResult, RemediationSummary

log = structlog.get_logger(__name__)


class RemediationQueries:
    def __init__(self, plans: RemediationReads) -> None:
        self._plans = plans

    def result(
        self, principal: Principal, session_id: str, scenario_id: str, include_history: bool
    ) -> RemediationResult:
        record = self._plans.find_result_of_scenario(scenario_id)
        status = None if record is None else RemediationStatus.from_record(record)
        _of_scenario(status, principal.entity_id, session_id, scenario_id)
        assert record is not None  # _of_scenario refused a missing plan
        scenario = self._plans.find_scenario_summary(scenario_id)
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
        if entity_id != principal.entity_id:
            raise Forbidden(SessionMessage.ENTITY_MISMATCH)
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
        filters: dict[str, Any] = {key: value for key, value in given.items() if value is not None}
        records, total = self._plans.list_for_entity(entity_id, filters, offset, limit)
        return RemediationList(
            items=[RemediationSummary.from_record(record) for record in records], total=total
        )


def find_plan_for_caller(session_id: str, scenario_id: str, entity_id: int) -> RemediationStatus:
    """The plan of a scenario in a run, as every `.../treatment-plan` route reads it first: 404 when the
    scenario has no plan or is not in this run, 403 another entity's."""
    status = RemediationReads(get_mongodb()).find_status_of_scenario(scenario_id)
    return _of_scenario(status, entity_id, session_id, scenario_id)


def find_remediation_status_for_caller(remediation_id: str, entity_id: int) -> RemediationStatus:
    """A plan by its id (a job control's check): 404 unknown, 403 another entity's."""
    status = RemediationReads(get_mongodb()).find_status(remediation_id)
    if status is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    return _owned(status, entity_id)


def read_current_remediation_status(remediation_id: str) -> dict[str, Any] | None:
    """The plan's status body read now; None when MongoDB cannot say (the next published change follows
    anyway); NotFound once the plan is gone (deleted with its run, G214)."""
    try:
        status = RemediationReads(get_mongodb()).find_status(remediation_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    if status is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    return status.model_dump(mode="json")


def _of_scenario(
    status: RemediationStatus | None, entity_id: int, session_id: str, scenario_id: str
) -> RemediationStatus:
    if status is None or status.session_id != session_id:
        message = RemediationMessage.PLAN_NOT_REQUESTED.format(scenario_id=scenario_id, session_id=session_id)
        raise NotFound(message)
    return _owned(status, entity_id)


def _owned(status: RemediationStatus, entity_id: int) -> RemediationStatus:
    if status.entity_id != entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=status.remediation_id))
    return status


@singleton
def get_remediation_queries() -> RemediationQueries:
    return RemediationQueries(RemediationReads(get_mongodb()))
