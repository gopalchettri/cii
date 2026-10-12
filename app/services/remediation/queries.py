"""Reading remediation plans: a plan's status, its result,
an entity's plans and the status a live-update stream reads. Each is one projected read (+ the
scenario for a result, + one count for a list), the caller's entity checked (404 unknown, 403 another
entity's)."""

from typing import Any

import structlog

from app.core.constants import Decision, Dependency, LogEvent, RemediationMessage, Status
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

    def status(self, principal: Principal, remediation_id: str) -> RemediationStatus:
        return _owned(self._plans.find_status(remediation_id), principal.entity_id, remediation_id)

    def result(self, principal: Principal, remediation_id: str, include_history: bool) -> RemediationResult:
        record = self._plans.find_result(remediation_id)
        status = None if record is None else RemediationStatus.from_record(record)
        _owned(status, principal.entity_id, remediation_id)
        assert record is not None  # _owned refused a missing plan
        scenario = self._plans.find_scenario_summary(record["scenario_id"])
        return RemediationResult.from_records(record, scenario, include_history)

    def list_plans(  # noqa: PLR0913 — the list's filters, each its own query parameter
        self,
        principal: Principal,
        session_id: str | None,
        scenario_id: str | None,
        status: Status | None,
        decision: Decision | None,
        risk_level: str | None,
        offset: int,
        limit: int,
    ) -> RemediationList:
        """The caller's entity's plans, newest first, filtered by every filter given."""
        given = {
            "session_id": session_id,
            "scenario_id": scenario_id,
            "status": status,
            "decision": decision,
            "risk_level": risk_level,
        }
        filters: dict[str, Any] = {key: value for key, value in given.items() if value is not None}
        records, total = self._plans.list_for_entity(principal.entity_id, filters, offset, limit)
        return RemediationList(
            items=[RemediationSummary.from_record(record) for record in records], total=total
        )


def find_remediation_status_for_caller(remediation_id: str, entity_id: int) -> RemediationStatus:
    """What a live-update stream checks before it starts (404, 403)."""
    return _owned(RemediationReads(get_mongodb()).find_status(remediation_id), entity_id, remediation_id)


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


def _owned(status: RemediationStatus | None, entity_id: int, remediation_id: str) -> RemediationStatus:
    if status is None:
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    if status.entity_id != entity_id:
        raise Forbidden(RemediationMessage.PLAN_OTHER_ENTITY.format(remediation_id=remediation_id))
    return status


@singleton
def get_remediation_queries() -> RemediationQueries:
    return RemediationQueries(RemediationReads(get_mongodb()))
