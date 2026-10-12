"""What the API shows of remediation plans (BLUEPRINT M11 R10; BUILD_PLAN S53): a plan's status (#15, #28),
its result without snapshots and its scenario's summary (#16), an entity's plans (#17). Read only."""

from typing import Any

from pymongo.database import Database

from app.core.constants import Collection
from app.models.remediation import RemediationStatus
from app.models.remediation_views import RemediationSummary

#: (the records of one page, the total matching)
Page = tuple[list[dict[str, Any]], int]
#: What a result shows of the planned scenario.
_SUMMARY_FIELDS = {"content": 1, "controls.items": 1}


class RemediationReads:
    def __init__(self, db: Database) -> None:
        self._plans = db[Collection.REMEDIATIONS]
        self._scenarios = db[Collection.SCENARIOS]

    def find_status(self, remediation_id: str) -> RemediationStatus | None:
        """A plan's status; reads only the fields the status body shows, never a snapshot or a plan."""
        record = self._plans.find_one({"_id": remediation_id}, RemediationStatus.RECORD_FIELDS)
        return None if record is None else RemediationStatus.from_record(record)

    def find_result(self, remediation_id: str) -> dict[str, Any] | None:
        """The whole plan record but its versions' snapshots (never shown, the largest part)."""
        return self._plans.find_one({"_id": remediation_id}, {"versions.snapshot": 0})

    def list_for_entity(self, entity_id: int, filters: dict[str, Any], offset: int, limit: int) -> Page:
        """Newest first: one index scan per filter (ensure_indexes) and one count with the same filter."""
        query = {"entity_id": entity_id, **filters}
        found = self._plans.find(query, RemediationSummary.RECORD_FIELDS).sort("created_at", -1)
        return list(found.skip(offset).limit(limit)), self._plans.count_documents(query)

    def find_scenario_summary(self, scenario_id: str) -> dict[str, Any] | None:
        return self._scenarios.find_one({"_id": scenario_id}, _SUMMARY_FIELDS)
