"""tsg_remediations: one plan per scenario (a unique index, race-free), with its versions. Its indexes, its
insert, and what a plan request and the plan job read."""

from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection
from app.models.remediation import RemediationStatus

#: The list filters: each with the newest-first sort is one index scan.
_LIST_FILTERS = ("status", "decision", "risk_level", "session_id")
#: What a plan request and its plan job read of the scenario: owner, decision, content, controls, and what
#: its plan job still has to find.
_SCENARIO_FIELDS = dict.fromkeys(
    ("entity_id", "session_id", "asset_id", "source", "status", "decision", "content", "controls", "pending"),
    1,
)


class RemediationRepository:
    def __init__(self, db: Database) -> None:
        self._plans = db[Collection.REMEDIATIONS]
        self._scenarios = db[Collection.SCENARIOS]  # read only: a plan's scenario

    def ensure_indexes(self) -> None:
        """One plan per scenario, and the list's reads."""
        self._plans.create_index("scenario_id", unique=True)
        self._plans.create_index([("entity_id", 1), ("created_at", -1)])
        for field in _LIST_FILTERS:
            self._plans.create_index([("entity_id", 1), (field, 1), ("created_at", -1)])

    def insert(self, record: dict[str, Any]) -> bool:
        """False when the scenario already has a plan (a request made at the same moment won)."""
        try:
            self._plans.insert_one(record)
        except DuplicateKeyError:
            return False
        return True

    def remove(self, remediation_id: str) -> None:
        """A plan just inserted for a scenario deleted meanwhile: it never outlives its scenario."""
        self._plans.delete_one({"_id": remediation_id})

    def find_for_scenario(self, scenario_id: str) -> RemediationStatus | None:
        """The scenario's plan status, if it has one."""
        record = self._plans.find_one({"scenario_id": scenario_id}, RemediationStatus.RECORD_FIELDS)
        return None if record is None else RemediationStatus.from_record(record)

    def find_scenario(self, scenario_id: str) -> dict[str, Any] | None:
        """The plan's scenario, as a plan request reads it."""
        return self._scenarios.find_one({"_id": scenario_id}, _SCENARIO_FIELDS)

    def find_snapshot(self, remediation_id: str, version: int) -> dict[str, Any] | None:
        """One version's frozen input alone (the plan job's input, a regenerate's register half); None when
        the plan or the version is gone."""
        found = self._plans.find_one({"_id": remediation_id, "versions.version": version}, {"versions.$": 1})
        return None if found is None else found["versions"][0]["snapshot"]
