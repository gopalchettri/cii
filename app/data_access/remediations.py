"""tsg_remediations: one document per scenario's remediation plan, with its versions (BLUEPRINT M11, §12.2;
BUILD_PLAN S50). Its job fields are written by app/data_access/job_records.py: the latest version's status and
error live there (R3). This module makes the collection's indexes, inserts a plan, and reads what a request
and the plan job need: a scenario's plan, the scenario, one version's snapshot. What the API shows is
remediation_reads.py; regenerates and decisions are remediation_versions.py.
The unique `scenario_id` index makes "one plan per scenario" race-free without a lock."""

from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import Collection
from app.models.remediation import RemediationStatus

#: The list filters (#17): each with the newest-first sort is one index scan. scenario_id has its unique
#: index.
_LIST_FILTERS = ("status", "decision", "risk_level", "session_id")
#: What a plan request (and its plan job, G262) reads of its scenario: who owns it, whether it is accepted,
#: its content and controls, and what its plan job still has to find (a hand-written scenario's attackers).
_SCENARIO_FIELDS = dict.fromkeys(
    ("entity_id", "session_id", "asset_id", "source", "status", "decision", "content", "controls", "pending"),
    1,
)


class RemediationRepository:
    def __init__(self, db: Database) -> None:
        self._plans = db[Collection.REMEDIATIONS]
        self._scenarios = db[Collection.SCENARIOS]  # read only: a plan's scenario

    def ensure_indexes(self) -> None:
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
        """A plan just inserted for a scenario deleted meanwhile (G214): it never outlives its scenario."""
        self._plans.delete_one({"_id": remediation_id})

    def find_for_scenario(self, scenario_id: str) -> RemediationStatus | None:
        """The scenario's plan, if it has one: checked before a request maps any control (R1 step 3)."""
        record = self._plans.find_one({"scenario_id": scenario_id}, RemediationStatus.RECORD_FIELDS)
        return None if record is None else RemediationStatus.from_record(record)

    def find_scenario(self, scenario_id: str) -> dict[str, Any] | None:
        return self._scenarios.find_one({"_id": scenario_id}, _SCENARIO_FIELDS)

    def find_snapshot(self, remediation_id: str, version: int) -> dict[str, Any] | None:
        """One version's frozen input alone (the plan job's input, a regenerate's register half); None when
        the plan or the version is gone."""
        found = self._plans.find_one({"_id": remediation_id, "versions.version": version}, {"versions.$": 1})
        return None if found is None else found["versions"][0]["snapshot"]
