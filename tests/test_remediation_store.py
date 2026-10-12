"""tsg_remediations' data access (BLUEPRINT M11 R1, R3, R8-R9; BUILD_PLAN S50): one plan per scenario, one
version's snapshot alone, a version appended only on the finished version read (its outcome frozen on its
item), a decision refused on a stale read. The test database."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.constants import Collection, Decision, Status
from app.core.database import get_mongodb
from app.data_access.remediation_reads import RemediationReads
from app.data_access.remediation_versions import RemediationVersions
from app.data_access.remediations import RemediationRepository

NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
STATEMENT = "A cybercriminal could push unsigned firmware."


@pytest.fixture(scope="module")
def plans() -> RemediationRepository:
    repository = RemediationRepository(get_mongodb())
    repository.ensure_indexes()
    return repository


def _job(epoch: int) -> dict[str, Any]:
    return {"task": "tsg_write_plan", "epoch": epoch, "attempts": 0, "due_at": NOW, "error": None}


def _version(version: int, statement: str = STATEMENT) -> dict[str, Any]:
    return {
        "version": version,
        "status": Status.QUEUED,
        "snapshot": {"scenario": {"statement": statement}},
        "plan": None,
        "decision": Decision.PENDING,
        "requested_at": NOW,
    }


def _plan(plans: RemediationRepository, **fields: Any) -> str:
    record = {
        "_id": uuid.uuid4().hex,
        "scenario_id": uuid.uuid4().hex,
        "session_id": "run1",
        "entity_id": 135,
        "versions": [_version(1)],
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "status": Status.QUEUED,
        "active": True,
        "job": _job(1),
        "created_at": NOW,
        "updated_at": NOW,
    } | fields
    assert plans.insert(record)
    return record["_id"]


def _record(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def test_one_plan_per_scenario_and_its_status_and_snapshot(plans: RemediationRepository) -> None:
    remediation_id = _plan(plans)
    scenario_id = _record(remediation_id)["scenario_id"]
    assert plans.insert(_record(remediation_id) | {"_id": uuid.uuid4().hex}) is False
    status = plans.find_for_scenario(scenario_id)
    assert status is not None and (status.remediation_id, status.entity_id) == (remediation_id, 135)
    assert RemediationReads(get_mongodb()).find_status(remediation_id) == status
    assert plans.find_snapshot(remediation_id, 1) == {"scenario": {"statement": STATEMENT}}
    assert (
        plans.find_snapshot(remediation_id, 2) is None
        and RemediationReads(get_mongodb()).find_status("gone") is None
    )


def test_a_version_is_appended_only_on_the_finished_version_read(plans: RemediationRepository) -> None:
    """R8: refused while the latest is queued; on a failed latest its outcome is frozen onto its item in the
    same write; refused again on the same stale read; a "$" text stays text."""
    versions = RemediationVersions(get_mongodb())
    remediation_id = _plan(plans)
    assert versions.append_version(remediation_id, 1, _version(2), _job(2), NOW) is False
    error = {"code": "generation_failed", "message": "The AI could not write a usable remediation plan."}
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"status": Status.FAILED, "job.error": error, "finished_at": NOW}}
    )
    assert versions.append_version(remediation_id, 1, _version(2, "$status costs $5"), _job(2), NOW)
    record = _record(remediation_id)
    assert [(v["version"], v["status"]) for v in record["versions"]] == [
        (1, Status.FAILED),
        (2, Status.QUEUED),
    ]
    assert record["versions"][0]["error"] == error
    assert record["versions"][1]["snapshot"]["scenario"]["statement"] == "$status costs $5"
    assert (record["status"], record["active"], record["job"]["epoch"]) == (Status.QUEUED, True, 2)
    assert "finished_at" not in record and record["job"]["error"] is None
    assert versions.append_version(remediation_id, 1, _version(3), _job(3), NOW) is False
    # A decision computed on a read taken before the append (decision_seq 0) must read again.
    assert record["decision_seq"] == 1 and record["decision"] == Decision.PENDING
    assert versions.decide(remediation_id, 0, {"decision": Decision.REJECTED}, []) is False
    assert versions.find_for_change(remediation_id)["versions"] == [
        {"version": 1, "status": Status.FAILED, "decision": Decision.PENDING},
        {"version": 2, "status": Status.QUEUED, "decision": Decision.PENDING},
    ]


def test_a_decision_on_a_stale_read_is_refused(plans: RemediationRepository) -> None:
    """S44 ruling: every decision filters on decision_seq and increments it; two made on one read cannot both
    apply (accepted_version alone let two rejects of different versions both match)."""
    versions = RemediationVersions(get_mongodb())
    remediation_id = _plan(plans, status=Status.DONE)
    picked = [{"v.version": 1}]
    accept = {
        "accepted_version": 1,
        "decision": Decision.ACCEPTED,
        "versions.$[v].decision": Decision.ACCEPTED,
    }
    assert versions.decide(remediation_id, 0, accept, picked)
    reject = {"decision": Decision.REJECTED, "versions.$[v].decision": Decision.REJECTED}
    assert versions.decide(remediation_id, 0, reject, picked) is False
    record = _record(remediation_id)
    decided = (record["decision"], record["decision_seq"], record["versions"][0]["decision"])
    assert decided == (Decision.ACCEPTED, 1, Decision.ACCEPTED)
