"""tsg_remediations' data access : one plan per scenario, one
version's snapshot alone, a version appended only on the finished version read (its outcome frozen on its
item), a decision refused on a stale read. The test database."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app import container
from app.core.constants import Collection, Decision, Status
from app.core.database import get_mongodb
from app.core.exceptions import DuplicateRecord
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.models.remediation.reviews import DecisionChange

NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
STATEMENT = "A cybercriminal could push unsigned firmware."


@pytest.fixture(scope="module")
def plans() -> RemediationRepository:
    remediations = container.get_remediation_repository()
    remediations.create_indexes()
    return remediations


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
    plans.create(record)
    return record["_id"]


def _change(version: int, decision: Decision, **fields: Any) -> DecisionChange:
    stamp = {"decided_by": "u1", "decided_by_client": "c1", "decided_at": NOW, "review_comment": None}
    defaults = {"back_to_pending": None, "accepted_version": None, "record_decision": decision}
    return DecisionChange(version, decision, stamp, **(defaults | fields))


def _record(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def test_one_plan_per_scenario_and_its_status_and_snapshot(plans: RemediationRepository) -> None:
    remediation_id = _plan(plans)
    scenario_id = _record(remediation_id)["scenario_id"]
    with pytest.raises(DuplicateRecord) as clash:
        plans.create(_record(remediation_id) | {"_id": uuid.uuid4().hex})
    assert clash.value.index_name == "scenario_id_1"
    status = plans.get_remediation_plan_status_of_scenario(scenario_id)
    assert status is not None and (status.remediation_id, status.entity_id) == (remediation_id, 135)
    assert plans.get_remediation_plan_status(remediation_id) == status
    snapshot = plans.get_remediation_plan_version_snapshot(remediation_id, 1)
    assert snapshot == {"scenario": {"statement": STATEMENT}}
    assert plans.get_remediation_plan_version_snapshot(remediation_id, 2) is None
    assert plans.get_remediation_plan_status("gone") is None


def test_a_version_is_appended_only_on_the_finished_version_read(plans: RemediationRepository) -> None:
    """R8: refused while the latest is queued; on a failed latest its outcome is frozen onto its item in the
    same write; refused again on the same stale read; a "$" text stays text."""
    remediation_id = _plan(plans)
    assert plans.create_remediation_plan_version(remediation_id, 1, _version(2), _job(2), NOW) is False
    error = {"code": "generation_failed", "message": "The AI could not write a usable remediation plan."}
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"status": Status.FAILED, "job.error": error, "finished_at": NOW}}
    )
    assert plans.create_remediation_plan_version(
        remediation_id, 1, _version(2, "$status costs $5"), _job(2), NOW
    )
    record = _record(remediation_id)
    assert [(v["version"], v["status"]) for v in record["versions"]] == [
        (1, Status.FAILED),
        (2, Status.QUEUED),
    ]
    assert record["versions"][0]["error"] == error
    assert record["versions"][1]["snapshot"]["scenario"]["statement"] == "$status costs $5"
    assert (record["status"], record["active"], record["job"]["epoch"]) == (Status.QUEUED, True, 2)
    assert "finished_at" not in record and record["job"]["error"] is None
    assert plans.create_remediation_plan_version(remediation_id, 1, _version(3), _job(3), NOW) is False
    # A decision computed on a read taken before the append (decision_seq 0) must read again.
    assert record["decision_seq"] == 1 and record["decision"] == Decision.PENDING
    assert plans.update_remediation_plan_decision(remediation_id, 0, _change(1, Decision.REJECTED)) is False
    assert plans.get(fields="change", _id=remediation_id)["versions"] == [
        {"version": 1, "status": Status.FAILED, "decision": Decision.PENDING},
        {"version": 2, "status": Status.QUEUED, "decision": Decision.PENDING},
    ]


def test_a_decision_on_a_stale_read_is_refused(plans: RemediationRepository) -> None:
    """S44 ruling: every decision filters on decision_seq and increments it; two made on one read cannot both
    apply (accepted_version alone let two rejects of different versions both match)."""
    remediation_id = _plan(plans, status=Status.DONE)
    accept = _change(1, Decision.ACCEPTED, accepted_version=1, record_decision=Decision.ACCEPTED)
    assert plans.update_remediation_plan_decision(remediation_id, 0, accept)
    reject = _change(1, Decision.REJECTED)
    assert plans.update_remediation_plan_decision(remediation_id, 0, reject) is False
    record = _record(remediation_id)
    decided = (record["decision"], record["decision_seq"], record["versions"][0]["decision"])
    assert decided == (Decision.ACCEPTED, 1, Decision.ACCEPTED)


def test_accepting_another_version_puts_the_accepted_one_back_to_pending(
    plans: RemediationRepository,
) -> None:
    """One accepted version at a time: the one accepted before loses its decision and its stamp."""
    remediation_id = _plan(plans, status=Status.DONE, versions=[_version(1), _version(2)], job=_job(2))
    first = _change(1, Decision.ACCEPTED, accepted_version=1, record_decision=Decision.ACCEPTED)
    assert plans.update_remediation_plan_decision(remediation_id, 0, first)
    second = _change(
        2, Decision.ACCEPTED, back_to_pending=1, accepted_version=2, record_decision=Decision.ACCEPTED
    )
    assert plans.update_remediation_plan_decision(remediation_id, 1, second)
    record = _record(remediation_id)
    assert [(v["decision"], v.get("decided_by")) for v in record["versions"]] == [
        (Decision.PENDING, None),
        (Decision.ACCEPTED, "u1"),
    ]
    assert (record["accepted_version"], record["decision_seq"]) == (2, 2)


def test_an_unknown_stored_status_or_decision_is_read_as_a_safe_default(plans: RemediationRepository) -> None:
    """D7: a value no release knows (a newer one's, a hand edit) never answers 500: the status reads failed,
    the decision pending, the plan's and a version's alike."""
    remediation_id = _plan(
        plans, status="paused", decision="escalated", versions=[_version(1) | {"status": "x"}]
    )
    status = plans.get_remediation_plan_status(remediation_id)
    assert status is not None
    assert (status.latest_status, status.decision) == (Status.FAILED, Decision.PENDING)
    read = plans.get(fields="change", _id=remediation_id)
    assert read is not None and read["versions"][0]["status"] == Status.FAILED
    assert [found["status"] for found in plans.list(_id=remediation_id)] == [Status.FAILED]
