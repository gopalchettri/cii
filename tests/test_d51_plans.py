"""Plans: the progress a plan shows once its scenario is no longer accepted, and a regenerate that loses the
race with its run's delete leaving the plan exactly as it was."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import Collection, ConflictReason, Decision, Status, TaskName
from app.core.database import get_mongodb
from app.data_access.scenario.threat_scenario_session_repository import DELETING_MARK
from tests.plan_job_fakes import api_key_fixture, world_fixture  # noqa: F401 — fixtures
from tests.test_remediation_api import _done_plan, _post, _record, _result, _status


def _overall(client: TestClient, api_key: str, world: dict[str, Any], remediation_id: str) -> list[str]:
    """progress.overall as the status route, the result route and the live stream read it."""
    live = world["service"].get_remediation_plan_live_status(remediation_id)
    return [
        _status(client, api_key, remediation_id).json()["progress"]["overall"],
        _result(client, api_key, remediation_id).json()["progress"]["overall"],
        live["progress"]["overall"],
    ]


def test_an_undecided_plan_of_a_scenario_no_longer_accepted_reads_read_only(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Its scenario back to pending, every review is refused, so no read says awaiting_review; accepted
    again, it awaits review once more."""
    remediation_id = _done_plan(client, api_key, world)
    scenarios, scenario = get_mongodb()[Collection.SCENARIOS], {"_id": _record(remediation_id)["scenario_id"]}
    assert _overall(client, api_key, world, remediation_id) == ["awaiting_review"] * 3
    scenarios.update_one(scenario, {"$set": {"decision": Decision.PENDING}})
    refused = _post(client, api_key, remediation_id, "accept", {"version": 1})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    assert _overall(client, api_key, world, remediation_id) == ["read_only"] * 3
    scenarios.update_one(scenario, {"$set": {"decision": Decision.ACCEPTED}})
    assert _overall(client, api_key, world, remediation_id) == ["awaiting_review"] * 3


def test_a_regenerate_that_meets_its_runs_delete_leaves_the_plan_as_it_was(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delete marks the run just after the new version is appended: 409 run_being_deleted, nothing sent,
    and the append undone (no cancelled version, no slot used, the rejection kept)."""
    remediation_id = _done_plan(client, api_key, world)
    assert _post(client, api_key, remediation_id, "reject", {"version": 1}).status_code == 200
    before = _record(remediation_id)
    plans, runs = container.get_remediation_repository(), get_mongodb()[Collection.SESSIONS]
    real_append = plans.create_remediation_plan_version

    def appended_then_the_delete_marks(*args: Any) -> bool:
        appended = real_append(*args)
        runs.update_one({"_id": before["session_id"]}, {"$set": {DELETING_MARK: datetime.now(UTC)}})
        return appended

    with monkeypatch.context() as raced:
        raced.setattr(plans, "create_remediation_plan_version", appended_then_the_delete_marks)
        refused = _post(client, api_key, remediation_id, "regenerate", {})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    after = _record(remediation_id)
    kept = ("job", "status", "decision", "finished_at", "accepted_version")
    assert {field: after.get(field) for field in kept} == {field: before.get(field) for field in kept}
    assert (len(after["versions"]), after["status"], "cancelled" in after) == (1, Status.DONE, False)
    assert after["decision_seq"] > before["decision_seq"]  # a decision read in between reads again
    assert (TaskName.WRITE_PLAN, remediation_id, 2) not in world["sent"]
    runs.update_one({"_id": before["session_id"]}, {"$unset": {DELETING_MARK: ""}})  # the delete stopped
    again = _post(client, api_key, remediation_id, "regenerate", {})
    assert (again.status_code, again.json()["version"]) == (202, 2), again.text


@pytest.mark.parametrize(
    ("first_review", "review_meanwhile", "accepted_version", "decision"),
    [("reject", "accept", 1, Decision.ACCEPTED), (None, "reject", None, Decision.REJECTED)],
)
def test_a_review_landing_before_the_regenerate_undoes_its_append_is_kept(  # noqa: PLR0913 — fixtures
    client: TestClient,
    api_key: str,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    first_review: str | None,
    review_meanwhile: str,
    accepted_version: int | None,
    decision: Decision,
) -> None:
    """v1 is reviewed between the regenerate's append and its undo: the plan's decision follows that review,
    not the regenerate's earlier read."""
    remediation_id = _done_plan(client, api_key, world)
    if first_review is not None:
        assert _post(client, api_key, remediation_id, first_review, {"version": 1}).status_code == 200
    plans, runs = container.get_remediation_repository(), get_mongodb()[Collection.SESSIONS]
    session_id, real_append = _record(remediation_id)["session_id"], plans.create_remediation_plan_version
    answers: list[Any] = []

    def appended_then_reviewed_then_the_delete_marks(*args: Any) -> bool:
        appended = real_append(*args)
        answers.append(_post(client, api_key, remediation_id, review_meanwhile, {"version": 1}))
        runs.update_one({"_id": session_id}, {"$set": {DELETING_MARK: datetime.now(UTC)}})
        return appended

    with monkeypatch.context() as raced:
        raced.setattr(plans, "create_remediation_plan_version", appended_then_reviewed_then_the_delete_marks)
        refused = _post(client, api_key, remediation_id, "regenerate", {})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    assert answers[0].status_code == 200, answers[0].text
    after = _record(remediation_id)
    assert (len(after["versions"]), after["versions"][0]["decision"]) == (1, decision)  # v1 as reviewed
    assert (after["accepted_version"], after["decision"]) == (accepted_version, decision)
    status = _status(client, api_key, remediation_id).json()
    assert (status["accepted_version"], status["decision"]) == (accepted_version, decision)
