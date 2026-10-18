"""scenario_sessions rules: unique-clash mapping, insert-once manual start, guarded new write job, fenced plan
write with counts newer-wins."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.constants import RunActionKind, RunClash, Status, Step
from app.core.exceptions import LeaseLost
from app.data_access.scenario.repository import scenario_sessions, session_status_from_record


@pytest.fixture(autouse=True)
def indexes(empty_test_database: None) -> None:
    scenario_sessions.create_indexes()


def _session(**fields: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    record = {"_id": uuid.uuid4().hex, "entity_id": 86, "asset_id": int(uuid.uuid4().int % 10**8)}
    return (
        record
        | {"status": Status.DONE, "step": Step.SCENARIOS, "job": {"epoch": 1}, "updated_at": now}
        | fields
    )


def test_a_start_clash_names_the_unique_rule() -> None:
    first = _session(active=True, idempotency_key=uuid.uuid4().hex)
    assert scenario_sessions.create_scenario_session(first) is None
    same_asset = _session(asset_id=first["asset_id"], active=True)
    assert scenario_sessions.create_scenario_session(same_asset) is RunClash.ACTIVE_RUN
    same_key = _session(idempotency_key=first["idempotency_key"])
    assert scenario_sessions.create_scenario_session(same_key) is RunClash.IDEMPOTENCY_KEY


def test_a_manual_start_is_saved_once_and_another_body_is_refused() -> None:
    manual = _session(request_hash="a")
    assert scenario_sessions.create_manual_scenario_session(manual) is None
    assert scenario_sessions.create_manual_scenario_session(manual) is None  # a retry changes nothing
    assert (
        scenario_sessions.create_manual_scenario_session(manual | {"request_hash": "b"})
        is RunClash.IDEMPOTENCY_KEY
    )


def test_of_two_clicks_on_one_epoch_one_queues_and_a_deleting_session_is_told_so() -> None:
    record = _session()
    scenario_sessions.create(record)
    status = session_status_from_record(record)
    batch = [{"path_id": "p1"}]
    assert scenario_sessions.update_scenario_session_job(status, RunActionKind.REGENERATE, batch) is None
    assert (
        scenario_sessions.update_scenario_session_job(status, RunActionKind.REGENERATE, batch)
        is RunClash.CHANGED
    )
    marked = _session(deleting_at=datetime.now(UTC))
    scenario_sessions.create(marked)
    clash = scenario_sessions.update_scenario_session_job(
        session_status_from_record(marked), RunActionKind.NEXT_SET, batch
    )
    assert clash is RunClash.DELETING


def test_the_plan_write_is_fenced_and_keeps_a_newer_count(monkeypatch: pytest.MonkeyPatch) -> None:
    job = {"epoch": 1, "task_id": "t", "attempts": 1}
    later = datetime.now(UTC) + timedelta(hours=1)
    record = _session(status=Status.RUNNING, job=job, plan={"paths": [{"path_id": "p1"}]}, counts_at=later)
    record["counts"] = {"written": 9}
    scenario_sessions.create(record)
    counted = SimpleNamespace(count_scenarios_of_session=lambda _: {"written": 1})
    monkeypatch.setattr("app.data_access.scenario.repository.scenarios", counted)
    lease = SimpleNamespace(record_id=record["_id"], **job)
    figures = {"planned": 1, "remaining": 0}
    scenario_sessions.update_scenario_session_plan(lease, {"p1": {"served": "s1"}}, figures)  # type: ignore[arg-type]
    stored = scenario_sessions.get(_id=record["_id"])
    assert stored is not None
    assert (
        stored["plan"]["paths"][0]["served"],
        stored["counts"]["written"],
        stored["counts"]["planned"],
    ) == ("s1", 9, 1)
    lost = SimpleNamespace(record_id=record["_id"], epoch=1, task_id="other", attempts=1)
    with pytest.raises(LeaseLost):
        scenario_sessions.update_scenario_session_plan(lost, {}, figures)  # type: ignore[arg-type]
