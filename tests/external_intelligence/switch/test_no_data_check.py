"""With external intelligence on and nothing imported yet, a start, a next set or a regenerate is refused at
once (409 intel_no_data, naming the import API), never queued to retry its evidence searches and fail."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.constants import ConflictReason, ScenarioStatus, Status, Step
from app.core.exceptions import Conflict
from app.models.scenario.views import ScenarioIdsRequest, SessionStatus, StartRunRequest
from tests.service_builders import threat_scenario_service

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def _world(on: bool, active: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """The switch and the active snapshot as given, as the service's parts; the reads of the snapshot,
    recorded."""
    reads: list[str] = []

    def read_active_snapshot() -> dict[str, Any] | None:
        reads.append("active")
        return active

    store = SimpleNamespace(get=lambda *fields, **where: read_active_snapshot())
    return {"switch": SimpleNamespace(is_on=lambda: on), "intel_snapshots": store}, reads


@pytest.mark.parametrize("active", [None, {"counts": {"indexed": 0}}])  # never built; every source revoked
def test_on_with_nothing_imported_refuses_a_run_before_any_other_read(active: dict[str, Any] | None) -> None:
    world, _ = _world(on=True, active=active)
    read = lambda *args: pytest.fail("the asset was read for a refused run")  # noqa: E731
    never = SimpleNamespace(get_asset_context=read)
    runs = threat_scenario_service(assets=never, **world)
    principal: Any = SimpleNamespace(entity_id=1, user_id="u1", client_id="c1")
    request = StartRunRequest(asset_id=1, supporting_system_ids=[2])
    with pytest.raises(Conflict) as refused:
        runs.create_threat_scenario_session(principal, request, None)
    assert refused.value.reason == ConflictReason.INTEL_NO_DATA
    assert "POST /v1/tsg/intel/refresh" in refused.value.detail


def test_on_with_nothing_imported_refuses_a_regenerate_before_it_is_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A next set and a regenerate queue their write job in one place, refused there like a start."""
    world, _ = _world(on=True, active=None)
    targets = {"s1": {"path_id": "p1", "status": ScenarioStatus.DONE}}
    never = SimpleNamespace(update_scenario_session_job=lambda *args: pytest.fail("a refused job was queued"))
    actions = threat_scenario_service(sessions=never, **world)
    monkeypatch.setattr(actions, "_list_review_targets", lambda *args: targets)
    run = SessionStatus(
        session_id="run", entity_id=1, asset_id=1, status=Status.DONE, step=Step.SCENARIOS, updated_at=NOW
    )
    caller: Any = SimpleNamespace(entity_id=1, user_id="u1", client_id="c1")  # a Principal's fields
    with pytest.raises(Conflict) as refused:
        actions.regenerate_threat_scenarios(caller, run, ScenarioIdsRequest(scenario_ids=["s1"]))
    assert refused.value.reason == ConflictReason.INTEL_NO_DATA


def test_off_reads_nothing_and_on_with_data_lets_the_run_start() -> None:
    world, reads = _world(on=False, active=None)
    threat_scenario_service(**world)._refuse_without_intel_data()
    assert reads == []
    world, reads = _world(on=True, active={"snapshot_id": "s1", "counts": {"indexed": 12}})
    threat_scenario_service(**world)._refuse_without_intel_data()
    assert reads == ["active"]
