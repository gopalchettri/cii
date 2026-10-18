"""With external intelligence on and nothing imported yet, a start, a next set or a regenerate is refused at
once (409 intel_no_data, naming the import API), never queued to retry its evidence searches and fail."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.constants import ConflictReason, ScenarioStatus, Status, Step
from app.core.exceptions import Conflict
from app.models.scenario.views import ScenarioIdsRequest, SessionStatus, StartRunRequest
from app.services.scenario import runs as runs_module
from app.services.scenario.runs import RunActions, RunService

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def _world(monkeypatch: pytest.MonkeyPatch, on: bool, active: dict[str, Any] | None) -> list[str]:
    """The switch and the active snapshot as given; the reads of the snapshot, recorded."""
    reads: list[str] = []

    def read_active_snapshot() -> dict[str, Any] | None:
        reads.append("active")
        return active

    monkeypatch.setattr(
        runs_module, "get_external_intelligence_switch", lambda: SimpleNamespace(is_on=lambda: on)
    )
    store = SimpleNamespace(get=lambda *fields, **where: read_active_snapshot())
    monkeypatch.setattr(runs_module, "intel_snapshots", store)
    return reads


@pytest.mark.parametrize("active", [None, {"counts": {"indexed": 0}}])  # never built; every source revoked
def test_on_with_nothing_imported_refuses_a_run_before_any_other_read(
    monkeypatch: pytest.MonkeyPatch, active: dict[str, Any] | None
) -> None:
    _world(monkeypatch, on=True, active=active)
    never = SimpleNamespace(read=lambda *args: pytest.fail("the asset was read for a refused run"))
    runs = RunService(never, SimpleNamespace())  # type: ignore[arg-type]
    principal: Any = SimpleNamespace(entity_id=1, user_id="u1", client_id="c1")
    with pytest.raises(Conflict) as refused:
        runs.start(principal, StartRunRequest(asset_id=1, supporting_system_ids=[2]), None)
    assert refused.value.reason == ConflictReason.INTEL_NO_DATA
    assert "POST /v1/tsg/intel/refresh" in refused.value.detail


def test_on_with_nothing_imported_refuses_a_regenerate_before_it_is_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A next set and a regenerate queue their write job in one place, refused there like a start."""
    _world(monkeypatch, on=True, active=None)
    targets = {"s1": {"path_id": "p1", "status": ScenarioStatus.DONE}}
    monkeypatch.setattr(runs_module, "list_review_targets", lambda *args: targets)
    never = SimpleNamespace(update_scenario_session_job=lambda *args: pytest.fail("a refused job was queued"))
    actions = RunActions(never, SimpleNamespace())  # type: ignore[arg-type]
    run = SessionStatus(
        session_id="run", entity_id=1, asset_id=1, status=Status.DONE, step=Step.SCENARIOS, updated_at=NOW
    )
    with pytest.raises(Conflict) as refused:
        actions.regenerate(SimpleNamespace(), run, ScenarioIdsRequest(scenario_ids=["s1"]))  # type: ignore[arg-type]
    assert refused.value.reason == ConflictReason.INTEL_NO_DATA


def test_off_reads_nothing_and_on_with_data_lets_the_run_start(monkeypatch: pytest.MonkeyPatch) -> None:
    reads = _world(monkeypatch, on=False, active=None)
    runs_module.refuse_without_intel_data()
    assert reads == []
    reads = _world(monkeypatch, on=True, active={"snapshot_id": "s1", "counts": {"indexed": 12}})
    runs_module.refuse_without_intel_data()
    assert reads == ["active"]
