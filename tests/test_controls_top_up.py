"""A plan request's control top-up (BLUEPRINT M11 Rule R1T, BUILD_PLAN S51): mapped in the request under
the scenario's own lease; a worker's live lease → 503 at once; past the deadline or on an outage the
controls go back to the controls job (a hand-written scenario's fail) and a late result is never saved; no
fitting control → 409 with its code. The test database; the mapper and the library faked."""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest

from app.ai import reranks_in_background
from app.ai.common import call_timeout
from app.core.constants import (
    Collection,
    ConflictReason,
    ControlMatch,
    ErrorCode,
    ErrorMessage,
    RunKind,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, ControlsNotMapped, Unavailable
from app.engine.scenarios.control_mapper import ControlMapper
from app.models.controls import ControlMapping, MappedControl
from app.search.service import LibrarySearch
from app.services.remediation import controls_top_up
from app.services.remediation.controls_top_up import ControlsTopUp
from tests.planner_samples import CONTEXT

FIRMWARE = MappedControl(
    1, "CII-CID-1", "Firmware integrity verification", "Integrity", "OT", 1, 87.0, ControlMatch.EXACT
)


class _Mapper:
    """ControlMapper's surface: one control after `seconds`, or `error` raised."""

    def __init__(self, seconds: float = 0.0, error: Exception | None = None) -> None:
        self.seconds, self.error, self.calls = seconds, error, 0
        self.in_background: list[bool] = []  # G222: a plan request's mapping is foreground work

    def map_controls(self, scenario: dict[str, Any], context: Any, snapshot: Any) -> ControlMapping:
        self.calls += 1
        self.in_background.append(reranks_in_background())
        time.sleep(self.seconds)
        if self.error is not None:
            raise self.error
        return ControlMapping((FIRMWARE,), query=scenario["content"]["statement"])


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A run and one accepted scenario whose controls wait; what the top-up publishes and sends."""
    run_id, scenario_id = f"run-{uuid.uuid4().hex}", uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": run_id, "context": CONTEXT.to_record(), "counts": {}}
    )
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": run_id, "path_id": "p1", "status": ScenarioStatus.DONE,
         "source": RunKind.GENERATED, "superseded_by": None, "decision": "accepted",
         "created_at": datetime.now(UTC),
         "content": {"statement": "A cybercriminal could push unsigned firmware to the RTU."},
         "controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": datetime.now(UTC)}}
    )  # fmt: skip
    state: dict[str, Any] = {"run_id": run_id, "scenario_id": scenario_id, "published": [], "sent": []}
    monkeypatch.setattr(controls_top_up, "publish_session_status", state["published"].append)
    monkeypatch.setattr(controls_top_up, "send_job", lambda *args: state["sent"].append(args))
    return state


def _top_up(mapper: _Mapper, deadline: float = 2.0) -> ControlsTopUp:
    library = SimpleNamespace(snapshot=lambda: SimpleNamespace(library=SimpleNamespace(stamp=())))
    return ControlsTopUp(get_mongodb(), cast(ControlMapper, mapper), cast(LibrarySearch, library), deadline)


def _controls(world: dict[str, Any]) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": world["scenario_id"]})["controls"]


def _set_controls(world: dict[str, Any], **fields: Any) -> None:
    changes = {f"controls.{key}": value for key, value in fields.items()}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": world["scenario_id"]}, {"$set": changes})


def test_unmapped_controls_are_mapped_in_the_request(world: dict[str, Any]) -> None:
    mapper = _Mapper()
    items = _top_up(mapper).map_now(world["scenario_id"])
    assert mapper.in_background == [False]  # G222: someone waits for it: never behind a waiting scenario
    assert [item["code"] for item in items] == ["CII-CID-1"]
    controls = _controls(world)
    assert (controls["status"], controls["attempts"], controls["lease_until"]) == (Status.DONE, 1, None)
    assert controls["items"] == items and controls["made_with"]["library"] == {}
    assert world["published"] == [world["run_id"]] and world["sent"] == []


def test_a_live_worker_lease_answers_503_at_once_and_a_finished_mapping_is_used(
    world: dict[str, Any],
) -> None:
    mapper = _Mapper()
    _set_controls(world, status=Status.RUNNING, lease_until=datetime.now(UTC) + timedelta(seconds=60))
    with pytest.raises(Unavailable) as refused:
        _top_up(mapper).map_now(world["scenario_id"])
    assert (refused.value.reason, refused.value.retry_after) == (ConflictReason.CONTROLS_NOT_READY, 30)
    _set_controls(world, status=Status.DONE, items=[FIRMWARE.to_record()])
    assert _top_up(mapper).map_now(world["scenario_id"]) == [FIRMWARE.to_record()] and mapper.calls == 0


def test_the_mappings_ai_calls_end_with_the_request(world: dict[str, Any]) -> None:
    """Review 2026-10-11 (R1T step 2): before, a mapping the request gave up on ran on with each AI call's
    own timeout (90-120 s) and retries, holding AI slots the jobs need, while a worker mapped the same
    scenario."""
    timeouts: list[float] = []
    mapper = _Mapper()
    mapping = mapper.map_controls

    def map_controls(scenario: dict[str, Any], context: Any, snapshot: Any) -> ControlMapping:
        timeouts.append(call_timeout(120.0))  # what any AI call inside the mapping would get
        return mapping(scenario, context, snapshot)

    mapper.map_controls = map_controls  # type: ignore[method-assign]
    _top_up(mapper, deadline=2.0).map_now(world["scenario_id"])
    assert 0 < timeouts[0] <= 2.0


def test_past_the_deadline_the_controls_go_back_and_the_late_result_is_dropped(world: dict[str, Any]) -> None:
    with pytest.raises(Unavailable) as late:
        _top_up(_Mapper(seconds=0.5), deadline=0.1).map_now(world["scenario_id"])
    assert late.value.reason == ConflictReason.CONTROLS_NOT_READY
    assert world["sent"] == [(TaskName.MAP_CONTROLS, world["run_id"], 0)]
    time.sleep(0.6)  # the mapping has ended in its pool thread by now
    controls = _controls(world)
    assert (controls["status"], "items" in controls) == (Status.QUEUED, False)
    assert controls["error"]["message"].startswith("Not mapped within the 0.1 seconds")


def test_a_hand_written_scenarios_controls_fail_instead(world: dict[str, Any]) -> None:
    """The background never maps a hand-written scenario: an outage fails its controls; nothing is sent. Its
    run's counts follow at once (review S56): a failed mapping no longer waits, so the run stops reading step
    "controls"."""
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": world["scenario_id"]}, {"$set": {"source": RunKind.MANUAL}}
    )
    with pytest.raises(Unavailable):
        _top_up(_Mapper(error=Unavailable("down"))).map_now(world["scenario_id"])
    assert (_controls(world)["status"], world["sent"]) == (Status.FAILED, [])
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": world["run_id"]})
    assert (run["counts"]["controls_waiting"], world["published"]) == (0, [world["run_id"]])


def test_a_top_up_that_never_started_is_cancelled_with_its_request(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review S56: one queued behind other top-ups when its request gave up must never run (no AI spent)."""
    busy, release = ThreadPoolExecutor(max_workers=1), threading.Event()
    monkeypatch.setattr(controls_top_up, "_POOL", busy)
    busy.submit(release.wait)  # the pool's one thread is taken
    mapper = _Mapper()
    with pytest.raises(Unavailable):
        _top_up(mapper, deadline=0.1).map_now(world["scenario_id"])
    release.set()
    busy.shutdown(wait=True)
    assert mapper.calls == 0


def test_an_outage_gives_the_controls_back_to_the_controls_job(world: dict[str, Any]) -> None:
    with pytest.raises(Unavailable):
        _top_up(_Mapper(error=Unavailable("The AI service is busy."))).map_now(world["scenario_id"])
    controls = _controls(world)
    assert (controls["status"], controls["error"]["message"]) == (Status.QUEUED, "The AI service is busy.")
    assert world["sent"] == [(TaskName.MAP_CONTROLS, world["run_id"], 0)]


def test_no_fitting_control_is_a_409_with_its_code(world: dict[str, Any]) -> None:
    """A retry cannot change an empty library or an asset no control fits: never 503 with Retry-After."""
    error = ControlsNotMapped(ErrorCode.NO_COMPATIBLE_CONTROL, ErrorMessage.NO_COMPATIBLE_CONTROL)
    with pytest.raises(Conflict) as refused:
        _top_up(_Mapper(error=error)).map_now(world["scenario_id"])
    assert refused.value.reason == ErrorCode.NO_COMPATIBLE_CONTROL
    assert _controls(world)["status"] == Status.FAILED and world["sent"] == []
