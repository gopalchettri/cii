"""A plan job completing its version's pending input (app/worker/remediation/plan_inputs.py, G262: a plan
request makes no AI call): a mapping the run's controls job makes now is waited for and used, never doubled;
an outage frees the scenario's controls and retries the job; a cancel stops a mapping at its next AI call; a
regenerate's lost controls are warned about; an empty control library is refused by the request itself. The
test database; the plan job's AI faked."""

import contextlib
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app import container
from app.core.constants import (
    AiOutage,
    AiTask,
    Collection,
    Controls,
    ErrorCode,
    SnapshotWarning,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, LeaseLost, Unavailable
from app.core.lease_signal import raise_if_lease_lost
from app.models.library.library import LoadedLibraries
from app.models.remediation.requests import PlanRequest
from app.worker import jobs
from tests.plan_addresses import generated, plan_url
from tests.test_remediation_planner import _answer, _control
from tests.test_remediation_requests import (  # noqa: F401 — api_key and world are fixtures
    ENTITY,
    _identity,
    _record,
    _request,
    _scenario,
    _service,
    api_key,
    world,
)
from tests.test_threat_identity import LIBRARY as THREATS


def _deliver(remediation_id: str, version: int = 1) -> None:
    task: Any = SimpleNamespace(
        name=TaskName.WRITE_PLAN, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )
    write = container.get_remediation_plan_job().write_remediation_plan_version
    with contextlib.suppress(Exception):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(task, Collection.REMEDIATIONS, remediation_id, version, write)


def _due_now(remediation_id: str) -> None:
    """The back-off a retry was given, over: the next delivery may claim the job."""
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"job.due_at": datetime.now(UTC) - timedelta(seconds=1)}}
    )


def _held_by_the_controls_job() -> dict[str, Any]:
    return {
        "status": Status.RUNNING,
        "attempts": 1,
        "task_id": "controls-job",
        "lease_until": datetime.now(UTC) + timedelta(seconds=60),
    }


def test_a_mapping_the_controls_job_makes_now_is_waited_for_and_used_never_doubled(
    client: TestClient,
    api_key: str,  # noqa: F811
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Controls, "PLAN_WAIT_POLL_SECONDS", 0.05)
    scenario_id = _scenario(controls=_held_by_the_controls_job())
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    mapped = [{"control_id": 1, "code": "CII-CID-1", "score": 80.0, "match": "exact"}]

    def the_controls_job_finishes() -> None:
        get_mongodb()[Collection.SCENARIOS].update_one(
            {"_id": scenario_id}, {"$set": {"controls.status": Status.DONE, "controls.items": mapped}}
        )

    threading.Timer(0.3, the_controls_job_finishes).start()
    world["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id)
    assert world["mapper"].asked == []  # its result was used: the scenario was never mapped twice
    record = _record(remediation_id)
    assert record["status"] == Status.DONE
    shown = record["versions"][0]["snapshot"]["existing_controls"]["library_mapped"]
    assert [control["control_code"] for control in shown] == ["CII-CID-1"]


def test_a_mapping_still_running_after_its_lease_gives_the_plan_job_back_for_a_later_try(
    client: TestClient,
    api_key: str,  # noqa: F811
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Controls, "PLAN_WAIT_POLL_SECONDS", 0.05)
    monkeypatch.setattr(Controls, "LEASE_SECONDS", 0.2)  # the wait's bound (the other job's lease is 60 s)
    scenario_id = _scenario(controls=_held_by_the_controls_job())
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    _deliver(remediation_id)
    record = _record(remediation_id)
    assert (record["status"], record["job"]["attempts"]) == (Status.QUEUED, 1)  # retried after its back-off
    assert world["mapper"].asked == [] and record["versions"][0]["snapshot"]["pending"] is True


def test_an_outage_frees_the_scenarios_controls_and_the_retry_maps_and_plans(
    client: TestClient,
    api_key: str,  # noqa: F811
    world: dict[str, Any],  # noqa: F811
) -> None:
    scenario_id = _scenario(controls={"status": Status.QUEUED, "attempts": 0})
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    world["mapper"].failure = Unavailable("The reranker is busy.", reason=AiOutage.BUSY)
    _deliver(remediation_id)
    controls = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]
    assert (controls["status"], controls["error"]["code"]) == (Status.QUEUED, ErrorCode.UNAVAILABLE)
    assert controls["error"]["reason"] == AiOutage.BUSY  # the card can say the AI was busy
    assert _record(remediation_id)["status"] == Status.QUEUED  # the job retries after its back-off
    _due_now(remediation_id)
    world["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id)
    assert world["mapper"].asked == [scenario_id, scenario_id]
    assert _record(remediation_id)["status"] == Status.DONE


@pytest.mark.parametrize("cancelled", ["plan", "run"])
def test_a_cancel_stops_the_plan_jobs_mapping_and_only_a_plan_cancel_ends_the_job(
    client: TestClient,
    api_key: str,  # noqa: F811
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    cancelled: str,
) -> None:
    """The mapping's next AI call sees either lease lost. A plan cancel ends the delivery as stopped by its
    owner; a run cancel (the scenario's control lease lost) gives the plan job back for its normal retry."""
    monkeypatch.setattr(jobs.Lease, "RENEW_EVERY_SECONDS", 0.02)
    scenario_id = _scenario(controls={"status": Status.QUEUED, "attempts": 0})
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    stopped_by: list[str] = []

    def map_until_stopped(*_args: Any) -> None:
        if cancelled == "plan":
            plans = get_mongodb()[Collection.REMEDIATIONS]
            plans.update_one({"_id": remediation_id}, {"$set": {"status": Status.CANCELLED}})
        else:  # a run cancel stops the controls being mapped
            cards = get_mongodb()[Collection.SCENARIOS]
            cards.update_one({"_id": scenario_id}, {"$set": {"controls.status": Status.CANCELLED}})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:  # every AI call checks the signal first
            try:
                raise_if_lease_lost()
            except LeaseLost as exc:
                stopped_by.append(str(exc))
                raise
            time.sleep(0.01)

    monkeypatch.setattr(world["mapper"], "map_controls", map_until_stopped)
    with capture_logs() as logs:
        _deliver(remediation_id)
    events = [entry["event"] for entry in logs]
    record = _record(remediation_id)
    assert "job.lease_lost" not in events
    if cancelled == "plan":
        assert stopped_by == [remediation_id] and "job.stopped_by_owner" in events
        assert record["status"] == Status.CANCELLED
        controls = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]
        assert controls.get("error") is None  # stopped, not failed: never told as an outage
    else:
        assert stopped_by == [scenario_id] and "job.retry_scheduled" in events
        assert (record["status"], record["job"]["attempts"]) == (Status.QUEUED, 1)


@pytest.fixture
def regenerations(world: dict[str, Any]) -> Any:  # noqa: F811
    """The world's service: it regenerates plans on the same fakes."""
    return world["service"]


def test_a_regenerate_that_waited_for_its_controls_still_warns_of_the_ones_it_lost(
    client: TestClient,
    api_key: str,  # noqa: F811
    world: dict[str, Any],  # noqa: F811
    regenerations: Any,
) -> None:
    """Version 1 had CII-CID-1; the scenario's controls were not mapped when the regenerate was asked: its
    plan job maps them (to CII-CID-2 now) and warns that CII-CID-1 is no longer mapped."""
    scenario_id = _scenario()
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    world["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id)
    unmapped = {"controls": {"status": Status.QUEUED, "attempts": 0}}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": unmapped})
    world["mapper"].control = (2, "CII-CID-2")
    regenerated = client.post(plan_url(remediation_id, "regenerate"), json={}, headers=_identity(api_key))
    assert regenerated.status_code == 202 and world["mapper"].asked == []
    world["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-2")))
    _deliver(remediation_id, 2)
    snapshot = _record(remediation_id)["versions"][1]["snapshot"]
    lost = SnapshotWarning.CONTROL_NO_LONGER_MAPPED.format(code="CII-CID-1", version=1)
    assert lost in snapshot["warnings"] and world["mapper"].asked == [scenario_id]


def test_an_empty_control_library_is_refused_by_the_request_itself(world: dict[str, Any]) -> None:  # noqa: F811
    """No AI is needed to know that no control could ever be kept: 409 control_library_empty at once."""
    empty = SimpleNamespace(get_loaded_libraries=lambda: LoadedLibraries((), THREATS, ()))
    service = _service(library=empty, send_job=lambda *args: world["sent"].append(args))
    principal: Any = SimpleNamespace(entity_id=ENTITY, user_id="u1", client_id="c1")
    with pytest.raises(Conflict) as refused:
        service.create_remediation_plan(principal, PlanRequest.model_validate(generated(_scenario())), None)
    assert refused.value.reason == ErrorCode.CONTROL_LIBRARY_EMPTY and world["sent"] == []
