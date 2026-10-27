"""The controls job's fixes: every controls change recounts and publishes its run, a delivery keeps its run's
request id, a message's outage retries are capped, and a failed run's status carries its error."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from structlog.testing import capture_logs

from app import container
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    Collection,
    Controls,
    ErrorCode,
    LogEvent,
    ScenarioStatus,
    StageState,
    Status,
    Step,
)
from app.core.database import get_mongodb
from app.core.exceptions import ControlsNotMapped, JobFailed, Unavailable
from app.core.logging import current_request_id
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.scenario.results import build_board, build_scenario_view
from app.models.scenario.views import SessionStatus, session_status_from_record
from app.worker.scenario import controls_job
from app.worker.scenario import tasks as scenario_tasks
from tests.test_control_mapping import (
    _CONTROLS,
    _OT_CONTEXT,
    _SCENARIO,
    _controls_job,
    _ScoresByText,
    _snapshot,
)
from tests.test_v1_scenario_format import _record

_LONG_AGO = timedelta(hours=1)


class _Raising(_ScoresByText):
    """A reranker that raises `error` on every call."""

    def __init__(self, error: Exception) -> None:
        super().__init__({})
        self.error = error

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        raise self.error


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """A finished run sent by request req-run, with one written scenario whose controls wait; each publish
    (with the request id it ran under) and each sent message kept."""
    record_id, now = f"run-{uuid.uuid4().hex}", datetime.now(UTC)
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 1, "status": Status.DONE, "step": Step.SCENARIOS,
         "context": _OT_CONTEXT.to_record(), "counts": {}, "updated_at": now,
         "job": {"request_id": "req-run"}}
    )  # fmt: skip
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": f"{record_id}-1", "session_id": record_id, "path_id": "p1", "status": ScenarioStatus.DONE,
         "superseded_by": None, "decision": "pending", "content": _SCENARIO["content"], "created_at": now,
         "controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": now}}
    )  # fmt: skip
    state: dict[str, Any] = {"record_id": record_id, "published": [], "sent": []}
    state["rerank"] = _ScoresByText({"Backup policy": 70.0})
    search = SimpleNamespace(snapshot=lambda: _snapshot(*_CONTROLS))
    monkeypatch.setattr(container, "get_controls_job", lambda: _controls_job(search, state["rerank"]))
    monkeypatch.setattr(
        controls_job,
        "publish_session_status",
        lambda run_id: state["published"].append((run_id, current_request_id())),
    )
    monkeypatch.setattr(controls_job, "send_job", lambda *args: state["sent"].append(args))
    # The run's counts as the write job left them: its controls waiting.
    container.get_threat_scenario_session_repository().update_scenario_session_counts(record_id)
    yield state


def _set_controls(record_id: str, **controls: Any) -> None:
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": f"{record_id}-1"}, {"$set": {f"controls.{key}": value for key, value in controls.items()}}
    )


def _controls(record_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": f"{record_id}-1"})["controls"]


def _counts(record_id: str) -> tuple[int, int, int]:
    """The run's saved (waiting, failed, cancelled) controls counts."""
    counts = get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})["counts"]
    return counts["controls_waiting"], counts["controls_failed"], counts["controls_cancelled"]


def _deliver(record_id: str) -> int:
    return container.get_controls_job().map_threat_scenario_controls(record_id, "task-1")


def test_an_outage_on_the_last_attempt_recounts_and_publishes_the_run(run: dict[str, Any]) -> None:
    """#2: the scenario fails for good; the run no longer reads "controls running" for ever."""
    record_id = run["record_id"]
    _set_controls(record_id, attempts=Controls.MAX_ATTEMPTS - 1)
    run["rerank"] = _Raising(Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN))
    assert _counts(record_id) == (1, 0, 0)
    with pytest.raises(Unavailable):
        _deliver(record_id)
    assert (_controls(record_id)["status"], _counts(record_id)) == (Status.FAILED, (0, 1, 0))
    assert (record_id, "req-run") in run["published"]
    board = build_board(
        session_status_from_record(get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id}))
    )
    assert board.progress.controls == StageState.ERROR


@pytest.mark.parametrize(
    ("error", "raised", "code"),
    [
        (ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, "empty"), None, ErrorCode.CONTROL_LIBRARY_EMPTY),
        (JobFailed(ErrorCode.PLAN_REFUSED, "refused"), JobFailed, ErrorCode.PLAN_REFUSED),
        (RuntimeError("a bug"), None, ErrorCode.INTERNAL_ERROR),
    ],
)
def test_each_failure_of_one_scenario_fails_it_and_recounts_and_publishes_the_run(
    run: dict[str, Any], error: Exception, raised: type[Exception] | None, code: str
) -> None:
    """The controls job's per-scenario failure branches: the scenario fails with its code (a job-wide failure
    is raised, a bug is logged), and the run is recounted and told either way."""
    record_id = run["record_id"]
    run["rerank"] = _Raising(error)
    with capture_logs() as logs:
        if raised:
            with pytest.raises(raised):
                _deliver(record_id)
        else:
            assert _deliver(record_id) == 0
    controls = _controls(record_id)
    assert (controls["status"], controls["error"]["code"], _counts(record_id)) == (
        Status.FAILED,
        code,
        (0, 1, 0),
    )
    assert (record_id, "req-run") in run["published"]
    assert (LogEvent.CONTROLS_MAP_FAILED in [entry["event"] for entry in logs]) == isinstance(
        error, RuntimeError
    )


@pytest.mark.parametrize(
    ("controls", "run_status", "counts"),
    [
        ({"status": Status.FAILED, "attempts": 1, "last_attempt_at": "long_ago"}, Status.DONE, (1, 0, 0)),
        (
            {"status": Status.RUNNING, "attempts": Controls.MAX_ATTEMPTS, "lease_until": "now"},
            Status.DONE,
            (0, 1, 0),
        ),
        ({}, Status.CANCELLED, (0, 0, 1)),
    ],
    ids=["requeued", "abandoned", "settled"],
)
def test_the_sweep_recounts_publishes_and_logs_every_run_it_changed(
    run: dict[str, Any], controls: dict[str, Any], run_status: Status, counts: tuple[int, int, int]
) -> None:
    """#2: requeue, abandon and settle each change a run's controls: its counts, watchers and the sweep's log
    line (controls.swept, by run) follow."""
    record_id, now = run["record_id"], datetime.now(UTC)
    times = {"long_ago": now - _LONG_AGO, "now": now - timedelta(seconds=1)}
    _set_controls(record_id, **{key: times.get(value, value) for key, value in controls.items()})
    container.get_threat_scenario_session_repository().update_scenario_session_counts(record_id)  # as before
    get_mongodb()[Collection.SESSIONS].update_one({"_id": record_id}, {"$set": {"status": run_status}})
    with capture_logs() as logs:
        scenario_tasks.retry_controls()
    assert _counts(record_id) == counts
    assert record_id in [run_id for run_id, _ in run["published"]]
    swept = next(entry for entry in logs if entry["event"] == LogEvent.CONTROLS_SWEPT)
    assert (
        swept["runs"][record_id]["controls_waiting"],
        swept["runs"][record_id]["controls_failed"],
    ) == counts[:2]


@pytest.mark.parametrize(("attempts", "exhausted"), [(1, False), (Controls.MAX_ATTEMPTS, True)])
def test_controls_read_exhausted_only_once_their_attempts_are_used_up(attempts: int, exhausted: bool) -> None:
    """#2: a failure with attempts left is tried again by the sweep: not exhausted yet."""
    view = build_scenario_view(_record(controls={"status": Status.FAILED, "items": [], "attempts": attempts}))
    assert view.controls_mapping_exhausted is exhausted


def test_the_delivery_claim_returns_the_runs_request_id_and_the_delivery_runs_under_it(
    run: dict[str, Any],
) -> None:
    """#3: a sweep's re-send carries no request id; the delivery takes the run's own from its job."""
    record_id = run["record_id"]
    claimed = container.get_threat_scenario_session_repository().claim_controls_delivery(record_id, "task-1")
    assert claimed is not None and claimed["job"]["request_id"] == "req-run"
    assert current_request_id() is None
    assert _deliver(record_id) == 1
    assert run["published"] == [(record_id, "req-run")]


@pytest.mark.parametrize(
    ("retries", "retried"), [(Controls.MAX_MESSAGE_RETRIES - 1, True), (Controls.MAX_MESSAGE_RETRIES, False)]
)
def test_a_message_stops_retrying_an_outage_after_its_last_retry(
    run: dict[str, Any], monkeypatch: pytest.MonkeyPatch, retries: int, retried: bool
) -> None:
    """#17: an outage before any claim retries the message Controls.MAX_MESSAGE_RETRIES times, then the
    message ends with a log line; the sweep re-sends it later."""
    calls: list[type] = []

    def retry(*_: Any, exc: Exception, **__: Any) -> Exception:
        calls.append(type(exc))
        return RuntimeError("retry")  # what self.retry raises, once recorded

    def store_down(self: ThreatScenarioSessionRepository, session_id: str, task_id: str) -> dict[str, Any]:
        raise Unavailable("mongo down")

    monkeypatch.setattr(scenario_tasks.map_controls, "retry", retry)
    monkeypatch.setattr(ThreatScenarioSessionRepository, "claim_controls_delivery", store_down)
    with capture_logs() as logs:
        result = scenario_tasks.map_controls.apply(
            args=(run["record_id"], 0), task_id="task-1", retries=retries
        )
    assert calls == ([Unavailable] if retried else [])
    assert result.successful() is not retried
    stopped = [entry for entry in logs if entry.get("reason") == "outage_retries_used"]
    assert [entry["event"] for entry in stopped] == ([] if retried else [LogEvent.JOB_NOT_CLAIMED])


@pytest.mark.parametrize(
    ("status", "error", "shown"),
    [
        (Status.FAILED, {"code": "unavailable", "message": "AI down", "reason": "ai_down"},
         {"code": "unavailable", "message": "AI down", "reason": "ai_down"}),
        (Status.FAILED, {"code": "plan_refused", "message": "No plan"},
         {"code": "plan_refused", "message": "No plan", "reason": None}),
        (Status.DONE, None, None),
    ],
)  # fmt: skip
def test_a_failed_runs_status_carries_its_error(
    status: Status, error: dict[str, str] | None, shown: Any
) -> None:
    """#24: the code, message and AI outage reason of a failed run's job, additive on the status body."""
    stored = SessionStatus(
        session_id="s", entity_id=1, asset_id=1, status=status, step=Step.THREATS, error=error,
        updated_at=datetime.now(UTC),
    )  # fmt: skip
    board = build_board(stored).model_dump(mode="json")
    assert board["error"] == shown
