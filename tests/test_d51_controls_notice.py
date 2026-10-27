"""Controls tracing and outage notice: each scenario is mapped under the request that wrote it, and a controls
outage retry shows on the run's status and in the jobs list until the next delivery claims the run."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from structlog.contextvars import bound_contextvars

from app import container
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    Controls,
    Lease,
    PlanCheckStatus,
    Route,
    Status,
)
from app.core.exceptions import Unavailable
from app.core.logging import current_request_id
from app.domain.scenario.results import build_board
from app.domain.scenario.write import written_record
from app.models.scenario.views import session_status_from_record
from app.models.scenario.write import PlanCheck, WrittenScenario
from app.services.jobs.job_service import _run_job
from app.worker.scenario import controls_job
from app.worker.scenario import tasks as scenario_tasks
from tests.planner_samples import CONTEXT
from tests.test_controls_fixes import (  # noqa: F401 - fixture
    _deliver,
    _Raising,
    _set_controls,
    run,
)
from tests.test_scenario_writing import _READ, _brief_of, _plan_threat


def test_a_written_cards_controls_keep_the_request_that_wrote_it() -> None:
    """The writer's request id is stored on the card's queued controls."""
    written = WrittenScenario(_READ, (), PlanCheck(PlanCheckStatus.CONSISTENT, ()), Route.STANDALONE, "T")
    run_record = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {"path_id": "p1", "category": "Tampering", "categories": ["Tampering"], "systems": [321]}
    with bound_contextvars(request_id="req-w"):
        record = written_record(run_record, path, _plan_threat(), _brief_of(_plan_threat()), written)
    assert record["controls"]["request_id"] == "req-w"


def test_each_scenario_is_mapped_under_the_request_that_wrote_it(
    run: dict[str, Any],  # noqa: F811 - the imported fixture
) -> None:
    """A delivery maps a card written by an earlier request under that request's id, not the run's latest;
    the delivery's own lines keep the run's."""
    record_id = run["record_id"]
    _set_controls(record_id, request_id="req-writer")
    assert _deliver(record_id) == 1
    assert (record_id, "req-writer") in run["published"]
    assert current_request_id() == "req-run"


def _shown_retrying(record_id: str) -> tuple[Any, Any]:
    """The run's notice as its status board and the jobs list show it, each read as the app reads it."""
    stored = container.get_threat_scenario_session_repository().get(fields="status", _id=record_id)
    listed, _ = container.get_work_control_repository().list_working_scenario_sessions(86)
    in_list = next((record for record in listed if record["_id"] == record_id), None)
    shown_in_list = _run_job(in_list).retrying if in_list else None  # listed while controls wait
    return build_board(session_status_from_record(stored)).progress.retrying, shown_in_list


@pytest.mark.parametrize("retries", [0, Controls.MAX_MESSAGE_RETRIES])
def test_a_controls_outage_shows_a_retry_notice_until_the_next_claim(
    run: dict[str, Any],  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
    retries: int,
) -> None:
    """The run's board shows stage controls, the outage, the try and when the next comes (the sweep's re-send
    after the last), and its watchers are told once it is stored; the next delivery's claim clears it while
    controls still wait."""
    record_id = run["record_id"]
    run["rerank"] = _Raising(Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN))
    monkeypatch.setattr(scenario_tasks.map_controls, "retry", lambda *_, **__: RuntimeError("retry"))
    seen_by_watchers: list[Any] = []  # the notice a stream re-reading the status would see at each publish
    monkeypatch.setattr(
        controls_job,
        "publish_session_status",
        lambda run_id: seen_by_watchers.append(_shown_retrying(run_id)[0]),
    )
    scenario_tasks.map_controls.apply(args=(record_id, 0), task_id="task-1", retries=retries)
    last = retries >= Controls.MAX_MESSAGE_RETRIES
    delay = Controls.RESEND_QUEUED_AFTER_SECONDS if last else Lease.RETRY_DELAYS_SECONDS[0]
    retrying, listed = _shown_retrying(record_id)
    assert retrying is not None and listed == retrying
    assert (retrying.stage, retrying.reason, retrying.attempt, retrying.max_attempts) == (
        "controls",
        AiOutage.DOWN,
        retries + 1,
        Controls.MAX_MESSAGE_RETRIES + 1,
    )
    expected_at = datetime.now(UTC) + timedelta(seconds=delay)
    assert abs((retrying.retry_at - expected_at).total_seconds()) < 5
    assert seen_by_watchers[-1] == retrying  # the recount's publish came before the notice was stored
    # The retry's claim; its card still waits, so only the claim's reset can hide the notice.
    assert container.get_threat_scenario_session_repository().claim_controls_delivery(record_id, "task-1")
    assert _shown_retrying(record_id) == (None, None)


def test_the_jobs_list_shows_a_controls_retry_while_controls_wait() -> None:
    """A done run mapping controls lists its controls outage notice; none once no control waits."""
    notice = {"reason": "ai_down", "message": "AI down", "attempt": 1, "max_attempts": 4}
    record = {
        "_id": "run-1",
        "status": Status.DONE,
        "counts": {"controls_waiting": 1},
        "controls_delivery": {"retry": notice | {"retry_at": datetime.now(UTC)}},
    }
    shown = _run_job(record).retrying
    assert shown is not None and (shown.stage, shown.reason) == ("controls", AiOutage.DOWN)
    assert _run_job(record | {"counts": {"controls_waiting": 0}}).retrying is None
