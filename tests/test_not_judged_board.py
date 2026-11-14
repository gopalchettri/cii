"""Threats the AI never judged are left out of the plan: the status board says so beside the threats step,
so a run reading complete never hides them; a count of 0, or a run planned before it was kept, shows
nothing. Fake AI models; the plan job runs on the test MongoDB."""

from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import AiTask, Collection, RunOverall, ThreatFinding
from app.core.database import get_mongodb
from app.data_access.scenario.threat_scenario_session_repository import SESSION_STATUS_FIELDS
from app.domain.scenario.session import build_status_board
from app.models.scenario.views import session_status_from_record
from app.worker import jobs
from app.worker.scenario.plan_job import PLAN_JOB_FIELDS
from tests.planner_samples import LOG_WIPE, PHISHING, finder, planner_chat
from tests.test_attack_paths import (  # noqa: F401 - `sent` is a fixture used by name
    _plan_job,
    _queued_run,
    _stored_run,
    _threats_task,
    sent,
)
from tests.test_run_board import _run, _written


def _left_out(count: int) -> str:
    why = "could not be checked by the AI and were left out (counted per STRIDE category)."
    return f"{count} threat(s) {why}"


@pytest.mark.parametrize(
    ("not_judged", "expected"),
    [
        pytest.param({"not_judged": 3}, {"threats": _left_out(3)}, id="three never judged"),
        pytest.param({"not_judged": 0}, {}, id="all judged"),
        pytest.param({}, {}, id="planned before the count was kept"),
    ],
)
def test_threats_the_ai_never_judged_are_named_beside_the_threats_step(
    not_judged: dict[str, int], expected: dict[str, str]
) -> None:
    progress = build_status_board(_run(**_written(planned=6, written=6, accepted=6, **not_judged))).progress
    assert (progress.overall, progress.error_message) == (RunOverall.COMPLETE, expected)


def test_a_planned_run_whose_gate_never_judged_a_threat_says_so_on_its_status(
    monkeypatch: pytest.MonkeyPatch,
    sent: list[tuple[Any, ...]],  # noqa: F811 - the imported fixture
) -> None:
    """The gate leaves the phishing slot out twice: it is not judged, the trace counts it and the status
    read through its own projection shows it."""
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    monkeypatch.setattr(ThreatFinding, "THREATS_PER_QUESTION", 35)  # one gate call, whatever the .env says
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: {
        "verdicts": [verdict for verdict in gate(user)["verdicts"] if verdict["threat"] != PHISHING.name]
    }
    record_id = _queued_run()
    plan = _plan_job(finder(chat))
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, plan, fields=PLAN_JOB_FIELDS)
    assert _stored_run(record_id)["plan_trace"]["counts"]["not_judged"] == 1
    record = get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id}, SESSION_STATUS_FIELDS)
    assert record is not None
    board = build_status_board(session_status_from_record(record))
    assert board.progress.error_message == {"threats": _left_out(1)}
