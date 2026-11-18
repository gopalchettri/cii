"""The pure rules behind job control, curator decisions, API keys and the intelligence refresh."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.api.routes.admin import decision_operation_key
from app.core.constants import ApiKey, ConflictReason, JobKind, Status, TaskName
from app.core.exceptions import Conflict
from app.core.security import Principal, could_be_minted_key, hash_api_key
from app.domain import jobs
from app.domain.intel.admin import evidence_settings
from app.domain.intel.refresh import is_cut_short_feed

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def _shown_job(status: Status, task: TaskName | None) -> tuple[JobKind, Status]:
    job = jobs._run_job({"_id": "s1", "status": status, "job": {"task": task}})
    return job.kind, job.status


def test_a_working_run_shows_its_job_and_a_finished_one_shows_control_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _shown_job(Status.QUEUED, TaskName.FIND_THREATS) == (JobKind.THREATS, Status.QUEUED)
    assert _shown_job(Status.RUNNING, TaskName.WRITE_SCENARIOS) == (JobKind.SCENARIOS, Status.RUNNING)
    assert _shown_job(Status.DONE, None) == (JobKind.CONTROLS, Status.RUNNING)
    stopped = [(False, 2), (False, 0)]  # controls only: the cancel goes on; nothing: 409
    monkeypatch.setattr(jobs.work_control, "cancel_scenario_session", lambda *_: stopped.pop(0))
    monkeypatch.setattr(jobs.publisher, "publish_session_status", lambda _: 1 / 0)  # reached: not refused
    principal, run = Principal("c", "u", 1, "t"), SimpleNamespace(session_id="s1")
    with pytest.raises(ZeroDivisionError):
        jobs.cancel_run(principal, run)  # type: ignore[arg-type]
    with pytest.raises(Conflict) as refused:
        jobs.cancel_run(principal, run)  # type: ignore[arg-type]
    assert refused.value.reason == ConflictReason.NOTHING_TO_CANCEL


def test_the_same_curator_decisions_share_one_operation_key() -> None:
    assert (
        decision_operation_key([1], [2], "u")
        == decision_operation_key([1], [2], "u")
        != decision_operation_key([2], [1], "u")
    )


def test_only_a_key_shaped_like_a_minted_one_is_looked_up() -> None:
    assert not could_be_minted_key("junk")
    assert not could_be_minted_key(ApiKey.PREFIX + "x")
    assert len(hash_api_key("k")) == 64


def test_a_cut_short_feed_is_refused() -> None:
    assert is_cut_short_feed(100, 1) and not is_cut_short_feed(100, 100) and not is_cut_short_feed(0, 0)


def test_the_evidence_settings_name_the_model_never_its_path() -> None:
    assert evidence_settings("C:\\models\\bge-reranker-v2-m3\\", 0.5)["rerank_model"] == "bge-reranker-v2-m3"


def test_the_threshold_is_calibrated_only_at_the_value_calibrated_on_that_model() -> None:
    """bge-reranker-v2-m3 was calibrated at 30: 30 is calibrated, with its date; 5 on it is not, nor is any
    threshold on a model never calibrated."""
    calibrated = evidence_settings("/m/bge-reranker-v2-m3", 30.0)
    assert (calibrated["threshold_calibrated"], calibrated["threshold_calibrated_on"]) == (True, "2026-10-19")
    for model, threshold in (("/m/bge-reranker-v2-m3", 5.0), ("/m/other", 30.0)):
        shown = evidence_settings(model, threshold)
        assert (shown["threshold_calibrated"], shown["threshold_calibrated_on"]) == (False, None)
