"""The shared library build under no job's lease, a job's AI answers read back on a retry, and AI log
fields that keep the job's task and show the limiter."""

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from structlog.testing import capture_logs

from app import ai
from app.ai.chat_messages import update_call_metrics
from app.ai.slots import AiSlots
from app.core.constants import AiOutcome, AiTask
from app.core.exceptions import JobFailed, LeaseLost
from app.core.lease_signal import lease_lost_signal, raise_if_lease_lost
from app.domain.remediation.plan import write_plan
from app.domain.scenario.write import draft_answer, write_set
from app.search.service import _SnapshotKeeper
from tests.fakes import FakeChatModel
from tests.test_remediation_plan import _snapshot
from tests.test_scenario_writing import _CLEAN, _brief_of, _plan_threat
from tests.test_scenario_writing import _CONSISTENT as _OK


class _HeldLibrary:
    """A library cache holding one library version, swapped by setting `library`."""

    def __init__(self, library: object) -> None:
        self.library = library

    def get_loaded_libraries(self) -> Any:
        return self.library


def test_one_jobs_cancel_during_the_shared_library_build_fails_no_other_job() -> None:
    """Job A builds the first snapshot while job B waits on it; A's owner cancels mid-build. B gets the
    snapshot, and so does A, which then sees its own cancel at its next check."""
    library = object()
    snapshot = SimpleNamespace(library=library)
    b_waits = threading.Event()
    outcomes: dict[str, Any] = {}

    with lease_lost_signal("A") as a_lost:

        def build(_library: object) -> Any:
            waiter.start()  # job B arrives while job A builds
            assert b_waits.wait(5)
            time.sleep(0.2)  # job B is waiting on the build's outcome by now
            a_lost.set()  # job A's owner cancels
            raise_if_lease_lost()  # as each AI call of the build does
            return snapshot

        keeper = _SnapshotKeeper(_HeldLibrary(library), build)  # type: ignore[arg-type]

        def job_b() -> None:
            with lease_lost_signal("B"):
                b_waits.set()
                try:
                    outcomes["B"] = keeper.get(wait=False)
                except LeaseLost as exc:
                    outcomes["B"] = exc

        waiter = threading.Thread(target=job_b)
        assert keeper.get(wait=False) is snapshot
        waiter.join(5)
        with pytest.raises(LeaseLost):
            raise_if_lease_lost()
    assert outcomes["B"] is snapshot


def test_a_background_library_build_keeps_the_callers_log_fields_but_not_its_lease() -> None:
    """A rebuild started in the background logs with the job's fields, and a lost lease of the job that
    started it does not stop it."""
    old, new = object(), object()
    held = _HeldLibrary(old)
    seen: dict[str, Any] = {}
    built = threading.Event()

    def build(library: object) -> Any:
        seen["fields"] = structlog.contextvars.get_contextvars()
        raise_if_lease_lost()
        built.set()
        return SimpleNamespace(library=library)

    keeper = _SnapshotKeeper(held, build)  # type: ignore[arg-type]
    keeper.get(wait=False)  # the first snapshot
    built.clear()
    held.library = new
    with structlog.contextvars.bound_contextvars(record_id="r-1"), lease_lost_signal("r-1") as lost:
        lost.set()
        assert keeper.get(wait=False).library is old  # the older snapshot serves while the new one builds
    assert built.wait(5)
    assert seen["fields"]["record_id"] == "r-1"


def test_the_reviewer_remediation_plan_and_writer_reuse_answers() -> None:
    """Every job ask passes reuse_earlier_answer: the scenario writer's set write and rewrite too (a new
    version is a new epoch)."""
    reuse_of: dict[AiTask, bool] = {}

    def refused(task: AiTask, *_args: Any, reuse_earlier_answer: bool = False, **_options: Any) -> Any:
        reuse_of[task] = reuse_earlier_answer
        raise ai.UnreadableAiAnswer("recorded only")

    planner = FakeChatModel()
    planner.ask_for_checked_json = refused  # type: ignore[method-assign]
    with pytest.raises(JobFailed):
        write_plan(planner, _snapshot())  # type: ignore[arg-type]
    writer = FakeChatModel()
    writer.queue(AiTask.WRITE_SCENARIO, {"scenario_title": "x"})  # unreadable: its slot is rewritten
    writer.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN),
        AiTask.PLAN_CHECK: lambda _: _OK,
    }
    answer = writer.ask_for_checked_json

    def recorded(task: AiTask, *args: Any, reuse_earlier_answer: bool = False, **options: Any) -> Any:
        reuse_of[task] = reuse_earlier_answer
        return answer(task, *args, reuse_earlier_answer=reuse_earlier_answer, **options)

    writer.ask_for_checked_json = recorded  # type: ignore[method-assign]
    list(write_set(writer, [("SC1", _brief_of(_plan_threat()))]))  # type: ignore[arg-type]
    assert reuse_of == {
        AiTask.REMEDIATION_PLAN: True,
        AiTask.WRITE_SCENARIO: True,
        AiTask.PLAN_CHECK: True,
        AiTask.REPAIR_SCENARIO: True,
    }


def test_ai_log_lines_keep_the_jobs_task_and_name_the_limiter_unmasked() -> None:
    """An AI step is logged as ai_task (the job's bound task stays), a limiter as limiter (never masked)."""
    with capture_logs() as logs:
        update_call_metrics(AiTask.PLAN_CHECK, "test-chat", AiOutcome.OK, 1, 2, 0.5)
        AiSlots(None, 0, 0, key="tsg:test-slots")._note_redis_failure()
    call, untracked = logs
    assert call["ai_task"] == AiTask.PLAN_CHECK and "task" not in call
    assert untracked["limiter"] == "tsg:test-slots" and "key" not in untracked
