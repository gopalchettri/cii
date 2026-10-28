"""The shared library build under no job's lease, a job's AI answers read back on a retry, and AI log
fields that keep the job's task and show the limiter."""

import threading
import time
import uuid
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import structlog
from structlog.testing import capture_logs

from app import ai
from app.ai.chat_messages import update_call_metrics
from app.ai.slots import AiSlots
from app.core.constants import AiOutcome, AiTask, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, LeaseLost
from app.core.lease_signal import lease_lost_signal, raise_if_lease_lost
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.domain.remediation.plan import write_plan
from app.domain.scenario.write import check_against_plan, split_threat_actions, write_scenario
from app.models.ai.profiles import ChatModelProfile
from app.search.service import _SnapshotKeeper
from tests.fakes import FakeChatModel
from tests.test_remediation_plan import _snapshot
from tests.test_scenario_writing import _CLEAN, _brief_of, _plan_threat


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


_JSON_CHAT = ChatModelProfile(
    max_output_tokens=100,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=20_100,
)


def test_a_retry_of_the_same_epoch_reads_back_the_split_and_a_new_prompt_is_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The threat-action split of a crashed delivery is read back by the next one; another threat is asked."""
    calls: list[dict] = []

    def answer(**request: Any) -> SimpleNamespace:
        calls.append(request)
        reply = SimpleNamespace(message=SimpleNamespace(content='{"actions": ["steal data"]}'))
        return SimpleNamespace(choices=[reply], usage=None)

    monkeypatch.setattr(litellm, "completion", answer)
    calls_store = AiCallRepository(get_mongodb()["test_ai_calls"])
    chat = ai.ChatModel([("test-chat", _JSON_CHAT)], "http://ai.invalid", "key", calls_store)
    job = {"record_id": uuid.uuid4().hex, "epoch": 1, "task": TaskName.WRITE_SCENARIOS, "task_id": "first"}
    with structlog.contextvars.bound_contextvars(**job):
        assert split_threat_actions(chat, "Steal data") == ("steal data",)
    with structlog.contextvars.bound_contextvars(**job | {"task_id": "resent"}):
        assert split_threat_actions(chat, "Steal data") == ("steal data",)  # read back: no AI call
        assert split_threat_actions(chat, "Wipe logs") == ("steal data",)  # another prompt: asked
    assert len(calls) == 2


def test_the_reviewer_split_remediation_plan_and_writer_reuse_answers() -> None:
    """Every job ask passes reuse_earlier_answer: the scenario writer too (a new version is a new epoch)."""
    reuse_of: dict[AiTask, bool] = {}

    def recording_ask(task: AiTask, *_args: Any, reuse_earlier_answer: bool = False, **_options: Any) -> Any:
        reuse_of[task] = reuse_earlier_answer
        raise ai.UnreadableAiAnswer("recorded only")

    chat = FakeChatModel()
    chat.ask_for_checked_json = recording_ask  # type: ignore[method-assign]
    brief = _brief_of(_plan_threat())
    split_threat_actions(chat, "Steal data")  # type: ignore[arg-type]
    check_against_plan(chat, brief, _CLEAN)  # type: ignore[arg-type]
    with pytest.raises(JobFailed):
        write_plan(chat, _snapshot())  # type: ignore[arg-type]
    with pytest.raises(ai.UnreadableAiAnswer):
        write_scenario(chat, brief)  # type: ignore[arg-type]
    assert reuse_of == {
        AiTask.THREAT_ACTIONS: True,
        AiTask.PLAN_CHECK: True,
        AiTask.REMEDIATION_PLAN: True,
        AiTask.WRITE_SCENARIO: True,
    }


def test_ai_log_lines_keep_the_jobs_task_and_name_the_limiter_unmasked() -> None:
    """An AI step is logged as ai_task (the job's bound task stays), a limiter as limiter (never masked)."""
    with capture_logs() as logs:
        update_call_metrics(AiTask.PLAN_CHECK, "test-chat", AiOutcome.OK, 1, 2, 0.5)
        AiSlots(None, 0, 0, key="tsg:test-slots")._note_redis_failure()
    call, untracked = logs
    assert call["ai_task"] == AiTask.PLAN_CHECK and "task" not in call
    assert untracked["limiter"] == "tsg:test-slots" and "key" not in untracked
