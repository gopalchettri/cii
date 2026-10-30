"""The scenario writer on a re-delivery of the same job: its accepted draft read back, and each path's card
and give-up counted once in tsg_scenarios_total."""

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import structlog
from fastapi.testclient import TestClient

from app import ai
from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, AiTask, Collection, Status, Step, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.jobs.job_repository import JobRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.scenario.write import slot_label, write_set
from app.models.ai.profiles import ChatModelProfile
from tests.fakes import FakeChatModel
from tests.test_run_actions import _deliver, _regenerate, api_key, queued  # noqa: F401 - fixtures by name
from tests.test_scenario_writing import _CONSISTENT, _brief_of, _plan_threat
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _answer_for,
    _deliver_until_done,
    _on_last_try,
    _queued_run,
    _scenarios_of,
    _sessions,
    _settled,
    _write_batch,
    chat,
    sent,
)

_ROOMY_CHAT = ChatModelProfile(
    max_output_tokens=8192,
    timeout_seconds=5,
    supports_json_mode=True,
    reasoning_effort="none",
    context_tokens=200_000,
)


def test_a_redelivery_of_the_same_job_reads_back_the_whole_set_with_no_ai_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The set's asks are the same on a re-delivery (slots in the batch's order, the second round built only
    from the first's answers), so a re-delivery of the same job (same record, epoch and stage) takes every
    answer its first delivery got: 0 AI calls, and the same scenarios come out."""
    answers = FakeChatModel()  # works each answer out from its prompt
    answers.queue(AiTask.WRITE_SCENARIO, {"scenario_title": "x"})  # SC1 unreadable: the second round runs
    answers.responders[AiTask.WRITE_SCENARIO] = _answer_for
    answers.responders[AiTask.PLAN_CHECK] = lambda _: _CONSISTENT

    def complete(**request: Any) -> SimpleNamespace:
        user = request["messages"][1]["content"]
        task = AiTask.PLAN_CHECK if "\nPLAN:\n" in user else AiTask.WRITE_SCENARIO
        task = AiTask.REPAIR_SCENARIO if "REJECTED:" in user else task
        reply = SimpleNamespace(message=SimpleNamespace(content=json.dumps(answers._answer(task, user))))
        return SimpleNamespace(choices=[reply], usage=None)

    monkeypatch.setattr(litellm, "completion", complete)
    calls = AiCallRepository(get_mongodb()["test_ai_calls"])
    model = ai.ChatModel([("test-chat", _ROOMY_CHAT)], "http://ai.invalid", "key", calls)
    threats = [_plan_threat(), _plan_threat(key="lib:298", name="Historian wipe")]
    briefs = [(slot_label(place), _brief_of(threat)) for place, threat in enumerate(threats, start=1)]
    job = {"record_id": uuid.uuid4().hex, "epoch": 1, "task": TaskName.WRITE_SCENARIOS}
    with structlog.contextvars.bound_contextvars(**job, task_id="first"):
        first = list(write_set(model, briefs))
    asked = len(answers.calls)
    with structlog.contextvars.bound_contextvars(**job, task_id="resent"):
        again = list(write_set(model, briefs))
    assert [task for task, _ in answers.calls] == [
        AiTask.WRITE_SCENARIO,
        AiTask.PLAN_CHECK,
        AiTask.REPAIR_SCENARIO,
        AiTask.PLAN_CHECK,
    ]
    assert len(answers.calls) == asked and again == first and len(first) == 2


@pytest.mark.usefixtures("sent")
def test_a_card_and_its_give_up_are_counted_once_when_a_redelivery_saves_the_path_again(
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delivery that saved a blocked card, then died before its path's fenced state write, counted
    nothing: the re-delivery saves the card again and counts the card and the give-up once each."""

    def cites_an_advisory(user_prompt: str) -> dict[str, Any]:
        answer = _answer_for(user_prompt)
        return answer | {"scenario_statement": answer["scenario_statement"] + " CVE-2024-1234 helps."}

    def dies(*_: Any) -> None:
        raise RuntimeError("the worker died")

    chat.responders[AiTask.WRITE_SCENARIO] = cites_an_advisory
    record_id = _queued_run(["Threat 1"])
    blocked, abandoned = _settled("blocked"), _settled("abandoned")
    with monkeypatch.context() as crash:
        crash.setattr(ThreatScenarioSessionRepository, "update_scenario_session_plan", dies)
        lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
        assert lease is not None
        with pytest.raises(RuntimeError):
            _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    assert _deliver_until_done(record_id) == 1
    assert (_settled("blocked"), _settled("abandoned")) == (blocked + 1, abandoned + 1)
    path = _sessions().find_one({"_id": record_id})["plan"]["paths"][0]
    assert (path["attempts"], path["abandoned"]) == (1, True)


def _answers_with(blocked: str, busy: set[str]) -> Any:
    """The writer's answers: `blocked`'s draft cites an advisory, the AI service is busy for `busy` (their
    first answers unreadable, their rewrite in the set's second round meeting the outage)."""

    def answer(user_prompt: str) -> dict[str, Any]:
        if any(f'"{name}"' in user_prompt for name in busy):
            if "REJECTED:" not in user_prompt:
                return {"scenario_title": "x"}
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)
        written = _answer_for(user_prompt)
        if blocked and f'"{blocked}"' in user_prompt:  # "" is in every slot's no-evidence line
            written["scenario_statement"] += " CVE-2024-1234 helps."
        return written

    return answer


@pytest.mark.usefixtures("queued", "sent")
def test_a_regenerate_retried_after_an_outage_settles_each_card_path_once(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """Regenerate three outage cards: p2's draft is blocked, p4 now repeats p1's scenario and the AI is busy
    for p3 on the job's first try. The retry writes p3 only: p2's block and both give-ups are counted once,
    and p2's attempts go up by one."""
    chat.responders[AiTask.WRITE_SCENARIO] = _answers_with("", {"Threat 2", "Threat 3", "Threat 4"})
    record_id = _queued_run(["Threat 1", "Threat 2", "Threat 3", "Threat 4"])
    _sessions().update_one({"_id": record_id}, {"$set": {"step": Step.SCENARIOS}})
    _write_batch(_on_last_try(record_id))  # p1 written, a busy card on each other path
    first, *cards = [scenario["_id"] for scenario in _scenarios_of(record_id)]
    scenarios = get_mongodb()[Collection.SCENARIOS]
    repeated = scenarios.find_one({"_id": cards[2]})["content"]["threat"]
    scenarios.update_one({"_id": first}, {"$set": {"content.threat": repeated}})
    assert _regenerate(client, api_key, record_id, cards).status_code == 202
    chat.responders[AiTask.WRITE_SCENARIO] = _answers_with("Threat 2", {"Threat 3"})
    blocked, abandoned = _settled("blocked"), _settled("abandoned")
    tried = _sessions().find_one({"_id": record_id})["plan"]["paths"][1]["attempts"]
    lease = JobRepository(_sessions()).claim_job(record_id, 2, TaskName.WRITE_SCENARIOS, "first")
    assert lease is not None
    with pytest.raises(Unavailable):
        _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    chat.responders[AiTask.WRITE_SCENARIO] = _answers_with("Threat 2", set())
    assert _deliver(record_id, 2) == 1
    assert (_settled("blocked"), _settled("abandoned")) == (blocked + 1, abandoned + 2)
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert [path["abandoned"] for path in paths] == [False, True, False, True]
    assert (paths[1]["attempts"], paths[2]["served"]) == (tried + 1, cards[1])
