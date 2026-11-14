"""A set sent as two calls whose second call is cut off keeps the first call's scenarios; only the cut-off
part's slots go to the rewrite. Fake AI model, no network."""

from typing import Any

import pytest

from app.core.constants import AiLimits, AiTask, ErrorCode, TaskName
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import build_writer_prompt, write_scenario_set
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import PathFailure, WrittenScenario
from tests.fakes import FakeChatModel, draft_answer, slot_blocks, truncated
from tests.test_scenario_sets import _briefs
from tests.test_scenario_writing import _CLEAN
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _queued_run,
    _scenarios_of,
    _sessions,
    _write_batch,
    chat,
    sent,
)


def _cut_off(_: str) -> dict[str, Any]:
    raise truncated()


@pytest.mark.parametrize("rewritten", [True, False], ids=["rewrite-answers", "rewrite-cut-off"])
def test_a_cut_off_second_half_keeps_the_first_halfs_scenarios(
    monkeypatch: pytest.MonkeyPatch, rewritten: bool
) -> None:
    """SC1 and SC2 go as one call each; SC2's is cut off. SC1 is kept from its write, and SC2 alone is asked
    in the rewrite: written there, or a failure card when the rewrite is cut off too."""
    briefs = _briefs(2)
    one = max(
        call_tokens(build_writer_prompt([(label, brief, "")]), AiTask.WRITE_SCENARIO)
        for label, brief in briefs
    )
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", one)

    def write(block: str) -> dict[str, Any]:
        return _cut_off(block) if '"Threat 2"' in block else draft_answer(_CLEAN)

    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: write,
        AiTask.REPAIR_SCENARIO: (lambda _: draft_answer(_CLEAN)) if rewritten else _cut_off,
    }
    outcomes = list(write_scenario_set(fake, briefs))  # type: ignore[arg-type]
    labels = [[label for label, _ in slot_blocks(prompt)] for task, prompt in fake.calls]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO] * 2 + [AiTask.REPAIR_SCENARIO]
    assert labels == [["SC1"], ["SC2"], ["SC2"]]
    (first, kept), (second, last) = outcomes
    assert first == "SC1" and isinstance(kept, WrittenScenario) and second == "SC2"
    if rewritten:
        assert isinstance(last, WrittenScenario)
    else:
        assert isinstance(last, PathFailure) and last.code == ErrorCode.GENERATION_FAILED and not last.final


def test_a_part_that_answers_with_no_usable_scenario_still_sends_the_set_to_the_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SC1's call answers but holds no usable scenario, SC2's is cut off: a part answered, so both slots go to
    the rewrite and are written there, instead of the whole set failing as cut off."""
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", 1)  # one slot per call
    fake = FakeChatModel()
    fake.queue(AiTask.WRITE_SCENARIO, {"scenarios": []}, truncated())
    fake.responders[AiTask.REPAIR_SCENARIO] = lambda _: draft_answer(_CLEAN)
    outcomes = list(write_scenario_set(fake, _briefs(2)))  # type: ignore[arg-type]
    tasks = [task for task, _ in fake.calls]
    assert tasks[:2] == [AiTask.WRITE_SCENARIO] * 2 and AiTask.REPAIR_SCENARIO in tasks
    assert [label for label, _ in outcomes] == ["SC1", "SC2"]
    assert all(isinstance(result, WrittenScenario) for _, result in outcomes)


@pytest.mark.usefixtures("sent")
def test_a_set_whose_every_part_is_cut_off_fails_with_the_cut_off_and_asks_no_rewrite(
    monkeypatch: pytest.MonkeyPatch,
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """Two paths go as one call each and both calls are cut off: no rewrite is asked (it would be cut off
    again), and each path's card names the cut-off, as a set sent in one call does."""
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", 1)  # one slot per call
    chat.responders[AiTask.WRITE_SCENARIO] = _cut_off
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first"))
    failures = [card["failure"] for card in _scenarios_of(record_id)]
    assert [(failure["code"], failure["message"]) for failure in failures] == [
        (ErrorCode.GENERATION_FAILED, str(truncated()))
    ] * 2
    assert (len(chat.asked(AiTask.WRITE_SCENARIO)), chat.asked(AiTask.REPAIR_SCENARIO)) == (2, [])
