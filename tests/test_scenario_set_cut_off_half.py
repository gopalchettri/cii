"""A set sent as two calls whose second call is cut off keeps the first call's scenarios; only the cut-off
part's slots go to the rewrite. Fake AI model, no network."""

from typing import Any

import pytest

from app.core.constants import AiLimits, AiTask, ErrorCode
from app.domain.scenario.write import build_writer_prompt, write_scenario_set
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import PathFailure, WrittenScenario
from tests.fakes import FakeChatModel, draft_answer, slot_blocks, truncated
from tests.test_scenario_sets import _briefs
from tests.test_scenario_writing import _CLEAN


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
