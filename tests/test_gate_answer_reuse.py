"""The planner's AI asks reuse the answers an earlier delivery of the job got."""

from typing import Any

from app.core.constants import AiTask
from tests.planner_samples import CONTEXT, LOG_WIPE, finder, planner_chat


def test_the_gate_and_gap_fill_ask_with_their_earlier_answers_reused() -> None:
    """Every gate and gap-fill ask passes reuse_earlier_answer: a job's next delivery asks no prompt twice."""
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    asked_with: set[tuple[AiTask, bool]] = set()
    ask = chat.ask_for_checked_json

    def recording_ask(task: AiTask, *args: Any, reuse_earlier_answer: bool = False, **options: Any) -> Any:
        asked_with.add((task, reuse_earlier_answer))
        return ask(task, *args, **options)

    chat.ask_for_checked_json = recording_ask  # type: ignore[method-assign]
    finder(chat).find_threats(CONTEXT)
    assert asked_with == {(AiTask.RELEVANCE_GATE, True), (AiTask.GAP_FILL, True)}
