"""The plan check (approved prompts): one AI call at temperature 0 reads a written
scenario against its plan and judges meaning, which code cannot. Its problems are notes on the scenario; a
check that cannot be made is a note too, never a failure: the scenario is still saved and shown."""

from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AiTask, FindingCode, FindingMessage, LogEvent, PlanCheckStatus, Writing
from app.core.tracing import traced
from app.engine.scenarios.writing.writing_prompts import plan_check_prompt
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_and_check
from app.engine.shared.names import shorten_text
from app.models.writing import Finding, PlanCheck, PlanCheckAnswer, ScenarioDraft, WriterBrief

log = structlog.get_logger(__name__)


class PlanChecker:
    def __init__(self, chat: ChatModel) -> None:
        self._chat = chat

    @traced("writing.plan_check")
    def check_against_plan(
        self, brief: WriterBrief, draft: ScenarioDraft
    ) -> tuple[PlanCheck, tuple[Finding, ...]]:
        """The check and its notes: none when consistent, one per problem when not, one saying why when the
        answer stayed unusable after its one re-ask. An outage (Unavailable) is raised: the job retries."""
        try:
            answer: PlanCheckAnswer = ask_ai_and_check(
                self._chat, AiTask.PLAN_CHECK, plan_check_prompt(brief, draft), _read_answer
            )
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.WRITER_PLAN_CHECK_NOT_MADE, error=str(exc))
            reason = shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS)
            note = Finding(
                FindingCode.PLAN_CHECK_NOT_MADE, FindingMessage.PLAN_CHECK_NOT_MADE.format(reason=reason)
            )
            return PlanCheck(PlanCheckStatus.UNCHECKED), (note,)
        if answer.consistent:
            return PlanCheck(PlanCheckStatus.CONSISTENT), ()
        problems = tuple(
            shorten_text(" ".join(problem.split()), Writing.PROBLEM_MAX_CHARS)
            for problem in answer.problems[: Writing.MAX_PLAN_PROBLEMS]
            if problem.strip()
        )
        notes = tuple(Finding(FindingCode.PLAN_CHECK, problem) for problem in problems)
        return PlanCheck(PlanCheckStatus.INCONSISTENT, problems), notes


def _read_answer(answer: dict[str, Any]) -> tuple[PlanCheckAnswer | None, list[str]]:
    problems = answer_item_problems(PlanCheckAnswer, answer, "the reply")
    return (None, problems) if problems else (PlanCheckAnswer.model_validate(answer), [])
