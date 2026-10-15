"""The plan check (approved prompts): one AI call at temperature 0 reads a written
scenario against its plan and judges meaning, which code cannot. Its problems are notes on the scenario; a
check that cannot be made is a note too, never a failure: the scenario is still saved and shown."""

import re
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import (
    AiTask,
    FindingCode,
    FindingMessage,
    LogEvent,
    PlanCheckStatus,
    WriterStyle,
    Writing,
)
from app.core.tracing import traced
from app.engine.external_intelligence.story.evidence_story_prompts import story_plan_check_prompt
from app.engine.scenarios.writing.writing_prompts import plan_check_prompt
from app.engine.shared.ask_ai import ChatPrompt, answer_item_problems, ask_ai_and_check
from app.engine.shared.names import shorten_text
from app.models.external_intelligence.evidence_view import markers_of
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
            prompt = _prompt_of(brief, draft)
            answer: PlanCheckAnswer = ask_ai_and_check(self._chat, AiTask.PLAN_CHECK, prompt, _read_answer)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.WRITER_PLAN_CHECK_NOT_MADE, error=str(exc))
            reason = shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS)
            note = Finding(
                FindingCode.PLAN_CHECK_NOT_MADE, FindingMessage.PLAN_CHECK_NOT_MADE.format(reason=reason)
            )
            return PlanCheck(PlanCheckStatus.UNCHECKED), (note,)
        flagged = _unsupported_citations(answer, brief, draft)  # G229: the same call, no AI call added
        if answer.consistent:
            return PlanCheck(PlanCheckStatus.CONSISTENT), flagged
        problems = tuple(
            shorten_text(" ".join(problem.split()), Writing.PROBLEM_MAX_CHARS)
            for problem in answer.problems[: Writing.MAX_PLAN_PROBLEMS]
            if problem.strip()
        )
        notes = tuple(Finding(FindingCode.PLAN_CHECK, problem) for problem in problems)
        return PlanCheck(PlanCheckStatus.INCONSISTENT, problems), notes + flagged


def _prompt_of(brief: WriterBrief, draft: ScenarioDraft) -> ChatPrompt:
    """An evidence story is checked with its own prompt, which also carries the evidence as delimited data."""
    if brief.style is WriterStyle.EVIDENCE_STORY:
        return story_plan_check_prompt(brief, draft)
    return plan_check_prompt(brief, draft)


def _unsupported_citations(
    answer: PlanCheckAnswer, brief: WriterBrief, draft: ScenarioDraft
) -> tuple[Finding, ...]:
    """An evidence story's markers the check says their entries do not support (G229), read leniently: only
    numbers the story really cites count, given as 2 or "[2]"."""
    if brief.style is not WriterStyle.EVIDENCE_STORY or not isinstance(answer.unsupported_citations, list):
        return ()
    cited = set(markers_of(f"{draft.statement}\n{draft.risk}"))
    named = {int(n) for item in answer.unsupported_citations for n in re.findall(r"\d+", str(item))}
    if not (flagged := sorted(named & cited)):
        return ()
    message = FindingMessage.CITATION_UNSUPPORTED.format(markers=", ".join(f"[{n}]" for n in flagged))
    return (Finding(FindingCode.CITATION_UNSUPPORTED, message, tuple(flagged)),)


def _read_answer(answer: dict[str, Any]) -> tuple[PlanCheckAnswer | None, list[str]]:
    problems = answer_item_problems(PlanCheckAnswer, answer, "the reply")
    return (None, problems) if problems else (PlanCheckAnswer.model_validate(answer), [])
