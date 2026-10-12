"""The scenario writer: one path's scenario in at most four
AI calls, plus a re-ask for an unreadable answer:
1. write: the answer is checked for shape (fields, text, an offered entry point), with one re-ask;
2. clean, then review: the exact rules and the AI plan check, together;
3. if either found a problem, ONE rewrite in the same conversation listing every problem; clean and review it;
4. keep the draft with fewer problems, blockers counted first (the rewrite on a tie).
An unreadable first answer raises UnreadableAiAnswer or TruncatedAiAnswer (the worker saves a failure
card); an unusable rewrite keeps the first draft; an outage raises Unavailable (the job retries)."""

import functools
import json
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AiTask, AnswerProblem, FindingCode, FindingSeverity, LogEvent
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.scenarios.writing.ai_plan_check import PlanChecker
from app.engine.scenarios.writing.draft_cleanup import clean_draft, title_suffix
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.engine.scenarios.writing.writing_prompts import writer_prompt
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_again_with_problems, ask_ai_and_check
from app.engine.shared.names import name_match_key
from app.models.writing import Finding, ScenarioAnswer, ScenarioDraft, WriterBrief, WrittenScenario

log = structlog.get_logger(__name__)


class ScenarioWriter:
    def __init__(self, chat: ChatModel, attackers: tuple[str, ...]) -> None:
        """`attackers`: every library attacker's name (the clean-up and the rules look for them)."""
        self._chat = chat
        self._attackers = attackers
        self._plan_checker = PlanChecker(chat)

    @traced("writing.write")
    def write_scenario(self, brief: WriterBrief) -> WrittenScenario:
        prompt = writer_prompt(brief)
        read = functools.partial(_read_draft, options=brief.entry_point_options)
        first = self._reviewed(
            brief, ask_ai_and_check(self._chat, AiTask.WRITE_SCENARIO, prompt, read), False
        )
        problems = [finding.message for finding in _problems(first)]
        _trace_first_draft(brief, first, problems)
        if not problems:
            _trace_rewrite_decision(brief, len(problems), {"rewritten": "no", "kept": "first, no problems"})
            return first
        try:
            draft = ask_ai_again_with_problems(
                self._chat, AiTask.REWRITE_SCENARIO, prompt, first.draft.to_answer(), problems, read
            )
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.WRITER_REWRITE_UNUSABLE, error=str(exc))
            _trace_rewrite_decision(
                brief, len(problems), {"rewritten": "no", "kept": "first, rewrite unusable"}
            )
            return first
        second = self._reviewed(brief, draft, True)
        kept = second if _score(second) <= _score(first) else first
        if step_detail_enabled():
            scores = {"first_score": _score_text(first), "second_score": _score_text(second)}
            outcome = {"rewritten": "yes", **scores, "kept": "rewrite" if kept is second else "first"}
            _trace_rewrite_decision(brief, len(problems), outcome)
        return kept

    def _reviewed(self, brief: WriterBrief, draft: ScenarioDraft, rewritten: bool) -> WrittenScenario:
        """The draft cleaned, then checked by the rules and the plan check."""
        cleaned = clean_draft(draft, brief, self._attackers)
        findings, route = check_exact_rules(cleaned, brief, self._attackers)
        plan_check, notes = self._plan_checker.check_against_plan(brief, cleaned)
        qualifier = title_suffix(brief, self._attackers)
        return WrittenScenario(cleaned, (*findings, *notes), plan_check, route, rewritten, qualifier)


def _problems(written: WrittenScenario) -> list[Finding]:
    """What a rewrite is asked to fix: every finding but a plan check that could not be made."""
    return [finding for finding in written.findings if finding.code != FindingCode.PLAN_CHECK_NOT_MADE]


def _score(written: WrittenScenario) -> tuple[int, int]:
    """Fewer is better: blockers first, then every problem."""
    problems = _problems(written)
    return sum(finding.severity == FindingSeverity.BLOCKER for finding in problems), len(problems)


def _score_text(written: WrittenScenario) -> str:
    blockers, problems = _score(written)
    return f"blockers {blockers}, problems {problems}"


def _trace_first_draft(brief: WriterBrief, first: WrittenScenario, problems: list[str]) -> None:
    if not step_detail_enabled():
        return
    record_detail(
        "first draft",
        brief.threat,
        given={"attacker": brief.attacker, "asset": brief.asset_name},
        produced={
            "title": first.draft.title,
            "score": _score_text(first),
            "problems": " | ".join(problems) or "none",
        },
    )


def _trace_rewrite_decision(brief: WriterBrief, problems: int, outcome: dict[str, str]) -> None:
    record_detail("rewrite decision", brief.threat, given={"problems_to_fix": problems}, produced=outcome)


def _read_draft(answer: dict[str, Any], options: tuple[str, ...]) -> tuple[ScenarioDraft | None, list[str]]:
    """The writer's answer as a draft, or the problems to re-ask with."""
    problems = answer_item_problems(ScenarioAnswer, answer, "the reply")
    if problems:
        return None, problems
    reply = ScenarioAnswer.model_validate(answer)
    entry_point = _offered_entry_point(reply.entry_point, options)
    if entry_point is None:
        offered = ", ".join(json.dumps(option, ensure_ascii=False) for option in options)
        return None, [AnswerProblem.ENTRY_POINT_NOT_OFFERED.format(options=offered)]
    draft = ScenarioDraft(
        title=reply.scenario_title.strip(),
        statement=reply.scenario_statement.strip(),
        risk=reply.risk_statement.strip(),
        assumptions=tuple(assumption.strip() for assumption in reply.assumptions),
        entry_point=entry_point,
    )
    return draft, []


def _offered_entry_point(written: str, options: tuple[str, ...]) -> str | None:
    """The option the answer names, as the brief spells it (case and spacing forgiven); "" when the threat
    acts on the asset itself, whatever was written; None when it names no option."""
    if not options:
        return ""
    return next((option for option in options if name_match_key(option) == name_match_key(written)), None)
