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
from app.core.constants import (
    NO_REWRITE_FINDINGS,
    AiTask,
    AnswerProblem,
    FindingCode,
    FindingSeverity,
    LogEvent,
    WriterStyle,
)
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.external_intelligence.story.evidence_story_prompts import story_writer_prompt
from app.engine.scenarios.writing.ai_plan_check import PlanChecker
from app.engine.scenarios.writing.draft_cleanup import clean_draft, title_suffix
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.engine.scenarios.writing.writing_prompts import writer_prompt
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_again_with_problems, ask_ai_and_check
from app.engine.shared.names import name_match_key
from app.models.writing import Anatomy, Finding, ScenarioAnswer, ScenarioDraft, WriterBrief, WrittenScenario

log = structlog.get_logger(__name__)


class ScenarioWriter:
    def __init__(self, chat: ChatModel, attackers: tuple[str, ...]) -> None:
        """`attackers`: every library attacker's name (the clean-up and the rules look for them)."""
        self._chat = chat
        self._attackers = attackers
        self._plan_checker = PlanChecker(chat)

    @traced("writing.write")
    def write_scenario(self, brief: WriterBrief) -> WrittenScenario:
        prompt = story_writer_prompt(brief) if _is_story(brief) else writer_prompt(brief)
        systems = tuple(system.name for system in brief.supporting_systems)
        read = functools.partial(_read_draft, options=brief.entry_point_options, systems=systems)
        first = self._reviewed(
            brief, ask_ai_and_check(self._chat, AiTask.WRITE_SCENARIO, prompt, read), False
        )
        problems = [finding.message for finding in _problems(first)]
        _trace_first_draft(brief, first, problems)
        if not _asks_rewrite(first):  # none, or only final ones (G229: they never cost an AI call)
            _trace_rewrite_decision(
                brief, len(problems), {"rewritten": "no", "kept": "first, no rewrite asked"}
            )
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


def _is_story(brief: WriterBrief) -> bool:
    return brief.style is WriterStyle.EVIDENCE_STORY


def _problems(written: WrittenScenario) -> list[Finding]:
    """What a rewrite is asked to fix: every finding but a plan check that could not be made."""
    return [finding for finding in written.findings if finding.code != FindingCode.PLAN_CHECK_NOT_MADE]


def _asks_rewrite(written: WrittenScenario) -> bool:
    """The one rewrite runs for a finding it was always run for; a final one (G229) only rides along."""
    return any(finding.code not in NO_REWRITE_FINDINGS for finding in _problems(written))


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


def _read_draft(
    answer: dict[str, Any], options: tuple[str, ...], systems: tuple[str, ...] = ()
) -> tuple[ScenarioDraft | None, list[str]]:
    """The writer's answer as a draft, or the problems to re-ask with. `systems`: every supporting system the
    brief lists, each needing its one-sentence reason (G216)."""
    problems = answer_item_problems(ScenarioAnswer, answer, "the reply")
    if problems:
        return None, problems
    reply = ScenarioAnswer.model_validate(answer)
    entry_point = _offered_entry_point(reply.entry_point, options)
    if entry_point is None:
        offered = ", ".join(json.dumps(option, ensure_ascii=False) for option in options)
        return None, [AnswerProblem.ENTRY_POINT_NOT_OFFERED.format(options=offered)]
    reasons, missing = _reasons_by_system(reply.system_reasons, systems)
    if missing:
        names = ", ".join(json.dumps(name, ensure_ascii=False) for name in missing)
        return None, [AnswerProblem.SYSTEM_REASONS_MISSING.format(names=names)]
    draft = ScenarioDraft(
        title=reply.scenario_title.strip(),
        statement=reply.scenario_statement.strip(),
        risk=reply.risk_statement.strip(),
        assumptions=tuple(assumption.strip() for assumption in reply.assumptions),
        entry_point=entry_point,
        system_reasons=reasons,
        evidence_links=_evidence_links(reply.evidence_links),
        anatomy=_anatomy(reply.anatomy),
    )
    return draft, []


def _anatomy(given: object) -> Anatomy | None:
    """The scenario's parts, read leniently: an answer giving none is None, a part not given is "" (the rules
    report it: a final finding, never a re-ask, so no AI call is added)."""
    if not isinstance(given, dict):
        return None
    keys = ("target", "entry_point", "mechanism", "consequence")
    parts = {key: str(given.get(key) or "").strip() for key in keys}
    needs = given.get("preconditions")
    listed = needs if isinstance(needs, list) else []
    return Anatomy(preconditions=tuple(str(need).strip() for need in listed if str(need).strip()), **parts)


def _evidence_links(given: object) -> tuple[tuple[int, str], ...]:
    """An evidence story's (marker, claim) pairs, read leniently: a malformed one is left out, so its marker
    is reported missing (a finding, never a re-ask: G229 adds no AI call)."""
    links = given if isinstance(given, list) else []
    return tuple(
        (link["n"], str(link.get("claim") or "").strip())
        for link in links
        if isinstance(link, dict) and isinstance(link.get("n"), int) and not isinstance(link.get("n"), bool)
    )


def _reasons_by_system(
    written: dict[str, str], systems: tuple[str, ...]
) -> tuple[tuple[tuple[str, str], ...], list[str]]:
    """(each brief system with its reason, in the brief's order; the systems given none). A name is matched
    as the brief spells it, case and spacing forgiven."""
    by_key = {name_match_key(name): reason.strip() for name, reason in written.items()}
    reasons = tuple((name, by_key.get(name_match_key(name), "")) for name in systems)
    return reasons, [name for name, reason in reasons if not reason]


def _offered_entry_point(written: str, options: tuple[str, ...]) -> str | None:
    """The option the answer names, as the brief spells it (case and spacing forgiven); "" when the threat
    acts on the asset itself, whatever was written; None when it names no option."""
    if not options:
        return ""
    return next((option for option in options if name_match_key(option) == name_match_key(written)), None)
