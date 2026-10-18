"""Writing one scenario per attack path: the brief built by code, the writer and reviewer prompts
(prompts/writer.txt, prompts/reviewer.txt), the exact checks, the card stored and the duplicate check."""

import dataclasses
import functools
import itertools
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import (
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    STORY_FINDING_SEVERITIES,
    ActorRole,
    AiTask,
    AnswerProblem,
    ContextProperties,
    Decision,
    ErrorCode,
    ErrorMessage,
    EvidenceBlock,
    EvidenceFact,
    EvidenceMode,
    EvidenceSearchFailure,
    FindingCode,
    FindingMessage,
    FindingSeverity,
    IntelKind,
    LibraryStatus,
    LogEvent,
    PathProblem,
    PlanCheckStatus,
    Route,
    RunKind,
    ScenarioStatus,
    Status,
    StoryFindingCode,
    StoryFindingMessage,
    StoryLimits,
    StrideCategory,
    TextSafety,
    WriterStyle,
    Writing,
)
from app.core.exceptions import PathNotWritable, Unavailable
from app.core.redaction import redact
from app.domain.external_intelligence.injection_patterns import ECHO_PATTERNS
from app.domain.external_intelligence.text_cleaner import ID_IN_TEXT
from app.domain.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.domain.scenario.plan import attacker_unsupported, raw_system_facts
from app.domain.shared.ask_ai import (
    ChatPrompt,
    answer_item_problems,
    ask_ai_and_check,
)
from app.domain.shared.names import (
    find_name_mentions,
    is_same_name,
    name_match_key,
    shorten_text,
    threat_name_without_code,
)
from app.domain.shared.prompt_redaction import facts_safe_for_prompt
from app.models.asset_context import FrozenContext
from app.models.external_intelligence.evidence_view import markers_of
from app.models.library import ThreatLibrary
from app.models.scenario.write import (
    BriefSystem,
    Finding,
    LiveLibrary,
    PathFailure,
    PlanCheck,
    PlanCheckAnswer,
    ScenarioAnswer,
    ScenarioDraft,
    WriterBrief,
    WrittenScenario,
)

log = structlog.get_logger(__name__)

# --- what the writing shapes mean


def live_library_of(library: ThreatLibrary) -> LiveLibrary:
    """The active ids of `library`."""
    return LiveLibrary(
        frozenset(threat.catalogue_id for threat in library.threats),
        frozenset(threat.type_id for threat in library.threats),
        frozenset(actor.actor_id for actor in library.actors),
    )


def brief_evidence_mode(brief: WriterBrief) -> EvidenceMode:
    """Source-documented when the brief carries evidence, else inferred."""
    return EvidenceMode.SOURCE_DOCUMENTED if brief.evidence else EvidenceMode.INFERRED


def brief_entry_point_options(brief: WriterBrief) -> tuple[str, ...]:
    """The threat's systems; none = the attack reaches the asset itself."""
    return tuple(system["name"] for system in brief.systems)


def draft_answer(draft: ScenarioDraft) -> dict[str, Any]:
    """The draft as the writer's answer reads, for the reviewer."""
    answer: dict[str, Any] = {
        "scenario_title": draft.title,
        "scenario_statement": draft.statement,
        "risk_statement": draft.risk,
        "assumptions": list(draft.assumptions),
        "entry_point": draft.entry_point,
    }
    if draft.evidence_links:
        answer["evidence_links"] = [{"n": n, "claim": claim} for n, claim in draft.evidence_links]
    if draft.why_applies:
        answer["why_applies"] = draft.why_applies
    return answer | ({"system_reasons": dict(draft.system_reasons)} if draft.system_reasons else {})


def finding_severity(finding: Finding) -> FindingSeverity:
    """How serious the finding's code is."""
    if isinstance(finding.code, StoryFindingCode):
        return STORY_FINDING_SEVERITIES[finding.code]
    return FINDING_SEVERITIES[finding.code]


def finding_record(finding: Finding) -> dict[str, str]:
    """The finding as the scenario stores it."""
    return {"code": finding.code, "severity": finding_severity(finding), "message": finding.message}


def plan_check_record(check: PlanCheck) -> dict[str, Any]:
    """The check as stored: a check not made records no verdict, never a pass nobody judged."""
    made = check.status is not PlanCheckStatus.UNCHECKED
    verdicts = {
        "same_threat": check.same_threat if made else None,
        "same_impact": check.same_impact if made else None,
    }
    reviewed = {"problems": list(check.problems), "unsupported": list(check.unsupported)}
    return {"status": check.status, **reviewed, **verdicts}


def is_blocked(written: WrittenScenario) -> bool:
    """True when any finding is a blocker."""
    return any(finding_severity(finding) == FindingSeverity.BLOCKER for finding in written.findings)


def blocking_codes(written: WrittenScenario) -> list[str]:
    """The codes of the findings that block it, sorted, each once."""
    return sorted({f.code for f in written.findings if finding_severity(f) == FindingSeverity.BLOCKER})


def is_final(written: WrittenScenario) -> bool:
    """Blocked by a rule no new attempt is asked to fix: its path is given up at once."""
    return any(finding.code in FINAL_FINDINGS for finding in written.findings)


def blocking_finding_code(written: WrittenScenario) -> str:
    """The code of the finding that blocks it, a final one first ("": none)."""
    blockers = [f for f in written.findings if finding_severity(f) == FindingSeverity.BLOCKER]
    first = min(blockers, key=lambda finding: finding.code not in FINAL_FINDINGS, default=None)
    return str(first.code) if first else ""


# --- the writer's and the reviewer's prompts

#: Stored on every scenario it writes.
WRITER_PROMPT_VERSION = "scenario writer-1"
_PROMPTS = Path(__file__).with_name("prompts")
WRITER_SYSTEM_PROMPT = (_PROMPTS / "writer.txt").read_text(encoding="utf-8")
PLAN_CHECK_SYSTEM_PROMPT = (_PROMPTS / "reviewer.txt").read_text(encoding="utf-8")
#: With intelligence off: no evidence is fabricated or implied.
NO_EVIDENCE = (
    "\nNo EVIDENCE is given: return evidence_links as [], cite nothing and tell no real-world event.\n"
)
_NO_EVIDENCE_REVIEW = (
    "\nNo EVIDENCE is given: any [n] marker or real-world event breaks rule 8; unsupported_citations is [].\n"
)
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)),
    re.IGNORECASE,
)
#: Facts true of a technique in general, never of who used it: kept on the card, never shown to the AI.
_GENERAL_FACTS = tuple(
    str(words).split("{")[0] for words in (EvidenceFact.TACTICS, EvidenceFact.MITIGATED_BY)
)


def writer_prompt(brief: WriterBrief) -> ChatPrompt:
    """The writer's system prompt with the configured word limits; the BRIEF, then the evidence."""
    if _is_story(brief):
        return with_word_limits(
            WRITER_SYSTEM_PROMPT
        ), f"BRIEF:\n{_brief_text(brief)}\n{evidence_block(brief)}"
    return with_word_limits(WRITER_SYSTEM_PROMPT) + NO_EVIDENCE, f"BRIEF:\n{_brief_text(brief)}"


def plan_check_prompt(brief: WriterBrief, draft: ScenarioDraft) -> ChatPrompt:
    """The reviewer's PLAN (the writer's BRIEF plus the critical service), the evidence and the scenario."""
    plan = _brief_record(brief) | {"critical_service": brief.critical_service}
    scenario = f"SCENARIO:\n{_as_json(draft_answer(draft))}"
    if _is_story(brief):
        return PLAN_CHECK_SYSTEM_PROMPT, f"PLAN:\n{_as_json(plan)}\n{evidence_block(brief)}\n{scenario}"
    return PLAN_CHECK_SYSTEM_PROMPT + _NO_EVIDENCE_REVIEW, f"PLAN:\n{_as_json(plan)}\n{scenario}"


def _brief_record(brief: WriterBrief) -> dict[str, Any]:
    """The brief as the writer reads it: what the scenario may take from."""
    record: dict[str, Any] = {
        "asset": brief.asset,
        "category": brief.category,
        "attacker": brief.attacker,
        "threat": {
            "threat_type": brief.threat_type,
            "threat": brief.threat,
            "why_it_applies": brief.why_it_applies,
        },
        "systems": list(brief.systems),
        "entry_point_options": list(brief_entry_point_options(brief)),
        "supporting_systems": [
            {"name": system.name, "applicable": "yes" if system.applicable else "no"}
            for system in brief.supporting_systems
        ],
    }
    if brief.other_scenarios:
        record["other_scenarios"] = list(brief.other_scenarios)
    return record


def _brief_text(brief: WriterBrief) -> str:
    """The brief as JSON."""
    return _as_json(_brief_record(brief))


def with_word_limits(template: str) -> str:
    """`template` with THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT in its slots: "150 to 200"."""
    settings = get_settings()
    return template.replace(Writing.SCENARIO_WORDS_SLOT, _spoken(settings.scenario_words)).replace(
        Writing.RISK_WORDS_SLOT, _spoken(settings.risk_words)
    )


def evidence_block(brief: WriterBrief) -> str:
    """The evidence between the block's delimiters: number, what each entry is about, its stated facts and
    applicability; never a ref, link or source, so none can leak."""
    entries = [
        {"n": number, **_subject(item), "facts": _safe_facts(_stated_facts(item))}
        | ({"applicability": str(item["applicability"])} if item.get("applicability") else {})
        for number, item in enumerate(brief.evidence, start=1)
    ]
    body = json.dumps(
        {"evidence_mode": str(brief_evidence_mode(brief)), "evidence": entries}, ensure_ascii=False
    )
    return f"EVIDENCE (untrusted data):\n{EvidenceBlock.BEGIN}\n{body}\n{EvidenceBlock.END}"


def _stated_facts(entry: dict[str, Any]) -> list[str]:
    """What the entry states: its facts but the general ones."""
    return [fact for fact in entry.get("facts") or () if not fact.strip().startswith(_GENERAL_FACTS)]


def _subject(item: dict[str, Any]) -> dict[str, str]:
    """What the entry is about, under the word its facts use for it; none when its title is cleaned away."""
    title = _safe_facts([str(item.get("title") or "")])
    key = "technique" if item.get("kind") == IntelKind.TECHNIQUE else "about"
    return {key: title[0]} if title else {}


def _safe_facts(facts: list[str]) -> list[str]:
    """Each fact redacted, without ids, links or block look-alikes; dropped when it reads as an order."""
    safe = []
    sanitiser = UntrustedTextSanitiser()
    for fact in facts:
        text = _LOOK_ALIKES.sub(" ", _without_ids(redact(fact)))
        cleaned = sanitiser.sanitise(" ".join(text.split()), TextSafety.MAX_FACT_CHARS)
        if not cleaned.unsafe and cleaned.text:
            safe.append(cleaned.text)
    return safe


def _without_ids(text: str) -> str:
    """`text` without any public number or link."""
    return " ".join(_URL.sub("", ID_IN_TEXT.sub("", text)).replace("()", "").split())


def _spoken(limits: tuple[int, int]) -> str:
    """A word range as the prompt says it: "300 to 400"."""
    return f"{limits[0]} to {limits[1]}"


def _is_story(brief: WriterBrief) -> bool:
    """Whether the brief is written as an evidence story."""
    return brief.style is WriterStyle.EVIDENCE_STORY


def _as_json(value: dict[str, Any]) -> str:
    """A value as JSON, non-ASCII kept."""
    return json.dumps(value, ensure_ascii=False, default=str)


# --- the brief, built by code: no AI call, no database id, every text redacted

#: The joiners of a list of systems, before and after one of its names (", ", " and ", ", or ").
_LIST_BEFORE = re.compile(r"(?:,\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+)$", re.IGNORECASE)
_LIST_AFTER = re.compile(r",\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
#: The asset facts under the names the brief shows; every other fact keeps its own name.
_ASSET_FACT_NAMES = {
    "cii_asset_description": "description",
    "asset_type": "type",
    "asset_priority": "priority",
}


def build_brief(
    threats: dict[str, dict[str, Any]],
    path: dict[str, Any],
    context: FrozenContext,
    budget: int,
    live: LiveLibrary,
    other_scenarios: tuple[str, ...] = (),
    style: WriterStyle = WriterStyle.ORIGINAL,
) -> WriterBrief:
    """The brief for `path`: its asset's and systems' facts within `budget` characters together, the acting
    attacker and why the threat applies; `other_scenarios`: the versions a regenerate must differ from.
    Raises PathNotWritable for a path missing a fact or whose threat or attacker was retired."""
    threat = _path_threat(threats, path)
    _check_still_live(threat, path["path_id"], live)
    facts = [_named_facts(context.asset["name"], _asset_facts(context, style))] + [
        _named_facts(system["name"], raw_system_facts(system)) for system in _path_systems(path, context)
    ]
    asset, *systems = _cut_to_fit(facts, budget)
    return WriterBrief(
        asset=asset,
        asset_name=asset["name"],
        critical_service=_critical_service(context),
        category=StrideCategory(path["category"]),
        attacker=threat["actors"][0]["name"],
        threat_type=threat_name_without_code(threat["type"]["name"]),
        threat=threat_name_without_code(threat["name"]),
        why_it_applies=redact(_reason_on_path(_kind_reason(threat, path), path, context)),
        systems=tuple(systems),
        other_systems=tuple(
            redact(system["name"]) for system in context.systems if system["id"] not in path["systems"]
        ),
        other_scenarios=_newest_within(_without_citations(other_scenarios, style), budget // 4),
        style=style,
        supporting_systems=tuple(
            BriefSystem(system["id"], redact(system["name"]), system["id"] in path["systems"])
            for system in context.systems
        ),
        evidence=tuple(threat.get("evidence") or ()) if style is WriterStyle.EVIDENCE_STORY else (),
    )


def evidence_problem(threat: dict[str, Any]) -> PathFailure | Unavailable | None:
    """Why this threat's evidence story cannot be written (None: its evidence is there), before any AI call:
    a search that could not be made is an outage (retried); one that kept nothing fails the path for good."""
    search = threat.get("intel_search")
    if search is None or search.get("failure") is not None or search.get("snapshot_id") is None:
        failure = (search or {}).get("failure") or EvidenceSearchFailure.NO_SNAPSHOT
        return Unavailable(ErrorMessage.EVIDENCE_SEARCH_UNAVAILABLE.format(reason=failure))
    if not threat.get("evidence"):
        message = ErrorMessage.EVIDENCE_NOT_FOUND.format(searches=1 + len(search.get("attempts") or ()))
        return PathFailure(ErrorCode.EVIDENCE_NOT_FOUND, message, final=True)
    return None


def _kind_reason(threat: dict[str, Any], path: dict[str, Any]) -> str:
    """Why the threat applies as the kind the path is written as, else the threat's own reason."""
    return str((threat.get("reasons") or {}).get(path["category"]) or threat["reason"])


def _asset_facts(context: FrozenContext, style: WriterStyle) -> dict[str, Any]:
    """The asset's own facts under the brief's names, the organisation's under one background key; an
    evidence story also reads the deployment's country."""
    own, organisation = context.own_and_organisation_facts()
    facts = {_ASSET_FACT_NAMES.get(key, key): value for key, value in own.items()}
    if style is WriterStyle.EVIDENCE_STORY:
        facts[ContextProperties.COUNTRY_KEY] = get_settings().context_country
    background = "; ".join(str(value) for value in organisation.values() if value)
    return facts | ({ContextProperties.ORGANISATION_BRIEF_KEY: background} if background else {})


def _reason_on_path(reason: str, path: dict[str, Any], context: FrozenContext) -> str:
    """The relevance check's reason without the names of the systems this path is not on (each has its own
    path), so the scenario never tells another system's story."""
    names = [system["name"] for system in context.systems]
    spans = sorted(
        span
        for system in context.systems
        if system["id"] not in path["systems"]
        for span in find_name_mentions(system["name"], reason)
    )
    edge = len(reason) + 1
    for start, end in reversed(spans):  # from the end, so earlier spans keep their place; overlaps skipped
        if end <= edge:
            start -= 4 if reason[max(start - 4, 0) : start].lower() == "the " else 0  # "the Historian"
            reason, edge = _without_name(reason, start, end, names), start
    repeated = rf"{Writing.OTHER_SYSTEM}(?:,? (?:and |or )?{Writing.OTHER_SYSTEM})+"
    return re.sub(repeated, Writing.OTHER_SYSTEMS, reason)


def _without_name(reason: str, start: int, end: int, names: list[str]) -> str:
    """`reason` without the system name at [start, end): one item of a list goes with its joiner ("A, B and
    C" without B: "A and C"); a name standing alone becomes the placeholder."""
    head, tail = reason[:start], reason[end:]
    joiner = _LIST_BEFORE.search(head)
    if joiner and _ends_with_name(head[: joiner.start()], names):
        return head[: joiner.start()] + tail
    joiner = _LIST_AFTER.match(tail)
    if joiner and _starts_with_name(tail[joiner.end() :], names):
        return head + tail[joiner.end() :]
    return head + Writing.OTHER_SYSTEM + tail


def _ends_with_name(text: str, names: list[str]) -> bool:
    """Whether `text` ends with a system's name or the placeholder."""
    folded = text.rstrip().casefold()
    return any(folded.endswith(name.casefold()) for name in (*names, Writing.OTHER_SYSTEM))


def _starts_with_name(text: str, names: list[str]) -> bool:
    """Whether `text` starts with a system's name or the placeholder."""
    folded = text.casefold().removeprefix("the ")
    return any(folded.startswith(name.casefold()) for name in (*names, Writing.OTHER_SYSTEM))


def _path_systems(path: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The path's own systems as the run froze them; PathNotWritable when one is not in the run."""
    by_id = {system["id"]: system for system in context.systems}
    if any(system_id not in by_id for system_id in path["systems"]):
        raise PathNotWritable(path["path_id"], PathProblem.SYSTEM_NOT_IN_RUN)
    return [by_id[system_id] for system_id in path["systems"]]


def _critical_service(context: FrozenContext) -> str | None:
    """The critical service(s) the asset supports, redacted."""
    service = context.asset_context.get("critical_service")
    return redact(service) if service else None


def _without_citations(statements: tuple[str, ...], style: WriterStyle) -> tuple[str, ...]:
    """The versions as the writer of `style` may read them: the original never sees a cited sentence."""
    if style is WriterStyle.EVIDENCE_STORY:
        return statements
    kept = (" ".join(s for s in _SENTENCE_END.split(st) if not markers_of(s)) for st in statements)
    return tuple(text for text in kept if text)


def _newest_within(statements: tuple[str, ...], budget: int) -> tuple[str, ...]:
    """The newest versions (given oldest first) within `budget` characters in all, redacted, oldest first."""
    kept: list[str] = []
    used = 0
    for statement in reversed(statements):
        text = redact(statement)
        used += len(text)
        if used > budget:
            break
        kept.append(text)
    return tuple(reversed(kept))


def _path_threat(threats: dict[str, dict[str, Any]], path: dict[str, Any]) -> dict[str, Any]:
    """The path's one threat, checked whole before any AI call."""
    steps = path.get("steps") or []
    threat = threats.get(steps[0]) if len(steps) == 1 else None
    if threat is None:
        raise PathNotWritable(path["path_id"], PathProblem.NOT_ONE_THREAT)
    if path.get("category") not in StrideCategory:
        raise PathNotWritable(path["path_id"], PathProblem.CATEGORY_UNKNOWN)
    if not (threat["type"]["name"] or "").strip() or not (threat["name"] or "").strip():
        raise PathNotWritable(path["path_id"], PathProblem.THREAT_UNNAMED)
    if not threat["actors"] or threat["actors"][0]["role"] != ActorRole.ACTING:
        raise PathNotWritable(path["path_id"], PathProblem.NO_ACTING_ATTACKER)
    if attacker_unsupported(threat.get("attacker_check"), threat["actors"][0]):  # never a forced attribution
        raise PathNotWritable(path["path_id"], PathProblem.ATTACKER_UNSUPPORTED)
    return threat


def _check_still_live(threat: dict[str, Any], path_id: str, live: LiveLibrary) -> None:
    """A library threat by its own record, an AI-proposed one by its library type; the acting attacker too."""
    if threat["library_id"] is not None:
        retired = threat["library_id"] not in live.threat_ids
    else:
        retired = threat["type"]["id"] not in live.type_ids
    if retired:
        raise PathNotWritable(path_id, PathProblem.THREAT_RETIRED, ErrorCode.LIBRARY_RECORD_RETIRED)
    if threat["actors"][0]["id"] not in live.actor_ids:
        raise PathNotWritable(path_id, PathProblem.ATTACKER_RETIRED, ErrorCode.LIBRARY_RECORD_RETIRED)


def _named_facts(name: str, facts: dict[str, Any]) -> dict[str, Any]:
    """A part's name first, then its recorded facts cleaned for a prompt; the name is never dropped."""
    return {"name": redact(" ".join(str(name).split())), **facts_safe_for_prompt(facts | {"name": None})}


def _json_length(facts: dict[str, Any]) -> int:
    """How many characters `facts` take as JSON."""
    return len(json.dumps(facts, ensure_ascii=False, default=str))


def _cut_to_fit(parts: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """`parts` within `limit` JSON characters together: the longest text fact (never a name) is cut first,
    so each part stays one valid JSON object."""
    # ponytail: lists (technology, platforms) are never cut: they hold the platform's short option names.
    kept = [dict(part) for part in parts]
    while (over := sum(map(_json_length, kept)) - limit) > 0:
        texts = [
            (len(value), index, key)
            for index, part in enumerate(kept)
            for key, value in part.items()
            if key != "name" and isinstance(value, str)
        ]
        length, index, key = max(texts, default=(0, 0, ""))
        if length <= 1:
            break
        kept[index][key] = shorten_text(kept[index][key], max(length - over, 1))
    return kept


# --- the exact checks: safety and data integrity only; meaning is the reviewer's

#: The planner's aliases and slots (SYS1, THR7): never in a brief, so one in a scenario was made up.
_INTERNAL_LABEL = re.compile(r"\b(?:SYS|THR)\d+\b")
#: A public advisory number: CVE, CISA ICS advisory (ICSA, ICSMA), GitHub (GHSA), Microsoft bulletin, CERT/CC.
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3})\b|\bVU#\d+",
    re.IGNORECASE,
)
_ECHO_SANITISER = UntrustedTextSanitiser(ECHO_PATTERNS, (), ())


def check_exact_rules(draft: ScenarioDraft, brief: WriterBrief) -> tuple[Finding, ...]:
    """Every exact finding in the texts the card serves: made-up labels, advisory ids the brief did not give
    (any while intelligence is off), unknown markers and instructions echoed from untrusted evidence."""
    reasons = (reason for _, reason in draft.system_reasons)
    text = "\n".join(
        (draft.title, draft.statement, draft.risk, *draft.assumptions, draft.why_applies, *reasons)
    )
    given = _brief_text(brief).casefold()  # a label or number the brief gives was supplied, not made up
    advisory_given = given if brief.style is WriterStyle.EVIDENCE_STORY else ""
    findings = []
    if labels := _unsupplied(_INTERNAL_LABEL, text, given):
        findings.append(Finding(FindingCode.UNKNOWN_ID, FindingMessage.UNKNOWN_ID.format(labels=labels)))
    if advisories := _unsupplied(_ADVISORY_ID, text, advisory_given):
        message = FindingMessage.UNCITED_ADVISORY_ID.format(ids=advisories)
        findings.append(Finding(FindingCode.UNCITED_ADVISORY_ID, message))
    count = len(brief.evidence) if brief.style is WriterStyle.EVIDENCE_STORY else 0
    return (*findings, *_marker_findings(text, count), *echo_findings(text))


def echo_findings(text: str) -> list[Finding]:
    """A draft repeating an instruction aimed at an AI system is blocked: the evidence is untrusted."""
    if _ECHO_SANITISER.sanitise(text, len(text) + 1).unsafe:
        return [Finding(StoryFindingCode.INJECTION_ECHO, StoryFindingMessage.INJECTION_ECHO)]
    return []


def _marker_findings(text: str, count: int) -> list[Finding]:
    """Every marker must name an entry 1..count; with intelligence off (count 0) any marker cites nothing."""
    unknown = ", ".join(dict.fromkeys(f"[{n}]" for n in markers_of(text) if not 1 <= n <= count))
    if not unknown:
        return []
    if count:
        message = StoryFindingMessage.UNKNOWN_MARKER.format(markers=unknown, count=count)
    else:
        message = StoryFindingMessage.NO_INTELLIGENCE_MARKER.format(markers=unknown)
    return [Finding(StoryFindingCode.UNKNOWN_MARKER, message)]


def _unsupplied(pattern: re.Pattern[str], text: str, given: str) -> str:
    """Each match the brief did not supply, once, in order, joined for a message ('' when none)."""
    found = (match[0] for match in pattern.finditer(text) if match[0].casefold() not in given)
    return ", ".join(dict.fromkeys(found))


# --- the reviewer: one AI call judging meaning against the plan


def check_against_plan(
    chat: ChatModel, brief: WriterBrief, draft: ScenarioDraft
) -> tuple[PlanCheck, tuple[Finding, ...]]:
    """The reviewer's check and its findings: a note per broken rule, a blocker when the threat or impact
    changed, a warning when its answer stayed unusable (the scenario is still saved, flagged)."""
    try:
        prompt = plan_check_prompt(brief, draft)
        answer: PlanCheckAnswer = ask_ai_and_check(chat, AiTask.PLAN_CHECK, prompt, _read_plan_check)
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(LogEvent.WRITER_PLAN_CHECK_NOT_MADE, error=str(exc))
        reason = shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS)
        warning = Finding(
            FindingCode.PLAN_CHECK_NOT_MADE, FindingMessage.PLAN_CHECK_NOT_MADE.format(reason=reason)
        )
        return PlanCheck(PlanCheckStatus.UNCHECKED), (warning,)
    problems = _broken_rules(answer)
    status = PlanCheckStatus.INCONSISTENT if problems else PlanCheckStatus.CONSISTENT
    check = PlanCheck(
        status,
        problems,
        same_threat=answer.same_threat,
        same_impact=answer.same_impact,
        unsupported=_unsupported_citations(answer, brief, draft),
    )
    notes = tuple(Finding(FindingCode.PLAN_CHECK, problem) for problem in problems)
    return check, notes + _mismatch(answer)


def _broken_rules(answer: PlanCheckAnswer) -> tuple[str, ...]:
    """Each rule the reviewer says is broken, as "Rule n: <its words>", cut to a note's size."""
    broken = (
        f"Rule {number.strip()}: {verdict.strip()[len('broken') :].lstrip(' :-')}"
        for number, verdict in answer.rules.items()
        if verdict.strip().casefold().startswith("broken")
    )
    return tuple(shorten_text(problem, Writing.PROBLEM_MAX_CHARS) for problem in broken)[
        : Writing.MAX_PLAN_PROBLEMS
    ]


def _mismatch(answer: PlanCheckAnswer) -> tuple[Finding, ...]:
    """A statement of another threat, or a risk of another impact: a blocker a new attempt may clear."""
    wrong = [
        part for part, same in (("threat", answer.same_threat), ("impact", answer.same_impact)) if not same
    ]
    if not wrong:
        return ()
    message = FindingMessage.SCENARIO_MISMATCH.format(parts=" and ".join(wrong))
    return (Finding(FindingCode.SCENARIO_MISMATCH, message),)


def _unsupported_citations(
    answer: PlanCheckAnswer, brief: WriterBrief, draft: ScenarioDraft
) -> tuple[int, ...]:
    """The cited markers the reviewer says their entries do not support (2 or "[2]"); none if no evidence."""
    if brief.style is not WriterStyle.EVIDENCE_STORY or not isinstance(answer.unsupported_citations, list):
        return ()
    cited = set(markers_of(f"{draft.statement}\n{draft.risk}"))
    named = {int(n) for item in answer.unsupported_citations for n in re.findall(r"\d+", str(item))}
    return tuple(sorted(named & cited))


def _read_plan_check(answer: dict[str, Any]) -> tuple[PlanCheckAnswer | None, list[str]]:
    """The reviewer's answer, or the problems to re-ask with."""
    problems = answer_item_problems(PlanCheckAnswer, answer, "the reply")
    return (None, problems) if problems else (PlanCheckAnswer.model_validate(answer), [])


# --- the writer: write, check, review

#: Each sentence with the space after it.
_SENTENCE = re.compile(r"[^.!?]*(?:[.!?]+|$)\s*")


def write_scenario(chat: ChatModel, brief: WriterBrief) -> WrittenScenario:
    """The scenario for `brief`, written once, then checked and reviewed. An unreadable answer raises; an
    outage raises Unavailable."""
    prompt = writer_prompt(brief)
    systems = tuple(system.name for system in brief.supporting_systems)
    read = functools.partial(_read_draft, options=brief_entry_point_options(brief), systems=systems)
    return _reviewed(chat, brief, ask_ai_and_check(chat, AiTask.WRITE_SCENARIO, prompt, read))


def _reviewed(chat: ChatModel, brief: WriterBrief, draft: ScenarioDraft) -> WrittenScenario:
    """The draft checked by the safety rules, then by the reviewer unless they block it, its unsupported
    citations taken out; an evidence story citing nothing is blocked."""
    findings = check_exact_rules(draft, brief)
    if any(finding_severity(finding) == FindingSeverity.BLOCKER for finding in findings):
        check, notes = PlanCheck(PlanCheckStatus.UNCHECKED), ()  # no verdict could clear an exact blocker
    else:
        check, notes = check_against_plan(chat, brief, draft)
    if check.unsupported:
        draft = _without_sentences_citing(draft, set(check.unsupported))
        markers = ", ".join(f"[{n}]" for n in check.unsupported)
        notes += (
            Finding(FindingCode.CITATION_REMOVED, FindingMessage.CITATION_REMOVED.format(markers=markers)),
        )
    if brief.style is WriterStyle.EVIDENCE_STORY and not markers_of(f"{draft.statement}\n{draft.risk}"):
        message = FindingMessage.NO_EVIDENCE_CITED.format(count=len(brief.evidence))
        notes += (Finding(FindingCode.NO_EVIDENCE_CITED, message),)
    return WrittenScenario(draft, (*findings, *notes), check, Route.STANDALONE, brief.threat)


def _without_sentences_citing(draft: ScenarioDraft, numbers: set[int]) -> ScenarioDraft:
    """The statement and risk without each sentence citing an unsupported source, marker and claim alike."""

    def without_cited_sentences(text: str) -> str:
        """`text` without the sentences citing an unsupported source."""
        sentences = _SENTENCE.findall(text)
        return "".join(part for part in sentences if not numbers & set(markers_of(part))).strip()

    links = tuple(link for link in draft.evidence_links if link[0] not in numbers)
    return dataclasses.replace(
        draft,
        statement=without_cited_sentences(draft.statement),
        risk=without_cited_sentences(draft.risk),
        evidence_links=links,
    )


def _read_draft(
    answer: dict[str, Any], options: tuple[str, ...], systems: tuple[str, ...]
) -> tuple[ScenarioDraft | None, list[str]]:
    """The writer's answer as a draft, or the problems to re-ask with: an offered entry point and a reason
    for every supporting system the brief lists."""
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
        why_applies=" ".join((reply.why_applies or "").split()),
    )
    return draft, []


def _evidence_links(given: object) -> tuple[tuple[int, str], ...]:
    """The (marker, claim) pairs, read leniently: a malformed one is left out."""
    links = given if isinstance(given, list) else []
    return tuple(
        (link["n"], str(link.get("claim") or "").strip())
        for link in links
        if isinstance(link, dict) and isinstance(link.get("n"), int) and not isinstance(link.get("n"), bool)
    )


def _reasons_by_system(
    written: dict[str, str], systems: tuple[str, ...]
) -> tuple[tuple[tuple[str, str], ...], list[str]]:
    """(each brief system with its reason, in the brief's order; the systems given none); a name matches in
    any of its forms ("DCS" for "Distributed Control System (DCS)")."""
    reasons = tuple(
        (name, next((reason.strip() for given, reason in written.items() if is_same_name(name, given)), ""))
        for name in systems
    )
    return reasons, [name for name, reason in reasons if not reason]


def _offered_entry_point(written: str, options: tuple[str, ...]) -> str | None:
    """The option the answer names, in any of its forms; "" when the threat acts on the asset itself; None
    when it names no option."""
    if not options:
        return ""
    return next((option for option in options if is_same_name(option, written)), None)


# --- the card stored for one path: the written (or blocked) scenario, or its failure

#: A path's first scenario is version 1; a regenerated one is the next version of its path.
_FIRST_VERSION = 1
_CITATION = re.compile(r"(\s?)\[(\d+(?:\s*,\s*\d+)*)\]")


def scenario_id(session_id: str, path_id: str, version: int) -> str:
    """The same run, path and version always give the same id, so a repeated delivery saves once."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tsg:{session_id}:{path_id}:{version}"))


def title_candidates(title: str, qualifier: str) -> Iterator[str]:
    """`title`, then `title (qualifier)`, then `title (2)`, `(3)` ... for when another scenario took each."""
    yield title
    if qualifier and name_match_key(qualifier) not in name_match_key(title):
        yield f"{title} ({qualifier})"
    for number in itertools.count(2):
        yield f"{title} ({number})"


def written_record(
    run: dict[str, Any],
    path: dict[str, Any],
    threat: dict[str, Any],
    brief: WriterBrief,
    written: WrittenScenario,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A written scenario (done, its controls queued), or one kept for audit only (blocked: an evidence story
    citing nothing is never done). `replaces`: the version a regenerate follows ({_id, version})."""
    draft, now = written.draft, datetime.now(UTC)
    statement, risk, evidence = _cited(brief, draft)
    unproven = brief.style is WriterStyle.EVIDENCE_STORY and not evidence
    status = ScenarioStatus.BLOCKED if is_blocked(written) or unproven else ScenarioStatus.DONE
    content = {
        "title": draft.title,
        "statement": statement,
        "risk_statement": risk,
        "why_applies": draft.why_applies or None,
        "assumptions": list(draft.assumptions),
        **_threat_content(path, threat),
        **_systems_content(run, path, brief, draft),
        "route": {"status": written.route, "note": None},
        "prompt_version": _prompt_version_of(brief.style),
    } | _evidence_content(brief, threat, evidence)
    record = _record_fields(run, path, status, now, replaces) | {
        "title_key": name_match_key(draft.title),
        "content": content,
        "findings": [finding_record(finding) for finding in written.findings],
        "plan_check": plan_check_record(written.plan_check),
        "rewritten": False,  # stored field: scenarios are never rewritten
    }
    if status == ScenarioStatus.DONE:
        record["controls"] = {"status": Status.QUEUED, "attempts": 0, "queued_at": now}
    return record


def _prompt_version_of(style: WriterStyle) -> str:
    """Which prompts wrote a scenario: the evidence story's or the original writer's."""
    return StoryLimits.PROMPT_VERSION if style is WriterStyle.EVIDENCE_STORY else WRITER_PROMPT_VERSION


def _cited(brief: WriterBrief, draft: ScenarioDraft) -> tuple[str, str, list[dict[str, Any]]]:
    """An evidence story's statement and risk with citations renumbered from [1], and what they cite."""
    if brief.style is not WriterStyle.EVIDENCE_STORY:
        return draft.statement, draft.risk, []
    evidence = [dict(item) for item in brief.evidence]
    return renumber_citations(draft.statement, draft.risk, evidence, dict(draft.evidence_links))


def _evidence_content(
    brief: WriterBrief, threat: dict[str, Any], cited: list[dict[str, Any]]
) -> dict[str, Any]:
    """An evidence story's proof: each cited entry under its number, the mode, how many vulnerabilities apply
    and the search's audit; nothing on an original-style scenario."""
    if brief.style is not WriterStyle.EVIDENCE_STORY:
        return {}
    applies = Counter(str(item["applicability"]) for item in cited if item.get("applicability"))
    return {
        "evidence": cited,
        "evidence_mode": brief_evidence_mode(brief),
        "applicability": dict(applies),
        "intel_search": threat.get("intel_search"),
    }


def renumber_citations(
    statement: str, risk: str, evidence: list[dict[str, Any]], claims: Mapping[int, str] | None = None
) -> tuple[str, str, list[dict[str, Any]]]:
    """(statement, risk, the cited entries with their new `n`): markers renumbered 1..k in order of first
    citation, one naming no entry dropped; `claims`: the writer's claim per old number, kept as `supports`."""
    known = dict(enumerate(evidence, start=1))
    new_number: dict[int, int] = {}

    def renumbered_marker(match: re.Match[str]) -> str:
        """One citation marker renumbered, or dropped when it names no entry."""
        numbers: list[int] = []
        for old in (int(n) for n in re.split(r"\s*,\s*", match.group(2))):
            if old in known:
                number = new_number.setdefault(old, len(new_number) + 1)
                numbers += [number] if number not in numbers else []
        return f"{match.group(1)}[{', '.join(map(str, numbers))}]" if numbers else ""

    statement, risk = (
        _CITATION.sub(renumbered_marker, statement).strip(),
        _CITATION.sub(renumbered_marker, risk).strip(),
    )
    supports = claims or {}
    cited = [
        {**known[old], "n": number} | ({"supports": supports[old]} if old in supports else {})
        for old, number in new_number.items()
    ]
    return statement, risk, cited


def _systems_content(
    run: dict[str, Any], path: dict[str, Any], brief: WriterBrief, draft: ScenarioDraft
) -> dict[str, Any]:
    """The card's systems with the entry point, and every supporting system of the run with whether the route
    goes through it and the writer's reason; by recorded name, never the prompt's redacted one."""
    names = {system["id"]: system["name"] for system in run["context"]["systems"]}
    entry = brief_entry_point_options(brief).index(draft.entry_point) if draft.entry_point else -1
    card = [
        {"id": system_id, "name": names[system_id], "entry_point": place == entry}
        for place, system_id in enumerate(path["systems"])  # in the brief's order: the path's systems
    ]
    entry_ids = {system["id"] for system in card if system["entry_point"]}
    reasons = dict(draft.system_reasons)  # by the brief's spelling of each name
    every = [
        {
            "id": system.id,
            "name": names.get(system.id, system.name),
            "applicable": system.applicable,
            "entry_point": system.id in entry_ids,
            "reason": reasons.get(system.name, ""),
        }
        for system in brief.supporting_systems
    ]
    return {"systems": card, "system_applicability": every}


def generation_stamp(epoch: int, started_at: datetime | None, record: dict[str, Any]) -> dict[str, Any]:
    """The write job that made `record`, when its AI work began (None: no AI call) and when it was made."""
    return {"epoch": epoch, "started_at": started_at, "finished_at": record["created_at"]}


def failure_record(
    run: dict[str, Any], path: dict[str, Any], threat: dict[str, Any] | None, failure: PathFailure
) -> dict[str, Any]:
    """A visible failure card: what was to be written and why it could not be."""
    content = _threat_content(path, threat) if threat is not None else _category(path)
    return _record_fields(run, path, ScenarioStatus.FAILED, datetime.now(UTC)) | {
        "content": content,
        "findings": [],
        "failure": {"code": failure.code, "message": failure.message},
    }


def _record_fields(
    run: dict[str, Any],
    path: dict[str, Any],
    status: ScenarioStatus,
    now: datetime,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The fields every card has: its id and version, its run and asset, and a pending decision."""
    version = _FIRST_VERSION if replaces is None else replaces["version"] + 1
    return {
        "_id": scenario_id(run["_id"], path["path_id"], version),
        "session_id": run["_id"],
        "entity_id": run["entity_id"],
        "asset_id": run["asset_id"],
        "path_id": path["path_id"],
        "version": version,
        "source": RunKind.GENERATED,
        "status": status,
        "decision": Decision.PENDING,
        "decided_by": None,
        "decided_at": None,
        "replaces": None if replaces is None else replaces["_id"],
        "superseded_by": None,
        "created_at": now,
        "updated_at": now,
    }


def _category(path: dict[str, Any]) -> dict[str, Any]:
    """The card's category and its library id, as the plan froze them."""
    return {"category": path.get("category"), "category_id": path.get("category_id")}


def _threat_content(path: dict[str, Any], threat: dict[str, Any]) -> dict[str, Any]:
    """The path's category and threat, and the threat's acting attacker; read with care, since a failure card
    is written for a threat that may lack a name, a type or an attacker."""
    threat_type = threat.get("type") or {}
    return _category(path) | {
        "contributing_categories": (path.get("categories") or [])[1:],
        "threat": {
            "key": threat.get("key"),
            "type": threat_name_without_code(threat_type.get("name") or ""),
            "name": threat_name_without_code(threat.get("name") or ""),
            "library_id": threat.get("library_id"),
            "ai_generated": threat.get("ai_generated"),
            "category": threat.get("category"),  # the threat's own category, apart from the kind written
            "category_id": threat.get("category_id"),
            "type_id": threat_type.get("id"),
            "confidence": threat.get("confidence"),
            "rank": path.get("rank"),
        },
        "also_applies": list(path.get("also_applies") or []),
        "actors": [
            {key: actor.get(key) for key in ("id", "name", "role", "closest")}
            | (
                {"selection": threat.get("attacker_check"), "reason": threat.get("attacker_check_reason")}
                if actor.get("role") == ActorRole.ACTING
                else {}
            )
            for actor in threat.get("actors") or []
        ],
    }


# --- duplicates, caught before a save

_MARKER = re.compile(r"\s*\[\d+(?:\s*,\s*\d+)*\]")


def duplicate_of(
    content: dict[str, Any],
    path_id: str,
    run_finished: Iterable[dict[str, Any]],
    elsewhere: Iterable[dict[str, Any]],
) -> Finding | None:
    """The finding when `content`, a new scenario of `path_id`, tells the same threat as the same kind on the
    same systems, or in the very same words, as one of its run's other paths' (`run_finished`) or one of its
    asset's other runs' (`elsewhere`, hand-written ones included); else None."""
    own_run = (item for item in run_finished if item.get("path_id") != path_id)
    for other in (*own_run, *elsewhere):
        if _same_path(content, other["content"]) or _same_words(content, other["content"]):
            return Finding(
                FindingCode.NEAR_DUPLICATE, FindingMessage.NEAR_DUPLICATE.format(scenario_id=other["_id"])
            )
    return None


def _same_path(mine: dict[str, Any], theirs: dict[str, Any]) -> bool:
    """The same threat (same key or same name) written as the same kind on the same systems."""
    key, name = _threat_key(mine), _threat_name(mine)
    return (
        ((key is not None and key == _threat_key(theirs)) or (bool(name) and name == _threat_name(theirs)))
        and mine.get("category") == theirs.get("category")
        and _system_ids(mine) == _system_ids(theirs)
    )


def _same_words(mine: dict[str, Any], theirs: dict[str, Any]) -> bool:
    """The same statement, markers, case and spacing aside."""
    statement = _plain(mine.get("statement") or "")
    return bool(statement) and statement == _plain(theirs.get("statement") or "")


def _threat_key(content: dict[str, Any]) -> str | None:
    """The threat's key; a hand-written scenario's live library id stands in ("lib:<id>")."""
    threat = content.get("threat") or {}
    if threat.get("key"):
        return threat["key"]
    library_id, status = threat.get("library_id"), threat.get("library_status")
    return f"lib:{library_id}" if library_id is not None and status in (None, LibraryStatus.ACTIVE) else None


def _threat_name(content: dict[str, Any]) -> str:
    """The threat's name as names are matched: library code left out, normalised ('' when it has none)."""
    return name_match_key(threat_name_without_code((content.get("threat") or {}).get("name") or ""))


def _system_ids(content: dict[str, Any]) -> set[Any]:
    """The ids of the systems a card is on."""
    return {system.get("id") for system in content.get("systems") or []}


def _plain(text: str) -> str:
    """The statement casefolded, without citation markers, its spaces collapsed."""
    return " ".join(_MARKER.sub("", text).casefold().split())
