"""Writing one scenario per attack path: the brief built by code, the writer and reviewer prompts
(prompts/writer.txt, prompts/reviewer.txt), the exact checks, the card stored and the duplicate check."""

import dataclasses
import functools
import itertools
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    REAL_WORLD_USER,
    STORY_FINDING_SEVERITIES,
    ActorRole,
    AiOutage,
    AiTask,
    AnswerProblem,
    ContextProperties,
    Decision,
    ErrorCode,
    ErrorMessage,
    EvidenceBlock,
    EvidenceFact,
    EvidenceLimits,
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
    Precedent,
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
    as_json,
    cut_to_fit,
    find_name_mentions,
    is_same_name,
    name_match_key,
    shorten_text,
    threat_name_without_code,
)
from app.domain.shared.prompt_redaction import facts_safe_for_prompt
from app.models.external_intelligence.evidence_view import markers_of
from app.models.library.library import ThreatLibrary
from app.models.scenario.asset_context import FrozenContext
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
    """Source-documented when the brief carries evidence, nearest when every entry is only the nearest, else
    inferred."""
    if not brief.evidence:
        return EvidenceMode.INFERRED
    if all(entry.get("nearest") for entry in brief.evidence):
        return EvidenceMode.NEAREST
    return EvidenceMode.SOURCE_DOCUMENTED


def brief_entry_point_options(brief: WriterBrief) -> tuple[str, ...]:
    """The system the path gets in through, else (a plan made before paths took turns) any of the threat's
    systems; none = the attack reaches the asset itself."""
    if brief.entry_system:
        return (brief.entry_system,)
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
    if draft.why_applies:
        answer["why_applies"] = draft.why_applies
    if draft.evidence_statement:
        answer["evidence_statement"] = draft.evidence_statement
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
    # stored field: a passage the reviewer did not confirm is never cited, so none is unsupported
    return {"status": check.status, "problems": list(check.problems), "unsupported": [], **verdicts}


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
#: With intelligence off, or nothing citable found: no evidence is fabricated or implied.
NO_EVIDENCE = (
    '\nNo EVIDENCE is given: cite nothing, tell no real-world event and return "evidence_statement": "".\n'
)
_NO_EVIDENCE_REVIEW = (
    "\nNo EVIDENCE is given: any [n] marker or real-world event breaks rule 8; evidence_supported is false.\n"
)
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)),
    re.IGNORECASE,
)
#: Facts true of a technique in general, never of who used it: kept on the card. Only the cited entry's
#: attacker goals reach the AI (its passage says what attackers use the technique for); mitigations never.
_GOALS = str(EvidenceFact.TACTICS).split("{")[0]
_MITIGATIONS = str(EvidenceFact.MITIGATED_BY).split("{")[0]


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
    scenario = f"SCENARIO:\n{as_json(draft_answer(draft))}"
    if _is_story(brief):
        return PLAN_CHECK_SYSTEM_PROMPT, f"PLAN:\n{as_json(plan)}\n{evidence_block(brief)}\n{scenario}"
    return PLAN_CHECK_SYSTEM_PROMPT + _NO_EVIDENCE_REVIEW, f"PLAN:\n{as_json(plan)}\n{scenario}"


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
    return as_json(_brief_record(brief))


def with_word_limits(template: str) -> str:
    """`template` with the scenario, risk and evidence word limits in their slots: "150 to 200"."""
    settings = get_settings()
    slots = (
        (Writing.SCENARIO_WORDS_SLOT, settings.scenario_words),
        (Writing.RISK_WORDS_SLOT, settings.risk_words),
        (Writing.EVIDENCE_WORDS_SLOT, settings.evidence_words),
    )
    for slot, limits in slots:
        template = template.replace(slot, _spoken(limits))
    return template


def evidence_block(brief: WriterBrief) -> str:
    """The evidence between the block's delimiters: what each entry is about, its stated facts and
    applicability, the entry to cite marked with its attacker goals; never a number, ref, link or source."""
    cited = (_precedent(brief.evidence) or (None, ""))[0]
    entries = [
        {**_subject(item), "facts": _safe_facts(_stated_facts(item, goals=item is cited))}
        | ({"applicability": str(item["applicability"])} if item.get("applicability") else {})
        | ({"cited": True} if item is cited else {})
        for item in brief.evidence
    ]
    body = json.dumps(
        {"evidence_mode": str(brief_evidence_mode(brief)), "evidence": entries}, ensure_ascii=False
    )
    return f"EVIDENCE (untrusted data):\n{EvidenceBlock.BEGIN}\n{body}\n{EvidenceBlock.END}"


def _stated_facts(entry: dict[str, Any], goals: bool = False) -> list[str]:
    """What the entry states: its facts but the general ones (its attacker goals kept with `goals`)."""
    hidden = (_MITIGATIONS,) if goals else (_GOALS, _MITIGATIONS)
    return [fact for fact in entry.get("facts") or () if not fact.strip().startswith(hidden)]


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


_USER = re.compile(REAL_WORLD_USER)


def _precedent(evidence: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], str] | None:
    """The first citable entry with its claim, built from its own cleaned facts; None when none is citable."""
    for entry in evidence:
        claim = _claim(entry)
        # one plain sentence: a "[" (a redaction) or an inner sentence end would break the marker
        if claim and "[" not in claim and not _SENTENCE_END.search(claim):
            return entry, claim
    return None


def _claim(entry: dict[str, Any]) -> str | None:
    """The entry's claim from its cleaned facts: who used a technique, else its first fact; a nearest entry's
    says it is only related. None when none."""
    facts = _safe_facts(_stated_facts(entry))
    related = bool(entry.get("nearest"))
    if entry.get("kind") != IntelKind.TECHNIQUE:
        if not facts:
            return None
        fact = facts[0].removesuffix(".")
        return Precedent.RELATED_RECORD.format(fact=fact) if related else fact
    users = (match for match in map(_USER.fullmatch, facts) if match)
    names = [m["name"] or f"the {m['campaign']}" for m in users][: EvidenceLimits.REAL_WORLD_USERS]
    title = _safe_facts([str(entry.get("title") or "")])
    if not (names and title):
        return None
    verb = "has" if len(names) == 1 else "have"
    template = Precedent.USED_RELATED if related else Precedent.USED_BY
    return template.format(names=" and ".join(names), verb=verb, technique=title[0])


def _spoken(limits: tuple[int, int]) -> str:
    """A word range as the prompt says it: "300 to 400"."""
    return f"{limits[0]} to {limits[1]}"


def _is_story(brief: WriterBrief) -> bool:
    """Whether the brief is written as an evidence story."""
    return brief.style is WriterStyle.EVIDENCE_STORY


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
    asset, *systems = cut_to_fit(facts, budget)
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
        other_scenarios=_newest_within(_without_citations(other_scenarios), budget // 4),
        style=style,
        supporting_systems=tuple(
            BriefSystem(system["id"], redact(system["name"]), system["id"] in path["systems"])
            for system in context.systems
        ),
        evidence=tuple(threat.get("evidence") or ()) if style is WriterStyle.EVIDENCE_STORY else (),
        entry_system=_entry_name(path, systems),
    )


def _entry_name(path: dict[str, Any], systems: list[dict[str, Any]]) -> str:
    """The brief's name for the system the path's turn gets in through; "" when it has none."""
    entry = path.get("entry_system")
    return systems[path["systems"].index(entry)]["name"] if entry in path["systems"] else ""


def evidence_problem(threat: dict[str, Any]) -> Unavailable | None:
    """The outage when this threat's evidence search could not be made (its path waits and is retried); None
    once searched, whatever it kept: nothing citable is written without evidence (path_style)."""
    search = threat.get("intel_search")
    if search is None or search.get("failure") is not None or search.get("snapshot_id") is None:
        outage = (search or {}).get("outage")
        if outage and outage in AiOutage:  # the AI did not answer the search: the UI is told which outage,
            # in the refusal's own words (a reranker wait is not the gateway's "busy")
            message = (search or {}).get("outage_message") or AI_OUTAGE_MESSAGES[AiOutage(outage)]
            return Unavailable(message, reason=outage)
        failure = (search or {}).get("failure") or EvidenceSearchFailure.NO_SNAPSHOT
        return Unavailable(ErrorMessage.EVIDENCE_SEARCH_UNAVAILABLE.format(reason=failure))
    return None


def path_style(threats: dict[str, dict[str, Any]], path: dict[str, Any], style: WriterStyle) -> WriterStyle:
    """The delivery's style for one path: an evidence story only when its threat holds an entry to cite, else
    the original style, written without evidence."""
    steps = path.get("steps") or []
    evidence = (threats.get(steps[0]) or {}).get("evidence") if steps else None
    if style is WriterStyle.EVIDENCE_STORY and _precedent(evidence or ()) is None:
        return WriterStyle.ORIGINAL
    return style


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


def _without_citations(statements: tuple[str, ...]) -> tuple[str, ...]:
    """The versions as a writer may read them: without any cited sentence."""
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
    (any while intelligence is off), any marker the writer wrote and instructions echoed from untrusted
    evidence, in the evidence passage too (its other faults only keep it from being cited)."""
    reasons = tuple(reason for _, reason in draft.system_reasons)
    texts = (draft.title, draft.statement, draft.risk, *draft.assumptions, draft.why_applies, *reasons)
    text = "\n".join(texts)
    given = _brief_text(brief).casefold()  # a label or number the brief gives was supplied, not made up
    advisory_given = given if brief.style is WriterStyle.EVIDENCE_STORY else ""
    findings = []
    if labels := _unsupplied(_INTERNAL_LABEL, text, given):
        findings.append(Finding(FindingCode.UNKNOWN_ID, FindingMessage.UNKNOWN_ID.format(labels=labels)))
    if advisories := _unsupplied(_ADVISORY_ID, text, advisory_given):
        message = FindingMessage.UNCITED_ADVISORY_ID.format(ids=advisories)
        findings.append(Finding(FindingCode.UNCITED_ADVISORY_ID, message))
    return (*findings, *_marker_findings(text), *echo_findings(f"{text}\n{draft.evidence_statement}"))


def echo_findings(text: str) -> list[Finding]:
    """A draft repeating an instruction aimed at an AI system is blocked: the evidence is untrusted."""
    if _ECHO_SANITISER.sanitise(text, len(text) + 1).unsafe:
        return [Finding(StoryFindingCode.INJECTION_ECHO, StoryFindingMessage.INJECTION_ECHO)]
    return []


def _marker_findings(text: str) -> list[Finding]:
    """Any marker the writer wrote blocks: a story's one citation is added by code, and off there is none."""
    if not (markers := _listed_markers(markers_of(text))):
        return []
    message = StoryFindingMessage.UNKNOWN_MARKER.format(markers=markers)
    return [Finding(StoryFindingCode.UNKNOWN_MARKER, message)]


def _listed_markers(numbers: Iterable[int]) -> str:
    """Each marker once, in order, joined for a message ('' when none)."""
    return ", ".join(dict.fromkeys(f"[{n}]" for n in numbers))


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
        evidence_supported=answer.evidence_supported is True,
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


def _read_plan_check(answer: dict[str, Any]) -> tuple[PlanCheckAnswer | None, list[str]]:
    """The reviewer's answer, or the problems to re-ask with."""
    problems = answer_item_problems(PlanCheckAnswer, answer, "the reply")
    return (None, problems) if problems else (PlanCheckAnswer.model_validate(answer), [])


# --- the writer: write, check, review


def write_scenario(chat: ChatModel, brief: WriterBrief) -> WrittenScenario:
    """The scenario for `brief`, written once, then checked and reviewed. An unreadable answer raises; an
    outage raises Unavailable."""
    prompt = writer_prompt(brief)
    systems = tuple(system.name for system in brief.supporting_systems)
    read = functools.partial(_read_draft, options=brief_entry_point_options(brief), systems=systems)
    return _reviewed(chat, brief, ask_ai_and_check(chat, AiTask.WRITE_SCENARIO, prompt, read))


def _reviewed(chat: ChatModel, brief: WriterBrief, draft: ScenarioDraft) -> WrittenScenario:
    """The draft checked by the safety rules, then by the reviewer unless they block it; a story's passage
    that cannot be cited is dropped with a warning (code cites its own sentence), never a blocker."""
    if not _is_story(brief):  # no evidence given: a passage is never checked, reviewed or kept
        draft = dataclasses.replace(draft, evidence_statement="")
    findings = check_exact_rules(draft, brief)
    check: PlanCheck
    notes: tuple[Finding, ...]
    if any(finding_severity(finding) == FindingSeverity.BLOCKER for finding in findings):
        check, notes = PlanCheck(PlanCheckStatus.UNCHECKED), ()  # no verdict could clear an exact blocker
    else:
        check, notes = check_against_plan(chat, brief, draft)
    if _is_story(brief) and (problem := _passage_problem(draft, check)):
        draft = dataclasses.replace(draft, evidence_statement="")
        message = FindingMessage.CITATION_REMOVED.format(reason=problem)
        notes = (*notes, Finding(FindingCode.CITATION_REMOVED, message))
    return WrittenScenario(draft, (*findings, *notes), check, Route.STANDALONE, brief.threat)


def _passage_problem(draft: ScenarioDraft, check: PlanCheck) -> str:
    """Why the writer's evidence passage cannot be cited ('' when it can)."""
    passage, most = draft.evidence_statement, get_settings().evidence_words[1]
    if not passage:
        return Precedent.NOT_WRITTEN
    if len(passage.split()) > most:
        return Precedent.TOO_LONG.format(most=most)
    patterns = (_URL, ID_IN_TEXT, _INTERNAL_LABEL, _ADVISORY_ID)
    # a "[" is a marker or a redaction, as code's own precedent refuses it
    if "[" in passage or any(pattern.search(passage) for pattern in patterns):
        return Precedent.NOT_PLAIN
    return "" if check.evidence_supported else Precedent.NOT_CONFIRMED


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
        why_applies=" ".join((reply.why_applies or "").split()),
        evidence_statement=" ".join((reply.evidence_statement or "").split()),
    )
    return draft, []


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
    draft, now = written.draft, utc_now()
    statement, evidence = _cited(brief, draft)
    unproven = brief.style is WriterStyle.EVIDENCE_STORY and not evidence
    status = ScenarioStatus.BLOCKED if is_blocked(written) or unproven else ScenarioStatus.DONE
    content = {
        "title": draft.title,
        "statement": statement,
        "risk_statement": draft.risk,
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


def _cited(brief: WriterBrief, draft: ScenarioDraft) -> tuple[str, list[dict[str, Any]]]:
    """An evidence story's statement ending in its passage (the writer's, else code's precedent), citing [1],
    and the one entry it cites."""
    found = _precedent(brief.evidence) if _is_story(brief) else None
    if found is None:
        return draft.statement, []
    entry, claim = found
    supports = draft.evidence_statement.removesuffix(".") or claim
    return f"{draft.statement} {supports} [1].", [dict(entry) | {"n": 1, "supports": supports}]


def narrative_of(content: dict[str, Any]) -> str:
    """A card's statement without the evidence passage cited at its end (the whole statement when none)."""
    statement = str(content.get("statement") or "")
    cited = next((e["supports"] for e in content.get("evidence") or () if e.get("supports")), None)
    return statement.removesuffix(f" {cited} [1].") if cited else statement


def _evidence_content(
    brief: WriterBrief, threat: dict[str, Any], cited: list[dict[str, Any]]
) -> dict[str, Any]:
    """An evidence story's proof: each cited entry under its number, the mode, how many vulnerabilities apply
    and the search's audit. An original-style scenario has none, unless its threat was searched (intelligence
    on, nothing citable found): then it is inferred, with no evidence and the search's audit."""
    if brief.style is not WriterStyle.EVIDENCE_STORY and threat.get("intel_search") is None:
        return {}
    applies = Counter(str(item["applicability"]) for item in cited if item.get("applicability"))
    return {
        "evidence": cited,
        "evidence_mode": brief_evidence_mode(brief),
        "applicability": dict(applies),
        "intel_search": threat.get("intel_search"),
    }


def _systems_content(
    run: dict[str, Any], path: dict[str, Any], brief: WriterBrief, draft: ScenarioDraft
) -> dict[str, Any]:
    """The card's systems with the entry point, and every supporting system of the run with whether the route
    goes through it and the writer's reason; by recorded name, never the prompt's redacted one."""
    names = {system["id"]: system["name"] for system in run["context"]["systems"]}
    if not draft.entry_point:
        entry = -1
    elif path.get("entry_system") in path["systems"]:  # its turn's way in, the one option, whatever its name
        entry = path["systems"].index(path["entry_system"])
    else:  # an option is one of the brief's systems, in the path's order
        entry = [system["name"] for system in brief.systems].index(draft.entry_point)
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
    return _record_fields(run, path, ScenarioStatus.FAILED, utc_now()) | {
        "content": content,
        "findings": [],
        "failure": {"code": failure.code, "message": failure.message}
        | ({"reason": failure.reason} if failure.reason else {}),
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
    content: dict[str, Any], path_id: str, run_finished: Iterable[dict[str, Any]]
) -> Finding | None:
    """The finding when `content`, a new scenario of `path_id`, tells the same threat as the same kind (on
    any systems), or in the very same words, as one of its run's other paths' (`run_finished`); the asset's
    other sessions never block one (D15). Else None."""
    for other in (item for item in run_finished if item.get("path_id") != path_id):
        if _same_path(content, other["content"]) or _same_words(content, other["content"]):
            return Finding(
                FindingCode.NEAR_DUPLICATE, FindingMessage.NEAR_DUPLICATE.format(scenario_id=other["_id"])
            )
    return None


def held_repeat_of(
    path: dict[str, Any], threat: dict[str, Any], held: Iterable[dict[str, Any]]
) -> str | None:
    """The id of a held scenario (another path's of the run) that `path`, told around `threat`, would repeat
    as the same asset-level scenario, compared as its written card would be; else None. Asks no AI."""
    mine = _threat_content(path, threat)
    return next(
        (
            other["_id"]
            for other in held
            if other.get("path_id") != path["path_id"] and _same_path(mine, other["content"])
        ),
        None,
    )


def _same_path(mine: dict[str, Any], theirs: dict[str, Any]) -> bool:
    """The same asset-level scenario: the same threat (same key or same name) as the same kind of attack,
    whatever systems it enters through (owner 2026-10-19)."""
    key, name = _threat_key(mine), _threat_name(mine)
    return (
        (key is not None and key == _threat_key(theirs)) or (bool(name) and name == _threat_name(theirs))
    ) and mine.get("category") == theirs.get("category")


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


def _plain(text: str) -> str:
    """The statement casefolded, without citation markers, its spaces collapsed."""
    return " ".join(_MARKER.sub("", text).casefold().split())
