"""Writing one scenario per attack path, a set of paths at a time: the brief built by code, the writer and
reviewer prompts (app/prompts.toml), the exact checks, the card stored and the duplicate check."""

import dataclasses
import functools
import itertools
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    ACTOR_KIND_WORDS,
    AI_OUTAGE_MESSAGES,
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    REAL_WORLD_USER,
    STORY_FINDING_SEVERITIES,
    ActorRole,
    AiLimits,
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
    PromptVersion,
    Route,
    RunKind,
    ScenarioStatus,
    Status,
    StoryFindingCode,
    StoryFindingMessage,
    StrideCategory,
    TextSafety,
    WriterStyle,
    Writing,
)
from app.core.exceptions import PathNotWritable, Unavailable
from app.core.logging import current_job_origin, current_request_id
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.external_intelligence.injection_patterns import ECHO_PATTERNS
from app.domain.external_intelligence.text_cleaner import ID_IN_TEXT
from app.domain.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.domain.scenario.plan import attacker_unsupported, raw_system_facts
from app.domain.shared.ask_ai import (
    ChatPrompt,
    answer_item_problems,
    answers_for_asked_slots,
    ask_ai_and_check,
    within_call_limit,
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
from app.domain.shared.prompt_redaction import facts_safe_for_prompt, without_platform_note
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
    # stored field: code builds the cited sentence from its source's own facts, so none is unsupported
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


# --- the writer's and the reviewer's prompts ([scenario.writer] and [scenario.reviewer] in app/prompts.toml)

_WRITER: dict[str, str] = PROMPTS["scenario"]["writer"]
WRITER_SYSTEM_PROMPT: str = _WRITER["text"]
PLAN_CHECK_SYSTEM_PROMPT: str = PROMPTS["scenario"]["reviewer"]["text"]
#: The reviewer's system prompt for a set: each slot its own PLAN, EVIDENCE and SCENARIO.
PLAN_CHECK_SET_PROMPT: str = PLAN_CHECK_SYSTEM_PROMPT + PROMPTS["scenario"]["reviewer"]["set"]
#: A slot's line with intelligence off, or nothing citable found: no evidence is fabricated or implied.
NO_EVIDENCE: str = _WRITER["no_evidence"].strip()
_REPAIR: str = _WRITER["repair"]  # a slot's listed actions its review found not carried out
_REWRITE: str = _WRITER["rewrite"]  # a slot's problems in its earlier answer
_NO_EVIDENCE_REVIEW: str = PROMPTS["scenario"]["reviewer"]["no_evidence"].strip()
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)),
    re.IGNORECASE,
)
#: Facts true of a technique in general, never of who used it: kept on the card, never shown to an AI.
_GOALS = str(EvidenceFact.TACTICS).split("{")[0]
_MITIGATIONS = str(EvidenceFact.MITIGATED_BY).split("{")[0]


def slot_label(place: int) -> str:
    """A set's slot label, by the path's place in its batch: never a path or database id."""
    return f"SC{place}"


def writer_system_prompt() -> str:
    """The writer's system prompt with the configured word limits, ending with how a set is answered."""
    return with_word_limits(WRITER_SYSTEM_PROMPT + _WRITER["set"])


def writer_slot(label: str, brief: WriterBrief, note: str = "") -> str:
    """One slot of the writer's user prompt: its BRIEF, its evidence or the line saying none is given, and
    any `note` (a rewrite's problems or a repair's actions)."""
    evidence = evidence_block(brief) if _is_story(brief) else NO_EVIDENCE
    return f"SLOT {label}\nBRIEF:\n{_brief_text(brief)}\n{evidence}{note}"


def plan_check_slot(label: str, brief: WriterBrief, draft: ScenarioDraft) -> str:
    """One slot of the reviewer's user prompt: its PLAN (the writer's BRIEF plus the critical service), its
    evidence or the line saying none is given, and its scenario."""
    plan = _brief_record(brief) | {"critical_service": brief.critical_service}
    evidence = evidence_block(brief) if _is_story(brief) else _NO_EVIDENCE_REVIEW
    return f"SLOT {label}\nPLAN:\n{as_json(plan)}\n{evidence}\nSCENARIO:\n{as_json(draft_answer(draft))}"


def _brief_record(brief: WriterBrief) -> dict[str, Any]:
    """The brief as the writer reads it: what the scenario may take from."""
    return {
        "asset": brief.asset,
        "category": brief.category,
        "attacker": brief.attacker,
        "threat": {
            "threat_type": brief.threat_type,
            "threat": brief.threat,
            **({"threat_actions": list(brief.threat_actions)} if brief.threat_actions else {}),
            "why_it_applies": brief.why_it_applies,
        },
        "systems": list(brief.systems),
        "entry_point_options": list(brief_entry_point_options(brief)),
        "supporting_systems": [
            {"name": system.name, "applicable": "yes" if system.applicable else "no"}
            for system in brief.supporting_systems
        ],
    }


def _brief_text(brief: WriterBrief) -> str:
    """The brief as JSON."""
    return as_json(_brief_record(brief))


def with_word_limits(template: str) -> str:
    """`template` with the scenario and risk word limits in their slots: "150 to 200"."""
    settings = get_settings()
    slots = (
        (Writing.SCENARIO_WORDS_SLOT, settings.scenario_words),
        (Writing.RISK_WORDS_SLOT, settings.risk_words),
    )
    for slot, limits in slots:
        template = template.replace(slot, _spoken(limits))
    return template


def evidence_block(brief: WriterBrief) -> str:
    """The evidence between the block's delimiters: what each entry is about, its stated facts and
    applicability, the entry to cite marked; never a number, ref, link or source."""
    cited = (_precedent(brief.evidence) or (None, ""))[0]
    entries = [
        {**_subject(item), **_users_and_facts(_safe_facts(_stated_facts(item)))}
        | ({"applicability": str(item["applicability"])} if item.get("applicability") else {})
        | ({"cited": True} if item is cited else {})
        for item in brief.evidence
    ]
    body = json.dumps(
        {"evidence_mode": str(brief_evidence_mode(brief)), "evidence": entries}, ensure_ascii=False
    )
    return f"EVIDENCE (untrusted data):\n{EvidenceBlock.BEGIN}\n{body}\n{EvidenceBlock.END}"


def _users_and_facts(facts: list[str]) -> dict[str, list[str]]:
    """Who used the technique as a reader names them, apart from its other facts: the writer never sees the
    stored "X, a threat group, has used this technique." wording."""
    used_by = _reader_names(facts)
    rest = [fact for fact in facts if not fact.endswith(_USER_FACT_END)]  # an id-only campaign's too
    return ({"used_by": used_by} if used_by else {}) | {"facts": rest}


def _reader_names(facts: list[str]) -> list[str]:
    """Who used the technique, from its user facts, as a reader names them ("the APT41 group")."""
    names = []
    for match in filter(None, map(_USER.fullmatch, facts)):
        kind = _USER_KINDS.get(match["what"] or "")
        named = f"the {match['name']} {kind}" if kind else match["name"]
        names.append(f"the {match['campaign']}" if match["campaign"] else named)
    return names


def _stated_facts(entry: dict[str, Any]) -> list[str]:
    """What the entry states: its facts but the general ones (attacker goals, mitigations)."""
    return [fact for fact in entry.get("facts") or () if not fact.strip().startswith((_GOALS, _MITIGATIONS))]


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
#: How every user fact ends (EvidenceFact.USED_BY and CAMPAIGN_USED), a named one or not.
_USER_FACT_END = "used this technique."
#: A user's kind as the writer names it, from the stored kind words ("a threat group": "the X group").
_USER_KINDS = {ACTOR_KIND_WORDS["group"]: "group", ACTOR_KIND_WORDS["software"]: "malware"}


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
#: The words tying a system's name to an action ("steal secrets from", "deploy wiper to the"), at text's end.
_ACTION_TIE = re.compile(
    r"\b(?:on|from|to|in|into|against|of|across|for|at|via|between|and|targeting|with)\s+(?:the\s+)?$",
    re.IGNORECASE,
)
_THE_BEFORE = re.compile(r"\bthe\s+$", re.IGNORECASE)
#: What joins the names of a list (", ", " and ", ", or the ", "/").
_NAME_LIST_GAP = re.compile(r"\s*(?:,\s*(?:(?:and|or)\s+)?|(?:and|or)\s+|/\s*)(?:the\s+)?", re.IGNORECASE)
#: A system's name describing the word after it ("<system> data", "<system>'s staff"), not tied by one.
_NAME_DESCRIBES = re.compile(
    r"(?:['’]s)?\s+(?!(?:and|or|to|from|on|in|into|via|with|without|for|at|by|across|between|then"
    r"|through|over|under|using|as)\b)[a-z]",
    re.IGNORECASE,
)
#: A threat name's "or", and the joiners that make it name several acts ("Command and Control", "with").
_OR_JOINER = re.compile(r"\bor\b", re.IGNORECASE)
_AND_JOINER = re.compile(r"\b(?:and|with)\b|&", re.IGNORECASE)
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
    style: WriterStyle = WriterStyle.ORIGINAL,
) -> WriterBrief:
    """The brief for `path`: its asset's and systems' facts within `budget` characters together, the acting
    attacker and why the threat applies. Raises PathNotWritable for a path missing a fact or whose threat or
    attacker was retired."""
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
        threat_actions=tuple(redact(action) for action in _brief_actions(threat, context)),
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
    """Why the threat applies as the kind the path is written as, else the threat's own reason; without the
    platform note."""
    reason = (threat.get("reasons") or {}).get(path["category"]) or threat["reason"]
    return without_platform_note(str(reason))


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


def _brief_actions(threat: dict[str, Any], context: FrozenContext) -> tuple[str, ...]:
    """The threat's listed actions as the writer reads them: no system named, repeats dropped, and the
    alternatives of a name joined only by "or" one item ("steal secrets or steal API keys")."""
    names = [system["name"] for system in context.systems]
    actions: dict[str, str] = {}
    for action in threat.get("actions") or ():
        bare = _without_system_names(str(action), names)
        if key := name_match_key(bare):
            actions.setdefault(key, bare)
    name = threat_name_without_code(threat["name"])
    if len(actions) > 1 and _OR_JOINER.search(name) and not _AND_JOINER.search(name):
        return (" or ".join(actions.values()),)
    return tuple(actions.values())


def _without_system_names(action: str, names: list[str]) -> str:
    """`action` without any system's name, keeping its meaning: "steal secrets from X" is "steal secrets",
    "extort with X data" is "extort with data", "encrypt X" is "encrypt the system"."""
    spans = _merged_spans(sorted(span for name in names for span in find_name_mentions(name, action)), action)
    for start, end in reversed(spans):  # from the end, so earlier spans keep their place
        action = _without_name_at(action, start, end)
    return " ".join(action.split())


def _merged_spans(spans: list[tuple[int, int]], action: str) -> list[tuple[int, int]]:
    """Sorted spans with overlapping ones, and a list of names ("A, B and C"), joined into one span."""
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and (start < merged[-1][1] or _NAME_LIST_GAP.fullmatch(action[merged[-1][1] : start])):
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _without_name_at(action: str, start: int, end: int) -> str:
    """`action` without the system name at [start, end): a name describing the next word goes alone, one
    tied to the act goes with its tying word, and one the act is done to becomes "the system"."""
    head, tail = action[:start], action[end:]
    the = _THE_BEFORE.search(head)
    bare_head = head[: the.start()] if the else head
    if described := _NAME_DESCRIBES.match(tail):
        return f"{bare_head} {tail[described.end() - 1 :]}"
    tie = _ACTION_TIE.search(head)
    if tie and len(head[: tie.start()].split()) > 1:  # more than a bare verb is left
        return head[: tie.start()] + tail
    return f"{bare_head}{Writing.ACTION_SYSTEM}{tail}" if bare_head.strip() else tail


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

#: The planner's aliases and slots (SYS1, THR7) and a set's slots (SC2): never in a brief, so one in a
#: scenario was made up or leaked from another slot.
_INTERNAL_LABEL = re.compile(r"\b(?:SYS|THR|SC)\d+\b")
_LEADING_ARTICLE = re.compile(r"^the\s+", re.IGNORECASE)
#: A public advisory number: CVE, CISA ICS advisory (ICSA, ICSMA), GitHub (GHSA), Microsoft bulletin, CERT/CC.
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3})\b|\bVU#\d+",
    re.IGNORECASE,
)
_ECHO_SANITISER = UntrustedTextSanitiser(ECHO_PATTERNS, (), ())


def check_exact_rules(draft: ScenarioDraft, brief: WriterBrief) -> tuple[Finding, ...]:
    """Every exact finding in the texts the card serves: made-up labels, advisory ids the brief did not give
    (any while intelligence is off), any marker the writer wrote and instructions echoed from untrusted
    evidence, in the evidence sentence too (its step's other faults only keep it from being cited)."""
    reasons = tuple(reason for _, reason in draft.system_reasons)
    texts = (draft.title, draft.statement, draft.risk, *draft.assumptions, *reasons)
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


# --- writing a set: one write and one review, then one rewrite and one review for the slots that need them

#: A slot's own problems in a set's answer, told in its rewrite.
_SLOT_MISSING: str = _WRITER["slot_missing"]
_THREAT_NOT_COPIED: str = _WRITER["threat_not_copied"]


@dataclasses.dataclass
class _Slot:
    """One scenario of a set as its rounds settle it."""

    label: str
    brief: WriterBrief
    place: int  # the set's epoch plus its place in the set: picks its evidence sentence's link and users form
    draft: ScenarioDraft | None = None  # its usable draft; a repair's while it is written
    problems: tuple[str, ...] = ()  # why the second round writes it again
    review: PlanCheckAnswer | None = None  # its usable review
    review_problems: tuple[str, ...] = ()  # why its review is asked again (unusable, or no action judged)
    first: WrittenScenario | None = None  # its reviewed first draft while its repair is written


def write_set(
    chat: ChatModel, briefs: Sequence[tuple[str, WriterBrief]], epoch: int = 0
) -> Iterator[tuple[str, WrittenScenario | PathFailure]]:
    """Each slot's scenario (or failure card) as soon as it is final, in at most 4 AI calls: one write and one
    review, then one rewrite for the slots that need it (unreadable, a re-ask fault, or listed actions or a
    reviewer's mismatch to repair, each with its reviewed draft kept) and one review for those and the slots
    whose review is asked again; there is no third round. With the reviewer off (D64) there is no review
    call, so at most 2. `epoch` (the set's job epoch) rotates the evidence sentences' links from set to set.
    A whole write answer still unusable raises UnreadableAiAnswer or TruncatedAiAnswer; an outage raises
    Unavailable."""
    # ponytail: the place within this call; a later batch or retry of the same set may repeat a link
    slots = [_Slot(label, brief, epoch + place) for place, (label, brief) in enumerate(briefs)]
    if not slots:
        return
    blocks = [(slot.label, writer_slot(slot.label, slot.brief)) for slot in slots]
    answers = _ask_set(chat, AiTask.WRITE_SCENARIO, writer_system_prompt(), blocks, "scenarios")
    for slot in slots:
        item = answers.get(slot.label)
        slot.draft, problems = _read_slot_draft(slot, item)
        slot.problems = tuple(problems if slot.draft is None else _first_answer_faults(slot.brief, item))
    _review(chat, [slot for slot in slots if not slot.problems and _reviewable(slot)])
    second = []
    for slot in slots:
        if (written := _first_round_end(slot)) is None:
            second.append(slot)
        else:
            yield slot.label, written
    yield from _second_round(chat, second)


def _second_round(chat: ChatModel, slots: list[_Slot]) -> Iterator[tuple[str, WrittenScenario | PathFailure]]:
    """One rewrite call for the slots to write again (each told its problems or its repair), then one review
    call for every slot with a draft to judge (one whose review is asked again is reviewed again, never
    rewritten). On an outage each slot keeps its usable draft (_firsts_kept); one with none raises."""
    rewrite = [slot for slot in slots if slot.draft is None or slot.problems or slot.first]
    try:
        blocks = [(slot.label, writer_slot(slot.label, slot.brief, _note(slot))) for slot in rewrite]
        answers = _ask_set(chat, AiTask.REPAIR_SCENARIO, writer_system_prompt(), blocks, "scenarios")
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:  # every slot's rewrite is unusable
        log.warning(LogEvent.WRITER_PATH_FAILED, message=str(exc), error_type=type(exc).__name__)
        answers = {}
    except Unavailable as exc:
        yield from _firsts_kept(slots, exc)
        return
    for slot in rewrite:
        _take_rewrite(slot, answers.get(slot.label))
    try:
        _review(chat, [slot for slot in slots if _reviewable(slot)])
    except Unavailable as exc:
        yield from _firsts_kept(slots, exc)
        return
    for slot in slots:
        yield slot.label, _second_round_end(slot)


def _ask_set(
    chat: ChatModel, task: AiTask, system: str, blocks: list[tuple[str, str]], key: str
) -> dict[str, dict[str, Any]]:
    """Each slot's item of the answer to `blocks` ((label, text)), asked in one call or in the halves the size
    check makes; an answer holding no list under `key` after its one re-ask raises. A slot's own faults are
    never re-asked here: they are its own, so one bad slot never costs the set a second ask."""
    items: dict[str, dict[str, Any]] = {}
    for part in within_call_limit(blocks, functools.partial(_set_prompt, system), task) if blocks else ():
        read = functools.partial(_read_set, key=key, asked={label for label, _ in part})
        items |= ask_ai_and_check(chat, task, _set_prompt(system, part), read, reuse_earlier_answer=True)
    return items


def _set_prompt(system: str, blocks: Sequence[tuple[str, str]]) -> ChatPrompt:
    """The system prompt and every slot's block, in the set's order."""
    return system, "\n\n".join(text for _, text in blocks)


def _read_set(
    answer: dict[str, Any], key: str, asked: set[str]
) -> tuple[dict[str, dict[str, Any]] | None, list[str]]:
    """The answer's item for each asked slot, or the problem when it holds no list under `key`."""
    kept, problems = answers_for_asked_slots(answer, key, asked)
    if not isinstance(answer.get(key), list):
        return None, problems
    return {str(item["slot"]): _with_ampersands(item) for item in kept}, []


def _with_ampersands(value: Any) -> Any:
    """An answer with "&amp;" read as "&": the model escapes names such as "Command & Control"."""
    if isinstance(value, str):
        return value.replace("&amp;", "&")
    if isinstance(value, dict):
        return {_with_ampersands(key): _with_ampersands(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_with_ampersands(item) for item in value]
    return value


def _read_slot_draft(slot: _Slot, item: dict[str, Any] | None) -> tuple[ScenarioDraft | None, list[str]]:
    """A slot's draft from its item, or its problems: no item, another threat copied back, or an unreadable
    answer (_read_draft); a story's closing sentence is code's, from its step (none with no evidence)."""
    brief = slot.brief
    if item is None:
        return None, [_SLOT_MISSING]
    if name_match_key(str(item.get("threat") or "")) != name_match_key(brief.threat):
        return None, [_THREAT_NOT_COPIED]  # another slot's answer, or none: written again
    draft, problems = _read_draft(item, brief_entry_point_options(brief), brief.supporting_systems)
    if draft is not None:
        cited = _cited_entry(brief) if _is_story(brief) else None
        sentence = evidence_sentence(draft.evidence_step, cited, slot.place)[0]
        draft = dataclasses.replace(draft, evidence_statement=sentence)
    return draft, problems


def _first_answer_faults(brief: WriterBrief, item: dict[str, Any] | None) -> list[str]:
    """A first answer's faults that have it written again (its draft is kept should that fail): a listed
    action shown in no sentence of its own story."""
    return _acts_without_a_sentence(item or {}, brief.threat_actions) if brief.threat_actions else []


def _reviewable(slot: _Slot) -> bool:
    """Whether the slot has a draft the reviewer may judge: one no exact finding blocks."""
    return slot.draft is not None and not _exactly_blocked(slot.draft, slot.brief)


def _exactly_blocked(draft: ScenarioDraft, brief: WriterBrief) -> bool:
    """Whether an exact finding blocks the draft."""
    return _blocks(check_exact_rules(draft, brief))


def _blocks(findings: Iterable[Finding]) -> bool:
    """Whether any finding is a blocker."""
    return any(finding_severity(finding) == FindingSeverity.BLOCKER for finding in findings)


def _review_on() -> bool:
    """Whether the AI reviewer judges each written set (CII_SCENARIO_REVIEW_ENABLED, off by default: D64)."""
    return get_settings().scenario_review_enabled


def _review(chat: ChatModel, slots: list[_Slot]) -> None:
    """One reviewer call for every slot's draft: each slot keeps its usable review, or notes why it got none
    (an earlier usable review then stays); no call while the reviewer is off."""
    if not slots or not _review_on():
        return
    blocks = [(slot.label, plan_check_slot(slot.label, slot.brief, _draft_of(slot))) for slot in slots]
    try:  # temperature 0: a retry's same ask gets the same answer, so it is read back
        reviews = _ask_set(chat, AiTask.PLAN_CHECK, PLAN_CHECK_SET_PROMPT, blocks, "reviews")
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(LogEvent.WRITER_PLAN_CHECK_NOT_MADE, message=str(exc))
        reviews = {}
    for slot in slots:
        review, problems = _read_slot_review(slot.brief, reviews.get(slot.label))
        slot.review, slot.review_problems = review or slot.review, tuple(problems)


def _read_slot_review(
    brief: WriterBrief, item: dict[str, Any] | None
) -> tuple[PlanCheckAnswer | None, list[str]]:
    """A slot's review, or its problems; one judging none of the brief's listed actions is usable but asked
    again."""
    if item is None:
        return None, [_SLOT_MISSING]
    if name_match_key(str(item.get("threat") or "")) != name_match_key(brief.threat):
        return None, [_THREAT_NOT_COPIED]
    answer, problems = _read_plan_check(item)
    if answer is not None and brief.threat_actions:
        problems = _unjudged_actions(item)
    return answer, problems


def _draft_of(slot: _Slot) -> ScenarioDraft:
    """The slot's draft, once it has one."""
    assert slot.draft is not None  # only a slot with a usable draft is reviewed
    return slot.draft


def _first_round_end(slot: _Slot) -> WrittenScenario | None:
    """The slot's scenario when the first round settles it; None while the second round must write or
    review it again (the reviewed first draft of an act or mismatch repair is kept on it)."""
    if slot.draft is None or slot.problems or slot.review_problems:
        return None
    written = _checked(slot)
    if _listed_actions(written.plan_check) or _mismatched(written):
        slot.first = written
        return None
    return written


def _listed_actions(check: PlanCheck) -> tuple[str, ...]:
    """The listed actions to repair: those an inconsistent review found not carried out; none for a
    consistent review, whose unjudged actions are never repaired."""
    return check.actions_not_carried_out if check.status is PlanCheckStatus.INCONSISTENT else ()


def _mismatched(written: WrittenScenario) -> bool:
    """Whether the reviewer's mismatch is the only thing blocking it (an exact blocker is never repaired)."""
    return blocking_codes(written) == [FindingCode.SCENARIO_MISMATCH]


def _mismatch_problems(written: WrittenScenario) -> tuple[str, ...]:
    """A mismatched draft's blocker, then the reviewer's broken rules in its own quoted words; none when no
    mismatch blocks it."""
    if not _mismatched(written):
        return ()
    blocker = (f.message for f in written.findings if f.code == FindingCode.SCENARIO_MISMATCH)
    return (*blocker, *written.plan_check.problems)


def _note(slot: _Slot) -> str:
    """What a slot's rewrite is told: the listed actions to repair, then a mismatch's review and its earlier
    answer's problems."""
    actions = _listed_actions(slot.first.plan_check) if slot.first else ()
    listed = ", ".join(json.dumps(act, ensure_ascii=False) for act in actions)
    # a mismatch's review is its rewrite's whole instruction: it keeps a stored problem's size
    reviewed = _mismatch_problems(slot.first) if slot.first else ()
    mismatch = [_within_reask(problem, Writing.PROBLEM_MAX_CHARS) for problem in reviewed]
    problems = (*mismatch, *(_within_reask(problem) for problem in slot.problems))
    shown = problems[: AiLimits.REASK_MAX_PROBLEMS]
    repair = _REPAIR.replace("{actions}", listed) if actions else ""
    return repair + (_REWRITE.replace("{problems}", "; ".join(shown)) if problems else "")


#: A reviewer's problem: 'Rule n: "<quoted words>" - <reason>'.
_QUOTED_PROBLEM = re.compile(r'(?P<rule>Rule \d+: )"(?P<quote>.*)"(?P<reason> - .*)', re.DOTALL)
_LEAST_QUOTE_CHARS = 30  # a shorter quote no longer finds its sentence


def _within_reask(problem: str, most: int = AiLimits.REASK_PROBLEM_CHARS) -> str:
    """A problem within `most` characters, cut at a word: a reviewer's long quote is shortened so its
    reason stays whole."""
    if len(problem) <= most:
        return problem
    parts = _QUOTED_PROBLEM.fullmatch(problem)
    room = most - len(parts["rule"]) - len(parts["reason"]) - 3 if parts else 0
    if parts and room >= _LEAST_QUOTE_CHARS:
        return f'{parts["rule"]}"{parts["quote"][:room].rsplit(" ", 1)[0]}…"{parts["reason"]}'
    return problem[:most].rsplit(" ", 1)[0]


def _take_rewrite(slot: _Slot, item: dict[str, Any] | None) -> None:
    """The slot's rewrite in place of its draft when it reads; else a repair is dropped (its first draft
    stays) and a slot keeps its usable first draft, if it had one, also over a rewrite an exact rule blocks
    when that draft is not blocked (it is reviewed in round 2 instead)."""
    draft, problems = _read_slot_draft(slot, item)
    old = slot.draft if slot.first is None else None
    if draft and old and _exactly_blocked(draft, slot.brief) and not _exactly_blocked(old, slot.brief):
        draft = None
    if draft is not None or slot.first is not None:
        slot.draft, slot.review, slot.review_problems = draft, None, ()
    slot.problems = tuple(problems) if slot.draft is None else ()


def _second_round_end(slot: _Slot) -> WrittenScenario | PathFailure:
    """The slot's final scenario: a repair or its first draft, the draft checked and reviewed, or a failure
    card when no usable draft came."""
    if slot.first is not None:
        return _repair_or_first(slot, slot.first)
    if slot.draft is None:
        return PathFailure(ErrorCode.GENERATION_FAILED, _rejected(AiTask.REPAIR_SCENARIO, slot.problems))
    return _checked(slot)


def _repair_or_first(slot: _Slot, first: WrittenScenario) -> WrittenScenario:
    """The repair, marked rewritten, when it fixes the first draft (_fixes) with a review not asked again;
    else the first draft."""
    if slot.draft is None:
        log.warning(LogEvent.WRITER_SCENARIO_REPAIRED, outcome="kept_first", message="; ".join(slot.problems))
        return first
    repair = _checked(slot)
    # a blocked first draft costs its path: any reviewed repair no rule blocks is better
    better = _reviewed_unblocked(repair) if _mismatched(first) else _fixes(repair, first)
    fixed = better and not slot.review_problems
    log.info(LogEvent.WRITER_SCENARIO_REPAIRED, outcome="fixed" if fixed else "kept_first")
    return dataclasses.replace(repair, rewritten=True) if fixed else first


def _reviewed_unblocked(written: WrittenScenario) -> bool:
    """Whether a draft was reviewed and nothing blocks it."""
    return written.plan_check.status is not PlanCheckStatus.UNCHECKED and not is_blocked(written)


def _firsts_kept(slots: list[_Slot], outage: Unavailable) -> Iterator[tuple[str, WrittenScenario]]:
    """On an outage in the second round, each slot's usable draft, kept: a repair's first draft as it was,
    else its own draft checked, flagged with the outage when it has no review; a slot with no usable draft
    raises the outage (its path is retried, so a retry never throws a usable draft away)."""
    for slot in slots:
        if slot.first is not None:
            log.warning(
                LogEvent.WRITER_SCENARIO_REPAIRED, outcome="kept_first", error_type=type(outage).__name__
            )
            yield slot.label, slot.first
        elif slot.draft is not None:
            yield slot.label, _checked(slot, outage)
    if any(slot.first is None and slot.draft is None for slot in slots):
        raise outage


def _checked(slot: _Slot, outage: Unavailable | None = None) -> WrittenScenario:
    """The slot's draft with its exact findings and, unless one blocks it or the reviewer is off (unchecked,
    no warning), its review's verdict (`outage`: why it has none); a story whose step cannot open code's
    sentence gets a warning (code cites its own precedent), never a blocker."""
    draft, brief = _draft_of(slot), slot.brief
    findings = check_exact_rules(draft, brief)
    check: PlanCheck
    notes: tuple[Finding, ...]
    if _blocks(findings) or not _review_on():
        # no verdict could clear an exact blocker; with the reviewer off none is due, so none is missing
        check, notes = PlanCheck(PlanCheckStatus.UNCHECKED), ()
    else:
        not_made = str(outage) if outage else _rejected(AiTask.PLAN_CHECK, slot.review_problems)
        check, notes = _plan_check_of(brief, slot.review, not_made)
    cited = _cited_entry(brief) if _is_story(brief) else None
    if problem := evidence_sentence(draft.evidence_step, cited, slot.place)[1]:
        message = FindingMessage.CITATION_REMOVED.format(reason=problem)
        notes = (*notes, Finding(FindingCode.CITATION_REMOVED, message))
    return WrittenScenario(draft, (*findings, *notes), check, Route.STANDALONE, brief.threat)


def _rejected(task: AiTask, problems: Sequence[str]) -> str:
    """Why an answer stayed unusable, as a card or a warning says it."""
    message = ErrorMessage.AI_ANSWER_REJECTED.format(task=task, problems="; ".join(problems[:3]))
    return shorten_text(message, Writing.PROBLEM_MAX_CHARS)


# --- the reviewer's verdicts: meaning judged against the plan


def _plan_check_of(
    brief: WriterBrief, answer: PlanCheckAnswer | None, not_made: str
) -> tuple[PlanCheck, tuple[Finding, ...]]:
    """The review's check and its findings: a note per broken rule, a blocker when the threat or impact
    changed, a warning saying why (`not_made`) when no usable review came (the scenario is still saved)."""
    if answer is None:
        reason = shorten_text(not_made, Writing.PROBLEM_MAX_CHARS)
        log.warning(LogEvent.WRITER_PLAN_CHECK_NOT_MADE, message=reason)
        warning = FindingMessage.PLAN_CHECK_NOT_MADE.format(reason=reason)
        return PlanCheck(PlanCheckStatus.UNCHECKED), (Finding(FindingCode.PLAN_CHECK_NOT_MADE, warning),)
    broken = _broken_rules(answer)
    status = PlanCheckStatus.INCONSISTENT if broken else PlanCheckStatus.CONSISTENT
    check = PlanCheck(
        status,
        broken,
        same_threat=answer.same_threat,
        same_impact=answer.same_impact,
        actions_not_carried_out=_not_carried_out(brief.threat_actions, answer),
    )
    notes = tuple(Finding(FindingCode.PLAN_CHECK, problem) for problem in broken)
    return check, notes + _mismatch(answer)


def _not_carried_out(listed: tuple[str, ...], answer: PlanCheckAnswer) -> tuple[str, ...]:
    """Each of the brief's `listed` actions the reviewer did not judge "carried out", one left unjudged
    included."""
    done = {
        name_match_key(action)
        for action, verdict in answer.threat_actions.items()
        if verdict.strip().casefold() == "carried out"
    }
    return tuple(action for action in listed if name_match_key(action) not in done)


def _broken_rules(answer: PlanCheckAnswer) -> tuple[str, ...]:
    """Each listed action the reviewer says is not carried out, as a rule 1 note, then each rule it says is
    broken, as "Rule n: <its words>"; each cut to a note's size."""
    not_done = (
        f'Rule 1: "{action.strip()}" is {verdict.strip()}, not carried out'
        for action, verdict in answer.threat_actions.items()
        if verdict.strip().casefold() != "carried out"
    )
    broken = (
        f"Rule {number.strip()}: {verdict.strip()[len('broken') :].lstrip(' :-')}"
        for number, verdict in answer.rules.items()
        if verdict.strip().casefold().startswith("broken") and number.strip() not in Writing.RETIRED_RULES
    )
    return tuple(_within_reask(problem, Writing.PROBLEM_MAX_CHARS) for problem in (*not_done, *broken))[
        : Writing.MAX_PLAN_PROBLEMS
    ]


def _mismatch(answer: PlanCheckAnswer) -> tuple[Finding, ...]:
    """A statement of another threat, or a risk of another impact: a blocker round 2's repair may clear."""
    wrong = [
        part for part, same in (("threat", answer.same_threat), ("impact", answer.same_impact)) if not same
    ]
    if not wrong:
        return ()
    message = FindingMessage.SCENARIO_MISMATCH.format(parts=" and ".join(wrong))
    return (Finding(FindingCode.SCENARIO_MISMATCH, message),)


def _read_plan_check(answer: dict[str, Any]) -> tuple[PlanCheckAnswer | None, list[str]]:
    """The reviewer's answer, or the problems it has."""
    problems = answer_item_problems(PlanCheckAnswer, answer, "the reply")
    return (None, problems) if problems else (PlanCheckAnswer.model_validate(answer), [])


def _unjudged_actions(answer: dict[str, Any]) -> list[str]:
    """The problem when the reviewer judged none of PLAN's listed actions."""
    return [] if answer.get("threat_actions") else [AnswerProblem.THREAT_ACTION_VERDICTS_REQUIRED]


# --- the writer's own faults, found in code


def _acts_without_a_sentence(answer: dict[str, Any], actions: tuple[str, ...]) -> list[str]:
    """The problem when `answer`'s action_sentences gives no sentence number of its own scenario_statement
    for one of the brief's listed `actions`: each action must happen in the story, not only in the risk."""
    count = len(_story_sentences(str(answer.get("scenario_statement") or "")))
    given = answer.get("action_sentences")
    numbers = (
        {name_match_key(str(act)): _sentence_number(number) for act, number in given.items()}
        if isinstance(given, dict)
        else {}
    )
    missing = [act for act in actions if not 1 <= numbers.get(name_match_key(act), 0) <= count]
    if not missing:
        return []
    listed = ", ".join(json.dumps(act, ensure_ascii=False) for act in missing)
    return [AnswerProblem.ACTION_SENTENCES_MISSING.format(actions=listed)]


def _story_sentences(statement: str) -> list[str]:
    """`statement`'s sentences in order, the first numbered 1."""
    return [sentence for sentence in _SENTENCE_END.split(statement.strip()) if sentence]


def _sentence_number(value: Any) -> int:
    """`value` as a sentence number (an integer or a numeric string); 0, never a sentence, otherwise."""
    if isinstance(value, str) and value.strip().isdecimal():
        return int(value)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _fixes(repair: WrittenScenario, first: WrittenScenario) -> bool:
    """True when `repair` was reviewed, is not blocked (another threat or impact blocks), has no listed action
    to repair (_listed_actions) and breaks no rule `first` held (each problem starts "Rule n:")."""
    check = repair.plan_check
    if check.status is PlanCheckStatus.UNCHECKED or _listed_actions(check) or is_blocked(repair):
        return False  # a review not made is never a pass
    repair_rules, first_rules = (
        {problem.split(":", 1)[0] for problem in written.plan_check.problems} for written in (repair, first)
    )
    return repair_rules <= first_rules


# --- the evidence sentence: built by code from the writer's step and the cited entry


def evidence_sentence(step: str, cited: dict[str, Any] | None, place: int) -> tuple[str, str]:
    """(the closing sentence: the writer's `step`, a link, the cited entry's title and who used it, or its
    first fact; why the step cannot open it, '' when it can). The sentence is '' when the step fails or
    nothing is tied: code's precedent (_claim) is cited then."""
    title = (_safe_facts([str((cited or {}).get("title") or "")]) or [""])[0]
    # nothing to tie a step to, or a title that would break the marker: code's precedent stands alone
    if cited is None or not title or "[" in title or _SENTENCE_END.search(title):
        return "", ""
    step = " ".join(step.split()).rstrip(" .,;:")
    facts = _safe_facts(_stated_facts(cited))
    if fault := _step_fault(step, title, facts):
        return "", fault
    sentence = _tied(step[:1].upper() + step[1:], cited, title, facts, place)
    most = get_settings().evidence_words[1]
    if len(sentence.split()) > most:
        return "", Precedent.TOO_LONG.format(most=most)
    return sentence, ""


def _tied(step: str, cited: dict[str, Any], title: str, facts: list[str], place: int) -> str:
    """`step` tied to the cited entry by a link (a related one for nearest evidence) and, for a technique, a
    users form: `place` picks both, so the 6 slots of a set never share a link and use each form twice."""
    links = Precedent.RELATED_LINKS if cited.get("nearest") else Precedent.LINKS
    link = links[place % len(links)]
    if cited.get("kind") != IntelKind.TECHNIQUE:
        fact = facts[0].removesuffix(".")
        return Precedent.ABOUT_SENTENCE.format(step=step, link=link, title=title, fact=fact)
    names = _reader_names(facts)[: EvidenceLimits.REAL_WORLD_USERS]
    form = Precedent.USERS[place % len(Precedent.USERS)]
    users = form.format(names=" and ".join(names), verb="has" if len(names) == 1 else "have")
    return Precedent.SENTENCE.format(step=step, link=link, title=title, users=users)


def _step_fault(step: str, title: str, facts: list[str]) -> str:
    """Why the writer's step cannot open code's sentence ('' when it can): none, a marker, redaction, link,
    code, label or quote, more than one sentence, or an opening on the cited title or on who used it."""
    if not step:
        return Precedent.NOT_WRITTEN
    marked = any(mark in step for mark in '["“”')  # "[": a marker or a redaction
    if marked or any(pattern.search(step) for pattern in (_URL, ID_IN_TEXT, _INTERNAL_LABEL, _ADVISORY_ID)):
        return Precedent.NOT_PLAIN
    if _SENTENCE_END.search(step):
        return Precedent.MANY_SENTENCES
    users = [match["name"] or match["campaign"] for match in filter(None, map(_USER.fullmatch, facts))]
    opening = _LEADING_ARTICLE.sub("", step).casefold()
    on_evidence = any(opening.startswith(name.casefold()) for name in (title, *users))
    return Precedent.OPENS_ON_EVIDENCE if on_evidence else ""


def _cited_entry(brief: WriterBrief) -> dict[str, Any] | None:
    """The evidence entry a story cites (as code's own claim picks it); None when none is citable."""
    return (_precedent(brief.evidence) or (None, ""))[0]


def _read_draft(
    answer: dict[str, Any], options: tuple[str, ...], systems: tuple[BriefSystem, ...]
) -> tuple[ScenarioDraft | None, list[str]]:
    """The writer's answer as a draft, or the problems of an unreadable one; its entry point and every
    supporting system's reason are settled by code, never a fault."""
    problems = answer_item_problems(ScenarioAnswer, answer, "the reply")
    if problems:
        return None, problems
    reply = ScenarioAnswer.model_validate(answer)
    statement = reply.scenario_statement.strip()
    draft = ScenarioDraft(
        title=reply.scenario_title.strip(),
        statement=statement,
        risk=reply.risk_statement.strip(),
        assumptions=tuple(assumption.strip() for assumption in reply.assumptions),
        entry_point=_offered_entry_point(reply.entry_point, options),
        system_reasons=_reasons_by_system(reply.system_reasons, systems, statement),
        evidence_step=reply.evidence_step or "",
    )
    return draft, []


def _reasons_by_system(
    written: dict[str, str], systems: tuple[BriefSystem, ...], statement: str
) -> tuple[tuple[str, str], ...]:
    """Each brief system with its reason, in the brief's order (_system_reason)."""
    return tuple((system.name, _system_reason(system, written, statement)) for system in systems)


def _system_reason(system: BriefSystem, written: dict[str, str], statement: str) -> str:
    """Code's sentence for a "no" system; for a "yes" one the writer's reason (its name in any of its forms:
    "DCS" for "Distributed Control System (DCS)"), else the story's first sentence naming it, else code's."""
    if not system.applicable:
        return Writing.NOT_REACHED_REASON
    given = (reason.strip() for name, reason in written.items() if is_same_name(system.name, name))
    named = (line for line in _SENTENCE_END.split(statement) if find_name_mentions(system.name, line))
    return next(filter(None, given), "") or next(named, Writing.REACHED_REASON)


def _offered_entry_point(written: str, options: tuple[str, ...]) -> str:
    """The option the answer names, in any of its forms, else the first, as code assigns it from the path
    (D14); "" when the threat acts on the asset itself."""
    named = (option for option in options if is_same_name(option, written))
    return next(named, options[0] if options else "")


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
        "rewritten": written.rewritten,
    }
    if status == ScenarioStatus.DONE:
        record["controls"] = _queued_controls(now)
    return record


def _queued_controls(now: datetime) -> dict[str, Any]:
    """A done card's controls, queued with the writer's request id and API call: a later delivery maps them
    under these, whatever the run's job is now."""
    origin = {"request_id": current_request_id(), "origin": current_job_origin()}
    return {"status": Status.QUEUED, "attempts": 0, "queued_at": now, **origin}


def _prompt_version_of(style: WriterStyle) -> str:
    """Which prompts wrote a scenario: the evidence story's or the original writer's."""
    evidence_story = style is WriterStyle.EVIDENCE_STORY
    return PromptVersion.SCENARIO_WRITER_EVIDENCE if evidence_story else PromptVersion.SCENARIO_WRITER


def _cited(brief: WriterBrief, draft: ScenarioDraft) -> tuple[str, list[dict[str, Any]]]:
    """An evidence story's statement ending in its closing sentence (code's, from the writer's step, else
    code's precedent), citing [1], and the one entry it cites."""
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
    goes through it and its reason (_system_reason); by recorded name, never the prompt's redacted one."""
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
