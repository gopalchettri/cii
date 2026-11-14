"""Writing one scenario per attack path, a set at a time: brief, prompts, exact checks, card, duplicates."""

import dataclasses
import functools
import json
import re
import uuid
from collections import Counter
from collections.abc import Collection, Iterable, Iterator, Sequence
from datetime import datetime
from typing import Any

import structlog

from app.ai import ChatModel, RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
from app.core.asset_types import place_asset_types
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    EMBEDDING_SOURCE_TABLE,
    QUERY_TASKS,
    REAL_WORLD_USER,
    ActorRole,
    AiLimits,
    AiTask,
    AnswerProblem,
    AttackerCheck,
    ContextProperties,
    ControlMatch,
    ControlMessage,
    Controls,
    Decision,
    EmbeddingCorpus,
    ErrorCode,
    ErrorMessage,
    EvidenceBlock,
    EvidenceFact,
    FindingCode,
    FindingMessage,
    IntelKind,
    LibraryStatus,
    LogEvent,
    PathProblem,
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
    ThreatFinding,
    WriterStyle,
    Writing,
)
from app.core.exceptions import ControlsNotMapped, PathNotWritable, Unavailable
from app.core.logging import current_job_origin, current_request_id
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.external_intelligence.injection_patterns import ECHO_PATTERNS
from app.domain.external_intelligence.text_cleaner import ID_IN_TEXT
from app.domain.external_intelligence.untrusted_text import UntrustedTextSanitiser
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
    threat_name_key,
    threat_name_without_code,
)
from app.domain.shared.prompt_redaction import facts_safe_for_prompt, without_platform_note
from app.models.external_intelligence.evidence_view import markers_of
from app.models.library.library import LibraryControl
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.controls import ControlMapping, ControlQuery, ControlRule, MappedControl
from app.models.scenario.write import (
    BriefSystem,
    Finding,
    LiveLibrary,
    PathFailure,
    ScenarioAnswer,
    ScenarioDraft,
    WriterBrief,
    WrittenScenario,
)
from app.search.snapshot import LibrarySnapshot
from app.search.texts import describe_control

log = structlog.get_logger(__name__)

# --- the writer's prompts ([scenario.writer] in app/prompts.toml)

_WRITER_PROMPTS: dict[str, str] = PROMPTS["scenario"]["writer"]
WRITER_SYSTEM_PROMPT: str = _WRITER_PROMPTS["text"]
#: A slot's line with intelligence off, or nothing citable found: no evidence is fabricated or implied.
NO_EVIDENCE: str = _WRITER_PROMPTS["no_evidence"].strip()
_REWRITE_INSTRUCTION: str = _WRITER_PROMPTS["rewrite"]  # told with a slot's problems in its earlier answer
#: A slot's own problems in a set's answer, told in its rewrite.
_SLOT_MISSING: str = _WRITER_PROMPTS["slot_missing"]
_THREAT_NOT_COPIED: str = _WRITER_PROMPTS["threat_not_copied"]

# --- evidence: its texts cleaned once per brief, by one sanitiser (it holds only compiled patterns)

_SANITISER = UntrustedTextSanitiser()
_ECHO_SANITISER = UntrustedTextSanitiser(ECHO_PATTERNS, (), ())
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)),
    re.IGNORECASE,
)
#: Facts true of a technique in general, never of who used it: kept on the card, never shown to an AI.
_TACTICS_FACT_PREFIX = str(EvidenceFact.TACTICS).split("{")[0]
_MITIGATED_BY_FACT_PREFIX = str(EvidenceFact.MITIGATED_BY).split("{")[0]
_REAL_WORLD_USER_FACT = re.compile(REAL_WORLD_USER)
#: How every user fact ends (EvidenceFact.USED_BY and CAMPAIGN_USED), a named one or not.
_USER_FACT_END = "used this technique."

# --- the brief's name clean-up

#: The joiners of a list of systems, before and after one of its names (", ", " and ", ", or ").
_LIST_BEFORE = re.compile(r"(?:,\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+)$", re.IGNORECASE)
_LIST_AFTER = re.compile(r",\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
#: The words tying a system's name to an action ("steal secrets from", "deploy wiper to the"), at text's end.
_ACTION_TIE = re.compile(
    r"\b(?:on|from|to|in|into|against|of|across|for|at|via|between|and|targeting|with)\s+(?:the\s+)?$",
    re.IGNORECASE,
)
_TRAILING_THE = re.compile(r"\bthe\s+$", re.IGNORECASE)
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
#: The gate's likelihood as the brief says it.
_LIKELIHOOD_WORDS = {rank: word for word, rank in ThreatFinding.LIKELIHOOD_RANK.items()}
#: The asset facts under the names the brief shows; every other fact keeps its own name.
_ASSET_FACT_NAMES = {
    "cii_asset_description": "description",
    "asset_type": "type",
    "asset_priority": "priority",
}

# --- the exact checks: safety and data integrity only

#: The planner's aliases and slots (SYS1, THR7) and a set's slots (SC2): never in a brief, so one in a
#: scenario was made up or leaked from another slot.
_INTERNAL_LABEL = re.compile(r"\b(?:SYS|THR|SC)\d+\b")
#: Letters outside the Latin script ("恢复"): an answer that left English, unless the brief gave them.
_NOT_LATIN = re.compile(r"[^\W\d_A-Za-zª-ɏḀ-ỿ]+")
_LEADING_ARTICLE = re.compile(r"^the\s+", re.IGNORECASE)
#: A public advisory number: CVE, CISA ICS advisory (ICSA, ICSMA), GitHub (GHSA), Microsoft bulletin, CERT/CC.
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3})\b|\bVU#\d+",
    re.IGNORECASE,
)
_CITATION_MARKER = re.compile(r"\s*\[\d+(?:\s*,\s*\d+)*\]")
#: A path's first scenario is version 1; a regenerated one is the next version of its path.
FIRST_VERSION = 1
_ABSENT = object()  # a fact the shared block does not hold


# --- the brief, built by code: no AI call, no database id, every text redacted


def build_writer_input(
    threats: dict[str, dict[str, Any]],
    path: dict[str, Any],
    context: FrozenContext,
    budget: int,
    live: LiveLibrary,
    style: WriterStyle = WriterStyle.ORIGINAL,
) -> WriterBrief:
    """Builds the path's brief within `budget` characters; a story only when an entry is citable."""
    threat, systems = _get_path_threat_or_refuse(threats, path, context, live)
    evidence = tuple(threat.get("evidence") or ()) if style is WriterStyle.EVIDENCE_STORY else ()
    cleaned, cited, claim = _clean_evidence_and_pick_cited_entry(evidence)
    asset, named = _shorten_facts_to_fit(context, systems, cited is not None, budget)
    supporting = tuple(
        BriefSystem(system["id"], redact(system["name"]), system["id"] in path["systems"])
        for system in context.systems
    )
    facts = _describe_path_for_writer(threat, path, context, named, supporting)
    return WriterBrief(
        asset=asset,
        systems=tuple(named),
        facts=facts,
        threat=facts["threat"]["threat"],
        threat_actions=tuple(facts["threat"].get("threat_actions") or ()),
        supporting_systems=supporting,
        entry_options=tuple(facts["entry_point_options"]),
        evidence=evidence if cited is not None else (),
        cleaned_evidence=cleaned if cited is not None else (),
        cited_index=cited,
        cited_claim=claim,
        brief_text=as_json({"asset": asset, "systems": named} | facts).casefold(),
    )


def _get_path_threat_or_refuse(
    threats: dict[str, dict[str, Any]], path: dict[str, Any], context: FrozenContext, live: LiveLibrary
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Returns the path's one threat and its frozen systems, or raises PathNotWritable before any AI call."""
    path_id, steps = path["path_id"], path.get("steps") or []
    threat = threats.get(steps[0]) if len(steps) == 1 else None
    if threat is None:
        raise PathNotWritable(path_id, PathProblem.NOT_ONE_THREAT)
    if path.get("category") not in StrideCategory:
        raise PathNotWritable(path_id, PathProblem.CATEGORY_UNKNOWN)
    if not (threat["type"]["name"] or "").strip() or not (threat["name"] or "").strip():
        raise PathNotWritable(path_id, PathProblem.THREAT_UNNAMED)
    if not threat["actors"] or threat["actors"][0]["role"] != ActorRole.ACTING:
        raise PathNotWritable(path_id, PathProblem.NO_ACTING_ATTACKER)
    if threat.get("attacker_check") == AttackerCheck.NONE_FITS:  # never a forced attribution
        raise PathNotWritable(path_id, PathProblem.ATTACKER_UNSUPPORTED)
    if threat["library_id"] is not None:
        retired = threat["library_id"] not in live.threat_ids
    else:
        retired = threat["type"]["id"] not in live.type_ids
    if retired:
        raise PathNotWritable(path_id, PathProblem.THREAT_RETIRED, ErrorCode.LIBRARY_RECORD_RETIRED)
    if threat["actors"][0]["id"] not in live.actor_ids:
        raise PathNotWritable(path_id, PathProblem.ATTACKER_RETIRED, ErrorCode.LIBRARY_RECORD_RETIRED)
    by_id = {system["id"]: system for system in context.systems}
    if any(system_id not in by_id for system_id in path["systems"]):
        raise PathNotWritable(path_id, PathProblem.SYSTEM_NOT_IN_RUN)
    return threat, [by_id[system_id] for system_id in path["systems"]]


def _shorten_facts_to_fit(
    context: FrozenContext, systems: list[dict[str, Any]], story: bool, budget: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Returns the asset's facts and each path system's, each its name first, cut to `budget`."""
    own, organisation = context.own_and_organisation_facts()
    asset = {_ASSET_FACT_NAMES.get(key, key): value for key, value in own.items()}
    if story:
        asset[ContextProperties.COUNTRY_KEY] = get_settings().context_country
    background = "; ".join(str(value) for value in organisation.values() if value)
    asset |= {ContextProperties.ORGANISATION_BRIEF_KEY: background} if background else {}
    parts = [(context.asset["name"], asset)]
    parts += [(system["name"], FrozenContext.read_system_facts(system)) for system in systems]
    named = [
        {"name": redact(" ".join(str(name).split())), **facts_safe_for_prompt(facts | {"name": None})}
        for name, facts in parts  # the name is never dropped
    ]
    cut_asset, *cut_systems = cut_to_fit(named, budget)
    return cut_asset, cut_systems


def _describe_path_for_writer(
    threat: dict[str, Any],
    path: dict[str, Any],
    context: FrozenContext,
    named: list[dict[str, Any]],
    supporting: tuple[BriefSystem, ...],
) -> dict[str, Any]:
    """Builds the brief's own fields: category, attacker, likelihood, threat, entry options, systems."""
    entry = path.get("entry_system")
    entry_name = named[path["systems"].index(entry)]["name"] if entry in path["systems"] else ""
    actions = _remove_system_names_from_actions(threat, context)
    why_attacker = _remove_other_system_names_from_reason(
        threat["attacker_check_reason"] or "", path, context
    )
    kind_reason = (threat.get("reasons") or {}).get(path["category"]) or threat["reason"]
    return {
        "category": StrideCategory(path["category"]),
        "attacker": threat["actors"][0]["name"],
        **({"why_this_attacker": why_attacker} if why_attacker else {}),
        "likelihood": _LIKELIHOOD_WORDS[threat["likelihood"]],
        "threat": {
            "threat_type": threat_name_without_code(threat["type"]["name"]),
            "threat": threat_name_without_code(threat["name"]),
            **({"threat_actions": list(actions)} if actions else {}),
            "why_it_applies": _remove_other_system_names_from_reason(
                without_platform_note(str(kind_reason)), path, context
            ),
        },
        "entry_point_options": [entry_name] if entry_name else [system["name"] for system in named],
        "supporting_systems": [
            {"name": system.name, "applicable": "yes" if system.applicable else "no"} for system in supporting
        ],
    }


def _remove_other_system_names_from_reason(reason: str, path: dict[str, Any], context: FrozenContext) -> str:
    """Removes from `reason` the systems this path is not on, then redacts it."""
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
            reason, edge = _remove_one_system_name_from_reason(reason, start, end, names), start
    repeated = rf"{Writing.OTHER_SYSTEM}(?:,? (?:and |or )?{Writing.OTHER_SYSTEM})+"
    return redact(re.sub(repeated, Writing.OTHER_SYSTEMS, reason))


def _remove_one_system_name_from_reason(reason: str, start: int, end: int, names: list[str]) -> str:
    """Removes the name at [start, end): with its list joiner, else as the placeholder."""
    head, tail = reason[:start], reason[end:]
    known = tuple(name.casefold() for name in (*names, Writing.OTHER_SYSTEM))
    joiner = _LIST_BEFORE.search(head)
    if joiner and head[: joiner.start()].rstrip().casefold().endswith(known):
        return head[: joiner.start()] + tail
    joiner = _LIST_AFTER.match(tail)
    if joiner and tail[joiner.end() :].casefold().removeprefix("the ").startswith(known):
        return head + tail[joiner.end() :]
    return head + Writing.OTHER_SYSTEM + tail


def _remove_system_names_from_actions(threat: dict[str, Any], context: FrozenContext) -> tuple[str, ...]:
    """Returns the threat's listed actions with no system named, each once, redacted."""
    names = [system["name"] for system in context.systems]
    actions: dict[str, str] = {}
    for listed in threat.get("actions") or ():
        action = str(listed)
        spans: list[tuple[int, int]] = []
        for start, end in sorted(span for name in names for span in find_name_mentions(name, action)):
            if spans and (start < spans[-1][1] or _NAME_LIST_GAP.fullmatch(action[spans[-1][1] : start])):
                spans[-1] = (spans[-1][0], max(end, spans[-1][1]))
            else:
                spans.append((start, end))
        for start, end in reversed(spans):  # from the end, so earlier spans keep their place
            action = _remove_one_system_name_from_action(action, start, end)
        bare = " ".join(action.split())
        if key := name_match_key(bare):
            actions.setdefault(key, bare)
    name = threat_name_without_code(threat["name"])
    if len(actions) > 1 and _OR_JOINER.search(name) and not _AND_JOINER.search(name):
        return (redact(" or ".join(actions.values())),)
    return tuple(redact(action) for action in actions.values())


def _remove_one_system_name_from_action(action: str, start: int, end: int) -> str:
    """Removes the system name at [start, end) from `action`, keeping its meaning."""
    head, tail = action[:start], action[end:]
    article = _TRAILING_THE.search(head)
    bare_head = head[: article.start()] if article else head
    if described := _NAME_DESCRIBES.match(tail):
        return f"{bare_head} {tail[described.end() - 1 :]}"
    tie_words = _ACTION_TIE.search(head)
    if tie_words and len(head[: tie_words.start()].split()) > 1:  # more than a bare verb is left
        return head[: tie_words.start()] + tail
    return f"{bare_head}{Writing.ACTION_SYSTEM}{tail}" if bare_head.strip() else tail


def _clean_evidence_and_pick_cited_entry(
    evidence: Sequence[dict[str, Any]],
) -> tuple[tuple[tuple[str, tuple[str, ...]], ...], int | None, str]:
    """Cleans each entry once; returns them, the first citable entry's index and its claim."""
    cleaned = []
    for entry in evidence:
        stated = [
            fact
            for fact in entry.get("facts") or ()
            if not fact.strip().startswith((_TACTICS_FACT_PREFIX, _MITIGATED_BY_FACT_PREFIX))
        ]
        texts = []
        for text in [str(entry.get("title") or ""), *stated]:
            bare = " ".join(_URL.sub("", ID_IN_TEXT.sub("", redact(text))).replace("()", "").split())
            safe = _SANITISER.sanitise(
                " ".join(_LOOK_ALIKES.sub(" ", bare).split()), TextSafety.MAX_FACT_CHARS
            )
            texts.append("" if safe.unsafe else safe.text)
        entry_title, *entry_facts = texts
        cleaned.append((entry_title, tuple(fact for fact in entry_facts if fact)))
    for index, (entry, (title, facts)) in enumerate(zip(evidence, cleaned, strict=True)):
        related = bool(entry.get("nearest"))
        claim = ""
        if entry.get("kind") != IntelKind.TECHNIQUE and facts:
            fact = facts[0].removesuffix(".")
            claim = Precedent.RELATED_RECORD.format(fact=fact) if related else fact
        elif (
            entry.get("kind") == IntelKind.TECHNIQUE
            and title
            and any(map(_REAL_WORLD_USER_FACT.fullmatch, facts))
        ):
            claim = (Precedent.RELATED_TO if related else Precedent.COULD_USE).format(technique=title)
        # one plain sentence: a "[" (a redaction) or an inner sentence end would break the marker
        if claim and "[" not in claim and not _SENTENCE_END.search(claim):
            return tuple(cleaned), index, claim
    return tuple(cleaned), None, ""


# --- the writer's prompts


def build_writer_system_prompt() -> str:
    """Builds the writer's system prompt with the configured word ranges."""
    settings = get_settings()
    prompt = WRITER_SYSTEM_PROMPT + _WRITER_PROMPTS["set"]
    ranges = (
        (Writing.SCENARIO_WORDS_SLOT, settings.scenario_words),
        (Writing.RISK_WORDS_SLOT, settings.risk_words),
    )
    for slot, (least, most) in ranges:
        prompt = prompt.replace(slot, f"{least} to {most}")
    return prompt


def build_writer_prompt(
    slots: Sequence[tuple[str, WriterBrief, str]], system_prompt: str | None = None
) -> ChatPrompt:
    """Builds one call's (system, user) prompt: the shared facts once, then each slot."""
    # ponytail: the asset's records are grouped under None, beside each system's records under its name
    by_name: dict[str | None, list[dict[str, Any]]] = {None: [brief.asset for _, brief, _ in slots]}
    for _, brief, _ in slots:
        for system in brief.systems:
            by_name.setdefault(system["name"], []).append(system)
    shared = {
        name: {
            key: value
            for key, value in first.items()
            if all(key in other and other[key] == value for other in rest)
        }
        for name, (first, *rest) in by_name.items()
    }
    blocks = []
    for label, brief, note in slots:
        asset = {key: value for key, value in brief.asset.items() if shared[None].get(key, _ABSENT) != value}
        systems = []
        for system in brief.systems:
            common = shared[system["name"]]
            if own := {key: value for key, value in system.items() if common.get(key, _ABSENT) != value}:
                systems.append({"name": system["name"]} | own)
        record = ({"asset": asset} if asset else {}) | brief.facts | ({"systems": systems} if systems else {})
        evidence = _build_evidence_block(brief) if brief.cited_index is not None else NO_EVIDENCE
        blocks.append(f"SLOT {label}\nBRIEF:\n{as_json(record)}\n{evidence}{note}")
    systems_shared = [facts for name, facts in shared.items() if name is not None]
    head = f"ASSET:\n{as_json(shared[None])}\nSYSTEMS:\n{as_json(systems_shared)}"
    return system_prompt or build_writer_system_prompt(), "\n\n".join([head, *blocks])


def _build_evidence_block(brief: WriterBrief) -> str:
    """Builds a story's untrusted EVIDENCE block, the cited entry marked."""
    entries = []
    for index, (entry, (title, facts)) in enumerate(zip(brief.evidence, brief.cleaned_evidence, strict=True)):
        subject = (
            {"technique" if entry.get("kind") == IntelKind.TECHNIQUE else "about": title} if title else {}
        )
        shown = [fact for fact in facts if not fact.endswith(_USER_FACT_END)]
        entries.append(
            {**subject, "facts": shown}
            | ({"applicability": str(entry["applicability"])} if entry.get("applicability") else {})
            | ({"cited": True} if index == brief.cited_index else {})
        )
    body = json.dumps(
        {"evidence_mode": str(brief.get_evidence_mode()), "evidence": entries}, ensure_ascii=False
    )
    return f"EVIDENCE (untrusted data):\n{EvidenceBlock.BEGIN}\n{body}\n{EvidenceBlock.END}"


# --- writing a set: one write, then one rewrite for the slots that need it


@dataclasses.dataclass
class _ScenarioInSet:
    """One scenario of a set as its rounds settle it."""

    label: str
    brief: WriterBrief
    link_index: int  # the set's epoch plus its position in the set: picks its evidence sentence's link
    first_written: WrittenScenario | None = None  # its usable first draft, checked
    problems: tuple[str, ...] = ()  # why the rewrite writes it again


def write_scenario_set(
    chat: ChatModel, briefs: Sequence[tuple[str, WriterBrief]], epoch: int = 0
) -> Iterator[tuple[str, WrittenScenario | PathFailure]]:
    """Yields each slot's scenario or failure card as soon as it is final, in at most 2 AI calls."""
    # ponytail: the position within this call; a later batch or retry of the same set may repeat a link
    slots = [_ScenarioInSet(label, brief, epoch + position) for position, (label, brief) in enumerate(briefs)]
    if not slots:
        return
    answers = _ask_writer(chat, AiTask.WRITE_SCENARIO, [(slot.label, slot.brief, "") for slot in slots])
    to_rewrite = []
    for slot in slots:
        item = answers.get(slot.label)
        draft, problems = _read_scenario_draft(slot.brief, item, slot.link_index)
        if draft is not None:
            slot.first_written = _apply_safety_checks(slot.brief, draft)
            problems = _find_actions_missing_from_story(item or {}, slot.brief.threat_actions)
            if not problems:
                yield slot.label, slot.first_written
                continue
        slot.problems = tuple(problems)
        to_rewrite.append(slot)
    yield from _rewrite_failed_scenarios(chat, to_rewrite)


def _rewrite_failed_scenarios(
    chat: ChatModel, slots: list[_ScenarioInSet]
) -> Iterator[tuple[str, WrittenScenario | PathFailure]]:
    """Asks one rewrite for the slots to write again and yields what each keeps."""
    most, asked = AiLimits.REASK_PROBLEM_CHARS, []
    for slot in slots:
        shown = slot.problems[: AiLimits.REASK_MAX_PROBLEMS]
        cut = (problem if len(problem) <= most else problem[:most].rsplit(" ", 1)[0] for problem in shown)
        asked.append((slot.label, slot.brief, _REWRITE_INSTRUCTION.replace("{problems}", "; ".join(cut))))
    try:
        answers = _ask_writer(chat, AiTask.REPAIR_SCENARIO, asked)
    except (UnreadableAiAnswer, TruncatedAiAnswer) as error:  # every slot's rewrite is unusable
        log.warning(LogEvent.WRITER_PATH_FAILED, message=str(error), error_type=type(error).__name__)
        answers = {}
    except Unavailable as outage:
        yield from ((slot.label, slot.first_written) for slot in slots if slot.first_written is not None)
        if any(slot.first_written is None for slot in slots):
            raise outage
        return
    for slot in slots:
        draft, problems = _read_scenario_draft(slot.brief, answers.get(slot.label), slot.link_index)
        rewrite, kept = (
            (_apply_safety_checks(slot.brief, draft) if draft is not None else None),
            slot.first_written,
        )
        if rewrite and (kept is None or kept.list_blocking_codes() or not rewrite.list_blocking_codes()):
            kept = rewrite
        if kept is None:
            message = ErrorMessage.AI_ANSWER_REJECTED.format(
                task=AiTask.REPAIR_SCENARIO, problems="; ".join(problems[:3])
            )
            yield (
                slot.label,
                PathFailure(ErrorCode.GENERATION_FAILED, shorten_text(message, Writing.PROBLEM_MAX_CHARS)),
            )
        else:
            yield slot.label, kept


def _ask_writer(
    chat: ChatModel, task: AiTask, slots: list[tuple[str, WriterBrief, str]]
) -> dict[str, dict[str, Any]]:
    """Returns each slot's answer item, from one call or the halves the size check makes."""
    items: dict[str, dict[str, Any]] = {}
    build_prompt = functools.partial(build_writer_prompt, system_prompt=build_writer_system_prompt())
    for part in within_call_limit(slots, build_prompt, task) if slots else ():
        read_answer = functools.partial(_read_writer_answer, asked={label for label, _, _ in part})
        items |= ask_ai_and_check(chat, task, build_prompt(part), read_answer, reuse_earlier_answer=True)
    return items


def _read_writer_answer(
    answer: dict[str, Any], asked: set[str]
) -> tuple[dict[str, dict[str, Any]] | None, list[str]]:
    """Returns each asked slot's item, or the problem when the answer holds no scenarios list."""
    kept, problems = answers_for_asked_slots(answer, "scenarios", asked)
    if not isinstance(answer.get("scenarios"), list):
        return None, problems
    # ponytail: the entity read back through the item's JSON text, so every key and value is covered at once
    unescaped = (json.loads(json.dumps(item, ensure_ascii=False).replace("&amp;", "&")) for item in kept)
    return {str(item["slot"]): item for item in unescaped}, []


def _read_scenario_draft(
    brief: WriterBrief, item: dict[str, Any] | None, link_index: int
) -> tuple[ScenarioDraft | None, list[str]]:
    """Returns a slot's draft from its answer item, or the problems that have it written again."""
    if item is None:
        return None, [_SLOT_MISSING]
    if name_match_key(str(item.get("threat") or "")) != name_match_key(brief.threat):
        return None, [_THREAT_NOT_COPIED]  # another slot's answer, or none: written again
    if words := _list_ids_not_given_to_writer(
        _NOT_LATIN, json.dumps(item, ensure_ascii=False), brief.brief_text
    ):
        return None, [AnswerProblem.NOT_ENGLISH.format(words=words)]  # a model slipping into Chinese
    if problems := answer_item_problems(ScenarioAnswer, item, "the reply"):
        return None, problems
    reply = ScenarioAnswer.model_validate(item)
    statement = reply.scenario_statement.strip()
    options = brief.entry_options
    sentence, evidence_problem = _build_evidence_sentence(reply.evidence_step or "", brief, link_index)
    draft = ScenarioDraft(
        title=reply.scenario_title.strip(),
        statement=statement,
        risk=reply.risk_statement.strip(),
        assumptions=tuple(assumption.strip() for assumption in reply.assumptions),
        entry_point=next(
            (option for option in options if is_same_name(option, reply.entry_point)),
            options[0] if options else "",
        ),
        system_reasons=tuple(
            (system.name, _pick_reason_for_system(system, reply.system_reasons, statement))
            for system in brief.supporting_systems
        ),
        evidence_statement=sentence,
        evidence_problem=evidence_problem,
    )
    return draft, []


def _pick_reason_for_system(system: BriefSystem, written: dict[str, str], statement: str) -> str:
    """Returns the reason the card shows for one supporting system."""
    if not system.applicable:
        return Writing.NOT_REACHED_REASON
    given = (reason.strip() for name, reason in written.items() if is_same_name(system.name, name))
    named = (line for line in _SENTENCE_END.split(statement) if find_name_mentions(system.name, line))
    return next(filter(None, given), "") or next(named, Writing.REACHED_REASON)


def _find_actions_missing_from_story(item: dict[str, Any], actions: tuple[str, ...]) -> list[str]:
    """Returns the problem when a listed action has no sentence number in its own story."""
    if not actions:
        return []
    count = len(
        [part for part in _SENTENCE_END.split(str(item.get("scenario_statement") or "").strip()) if part]
    )
    given = item.get("action_sentences")
    numbers: dict[str, list[int]] = {}
    for act, value in given.items() if isinstance(given, dict) else ():
        found: list[int] = []
        for number in value if isinstance(value, list) else [value]:
            if isinstance(number, str):
                found += [int(digits) for digits in re.findall(r"\d+", number)]
            elif isinstance(number, float) and number.is_integer() or type(number) is int:
                found.append(int(number))
        numbers[name_match_key(str(act))] = found
    missing = [
        act
        for act in actions
        if not any(1 <= number <= count for number in numbers.get(name_match_key(act), []))
    ]
    if not missing:
        return []
    listed = ", ".join(json.dumps(act, ensure_ascii=False) for act in missing)
    return [AnswerProblem.ACTION_SENTENCES_MISSING.format(actions=listed)]


def _build_evidence_sentence(step: str, brief: WriterBrief, link_index: int) -> tuple[str, str]:
    """Returns (a story's closing sentence, why the writer's step cannot open it)."""
    title, facts = brief.cleaned_evidence[brief.cited_index] if brief.cited_index is not None else ("", ())
    # nothing to tie a step to, or a title that would break the marker: code's claim stands alone
    if not title or "[" in title or _SENTENCE_END.search(title):
        return "", ""
    cited = brief.evidence[brief.cited_index] if brief.cited_index is not None else {}
    step = " ".join(step.split()).rstrip(" .,;:")
    users = [
        match["name"] or match["campaign"]
        for match in filter(None, map(_REAL_WORLD_USER_FACT.fullmatch, facts))
    ]
    is_gerund_title = bool(title.split()[:1]) and title.split()[0].casefold().endswith("ing")
    patterns = (_URL, ID_IN_TEXT, _INTERNAL_LABEL, _ADVISORY_ID)
    if not step:
        return "", Precedent.NOT_WRITTEN
    if any(mark in step for mark in '["“”') or any(pattern.search(step) for pattern in patterns):
        return "", Precedent.NOT_PLAIN
    if _SENTENCE_END.search(step):
        return "", Precedent.MANY_SENTENCES
    if any(find_name_mentions(user, step) for user in users if user):
        return "", Precedent.NAMES_A_USER
    if not is_gerund_title and _LEADING_ARTICLE.sub("", step).casefold().startswith(title.casefold()):
        return "", Precedent.OPENS_ON_EVIDENCE
    links = Precedent.RELATED_LINKS if cited.get("nearest") else Precedent.LINKS
    link, step = links[link_index % len(links)], step[:1].upper() + step[1:]
    if cited.get("kind") != IntelKind.TECHNIQUE:
        fact = facts[0].removesuffix(".")
        sentence = Precedent.ABOUT_SENTENCE.format(step=step, link=link, title=title, fact=fact)
    else:
        sentence = Precedent.SENTENCE.format(step=step, link=link, title=title)
    most = get_settings().evidence_words[1]
    return ("", Precedent.TOO_LONG.format(most=most)) if len(sentence.split()) > most else (sentence, "")


def _list_ids_not_given_to_writer(pattern: re.Pattern[str], text: str, given: str) -> str:
    """Lists each match the brief did not supply, once, in order ('' when none)."""
    found = (match[0] for match in pattern.finditer(text) if match[0].casefold() not in given)
    return ", ".join(dict.fromkeys(found))


def _apply_safety_checks(brief: WriterBrief, draft: ScenarioDraft) -> WrittenScenario:
    """Returns the draft with its exact findings: safety and data integrity only."""
    reasons = tuple(reason for _, reason in draft.system_reasons)
    text = "\n".join((draft.title, draft.statement, draft.risk, *draft.assumptions, *reasons))
    findings = []
    if labels := _list_ids_not_given_to_writer(_INTERNAL_LABEL, text, brief.brief_text):
        findings.append(Finding(FindingCode.UNKNOWN_ID, FindingMessage.UNKNOWN_ID.format(labels=labels)))
    advisory_given = brief.brief_text if brief.cited_index is not None else ""
    if advisories := _list_ids_not_given_to_writer(_ADVISORY_ID, text, advisory_given):
        message = FindingMessage.UNCITED_ADVISORY_ID.format(ids=advisories)
        findings.append(Finding(FindingCode.UNCITED_ADVISORY_ID, message))
    if markers := ", ".join(dict.fromkeys(f"[{number}]" for number in markers_of(text))):
        message = StoryFindingMessage.UNKNOWN_MARKER.format(markers=markers)
        findings.append(Finding(StoryFindingCode.UNKNOWN_MARKER, message))
    echoed = f"{text}\n{draft.evidence_statement}"
    if _ECHO_SANITISER.sanitise(echoed, len(echoed) + 1).unsafe:  # the evidence is untrusted
        findings.append(Finding(StoryFindingCode.INJECTION_ECHO, StoryFindingMessage.INJECTION_ECHO))
    if draft.evidence_problem:
        message = FindingMessage.CITATION_REMOVED.format(reason=draft.evidence_problem)
        findings.append(Finding(FindingCode.CITATION_REMOVED, message))
    return WrittenScenario(draft, tuple(findings))


# --- the card stored for one path: the written (or blocked) scenario, or its failure


def build_scenario_card(
    run: dict[str, Any],
    path: dict[str, Any],
    threat: dict[str, Any],
    brief: WriterBrief,
    written: WrittenScenario,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Builds a written scenario's card: done with its controls queued, or blocked."""
    draft, now = written.draft, utc_now()
    statement, evidence = _build_card_evidence(brief, threat, draft)
    status = ScenarioStatus.BLOCKED if written.list_blocking_codes() else ScenarioStatus.DONE
    story = brief.cited_index is not None
    content = {
        "title": draft.title,
        "statement": statement,
        "risk_statement": draft.risk,
        "assumptions": list(draft.assumptions),
        **build_card_threat_fields(path, threat),
        **_build_card_systems(run, path, brief, draft),
        "route": {"status": Route.STANDALONE, "note": None},
        "prompt_version": PromptVersion.SCENARIO_WRITER_EVIDENCE if story else PromptVersion.SCENARIO_WRITER,
    } | evidence
    record = _build_common_card_fields(run, path, status, now, replaces) | {
        "title_key": name_match_key(draft.title),
        "content": content,
        "findings": [finding.build_record() for finding in written.findings],
        "rewritten": False,
    }
    if status == ScenarioStatus.DONE:
        origin = {"request_id": current_request_id(), "origin": current_job_origin()}
        record["controls"] = {"status": Status.QUEUED, "attempts": 0, "queued_at": now, **origin}
    return record


def _build_card_evidence(
    brief: WriterBrief, threat: dict[str, Any], draft: ScenarioDraft
) -> tuple[str, dict[str, Any]]:
    """Returns the card's statement with its cited sentence, and its evidence fields."""
    if brief.cited_index is None:
        if threat.get("intel_search") is None:
            return draft.statement, {}
        statement, cited = draft.statement, []
    else:
        supports = draft.evidence_statement.removesuffix(".") or brief.cited_claim
        statement = f"{draft.statement} {supports} [1]."
        cited = [dict(brief.evidence[brief.cited_index]) | {"n": 1, "supports": supports}]
    applies = Counter(str(item["applicability"]) for item in cited if item.get("applicability"))
    return statement, {
        "evidence": cited,
        "evidence_mode": brief.get_evidence_mode(),
        "applicability": dict(applies),
        "intel_search": threat.get("intel_search"),
    }


def _build_card_systems(
    run: dict[str, Any], path: dict[str, Any], brief: WriterBrief, draft: ScenarioDraft
) -> dict[str, Any]:
    """Builds the card's systems and every supporting system's applicability, by recorded name."""
    names = {system["id"]: system["name"] for system in run["context"]["systems"]}
    if not draft.entry_point:
        entry = -1
    elif path.get("entry_system") in path["systems"]:  # its turn's way in, the one option, whatever its name
        entry = path["systems"].index(path["entry_system"])
    else:  # an option is one of the brief's systems, in the path's order
        entry = [system["name"] for system in brief.systems].index(draft.entry_point)
    card_systems = [
        {"id": system_id, "name": names[system_id], "entry_point": position == entry}
        for position, system_id in enumerate(path["systems"])  # in the brief's order: the path's systems
    ]
    entry_ids = {system["id"] for system in card_systems if system["entry_point"]}
    reasons = dict(draft.system_reasons)  # by the brief's spelling of each name
    applicability = [
        {
            "id": system.id,
            "name": names.get(system.id, system.name),
            "applicable": system.applicable,
            "entry_point": system.id in entry_ids,
            "reason": reasons.get(system.name, ""),
        }
        for system in brief.supporting_systems
    ]
    return {"systems": card_systems, "system_applicability": applicability}


def build_failure_card(
    run: dict[str, Any], path: dict[str, Any], threat: dict[str, Any] | None, failure: PathFailure
) -> dict[str, Any]:
    """Builds a visible failure card: what was to be written and why it could not be."""
    if threat is not None:
        content = build_card_threat_fields(path, threat)
    else:
        content = {"category": path.get("category"), "category_id": path.get("category_id")}
    return _build_common_card_fields(run, path, ScenarioStatus.FAILED, utc_now()) | {
        "content": content,
        "findings": [],
        "failure": {"code": failure.code, "message": failure.message}
        | ({"reason": failure.reason} if failure.reason else {}),
    }


def _build_common_card_fields(
    run: dict[str, Any],
    path: dict[str, Any],
    status: ScenarioStatus,
    now: datetime,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Builds the fields every card has: id, version, run, asset and a pending decision."""
    version = FIRST_VERSION if replaces is None else replaces["version"] + 1
    return {
        "_id": build_scenario_id(run["_id"], path["path_id"], version),
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


def build_card_threat_fields(path: dict[str, Any], threat: dict[str, Any]) -> dict[str, Any]:
    """Builds the card's category, threat and attackers; a failure card's threat may lack any."""
    threat_type = threat.get("type") or {}
    return {
        "category": path.get("category"),
        "category_id": path.get("category_id"),
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


def build_scenario_id(session_id: str, path_id: str, version: int) -> str:
    """Returns the card id: the same run, path and version always give the same id."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tsg:{session_id}:{path_id}:{version}"))


# --- duplicates, caught before a save


def find_duplicate_scenario_id(
    content: dict[str, Any], path_id: str, held: Iterable[dict[str, Any]]
) -> str | None:
    """Returns the id of a held card of another path telling the same threat or words, else None."""
    key, name, category, words = _read_card_comparison_keys(content)
    for other in held:
        if other.get("path_id") == path_id:
            continue
        their_key, their_name, their_category, their_words = _read_card_comparison_keys(other["content"])
        same_threat = (key is not None and key == their_key) or (bool(name) and name == their_name)
        if (same_threat and category == their_category) or (bool(words) and words == their_words):
            return other["_id"]
    return None


def _read_card_comparison_keys(content: dict[str, Any]) -> tuple[str | None, str, Any, str]:
    """Returns what two cards are compared by: threat key, name key, category, plain words."""
    threat = content.get("threat") or {}
    library_id, status = threat.get("library_id"), threat.get("library_status")
    key = threat.get("key") or None
    if key is None and library_id is not None and status in (None, LibraryStatus.ACTIVE):
        key = f"lib:{library_id}"
    words = " ".join(_CITATION_MARKER.sub("", content.get("statement") or "").casefold().split())
    return key, threat_name_key(threat.get("name") or ""), content.get("category"), words


def read_statement_without_citation(content: dict[str, Any]) -> str:
    """Returns a card's statement without the cited passage at its end."""
    statement = str(content.get("statement") or "")
    cited = next(
        (entry["supports"] for entry in content.get("evidence") or () if entry.get("supports")), None
    )
    return statement.removesuffix(f" {cited} [1].") if cited else statement


# --- control mapping: library controls that fit the asset and systems, searched by the scenario and risk
# statements, scored by the reranker and kept by the threshold rule; never written by an AI

_ABOUT_AI = re.compile(Controls.AI_THREAT_WORDS)
_NONE_RECORDED = "none recorded"
#: The search settings a stored shortlist must share to be reused.
_REUSED_IF_SAME = ("rerank_model", "embedding_model", "query_instruction", "library", "candidates")
_ScoredControls = list[tuple[LibraryControl, float]]


class ControlMapper:
    """Maps scenarios to library controls with one reranker."""

    def __init__(self, rerank: RerankModel) -> None:
        self._rerank = rerank

    def map_controls(
        self,
        scenario: dict[str, Any],
        context: FrozenContext,
        snapshot: LibrarySnapshot,
        query: ControlQuery | None = None,
    ) -> ControlMapping:
        """Map one scenario's controls (by `query` if built already); ControlsNotMapped: empty library."""
        if not snapshot.library.control_library:
            raise ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, ErrorMessage.CONTROL_LIBRARY_EMPTY)
        settings = get_settings()
        rule = ControlRule(
            settings.control_similarity_threshold,
            settings.control_candidates,
            settings.min_controls,
            settings.max_controls,
            settings.nearest_controls,
        )
        content = scenario["content"]
        query = query or build_control_query(content, context)
        scored, other_type = self._search_and_rerank_controls(
            content, context, snapshot, query, rule.candidates
        )
        return dataclasses.replace(
            pick_controls_to_keep(scored, rule, query.text, other_type),
            query_shortened=query.shortened,
            mitigations=query.mitigations,
            ai_controls=query.is_about_ai,
            shortlist=tuple((control.control_id, score) for control, score in scored),
        )

    def find_alternative_controls(
        self,
        scenario: dict[str, Any],
        context: FrozenContext,
        snapshot: LibrarySnapshot,
        identified: Collection[int],
        count: int,
        mapped: dict[str, Any] | None = None,
    ) -> _ScoredControls:
        """List the `count` best controls not `identified` nor a twin of one, reusing `mapped`'s shortlist."""
        if not snapshot.library.control_library:
            return []
        content, mapped = scenario["content"], mapped or {}
        query, settings = build_control_query(content, context), _read_control_search_settings(snapshot)
        made_with = mapped.get("made_with") or {}
        is_shortlist_current = (
            bool(mapped.get("shortlist"))
            and all(made_with.get(key) == settings[key] for key in _REUSED_IF_SAME)
            and made_with.get("ai_controls") == query.is_about_ai
            and mapped.get("query") == query.text
        )
        if is_shortlist_current:
            by_id = {control.control_id: control for control in snapshot.library.control_library}
            scored = [(by_id[entry["control_id"]], entry["score"]) for entry in mapped["shortlist"]]
        else:
            candidates = settings["candidates"]
            scored, _ = self._search_and_rerank_controls(content, context, snapshot, query, candidates)
        taken = {
            name_match_key(describe_control(control))
            for control in snapshot.library.control_library
            if control.control_id in identified
        }
        ranked = _rank_controls_without_duplicates(scored)
        return [pair for pair in ranked if name_match_key(describe_control(pair[0])) not in taken][:count]

    def _search_and_rerank_controls(
        self,
        content: dict[str, Any],
        context: FrozenContext,
        snapshot: LibrarySnapshot,
        query: ControlQuery,
        candidates: int,
    ) -> tuple[_ScoredControls, str | None]:
        """Search the controls of the scenario's types (else any type, warned) and rerank them 0-100."""
        systems = context.find_systems(system["id"] for system in content.get("systems") or [])
        allowed = place_asset_types(
            context.asset.get("category_code"), (system.get("category_code") for system in systems)
        )
        (found,) = snapshot.find_controls([query.text], candidates, allowed, ai_controls=query.is_about_ai)
        other_type = None
        if not found:
            types = ", ".join(sorted(allowed)) or _NONE_RECORDED
            (found,) = snapshot.find_controls([query.text], candidates, ai_controls=query.is_about_ai)
            other_type = ControlMessage.OTHER_TYPE.format(types=types)
        controls = [control for control, _ in found]
        scores = self._rerank.score_relevance(query.text, [describe_control(control) for control in controls])
        return list(zip(controls, scores, strict=True)), other_type


def _read_control_search_settings(snapshot: LibrarySnapshot) -> dict[str, Any]:
    """Read the models, query instruction, library version and rule a mapping is searched with."""
    settings = get_settings()
    profile = find_model_profile(EMBEDDING_MODEL_PROFILES, settings.embedding_model)
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.CONTROL]
    return {
        "rerank_model": settings.rerank_model,
        "embedding_model": settings.embedding_model,
        "query_instruction": profile.instruction_for(QUERY_TASKS[EmbeddingCorpus.CONTROL]),
        "library": {
            name: digest.hex() if digest else None for name, digest in snapshot.library.stamp if name == table
        },
        "threshold": settings.control_similarity_threshold,
        "candidates": settings.control_candidates,
        "min_controls": settings.min_controls,
        "max_controls": settings.max_controls,
        "nearest_controls": settings.nearest_controls,
    }


def build_controls_record(mapping: ControlMapping, snapshot: LibrarySnapshot) -> dict[str, Any]:
    """Build what a scenario keeps of its mapping: controls, warnings, shortlist and how it was searched."""
    return {
        "items": [item.to_record() for item in mapping.items],
        "warning": mapping.warning,
        "shortfall": mapping.shortfall,
        "left_out_over_max": mapping.left_out,
        "query": mapping.query,
        "shortlist": [{"control_id": control_id, "score": score} for control_id, score in mapping.shortlist],
        "made_with": {
            **_read_control_search_settings(snapshot),
            "query_shortened": list(mapping.query_shortened),
            "mitigations": list(mapping.mitigations),
            "ai_controls": mapping.ai_controls,
        },
    }


def pick_controls_to_keep(
    scored: _ScoredControls, rule: ControlRule, query: str, other_type: str | None = None
) -> ControlMapping:
    """Keep the strong controls up to the maximum, topped up with the nearest; none strong of another type."""
    unique = _rank_controls_without_duplicates(scored)
    strong = [] if other_type else [(control, score) for control, score in unique if score >= rule.cutoff]
    kept = strong[: rule.most]
    target = min(rule.least if kept else rule.nearest, rule.most)
    below = unique if other_type else [(control, score) for control, score in unique if score < rule.cutoff]
    chosen = [(pair, ControlMatch.EXACT) for pair in kept]
    chosen += [(pair, ControlMatch.NEAREST) for pair in below[: max(target - len(kept), 0)]]
    items = []
    for rank, ((control, score), match) in enumerate(chosen, 1):
        if other_type:
            template = ControlMessage.OTHER_TYPE_REASON
        elif match is ControlMatch.EXACT:
            template = ControlMessage.STRONG_REASON
        elif kept:
            template = ControlMessage.FALLBACK_REASON
        else:
            template = ControlMessage.NEAREST_REASON
        asset_type = control.asset_type or _NONE_RECORDED
        reason = template.format(
            score=score, cutoff=rule.cutoff, least=rule.least, nearest=rule.nearest, asset_type=asset_type
        )
        fields = (control.control_id, control.code, control.name, control.domain, control.asset_type)
        items.append(MappedControl(*fields, rank, score, match, control.description, reason))
    nearest_only = ControlMessage.NEAREST_ONLY.format(cutoff=rule.cutoff, nearest=target)
    warning = other_type or (None if kept else nearest_only)
    shortfall = (
        ControlMessage.SHORTFALL.format(kept=len(items), least=target) if len(items) < target else None
    )
    return ControlMapping(tuple(items), query, warning, shortfall, len(strong) - len(kept))


def _rank_controls_without_duplicates(scored: _ScoredControls) -> _ScoredControls:
    """Rank best first, keeping one of each control: by id, or by text (an IT and an OT copy)."""
    seen: set[object] = set()
    unique: _ScoredControls = []
    for control, score in sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)):
        keys = {control.control_id, name_match_key(describe_control(control))}
        if not keys & seen:
            seen |= keys
            unique.append((control, score))
    return unique


def build_control_query(content: dict[str, Any], context: FrozenContext) -> ControlQuery:
    """Build the redacted control query: a head never cut, then the parts sharing the room left."""
    threat = content.get("threat") or {}
    actors = content.get("actors") or []
    acting = next((actor["name"] for actor in actors if actor.get("role") == "acting"), "")
    asset_type = facts_safe_for_prompt({"type": context.asset_context.get("asset_type")}).get("type")
    cited = (str(name) for item in content.get("evidence") or [] for name in item.get("mitigations") or ())
    mitigations = tuple(dict.fromkeys(name for name in cited if name.strip()))[: Controls.QUERY_MITIGATIONS]
    head = [
        f"Category: {content.get('category') or ''}",
        f"Threat: {threat.get('type') or ''}: {threat.get('name') or ''}",
        f"Attacker: {acting}",
        f"Title: {content.get('title') or ''}",
        f"Asset: {context.asset.get('name') or ''}" + (f" ({asset_type})" if asset_type else ""),
        *([f"Mitigations (MITRE ATT&CK): {'; '.join(mitigations)}"] if mitigations else []),
    ]
    systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    facts = [
        (f"system {system['id']}", f"System {system['name']}", context.read_system_facts(system))
        for system in systems
    ]
    facts.append(("asset facts", "Asset facts", context.own_and_organisation_facts()[0]))
    parts = [
        (
            label,
            f"{title}: "
            + "; ".join(
                f"{name}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
                for name, value in facts_safe_for_prompt(recorded).items()
                if name != "name"
            ),
        )
        for label, title, recorded in facts
    ]
    parts.append(("scenario", f"Scenario: {content.get('statement') or ''}"))
    parts.append(("risk", f"Risk: {content.get('risk_statement') or ''}"))
    text, shortened = _shorten_query_parts_to_fit("\n".join(head), parts)
    return ControlQuery(text, shortened, mitigations, _is_about_ai(content))


def _is_about_ai(content: dict[str, Any]) -> bool:
    """Whether a card's threat or scenario is about AI, never by the real-world attackers it cites."""
    threat, statement = content.get("threat") or {}, content.get("statement") or ""
    for entry in content.get("evidence") or []:
        for fact in entry.get("facts") or []:
            if user := _REAL_WORLD_USER_FACT.fullmatch(str(fact)):
                statement = statement.replace(user["name"] or user["campaign"], "")
    return bool(_ABOUT_AI.search(f"{threat.get('type') or ''} {threat.get('name') or ''} {statement}"))


def _shorten_query_parts_to_fit(head: str, parts: list[tuple[str, str]]) -> tuple[str, tuple[str, ...]]:
    """Fit the redacted head and parts in QUERY_MAX_CHARS, shortest first; also return the labels cut."""
    head, texts = redact(head), [redact(text) for _, text in parts]
    room = max(Controls.QUERY_MAX_CHARS - len(head) - len(texts), 0)  # one line break before each part
    shares = [0] * len(texts)
    for position, index in enumerate(
        sorted(range(len(texts)), key=lambda text_index: (len(texts[text_index]), text_index))
    ):
        shares[index] = min(len(texts[index]), room // (len(texts) - position))
        room -= shares[index]
    fitted = [shorten_text(text, share) for text, share in zip(texts, shares, strict=True)]
    shortened = tuple(
        label for (label, _), text, share in zip(parts, texts, shares, strict=True) if len(text) > share
    )
    query = "\n".join([shorten_text(head, Controls.QUERY_MAX_CHARS), *(text for text in fitted if text)])
    return query, shortened
