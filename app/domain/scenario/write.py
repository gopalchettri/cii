"""Writing one scenario per attack path, a set at a time: brief, prompts, exact checks, card, duplicates."""

import functools
import json
import re
import uuid
from collections.abc import Collection, Iterable, Iterator, Sequence
from typing import Any

import structlog

from app.ai import ChatModel, RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
from app.core import constants as c
from app.core.asset_types import place_asset_types
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.exceptions import ControlsNotMapped, PathNotWritable, Unavailable
from app.core.logging import current_job_origin, current_request_id
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.intel.facts import ID_IN_TEXT
from app.domain.intel.patterns import ECHO_PATTERNS
from app.domain.intel.safety import UntrustedTextSanitiser
from app.domain.shared import ask_ai
from app.domain.shared import names as name_forms
from app.domain.shared.prompt_redaction import facts_safe_for_prompt, without_platform_note
from app.schemas import scenario_internal as write_models
from app.schemas.intel import markers_of
from app.schemas.library import LibraryControl
from app.schemas.scenario_internal import ControlQuery, FrozenContext
from app.search.snapshot import LibrarySnapshot, describe_control

log = structlog.get_logger(__name__)


_WRITER_PROMPTS: dict[str, str] = PROMPTS["scenario"]["writer"]
WRITER_SYSTEM_PROMPT: str = _WRITER_PROMPTS["text"]
NO_EVIDENCE: str = _WRITER_PROMPTS["no_evidence"].strip()


_SANITISER = UntrustedTextSanitiser()
_ECHO_SANITISER = UntrustedTextSanitiser(ECHO_PATTERNS, (), ())
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(c.EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)), re.IGNORECASE
)
_TACTICS_FACT_PREFIX = str(c.EvidenceFact.TACTICS).split("{")[0]
_MITIGATED_BY_FACT_PREFIX = str(c.EvidenceFact.MITIGATED_BY).split("{")[0]
_REAL_WORLD_USER_FACT = re.compile(c.REAL_WORLD_USER)
_USER_FACT_END = "used this technique."


_LIST_BEFORE = re.compile(r"(?:,\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+)$", re.IGNORECASE)
_LIST_AFTER = re.compile(r",\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_ACTION_TIE = re.compile(
    r"\b(?:on|from|to|in|into|against|of|across|for|at|via|between|and|targeting|with)\s+(?:the\s+)?$", re.IGNORECASE
)
_TRAILING_THE = re.compile(r"\bthe\s+$", re.IGNORECASE)
_NAME_LIST_GAP = re.compile(r"\s*(?:,\s*(?:(?:and|or)\s+)?|(?:and|or)\s+|/\s*)(?:the\s+)?", re.IGNORECASE)
_NAME_DESCRIBES = re.compile(
    r"(?:['’]s)?\s+(?!(?:and|or|to|from|on|in|into|via|with|without|for|at|by|across|between|then"
    r"|through|over|under|using|as)\b)[a-z]",
    re.IGNORECASE,
)
_OR_JOINER = re.compile(r"\bor\b", re.IGNORECASE)
_AND_JOINER = re.compile(r"\b(?:and|with)\b|&", re.IGNORECASE)
_LIKELIHOOD_WORDS = {rank: word for word, rank in c.ThreatFinding.LIKELIHOOD_RANK.items()}
_ASSET_FACT_NAMES = {"cii_asset_description": "description", "asset_type": "type", "asset_priority": "priority"}


_INTERNAL_LABEL = re.compile(r"\b(?:SYS|THR|SC)\d+\b")
_NOT_LATIN = re.compile(r"[^\W\d_A-Za-zª-ɏḀ-ỿ]+")
_LEADING_ARTICLE = re.compile(r"^the\s+", re.IGNORECASE)
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3})\b|\bVU#\d+",
    re.IGNORECASE,
)
_CITATION_MARKER = re.compile(r"\s*\[\d+(?:\s*,\s*\d+)*\]")
FIRST_VERSION = 1
_ABSENT = object()  # a fact the shared block does not hold


def build_writer_input(
    threats: dict[str, dict[str, Any]],
    path: dict[str, Any],
    context: FrozenContext,
    budget: int,
    live: write_models.LiveLibrary,
    style: c.WriterStyle = c.WriterStyle.ORIGINAL,
) -> write_models.WriterBrief:
    """Builds the path's brief within `budget` characters; a story only when an entry is citable."""
    threat, systems = _get_path_threat_or_refuse(threats, path, context, live)
    evidence = tuple(threat.get("evidence") or ()) if style is c.WriterStyle.EVIDENCE_STORY else ()
    cleaned, cited, claim = _clean_evidence_and_pick_cited_entry(evidence)
    asset, named = shorten_facts_to_fit(context, systems, cited is not None, budget)
    supporting = tuple(
        write_models.BriefSystem(system["id"], redact(system["name"]), system["id"] in path["systems"])
        for system in context.systems
    )
    facts = _describe_path_for_writer(threat, path, context, named, supporting)
    return write_models.WriterBrief(
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
        brief_text=name_forms.as_json({"asset": asset, "systems": named} | facts).casefold(),
    )


def _get_path_threat_or_refuse(
    threats: dict[str, dict[str, Any]], path: dict[str, Any], context: FrozenContext, live: write_models.LiveLibrary
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path_id, threat = path["path_id"], threats[path["steps"][0]]
    if not (threat["type"]["name"] or "").strip() or not (threat["name"] or "").strip():
        raise PathNotWritable(path_id, c.PathProblem.THREAT_UNNAMED)
    if threat.get("attacker_check") == c.AttackerCheck.NONE_FITS:  # never a forced attribution
        raise PathNotWritable(path_id, c.PathProblem.ATTACKER_UNSUPPORTED)
    if threat["library_id"] is not None:
        retired = threat["library_id"] not in live.threat_ids
    else:
        retired = threat["type"]["id"] not in live.type_ids
    if retired:
        raise PathNotWritable(path_id, c.PathProblem.THREAT_RETIRED, c.ErrorCode.LIBRARY_RECORD_RETIRED)
    if threat["actors"][0]["id"] not in live.actor_ids:
        raise PathNotWritable(path_id, c.PathProblem.ATTACKER_RETIRED, c.ErrorCode.LIBRARY_RECORD_RETIRED)
    by_id = {system["id"]: system for system in context.systems}
    return threat, [by_id[system_id] for system_id in path["systems"]]


def shorten_facts_to_fit(
    context: FrozenContext, systems: list[dict[str, Any]], story: bool, budget: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The asset's and each system's facts as a writer reads them: named, redacted, within `budget` characters."""
    own, organisation = context.own_and_organisation_facts()
    asset = {_ASSET_FACT_NAMES.get(key, key): value for key, value in own.items()}
    if story:
        asset[c.ContextProperties.COUNTRY_KEY] = get_settings().context_country
    background = "; ".join(str(value) for value in organisation.values() if value)
    asset |= {c.ContextProperties.ORGANISATION_BRIEF_KEY: background} if background else {}
    parts = [(context.asset["name"], asset)]
    parts += [(system["name"], FrozenContext.read_system_facts(system)) for system in systems]
    named = [
        {"name": redact(" ".join(str(name).split())), **facts_safe_for_prompt(facts | {"name": None})}
        for name, facts in parts  # the name is never dropped
    ]
    cut_asset, *cut_systems = name_forms.cut_to_fit(named, budget)
    return cut_asset, cut_systems


def _describe_path_for_writer(
    threat: dict[str, Any],
    path: dict[str, Any],
    context: FrozenContext,
    named: list[dict[str, Any]],
    supporting: tuple[write_models.BriefSystem, ...],
) -> dict[str, Any]:
    entry = path.get("entry_system")
    entry_name = named[path["systems"].index(entry)]["name"] if entry in path["systems"] else ""
    actions = _remove_system_names_from_actions(threat, context)
    why_attacker = _remove_other_system_names_from_reason(threat["attacker_check_reason"] or "", path, context)
    kind_reason = (threat.get("reasons") or {}).get(path["category"]) or threat["reason"]
    return {
        "category": c.StrideCategory(path["category"]),
        "attacker": threat["actors"][0]["name"],
        **({"why_this_attacker": why_attacker} if why_attacker else {}),
        "likelihood": _LIKELIHOOD_WORDS[threat["likelihood"]],
        "threat": {
            "threat_type": name_forms.threat_name_without_code(threat["type"]["name"]),
            "threat": name_forms.threat_name_without_code(threat["name"]),
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
    names = [system["name"] for system in context.systems]
    spans = sorted(
        span
        for system in context.systems
        if system["id"] not in path["systems"]
        for span in name_forms.find_name_mentions(system["name"], reason)
    )
    edge = len(reason) + 1
    for start, end in reversed(spans):  # from the end, so earlier spans keep their place; overlaps skipped
        if end <= edge:
            start -= 4 if reason[max(start - 4, 0) : start].lower() == "the " else 0  # "the Historian"
            reason, edge = _remove_one_system_name_from_reason(reason, start, end, names), start
    repeated = rf"{c.Writing.OTHER_SYSTEM}(?:,? (?:and |or )?{c.Writing.OTHER_SYSTEM})+"
    return redact(re.sub(repeated, c.Writing.OTHER_SYSTEMS, reason))


def _remove_one_system_name_from_reason(reason: str, start: int, end: int, names: list[str]) -> str:
    head, tail = reason[:start], reason[end:]
    known = tuple(name.casefold() for name in (*names, c.Writing.OTHER_SYSTEM))
    joiner = _LIST_BEFORE.search(head)
    if joiner and head[: joiner.start()].rstrip().casefold().endswith(known):
        return head[: joiner.start()] + tail
    joiner = _LIST_AFTER.match(tail)
    if joiner and tail[joiner.end() :].casefold().removeprefix("the ").startswith(known):
        return head + tail[joiner.end() :]
    return head + c.Writing.OTHER_SYSTEM + tail


def _remove_system_names_from_actions(threat: dict[str, Any], context: FrozenContext) -> tuple[str, ...]:
    names = [system["name"] for system in context.systems]
    actions: dict[str, str] = {}
    for listed in threat.get("actions") or ():
        action = str(listed)
        spans: list[tuple[int, int]] = []
        for start, end in sorted(span for name in names for span in name_forms.find_name_mentions(name, action)):
            if spans and (start < spans[-1][1] or _NAME_LIST_GAP.fullmatch(action[spans[-1][1] : start])):
                spans[-1] = (spans[-1][0], max(end, spans[-1][1]))
            else:
                spans.append((start, end))
        for start, end in reversed(spans):  # from the end, so earlier spans keep their place
            action = _remove_one_system_name_from_action(action, start, end)
        bare = " ".join(action.split())
        if key := name_forms.name_match_key(bare):
            actions.setdefault(key, bare)
    name = name_forms.threat_name_without_code(threat["name"])
    if len(actions) > 1 and _OR_JOINER.search(name) and not _AND_JOINER.search(name):
        return (redact(" or ".join(actions.values())),)
    return tuple(redact(action) for action in actions.values())


def _remove_one_system_name_from_action(action: str, start: int, end: int) -> str:
    head, tail = action[:start], action[end:]
    article = _TRAILING_THE.search(head)
    bare_head = head[: article.start()] if article else head
    if described := _NAME_DESCRIBES.match(tail):
        return f"{bare_head} {tail[described.end() - 1 :]}"
    tie_words = _ACTION_TIE.search(head)
    if tie_words and len(head[: tie_words.start()].split()) > 1:  # more than a bare verb is left
        return head[: tie_words.start()] + tail
    return f"{bare_head}{c.Writing.ACTION_SYSTEM}{tail}" if bare_head.strip() else tail


def _clean_evidence_and_pick_cited_entry(
    evidence: Sequence[dict[str, Any]],
) -> tuple[tuple[tuple[str, tuple[str, ...]], ...], int | None, str]:
    cleaned = []
    for entry in evidence:
        stated = [
            fact
            for fact in entry.get("facts") or ()
            if not fact.strip().startswith((_TACTICS_FACT_PREFIX, _MITIGATED_BY_FACT_PREFIX))
        ]
        texts = []
        for text in [str(entry.get("title") or ""), *stated]:
            bare = remove_ids_and_links(redact(text))
            safe = _SANITISER.sanitise(" ".join(_LOOK_ALIKES.sub(" ", bare).split()), c.TextSafety.MAX_FACT_CHARS)
            texts.append("" if safe.unsafe else safe.text)
        entry_title, *entry_facts = texts
        cleaned.append((entry_title, tuple(fact for fact in entry_facts if fact)))
    for index, (entry, (title, facts)) in enumerate(zip(evidence, cleaned, strict=True)):
        related = bool(entry.get("nearest"))
        claim = ""
        if entry.get("kind") != c.IntelKind.TECHNIQUE and facts:
            fact = facts[0].removesuffix(".")
            claim = c.Precedent.RELATED_RECORD.format(fact=fact) if related else fact
        elif entry.get("kind") == c.IntelKind.TECHNIQUE and title and any(map(_REAL_WORLD_USER_FACT.fullmatch, facts)):
            claim = (c.Precedent.RELATED_TO if related else c.Precedent.COULD_USE).format(technique=title)
        if claim and "[" not in claim and not _SENTENCE_END.search(claim):
            return tuple(cleaned), index, claim
    return tuple(cleaned), None, ""


def remove_ids_and_links(text: str) -> str:
    """Remove the public numbers (CVE, advisory, technique) and the links a story never shows; spaces single."""
    return " ".join(_URL.sub("", ID_IN_TEXT.sub("", text)).replace("()", "").split())


def build_writer_system_prompt() -> str:
    """Builds the writer's system prompt with the configured word ranges."""
    settings = get_settings()
    prompt = WRITER_SYSTEM_PROMPT + _WRITER_PROMPTS["set"]
    scenario, risk = settings.scenario_words, settings.risk_words
    prompt = prompt.replace(c.Writing.SCENARIO_WORDS_SLOT, f"{scenario[0]} to {scenario[1]}")
    return prompt.replace(c.Writing.RISK_WORDS_SLOT, f"{risk[0]} to {risk[1]}")


def build_writer_prompt(slots: Sequence[tuple[str, write_models.WriterBrief, str]]) -> ask_ai.ChatPrompt:
    """Builds one call's (system, user) prompt: the shared facts once, then each slot."""
    # ponytail: the asset's records are grouped under None, beside each system's records under its name
    by_name: dict[str | None, list[dict[str, Any]]] = {None: [brief.asset for _, brief, _ in slots]}
    for _, brief, _ in slots:
        for system in brief.systems:
            by_name.setdefault(system["name"], []).append(system)
    shared = {
        name: {
            key: value for key, value in first.items() if all(key in other and other[key] == value for other in rest)
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
        blocks.append(f"SLOT {label}\nBRIEF:\n{name_forms.as_json(record)}\n{evidence}{note}")
    systems_shared = [facts for name, facts in shared.items() if name is not None]
    head = f"ASSET:\n{name_forms.as_json(shared[None])}\nSYSTEMS:\n{name_forms.as_json(systems_shared)}"
    return build_writer_system_prompt(), "\n\n".join([head, *blocks])


def _build_evidence_block(brief: write_models.WriterBrief) -> str:
    entries = []
    for index, (entry, (title, facts)) in enumerate(zip(brief.evidence, brief.cleaned_evidence, strict=True)):
        subject = {"technique" if entry.get("kind") == c.IntelKind.TECHNIQUE else "about": title} if title else {}
        shown = [fact for fact in facts if not fact.endswith(_USER_FACT_END)]
        entries.append(
            {**subject, "facts": shown}
            | ({"applicability": str(entry["applicability"])} if entry.get("applicability") else {})
            | ({"cited": True} if index == brief.cited_index else {})
        )
    body = json.dumps({"evidence_mode": str(brief.get_evidence_mode()), "evidence": entries}, ensure_ascii=False)
    return f"EVIDENCE (untrusted data):\n{c.EvidenceBlock.BEGIN}\n{body}\n{c.EvidenceBlock.END}"


# A scenario to write again: label, brief, link index (epoch plus position), usable first draft, problems.
_ToRewrite = tuple[str, write_models.WriterBrief, int, write_models.WrittenScenario | None, list[str]]


def write_scenario_set(
    chat: ChatModel, briefs: Sequence[tuple[str, write_models.WriterBrief]], epoch: int = 0
) -> Iterator[tuple[str, write_models.WrittenScenario | write_models.PathFailure]]:
    """Yields each slot's scenario or failure card as soon as it is final, in at most 2 AI calls."""
    # ponytail: the position within this call; a later batch or retry of the same set may repeat a link
    if not briefs:
        return
    answers = _ask_writer(chat, c.AiTask.WRITE_SCENARIO, [(label, brief, "") for label, brief in briefs])
    to_rewrite: list[_ToRewrite] = []
    for link_index, (label, brief) in enumerate(briefs, epoch):
        item, first_written = answers.get(label), None
        draft, problems = _read_scenario_draft(brief, item, link_index)
        if draft is not None:
            first_written = apply_safety_checks(brief, draft)
            problems = _find_actions_missing_from_story(item or {}, brief.threat_actions)
            if not problems:
                yield label, first_written
                continue
        to_rewrite.append((label, brief, link_index, first_written, problems))
    yield from _rewrite_failed_scenarios(chat, to_rewrite)


def _rewrite_failed_scenarios(
    chat: ChatModel, slots: list[_ToRewrite]
) -> Iterator[tuple[str, write_models.WrittenScenario | write_models.PathFailure]]:
    most, asked = c.AiLimits.REASK_PROBLEM_CHARS, []
    for label, brief, _, _, found in slots:
        shown = found[: c.AiLimits.REASK_MAX_PROBLEMS]
        cut = (problem if len(problem) <= most else problem[:most].rsplit(" ", 1)[0] for problem in shown)
        asked.append((label, brief, _WRITER_PROMPTS["rewrite"].replace("{problems}", "; ".join(cut))))
    try:
        answers = _ask_writer(chat, c.AiTask.REPAIR_SCENARIO, asked)
    except (UnreadableAiAnswer, TruncatedAiAnswer) as error:  # every slot's rewrite is unusable
        log.warning(c.LogEvent.WRITER_PATH_FAILED, message=str(error), error_type=type(error).__name__)
        answers = {}
    except Unavailable as outage:
        yield from ((label, first) for label, _, _, first, _ in slots if first is not None)
        if any(first is None for _, _, _, first, _ in slots):
            raise outage
        return
    for label, brief, link_index, kept, _ in slots:
        draft, problems = _read_scenario_draft(brief, answers.get(label), link_index)
        rewrite = apply_safety_checks(brief, draft) if draft is not None else None
        if rewrite and (kept is None or kept.list_blocking_codes() or not rewrite.list_blocking_codes()):
            kept = rewrite
        if kept is None:
            message = c.ErrorMessage.AI_ANSWER_REJECTED.format(
                task=c.AiTask.REPAIR_SCENARIO, problems="; ".join(problems[:3])
            )
            yield (
                label,
                write_models.PathFailure(
                    c.ErrorCode.GENERATION_FAILED, name_forms.shorten_text(message, c.Writing.PROBLEM_MAX_CHARS)
                ),
            )
        else:
            yield label, kept


def _ask_writer(
    chat: ChatModel, task: c.AiTask, slots: list[tuple[str, write_models.WriterBrief, str]]
) -> dict[str, dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    parts = ask_ai.within_call_limit(slots, build_writer_prompt, chat, task) if slots else []
    cut, answered = None, False
    for part in parts:
        read_answer = functools.partial(_read_writer_answer, asked={label for label, _, _ in part})
        try:
            items |= ask_ai.ask_ai_and_check(
                chat, task, build_writer_prompt(part), read_answer, reuse_earlier_answer=True
            )
            answered = True
        except TruncatedAiAnswer as error:
            if len(parts) == 1:
                raise
            cut = error
            log.warning(
                c.LogEvent.WRITER_PATH_FAILED, ai_task=task, message=str(error), error_type=type(error).__name__
            )
    if cut is not None and not answered:  # a rewrite of the same briefs would be cut off again
        raise cut
    return items


def _read_writer_answer(answer: dict[str, Any], asked: set[str]) -> tuple[dict[str, dict[str, Any]] | None, list[str]]:
    kept, problems = ask_ai.answers_for_asked_slots(answer, "scenarios", asked)
    if not isinstance(answer.get("scenarios"), list):
        return None, problems
    # ponytail: the entity read back through the item's JSON text, so every key and value is covered at once
    unescaped = (json.loads(json.dumps(item, ensure_ascii=False).replace("&amp;", "&")) for item in kept)
    return {str(item["slot"]): item for item in unescaped}, []


def _read_scenario_draft(
    brief: write_models.WriterBrief, item: dict[str, Any] | None, link_index: int
) -> tuple[write_models.ScenarioDraft | None, list[str]]:
    if item is None:
        return None, [_WRITER_PROMPTS["slot_missing"]]
    if name_forms.name_match_key(str(item.get("threat") or "")) != name_forms.name_match_key(brief.threat):
        return None, [_WRITER_PROMPTS["threat_not_copied"]]  # another slot's answer, or none: written again
    if problems := find_not_english_problems(item, brief.brief_text):
        return None, problems
    if problems := ask_ai.answer_item_problems(write_models.ScenarioAnswer, item, "the reply"):
        return None, problems
    reply = write_models.ScenarioAnswer.model_validate(item)
    statement = reply.scenario_statement.strip()
    options = brief.entry_options
    sentence, evidence_problem = _build_evidence_sentence(reply.evidence_step or "", brief, link_index)
    draft = write_models.ScenarioDraft(
        title=reply.scenario_title.strip(),
        statement=statement,
        risk=reply.risk_statement.strip(),
        assumptions=tuple(assumption.strip() for assumption in reply.assumptions),
        entry_point=next(
            (option for option in options if name_forms.is_same_name(option, reply.entry_point)),
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


def _pick_reason_for_system(system: write_models.BriefSystem, written: dict[str, str], statement: str) -> str:
    if not system.applicable:
        return c.Writing.NOT_REACHED_REASON
    given = (reason.strip() for name, reason in written.items() if name_forms.is_same_name(system.name, name))
    named = (line for line in _SENTENCE_END.split(statement) if name_forms.find_name_mentions(system.name, line))
    return next(filter(None, given), "") or next(named, c.Writing.REACHED_REASON)


def split_sentences(text: str) -> list[str]:
    """Split a text into its sentences, none empty."""
    return [part for part in _SENTENCE_END.split(text.strip()) if part]


def _find_actions_missing_from_story(item: dict[str, Any], actions: tuple[str, ...]) -> list[str]:
    if not actions:
        return []
    count = len(split_sentences(str(item.get("scenario_statement") or "")))
    given = item.get("action_sentences")
    numbers: dict[str, list[int]] = {}
    for act, value in given.items() if isinstance(given, dict) else ():
        found: list[int] = []
        for number in value if isinstance(value, list) else [value]:
            if isinstance(number, str):
                found += [int(digits) for digits in re.findall(r"\d+", number)]
            elif isinstance(number, float) and number.is_integer() or type(number) is int:
                found.append(int(number))
        numbers[name_forms.name_match_key(str(act))] = found
    covered = {act for act, found in numbers.items() if any(1 <= number <= count for number in found)}
    missing = [  # an "X or Y" action is covered whole, or by a number for each of its parts
        act
        for act in actions
        if (key := name_forms.name_match_key(act)) not in covered and not set(key.split(" or ")) <= covered
    ]
    if not missing:
        return []
    listed = ", ".join(json.dumps(act, ensure_ascii=False) for act in missing)
    return [c.AnswerProblem.ACTION_SENTENCES_MISSING.format(actions=listed)]


def _build_evidence_sentence(step: str, brief: write_models.WriterBrief, link_index: int) -> tuple[str, str]:
    title, facts = brief.cleaned_evidence[brief.cited_index] if brief.cited_index is not None else ("", ())
    if not title or "[" in title or _SENTENCE_END.search(title):
        return "", ""
    cited = brief.evidence[brief.cited_index] if brief.cited_index is not None else {}
    step = " ".join(step.split()).rstrip(" .,;:")
    users = [match["name"] or match["campaign"] for match in filter(None, map(_REAL_WORLD_USER_FACT.fullmatch, facts))]
    is_gerund_title = bool(title.split()[:1]) and title.split()[0].casefold().endswith("ing")
    patterns = (_URL, ID_IN_TEXT, _INTERNAL_LABEL, _ADVISORY_ID)
    if not step:
        return "", c.Precedent.NOT_WRITTEN
    if any(mark in step for mark in '["“”') or any(pattern.search(step) for pattern in patterns):
        return "", c.Precedent.NOT_PLAIN
    if _SENTENCE_END.search(step):
        return "", c.Precedent.MANY_SENTENCES
    if any(name_forms.find_name_mentions(user, step) for user in users if user):
        return "", c.Precedent.NAMES_A_USER
    if not is_gerund_title and _LEADING_ARTICLE.sub("", step).casefold().startswith(title.casefold()):
        return "", c.Precedent.OPENS_ON_EVIDENCE
    links = c.Precedent.RELATED_LINKS if cited.get("nearest") else c.Precedent.LINKS
    link, step = links[link_index % len(links)], step[:1].upper() + step[1:]
    if cited.get("kind") != c.IntelKind.TECHNIQUE:
        fact = facts[0].removesuffix(".")
        sentence = c.Precedent.ABOUT_SENTENCE.format(step=step, link=link, title=title, fact=fact)
    else:
        sentence = c.Precedent.SENTENCE.format(step=step, link=link, title=title)
    most = get_settings().evidence_words[1]
    return ("", c.Precedent.TOO_LONG.format(most=most)) if len(sentence.split()) > most else (sentence, "")


def _list_ids_not_given_to_writer(pattern: re.Pattern[str], text: str, given: str) -> str:
    found = (match[0] for match in pattern.finditer(text) if match[0].casefold() not in given)
    return ", ".join(dict.fromkeys(found))


def find_not_english_problems(item: dict[str, Any], given: str) -> list[str]:
    """The re-ask line for an answer item with words of another script that `given` does not hold."""
    words = _list_ids_not_given_to_writer(_NOT_LATIN, json.dumps(item, ensure_ascii=False), given)
    return [c.AnswerProblem.NOT_ENGLISH.format(words=words)] if words else []  # a model slipping into Chinese


def apply_safety_checks(
    brief: write_models.WriterBrief, draft: write_models.ScenarioDraft
) -> write_models.WrittenScenario:
    """The draft with what the exact checks find: unknown labels, advisory numbers, markers, echoed instructions."""
    reasons = tuple(reason for _, reason in draft.system_reasons)
    text = "\n".join((draft.title, draft.statement, draft.risk, *draft.assumptions, *reasons))
    findings = []
    if labels := _list_ids_not_given_to_writer(_INTERNAL_LABEL, text, brief.brief_text):
        findings.append(
            write_models.Finding(c.FindingCode.UNKNOWN_ID, c.FindingMessage.UNKNOWN_ID.format(labels=labels))
        )
    advisory_given = brief.brief_text if brief.cited_index is not None else ""
    if advisories := _list_ids_not_given_to_writer(_ADVISORY_ID, text, advisory_given):
        message = c.FindingMessage.UNCITED_ADVISORY_ID.format(ids=advisories)
        findings.append(write_models.Finding(c.FindingCode.UNCITED_ADVISORY_ID, message))
    if markers := ", ".join(dict.fromkeys(f"[{number}]" for number in markers_of(text))):
        message = c.StoryFindingMessage.UNKNOWN_MARKER.format(markers=markers)
        findings.append(write_models.Finding(c.StoryFindingCode.UNKNOWN_MARKER, message))
    echoed = f"{text}\n{draft.evidence_statement}"
    if _ECHO_SANITISER.sanitise(echoed, len(echoed) + 1).unsafe:  # the evidence is untrusted
        findings.append(write_models.Finding(c.StoryFindingCode.INJECTION_ECHO, c.StoryFindingMessage.INJECTION_ECHO))
    if draft.evidence_problem:
        message = c.FindingMessage.CITATION_REMOVED.format(reason=draft.evidence_problem)
        findings.append(write_models.Finding(c.FindingCode.CITATION_REMOVED, message))
    return write_models.WrittenScenario(draft, tuple(findings))


def build_scenario_card(
    run: dict[str, Any],
    path: dict[str, Any],
    threat: dict[str, Any],
    brief: write_models.WriterBrief,
    written: write_models.WrittenScenario,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Builds a written scenario's card: done with its controls queued, or blocked."""
    draft = written.draft
    statement, evidence = _build_card_evidence(brief, threat, draft)
    status = c.ScenarioStatus.BLOCKED if written.list_blocking_codes() else c.ScenarioStatus.DONE
    story = brief.cited_index is not None
    content = {
        "title": draft.title,
        "statement": statement,
        "risk_statement": draft.risk,
        "assumptions": list(draft.assumptions),
        **build_card_threat_fields(path, threat),
        **_build_card_systems(run, path, brief, draft),
        "route": {"status": c.Route.STANDALONE, "note": None},
        "prompt_version": c.PromptVersion.SCENARIO_WRITER_EVIDENCE if story else c.PromptVersion.SCENARIO_WRITER,
    } | evidence
    record = _build_common_card_fields(run, path, status, replaces) | {
        "title_key": name_forms.name_match_key(draft.title),
        "content": content,
        "findings": [finding.build_record() for finding in written.findings],
        "rewritten": False,
    }
    if status == c.ScenarioStatus.DONE:
        origin = {"request_id": current_request_id(), "origin": current_job_origin()}
        record["controls"] = {"status": c.Status.QUEUED, "attempts": 0, "queued_at": record["created_at"], **origin}
    return record


def _build_card_evidence(
    brief: write_models.WriterBrief, threat: dict[str, Any], draft: write_models.ScenarioDraft
) -> tuple[str, dict[str, Any]]:
    if brief.cited_index is None:
        if threat.get("intel_search") is None:
            return draft.statement, {}
        statement, cited = draft.statement, []
    else:
        supports = draft.evidence_statement.removesuffix(".") or brief.cited_claim
        statement = f"{draft.statement} {supports} [1]."
        cited = [dict(brief.evidence[brief.cited_index]) | {"n": 1, "supports": supports}]
    return statement, {
        "evidence": cited,
        "evidence_mode": brief.get_evidence_mode(),
        "applicability": {str(item["applicability"]): 1 for item in cited if item.get("applicability")},
        "intel_search": threat.get("intel_search"),
    }


def _build_card_systems(
    run: dict[str, Any], path: dict[str, Any], brief: write_models.WriterBrief, draft: write_models.ScenarioDraft
) -> dict[str, Any]:
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
    run: dict[str, Any], path: dict[str, Any], threat: dict[str, Any], failure: write_models.PathFailure
) -> dict[str, Any]:
    """Builds a visible failure card: what was to be written and why it could not be."""
    return _build_common_card_fields(run, path, c.ScenarioStatus.FAILED) | {
        "content": build_card_threat_fields(path, threat),
        "findings": [],
        "failure": {"code": failure.code, "message": failure.message}
        | ({"reason": failure.reason} if failure.reason else {}),
    }


def _build_common_card_fields(
    run: dict[str, Any], path: dict[str, Any], status: c.ScenarioStatus, replaces: dict[str, Any] | None = None
) -> dict[str, Any]:
    version, now = FIRST_VERSION if replaces is None else replaces["version"] + 1, utc_now()
    return {
        "_id": build_scenario_id(run["_id"], path["path_id"], version),
        "session_id": run["_id"],
        "entity_id": run["entity_id"],
        "asset_id": run["asset_id"],
        "path_id": path["path_id"],
        "version": version,
        "source": c.RunKind.GENERATED,
        "status": status,
        "decision": c.Decision.PENDING,
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
            "type": name_forms.threat_name_without_code(threat_type.get("name") or ""),
            "name": name_forms.threat_name_without_code(threat.get("name") or ""),
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
                if actor.get("role") == c.ActorRole.ACTING
                else {}
            )
            for actor in threat.get("actors") or []
        ],
    }


def build_scenario_id(session_id: str, path_id: str, version: int) -> str:
    """Returns the card id: the same run, path and version always give the same id."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tsg:{session_id}:{path_id}:{version}"))


def find_duplicate_scenario_id(content: dict[str, Any], path_id: str, held: Iterable[dict[str, Any]]) -> str | None:
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
    threat = content.get("threat") or {}
    library_id, status = threat.get("library_id"), threat.get("library_status")
    key = threat.get("key") or None
    if key is None and library_id is not None and status in (None, c.LibraryStatus.ACTIVE):
        key = f"lib:{library_id}"
    words = " ".join(_CITATION_MARKER.sub("", content.get("statement") or "").casefold().split())
    return key, name_forms.threat_name_key(threat.get("name") or ""), content.get("category"), words


_ABOUT_AI = re.compile(c.Controls.AI_THREAT_WORDS)
_NONE_RECORDED = "none recorded"
_REUSED_IF_SAME = ("rerank_model", "embedding_model", "query_instruction", "library", "candidates")
_ScoredControls = list[tuple[LibraryControl, float]]


def map_controls(
    rerank: RerankModel,
    scenario: dict[str, Any],
    context: FrozenContext,
    snapshot: LibrarySnapshot,
    query: ControlQuery | None = None,
) -> dict[str, Any]:
    """Build one scenario's stored controls record (by `query` if built already); ControlsNotMapped: empty library."""
    if not snapshot.library.control_library:
        raise ControlsNotMapped(c.ErrorCode.CONTROL_LIBRARY_EMPTY, c.ErrorMessage.CONTROL_LIBRARY_EMPTY)
    settings = get_settings()
    content = scenario["content"]
    query = query or build_control_query(content, context)
    scored, is_other_type = _search_and_rerank_controls(
        rerank, content, context, snapshot, query, settings.control_candidates
    )
    items = pick_controls_to_keep(
        scored,
        settings.control_similarity_threshold,
        settings.min_controls,
        settings.max_controls,
        settings.nearest_controls,
        is_other_type,
    )
    return {
        "items": items,
        "query": query.text,
        "shortlist": [{"control_id": control.control_id, "score": score} for control, score in scored],
        "made_with": {**read_control_search_settings(snapshot), "ai_controls": query.is_about_ai},
    }


def find_alternative_controls(
    rerank: RerankModel,
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
    query, settings = build_control_query(content, context), read_control_search_settings(snapshot)
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
        scored, _ = _search_and_rerank_controls(rerank, content, context, snapshot, query, settings["candidates"])
    taken = {
        read_control_twin_key(control)
        for control in snapshot.library.control_library
        if control.control_id in identified
    }
    ranked = _rank_controls_without_duplicates(scored)
    return [pair for pair in ranked if read_control_twin_key(pair[0]) not in taken][:count]


def _search_and_rerank_controls(
    rerank: RerankModel,
    content: dict[str, Any],
    context: FrozenContext,
    snapshot: LibrarySnapshot,
    query: ControlQuery,
    candidates: int,
) -> tuple[_ScoredControls, bool]:
    systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    allowed = place_asset_types(context.asset.get("category_code"), (system.get("category_code") for system in systems))
    (found,) = snapshot.find_controls([query.text], candidates, allowed, ai_controls=query.is_about_ai)
    is_other_type = not found
    if is_other_type:
        (found,) = snapshot.find_controls([query.text], candidates, ai_controls=query.is_about_ai)
    controls = [control for control, _ in found]
    scores = rerank.score_relevance(query.text, [describe_control(control) for control in controls])
    return list(zip(controls, scores, strict=True)), is_other_type


def read_control_search_settings(snapshot: LibrarySnapshot) -> dict[str, Any]:
    """Read what a control search is made with: the models, the query instruction, the library's version."""
    settings = get_settings()
    profile = find_model_profile(EMBEDDING_MODEL_PROFILES, settings.embedding_model)
    table = c.EMBEDDING_SOURCE_TABLE[c.EmbeddingCorpus.CONTROL]
    return {
        "rerank_model": settings.rerank_model,
        "embedding_model": settings.embedding_model,
        "query_instruction": profile.instruction_for(c.QUERY_TASKS[c.EmbeddingCorpus.CONTROL]),
        "library": {name: digest.hex() if digest else None for name, digest in snapshot.library.stamp if name == table},
        "candidates": settings.control_candidates,
    }


def pick_controls_to_keep(
    scored: _ScoredControls, cutoff: float, least: int, most: int, nearest: int, is_other_type: bool = False
) -> list[dict[str, Any]]:
    """Keep the strong controls up to `most`, topped up with the nearest; none strong of another type."""
    unique = _rank_controls_without_duplicates(scored)
    kept = [] if is_other_type else [(control, score) for control, score in unique if score >= cutoff][:most]
    target = min(least if kept else nearest, most)
    below = unique if is_other_type else [(control, score) for control, score in unique if score < cutoff]
    chosen = [(pair, c.ControlMatch.EXACT) for pair in kept]
    chosen += [(pair, c.ControlMatch.NEAREST) for pair in below[: max(target - len(kept), 0)]]
    items = []
    for rank, ((control, score), match) in enumerate(chosen, 1):
        if is_other_type:
            template = c.ControlMessage.OTHER_TYPE_REASON
        elif match is c.ControlMatch.EXACT:
            template = c.ControlMessage.STRONG_REASON
        elif kept:
            template = c.ControlMessage.FALLBACK_REASON
        else:
            template = c.ControlMessage.NEAREST_REASON
        asset_type = control.asset_type or _NONE_RECORDED
        rationale = template.format(score=score, cutoff=cutoff, least=least, nearest=nearest, asset_type=asset_type)
        items.append(build_control_item(control, rank, round(score, 1), match, rationale))
    return items


def build_control_item(
    control: LibraryControl, rank: int, score: float | None, match: c.ControlMatch, rationale: str
) -> dict[str, Any]:
    """Build one stored control item: a searched control with its score, a picked one with none."""
    return {
        "control_id": control.control_id,
        "code": control.code,
        "name": control.name,
        "domain": control.domain,
        "asset_type": control.asset_type,
        "description": control.description,
        "rank": rank,
        "score": score,
        "match": match,
        "tier": c.CONTROL_TIERS[match],
        "rationale": rationale,
    }


def _rank_controls_without_duplicates(scored: _ScoredControls) -> _ScoredControls:
    seen: set[object] = set()
    unique: _ScoredControls = []
    for control, score in sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)):
        keys = {control.control_id, read_control_twin_key(control)}
        if not keys & seen:
            seen |= keys
            unique.append((control, score))
    return unique


def read_control_twin_key(control: LibraryControl) -> str:
    """Read the key an IT and an OT copy of one control share: its searched text."""
    return name_forms.name_match_key(describe_control(control))


def build_control_query(content: dict[str, Any], context: FrozenContext) -> ControlQuery:
    """Build the redacted control query: a head never cut, then the parts sharing the room left."""
    threat = content.get("threat") or {}
    actors = content.get("actors") or []
    acting = next((actor["name"] for actor in actors if actor.get("role") == "acting"), "")
    asset_type = facts_safe_for_prompt({"type": context.asset_context.get("asset_type")}).get("type")
    cited = (str(name) for item in content.get("evidence") or [] for name in item.get("mitigations") or ())
    mitigations = tuple(dict.fromkeys(name for name in cited if name.strip()))[: c.Controls.QUERY_MITIGATIONS]
    head = [
        f"Category: {content.get('category') or ''}",
        f"Threat: {threat.get('type') or ''}: {threat.get('name') or ''}",
        f"Attacker: {acting}",
        f"Title: {content.get('title') or ''}",
        f"Asset: {context.asset.get('name') or ''}" + (f" ({asset_type})" if asset_type else ""),
        *([f"Mitigations (MITRE ATT&CK): {'; '.join(mitigations)}"] if mitigations else []),
    ]
    systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    facts = [(f"System {system['name']}", context.read_system_facts(system)) for system in systems]
    facts.append(("Asset facts", context.own_and_organisation_facts()[0]))
    parts = [
        f"{title}: "
        + "; ".join(
            f"{name}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
            for name, value in facts_safe_for_prompt(recorded).items()
            if name != "name"
        )
        for title, recorded in facts
    ]
    parts.append(f"Scenario: {content.get('statement') or ''}")
    parts.append(f"Risk: {content.get('risk_statement') or ''}")
    return ControlQuery(_shorten_query_parts_to_fit("\n".join(head), parts), _is_about_ai(content))


def _is_about_ai(content: dict[str, Any]) -> bool:
    threat, statement = content.get("threat") or {}, content.get("statement") or ""
    for entry in content.get("evidence") or []:
        for fact in entry.get("facts") or []:
            if user := _REAL_WORLD_USER_FACT.fullmatch(str(fact)):
                statement = statement.replace(user["name"] or user["campaign"], "")
    return bool(_ABOUT_AI.search(f"{threat.get('type') or ''} {threat.get('name') or ''} {statement}"))


def _shorten_query_parts_to_fit(head: str, parts: list[str]) -> str:
    head, texts = redact(head), [redact(text) for text in parts]
    room = max(c.Controls.QUERY_MAX_CHARS - len(head) - len(texts), 0)  # one line break before each part
    shares = [0] * len(texts)
    for position, index in enumerate(
        sorted(range(len(texts)), key=lambda text_index: (len(texts[text_index]), text_index))
    ):
        shares[index] = min(len(texts[index]), room // (len(texts) - position))
        room -= shares[index]
    fitted = [name_forms.shorten_text(text, share) for text, share in zip(texts, shares, strict=True)]
    return "\n".join([name_forms.shorten_text(head, c.Controls.QUERY_MAX_CHARS), *(text for text in fitted if text)])
