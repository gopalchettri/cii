"""Planning a run: which threats apply to the asset, each with its attacker, and which attack paths, in which
order. Code checks every AI verdict; an outage or a broken reply is raised and the job retries."""

import dataclasses
import functools
import hashlib
import itertools
import json
import math
import threading
from collections.abc import Collection, Iterable, Mapping, Sequence
from concurrent.futures import Executor, ThreadPoolExecutor
from datetime import date
from decimal import Decimal
from typing import Any, Final

import structlog

from app.ai import (
    ChatModel,
    EmbeddingModel,
    RerankModel,
    TruncatedAiAnswer,
    UnreadableAiAnswer,
)
from app.core.asset_types import asset_type_fits
from app.core.config import get_settings
from app.core.constants import (
    STRIDE_DEFINITIONS,
    ActorRole,
    AiLimits,
    AiOutage,
    AiTask,
    AttackerCheck,
    CandidateRejection,
    ConflictReason,
    ContextProperties,
    ErrorCode,
    Generation,
    IntelMessage,
    LibraryRowKind,
    LogEvent,
    PlanLoss,
    PlanMessage,
    PlanStage,
    PlanTraceLimits,
    PromotionOutcome,
    PromptVersion,
    PropertyMessage,
    ReviewMessage,
    RunKind,
    SessionMessage,
    StrideCategory,
    ThreatFinding,
    UnselectedReason,
)
from app.core.exceptions import Conflict, Forbidden, Invalid, NotFound, PlanRefused, SetupError, Unavailable
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.scenario.library_rules import compatible_asset_types, place_asset_types
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
    name_match_key,
    quoted_for_prompt,
    remove_asset_name,
    replace_codes_with_names,
    shorten_text,
    threat_name_without_code,
)
from app.domain.shared.parallel import run_in_shared_pool
from app.domain.shared.prompt_redaction import DATABASE_KEYS, facts_safe_for_prompt
from app.models.library.library import (
    LibraryActor,
    LibraryThreat,
    LibraryThreatType,
    ThreatLibrary,
)
from app.models.scenario.asset_context import AssetContextRows, FrozenContext, Row
from app.models.scenario.plan import (
    ActorPick,
    AttackPath,
    CategoryAudit,
    CategoryFindings,
    GapFillResponse,
    KindPlace,
    Landscape,
    PlannedActor,
    PlannedThreat,
    RelevanceVerdict,
    ThreatFindings,
    Verdict,
)
from app.models.scenario.views import StartRunRequest
from app.search.service import LibrarySearch
from app.search.snapshot import LibrarySnapshot, linked_actors_by_type

log = structlog.get_logger(__name__)

# --- what the plan's shapes mean

#: The tie-break's "no library id": after every real one.
_NO_LIBRARY_ID = 1 << 62


def in_stride_order(categories: set[StrideCategory]) -> tuple[StrideCategory, ...]:
    """The categories in STRIDE order."""
    return tuple(category for category in STRIDE_DEFINITIONS if category in categories)


def attacker_unsupported(check: str | None, acting: Mapping[str, Any]) -> bool:
    """True when no check backs the acting attacker (`acting` as stored), so none is attributed; a
    curator-linked actor stays. `check`: how the attacker was decided (AttackerCheck)."""
    if check == AttackerCheck.NONE_FITS:
        return True
    return bool(acting.get("closest")) and check in (AttackerCheck.NOT_CHECKED, AttackerCheck.RANKED)


def verdict_applies(verdict: Verdict) -> bool:
    """Relevant on recorded facts alone: the AI may assume a detail, never that something exists."""
    return verdict.relevant and not verdict.needs


def threat_from_library(threat: PlannedThreat) -> bool:
    """True when the threat comes from the library."""
    return threat.catalogue_id is not None


def threat_reason_for(threat: PlannedThreat, kind: str) -> str:
    """Why it applies as `kind`: the gate's reason for that category, else its own reason."""
    return dict(threat.kind_reasons).get(kind, threat.reason)


def threat_reasons_by_kind(threat: PlannedThreat) -> dict[str, str]:
    """Every category's own reason."""
    return {str(category): threat_reason_for(threat, category) for category in threat.categories}


def place_for(threat: PlannedThreat, kind: str) -> KindPlace:
    """Where and how strongly the threat applies as `kind`: that category's verdict, else the threat's own."""
    own = KindPlace(threat.systems, threat.impact, threat.confidence, threat.actor_pick)
    return dict(threat.kind_places).get(kind) or own


def ways_in(place: Verdict | KindPlace) -> tuple[int, ...]:
    """The systems an attacker could get in through: those the gate named, else every system it involves
    (a plan made before the gate named them); () = the asset itself."""
    return place.entry_points or place.systems


def places_by_kind(threat: PlannedThreat) -> dict[str, KindPlace]:
    """Every category's own place."""
    return {str(category): place_for(threat, category) for category in threat.categories}


def plan_drop(
    key: str, name: str, kind: str | None, stage: PlanStage, reason: str, detail: str = ""
) -> dict[str, Any]:
    """One candidate that left the plan, as its trace lists it: the detail redacted and short."""
    return {
        "threat_key": key,
        "threat_name": threat_name_without_code(name),
        "kind": kind,
        "stage": stage,
        "reason": reason,
        "detail": shorten_text(redact(" ".join(detail.split())), PlanTraceLimits.DETAIL_MAX_CHARS),
    }


def planned_threat_record(threat: PlannedThreat) -> dict[str, Any]:
    """The threat as the plan stores it."""
    record: dict[str, Any] = {
        "key": threat.key,
        "library_id": threat.catalogue_id,
        "ai_generated": not threat_from_library(threat),
        "type": {"id": threat.type_id, "name": threat.type_name},
        "name": threat.name,
        "category": threat.categories[0],
        "categories": list(threat.categories),
        "systems": list(threat.systems),
        "reason": threat.reason,
        "reasons": threat_reasons_by_kind(threat),
        "impact": threat.impact,
        "confidence": threat.confidence,
        "actors": [
            {"id": actor.actor_id, "name": actor.name, "role": actor.role, "closest": False}
            for actor in threat.actors
        ],
        "attacker_check": threat.attacker_check,
        "attacker_check_reason": threat.attacker_check_reason or None,
        "actions": list(threat.actions),
    }
    return record


def attack_path_id(path: AttackPath) -> str:
    """A stable id from the path's threats and scope."""
    keys = "|".join(step.key for step in path.steps) + (f"@{path.scope}" if path.scope else "")
    return hashlib.sha256(keys.encode()).hexdigest()[:16]


def attack_path_categories(path: AttackPath) -> tuple[StrideCategory, ...]:
    """The first step's main category, then the others in STRIDE order."""
    first = path.steps[0].categories[0]
    rest = {category for step in path.steps for category in step.categories} - {first}
    return (first, *in_stride_order(rest))


def attack_path_systems(path: AttackPath) -> tuple[int, ...]:
    """Every system the path's steps touch, sorted."""
    return tuple(sorted({system for step in path.steps for system in step.systems}))


def attack_path_from_library(path: AttackPath) -> bool:
    """True when every step comes from the library."""
    return all(threat_from_library(step) for step in path.steps)


def attack_path_impact(path: AttackPath) -> int:
    """The highest impact of the path's steps."""
    return max(step.impact for step in path.steps)


def attack_path_confidence(path: AttackPath) -> float:
    """The lowest confidence of the path's steps."""
    return min(step.confidence for step in path.steps)


def attack_path_tie_break(path: AttackPath) -> tuple[bool, int, str, str]:
    """The same order on every run: library before AI, the lowest library id, the path id, the text."""
    library_ids = [step.catalogue_id for step in path.steps if step.catalogue_id is not None]
    text = " -> ".join(step.name for step in path.steps)
    digest = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
    lowest = min(library_ids, default=_NO_LIBRARY_ID)
    return (not attack_path_from_library(path), lowest, attack_path_id(path), digest)


# --- the landscape: the asset and its systems as one text

_SECTOR_KEYS = ("sector", "sub_sector", "critical_service")
#: The asset facts every step weighs: they lead the asset's text.
_LEAD_KEYS = (*_SECTOR_KEYS, "asset_priority")
#: A frozen system's keys that are not facts; every other key is one.
_NOT_SYSTEM_FACTS = frozenset(ContextProperties.ALWAYS_USED)


def raw_system_facts(system: dict[str, Any]) -> dict[str, Any]:
    """A system's recorded facts, its category as its asset type; not yet safe for a prompt."""
    return {
        "name": system["name"],
        **{
            "asset_type" if key == "category_name" else key: value
            for key, value in system.items()
            if key not in _NOT_SYSTEM_FACTS
        },
    }


def _sector_text(asset_context: dict[str, Any]) -> str:
    """The asset's sector, sub-sector and critical service as one line ('' when none is set)."""
    words = []
    for value in (asset_context.get(key) for key in _SECTOR_KEYS):
        for item in value if isinstance(value, list | tuple) else [value]:
            text = str(item).strip() if item is not None else ""
            if text:
                words.append(text)
    return " ".join(words)


def describe_asset_for_ai(context: FrozenContext, budget: int, country: str = "") -> Landscape:
    """The asset (its lead facts first, its systems by name and asset type, the organisation's facts on a
    background line) and each system by alias and quoted name with its facts, within `budget` characters:
    the longest fact is cut first, so every system keeps its line. `country`: a fact, intelligence on only."""
    own_facts, organisation_facts = context.own_and_organisation_facts()
    lead = {key: own_facts[key] for key in _LEAD_KEYS if key in own_facts}
    systems = [facts_safe_for_prompt(raw_system_facts(system)) for system in context.systems]
    asset_facts = facts_safe_for_prompt({**lead, **own_facts})
    parts = [asset_facts, facts_safe_for_prompt(organisation_facts), *systems]
    # unrecorded is left out, never null: the AI reads it as unknown
    listed: list[dict[str, Any]] = [
        {key: facts[key] for key in ("name", "asset_type") if key in facts} for facts in systems
    ]
    text = _landscape_text(context, country, listed, parts)
    if over := max(len(text) - budget, 0):
        cut = cut_to_fit(parts, sum(len(as_json(part)) for part in parts) - over)
        text = _landscape_text(context, country, listed, cut)
    return Landscape(
        # ponytail: names, aliases and lists are never cut; past them the text is cut, never a system's line
        text=shorten_text(text, budget),
        system_ids={system["alias"]: system["id"] for system in context.systems},
        system_names={system["alias"]: system["name"] for system in context.systems},
        sector=_sector_text(context.asset_context),
        cut=over > 0,
    )


def _landscape_text(
    context: FrozenContext, country: str, listed: list[dict[str, Any]], parts: list[dict[str, Any]]
) -> str:
    """The landscape's lines from its parts: the asset's facts, the organisation's, then each system's."""
    asset_facts, organisation, *systems = parts
    where = {ContextProperties.COUNTRY_KEY: country} if country else {}
    described = {
        "asset": redact(context.asset["name"]),
        **where,
        "asset_context": asset_facts,
        "supporting_systems": listed,
    }
    lines = ["ASSET: " + as_json(described)]
    if organisation:
        lines.append(ThreatFinding.ORGANISATION_LABEL + as_json(organisation))
    for system, facts in zip(context.systems, systems, strict=True):
        name = quoted_for_prompt(shorten_text(system["name"], ThreatFinding.SYSTEM_NAME_CHARS))
        lines.append(f"{system['alias']} {name}: {as_json(facts)}")
    return "\n".join(lines)


# --- the planner's prompts ([scenario.gate] and [scenario.gap_fill] in app/prompts.toml)

_GATE_RULES: str = PROMPTS["scenario"]["gate"]["text"]
_GATE_FOLLOW_UP: str = PROMPTS["scenario"]["gate"]["follow_up"]
_GAP_FILL_RULES: str = PROMPTS["scenario"]["gap_fill"]["text"]
_PLANNER_SYSTEM: str = PROMPTS["scenario"]["gate"]["system"]


def _stride_lines(categories: Iterable[StrideCategory]) -> str:
    """The STRIDE category lines a prompt's categories are judged by, once each."""
    return "STRIDE CATEGORIES:\n" + "".join(f"- {kind}: {STRIDE_DEFINITIONS[kind]}.\n" for kind in categories)


def relevance_gate_prompt(
    landscape: str, slots: list[dict[str, Any]], problems: Sequence[str] = ()
) -> ChatPrompt:
    """The gate's ask: does each candidate apply to the asset, under which of its own categories, and which
    listed attacker could do it; a follow-up is also told the `problems` the earlier answer had with them."""
    rules = _stride_lines(StrideCategory) + _GATE_RULES
    if problems:
        shown = (
            problem[: AiLimits.REASK_PROBLEM_CHARS] for problem in problems[: AiLimits.REASK_MAX_PROBLEMS]
        )
        rules += _GATE_FOLLOW_UP.replace("{problems}", "; ".join(shown))
    return _PLANNER_SYSTEM, f"LANDSCAPE:\n{landscape}\n\n{rules}\n\nCANDIDATES:\n" + json.dumps(
        slots, ensure_ascii=False
    )


def gap_fill_prompt(landscape: str, empty: Sequence[tuple[StrideCategory, int, Sequence[str]]]) -> ChatPrompt:
    """The one ask for an AI threat for each empty category: (category, library threats judged, the names of
    those judged not to apply)."""
    listed = [{"category": kind, "judged": judged, "rejected": list(names)} for kind, judged, names in empty]
    rules = _stride_lines(kind for kind, _, _ in empty) + _GAP_FILL_RULES
    return _PLANNER_SYSTEM, f"LANDSCAPE:\n{landscape}\n\n{rules}\n\nEMPTY CATEGORIES:\n" + json.dumps(
        listed, ensure_ascii=False
    )


# --- the relevance gate's verdicts, checked in code

#: Most threats judged per gate call (CII_THREATS_PER_QUESTION); more are split evenly over the fewest calls.
GATE_BATCH_SIZE = ThreatFinding.THREATS_PER_QUESTION
#: A STRIDE category by the key its name is matched with: "Denial-of-Service" is Denial of Service.
_STRIDE_BY_KEY: Final = {name_match_key(kind): kind for kind in StrideCategory}


def _gate_prompt_of(landscape: str, batch: Sequence[dict[str, Any]]) -> ChatPrompt:
    """The gate prompt a batch of candidates would be asked in."""
    return relevance_gate_prompt(landscape, list(batch))


def _candidate_for_gate(
    slot: str, threat_type: str, threat: str, categories: Iterable[StrideCategory], attackers: list[str]
) -> dict[str, Any]:
    """A candidate as the gate is shown it: names without library codes, its own categories."""
    return {
        "slot": slot,
        "threat_type": threat_name_without_code(threat_type),
        "threat": threat_name_without_code(threat),
        "categories": [str(kind) for kind in categories],
        "attackers": attackers,
    }


def parse_verdict(
    item: dict[str, Any], candidate: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[StrideCategory, Verdict] | None, list[str]]:
    """One threat's verdict checked against its `candidate`, as its verdict under each category it named and
    under each of its own (one it lists but did not name does not apply); a named category it does not list
    is kept for code to drop. Systems, ways in, confidence, needs, attacker and actions are the threat's."""
    named, problems = _verdict_problems(item, candidate, aliases)
    if problems:
        return None, problems
    relevant, reason = item["relevant"], str(item.get("reason") or "").strip()
    own = [kind for kind in named if kind in candidate["categories"]]
    entry_points = (item.get("entry_points") or ()) if relevant else ()
    shared = Verdict(
        relevant=False,
        systems=tuple(sorted({aliases[alias] for alias in item.get("systems") or ()})),
        entry_points=tuple(sorted({aliases[alias] for alias in entry_points})),
        reason=PlanMessage.OTHER_KINDS.format(kinds=", ".join(own))
        if relevant
        else reason[: ThreatFinding.REASON_MAX_CHARS],
        impact=0,
        confidence=float(item.get("confidence") or 0) if relevant else 0.0,
        needs=_needs(item.get("needs") or []),
        actor_pick=actor_pick(item, candidate["attackers"]) if relevant else None,
        kinds=tuple(own),
        actions=_actions(item.get("actions")) if relevant else (),
    )
    verdicts = {StrideCategory(kind): shared for kind in candidate["categories"]}
    for kind, (impact, kind_reason) in named.items():
        verdicts[kind] = dataclasses.replace(shared, relevant=True, impact=impact, reason=kind_reason)
    return verdicts, []


def _verdict_problems(
    item: dict[str, Any], candidate: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[StrideCategory, tuple[int, str]], list[str]]:
    """What is wrong with a verdict: its threat copied back, known aliases, a way in among them, its own
    categories and a 0-100 confidence when relevant, a reason when rejected. Its named categories too."""
    slot, relevant, systems = item["slot"], item.get("relevant"), item.get("systems") or []
    entry_points = (item.get("entry_points") or []) if relevant is True else None
    confidence, needs = item.get("confidence"), item.get("needs") or []
    problems = _place_problems(slot, systems, entry_points, aliases)
    if _name_key(str(item.get("threat") or "")) != _name_key(candidate["threat"]):
        problems.append(f"{slot}: threat must be this slot's own threat, copied exactly")
    if not isinstance(relevant, bool):
        problems.append(f"{slot}: relevant must be true or false")
    named, kind_problems = _named_kinds(slot, item.get("categories"), candidate["categories"])
    if relevant is True:
        problems += kind_problems
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int | float)
            or not 0 <= confidence <= 100
        ):
            problems.append(f"{slot}: confidence must be a number from 0 to 100")
    elif not str(item.get("reason") or "").strip():
        problems.append(f"{slot}: a threat that does not apply needs its reason")
    if not isinstance(needs, list) or any(not isinstance(need, str) for need in needs):
        problems.append(f"{slot}: needs must be a list of names ([] when everything it needs is recorded)")
    shown = {**item, "systems": systems, "needs": needs, "entry_points": entry_points or []}
    problems = problems or answer_item_problems(RelevanceVerdict, shown, slot)
    return (named if relevant is True else {}), problems


def _named_kinds(
    slot: str, named: Any, own: Sequence[str]
) -> tuple[dict[StrideCategory, tuple[int, str]], list[str]]:
    """The STRIDE categories a relevant verdict names, the main first, each with its impact and reason; a
    name that is no STRIDE category, or none of the slot's own, is a problem."""
    if not isinstance(named, list) or not named:
        return {}, [f"{slot}: categories must list the slot's own categories it belongs to, the main first"]
    kinds: dict[StrideCategory, tuple[int, str]] = {}
    problems = []
    for entry in named:
        entry = entry if isinstance(entry, dict) else {}
        kind = _STRIDE_BY_KEY.get(name_match_key(str(entry.get("name") or "")))
        impact, reason = str(entry.get("impact") or "").upper(), str(entry.get("reason") or "").strip()
        if kind is None:
            listed = ", ".join(own)
            problems.append(f"{slot}: {entry.get('name')!r} is no STRIDE category: copy its own: {listed}")
        elif impact not in ThreatFinding.IMPACT_RANK or not reason:
            problems.append(f"{slot}: {kind} needs its impact (HIGH, MEDIUM or LOW) and its reason")
        else:
            kinds.setdefault(
                kind, (ThreatFinding.IMPACT_RANK[impact], reason[: ThreatFinding.REASON_MAX_CHARS])
            )
    if not problems and not set(kinds) & set(own):
        problems.append(f"{slot}: categories must name at least one of its own: {', '.join(own)}")
    return kinds, problems


def _actions(listed: Any) -> tuple[str, ...]:
    """The gate's actions for a threat, each a non-empty phrase; () when it gave none usable (no re-ask)."""
    if not isinstance(listed, list):
        return ()
    return tuple(" ".join(action.split()) for action in listed if isinstance(action, str) and action.strip())


def _place_problems(slot: str, systems: Any, entry_points: Any, aliases: dict[str, int]) -> list[str]:
    """What is wrong with a verdict's systems and ways in: listed aliases only, the ways in among them, and at
    least one way in when it names systems."""
    if not isinstance(systems, list) or any(
        not isinstance(alias, str) or alias not in aliases for alias in systems
    ):
        return [f"{slot}: systems must be listed aliases only (SYS1, SYS2 ...)"]
    if entry_points is None:  # a rejected threat has no way in to name
        return []
    if not isinstance(entry_points, list) or any(alias not in systems for alias in entry_points):
        return [f"{slot}: entry_points must be aliases from its own systems"]
    if systems and not entry_points:
        return [f"{slot}: entry_points must name the systems among its own an attacker could get in through"]
    return []


def actor_pick(item: dict[str, Any], listed: Sequence[str]) -> ActorPick:
    """The gate's pick: a listed name with its reason (if any), else none fits; never an unchecked one."""
    by_key = {name_match_key(name): name for name in listed}
    reason = str(item.get("attacker_reason") or "").strip()[: ThreatFinding.REASON_MAX_CHARS]
    return ActorPick(by_key.get(name_match_key(str(item.get("attacker") or ""))), reason)


def _needs(names: list[str]) -> tuple[str, ...]:
    """What a verdict says its threat needs that nothing recorded mentions, blanks dropped and bounded."""
    kept = [" ".join(name.split())[: ThreatFinding.NEED_MAX_CHARS] for name in names if name.strip()]
    return tuple(kept[: ThreatFinding.NEEDS_MAX_ITEMS])


def _read_verdicts(
    answer: dict[str, Any], asked: dict[str, dict[str, Any]], aliases: dict[str, int]
) -> tuple[tuple[dict[str, dict[StrideCategory, Verdict]], dict[str, list[str]]], list[str]]:
    """({slot: its verdicts} for every asked slot answered well, {slot: its problems} for each answered
    wrongly) (`asked`: the candidates by slot); the re-ask problems only when no slot was answered well, so
    one bad slot never re-asks the whole batch."""
    items, problems = answers_for_asked_slots(answer, "verdicts", set(asked))
    judged, faults = {}, {}
    for item in items:
        verdicts, item_problems = parse_verdict(item, asked[item["slot"]], aliases)
        problems += item_problems
        if verdicts is None:
            faults[item["slot"]] = item_problems
        else:
            judged[item["slot"]] = verdicts
    return (judged, faults), [] if judged else problems


def _read_proposals(
    answer: dict[str, Any], asked: Sequence[StrideCategory], aliases: dict[str, int]
) -> tuple[dict[StrideCategory, dict[str, Any]], list[str]]:
    """{category: its proposal} for every asked category answered well; the problems only when none was."""
    items = answer.get("proposals")
    if not isinstance(items, list):
        return {}, ['the reply must be {"proposals": [...]}']
    by_key = {name_match_key(kind): kind for kind in asked}
    proposals: dict[StrideCategory, dict[str, Any]] = {}
    problems = []
    for item in items:
        named = str(item.get("category") or "") if isinstance(item, dict) else ""
        kind = by_key.get(name_match_key(named))
        if kind is None or kind in proposals:
            problems.append(f"category {named or '?'} is not listed or answered twice")
            continue
        proposal, item_problems = _read_proposal(item, aliases)
        problems += [f"{kind}: {problem}" for problem in item_problems]
        if proposal is not None:
            proposals[kind] = proposal
    return proposals, [] if proposals else problems


def _read_proposal(
    answer: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[str, Any] | None, list[str]]:
    """The gap-fill answer as {applies, threat_type, threat, attacker, reason, systems}, or its problems."""
    if not isinstance(answer.get("applies"), bool):
        return None, ['the reply must be {"applies": true|false, ...}']
    checked = answer if answer["applies"] else {"reason": "", **answer}  # "none applies" needs no reason
    if problems := answer_item_problems(GapFillResponse, checked, "the reply"):
        return None, problems
    if not answer["applies"]:
        return {"applies": False}, []
    fields = {
        name: str(answer.get(name) or "").strip() for name in ("threat_type", "threat", "attacker", "reason")
    }
    problems = [f"{name} is required" for name, value in fields.items() if not value]
    if len(fields["threat_type"]) + len(fields["threat"]) > ThreatFinding.GAP_FILL_MAX_CHARS:
        problems.append("the proposal is too long")
    systems = answer.get("systems") or []
    if not isinstance(systems, list) or any(not isinstance(a, str) or a not in aliases for a in systems):
        problems.append("systems must be listed aliases only (SYS1, SYS2 ...)")
    return (None, problems) if problems else ({**fields, "applies": True, "systems": systems}, [])


def _lost(threat: str, reason: str, detail: str = "") -> dict[str, Any]:
    """A gap-fill proposal not kept: its threat ('' when the reply was skipped), why, and a detail."""
    return {"threat": threat, "reason": reason, "detail": detail}


def _rejected(threat: LibraryThreat, code: CandidateRejection, detail: str = "") -> dict[str, Any]:
    """A library threat not kept under a category: its name feeds the gap-fill ask, its detail the trace."""
    return {"threat": threat.name, "library_id": threat.catalogue_id, "code": code, "detail": detail}


# --- one run's gate and gap fill

#: A gate or gap-fill ask: a job's retry or re-send takes the answers its earlier try got (tsg_ai_calls).
_ask_reusing = functools.partial(ask_ai_and_check, reuse_earlier_answer=True)
#: A gap fill's outcome for one category: its AI threat, else why the proposal was not kept (None: none).
_GapOutcome = tuple[PlannedThreat | None, dict[str, Any] | None]


def _attackers_for(threat: LibraryThreat | LibraryThreatType) -> list[str]:
    """What a candidate lists for the gate's pick: its type's linked actors."""
    return [actor.name for actor in threat.linked_actors]


def _own_verdicts(
    key: str, own: Sequence[StrideCategory], verdicts: dict[StrideCategory, Verdict] | None
) -> dict[StrideCategory, Verdict] | None:
    """A threat's verdicts under its own categories (None: not judged); a STRIDE category the gate named that
    the threat does not list is dropped, with a warning naming the threat."""
    if verdicts is None:
        return None
    if unlisted := sorted(set(verdicts) - set(own)):
        log.warning(LogEvent.PLANNER_CATEGORY_DROPPED, threat_key=key, categories=unlisted)
    return {kind: verdicts[kind] for kind in own}


def _file_verdict(result: CategoryFindings, threat: LibraryThreat, verdict: Verdict | None) -> None:
    """A library threat's verdict under one category, filed in that category's result: accepted, refused for
    a need nothing records, not relevant, or not judged (None)."""
    audit = result.audit
    if verdict is None:
        audit.not_judged.append(threat)
        return
    audit.judged_ids.add(threat.catalogue_id)
    if verdict_applies(verdict):
        result.accepted.append((threat, verdict))
    elif verdict.needs:
        needs = "; ".join(verdict.needs)
        audit.rejected.append(_rejected(threat, CandidateRejection.NEEDS_UNRECORDED, needs))
    else:
        audit.rejected.append(_rejected(threat, CandidateRejection.NOT_RELEVANT, verdict.reason))


def _checked_proposal(
    kind: StrideCategory,
    proposal: dict[str, Any],
    library_type: LibraryThreatType,
    verdicts: dict[StrideCategory, Verdict] | None,
) -> _GapOutcome:
    """A gap-fill proposal as the gate judged it: the AI threat it becomes, else why it was not kept."""
    threat = proposal["threat"]
    own = _own_verdicts(f"ai:{name_match_key(threat)}", (kind,), verdicts)
    if own is None:  # its gate reply was skipped
        return None, _lost(threat, PlanLoss.NOT_JUDGED)
    if not verdict_applies(verdict := own[kind]):
        code = CandidateRejection.NEEDS_UNRECORDED if verdict.needs else CandidateRejection.NOT_RELEVANT
        return None, _lost(threat, code, "; ".join(verdict.needs) or verdict.reason)
    return _ai_threat(kind, proposal, verdict, library_type), None


class _ThreatJudge:
    """One run's relevance gate and gap fill: one landscape, the run's judgeable library threats, one shared
    call pool."""

    def __init__(
        self,
        chat: ChatModel,
        matcher: "_ProposalMatcher",
        landscape: Landscape,
        threats: list[LibraryThreat],
        pool: Executor,
        last_attempt: bool,
    ) -> None:
        self._chat, self._matcher, self._landscape = chat, matcher, landscape
        self._threats, self._pool, self._last_attempt = threats, pool, last_attempt
        self._unavailable = threading.Event()  # set once a call raised Unavailable: no new gate call starts

    def judge_all(self) -> list[CategoryFindings]:
        """Every library threat judged once for all its own categories and filed under each: one result per
        category, in STRIDE order; a threat whose batch was skipped is not judged under any."""
        items = [
            _candidate_for_gate(
                f"{ThreatFinding.RECORD_SLOT}{n}", t.type_name, t.name, t.categories, _attackers_for(t)
            )
            for n, t in enumerate(self._threats, start=1)
        ]
        judged = self._judge(items)
        found = {kind: CategoryFindings([], None, CategoryAudit(kind)) for kind in StrideCategory}
        for item, threat in zip(items, self._threats, strict=True):
            verdicts = _own_verdicts(
                f"lib:{threat.catalogue_id}", threat.categories, judged.get(item["slot"])
            )
            for kind in threat.categories:
                _file_verdict(found[kind], threat, None if verdicts is None else verdicts[kind])
        return list(found.values())

    def fill_gaps(self, found: list[CategoryFindings]) -> list[CategoryFindings]:
        """One AI threat for each category none of whose library threats applies though all were judged: one
        gap-fill ask for all of them, then one gate check of the proposals."""
        empty = [result.audit for result in found if not result.accepted and self._all_judged(result.audit)]
        outcomes = self._gap_threats(empty) if empty else {}
        for audit in empty:
            audit.gap_fill_lost = outcomes[audit.category][1]
        return [
            dataclasses.replace(result, ai_threat=outcomes.get(result.audit.category, (None, None))[0])
            for result in found
        ]

    def _all_judged(self, audit: CategoryAudit) -> bool:
        """Whether every library threat of the category came back judged."""
        return {t.catalogue_id for t in self._threats if audit.category in t.categories} <= audit.judged_ids

    def _judge(self, items: list[dict[str, Any]]) -> dict[str, dict[StrideCategory, Verdict]]:
        """Every slot judged: at most GATE_BATCH_SIZE a batch, split evenly over the fewest batches and halved
        while a call would hold more than CII_AI_CALL_TOKENS_LIMIT, judged CII_THREAT_QUESTIONS_AT_ONCE at
        once; a skipped slot has no verdicts."""
        if not items:
            return {}
        size = math.ceil(len(items) / math.ceil(len(items) / GATE_BATCH_SIZE))
        prompt_of = functools.partial(_gate_prompt_of, self._landscape.text)
        batches = [
            list(part)
            for batch in itertools.batched(items, size)
            for part in within_call_limit(batch, prompt_of, AiTask.RELEVANCE_GATE)
        ]
        judged = run_in_shared_pool(self._pool, self._judge_batch, batches)
        return {slot: verdicts for batch in judged for slot, verdicts in batch.items()}

    def _judge_batch(
        self, batch: list[dict[str, Any]], problems: list[str] | None = None, halved: bool = False
    ) -> dict[str, dict[StrideCategory, Verdict]]:
        """One gate call's verdicts (`problems`: this is the follow-up, told what the earlier answer got wrong
        with its slots). A cut-off first ask is asked again as halves once, each a first ask of its own; the
        slots a first ask left out or got wrong get the one follow-up. None: skipped, or the job retries."""
        if self._unavailable.is_set():
            return {}
        first_ask = problems is None
        prompt = relevance_gate_prompt(self._landscape.text, batch, problems or ())
        asked = {item["slot"]: item for item in batch}
        read = functools.partial(_read_verdicts, asked=asked, aliases=self._landscape.system_ids)
        judged: dict[str, dict[StrideCategory, Verdict]]
        faults: dict[str, list[str]]
        try:
            judged, faults = _ask_reusing(self._chat, AiTask.RELEVANCE_GATE, prompt, read)
        except Unavailable:
            self._unavailable.set()
            raise
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            if isinstance(exc, TruncatedAiAnswer) and first_ask and not halved and len(batch) > 1:
                half = (len(batch) + 1) // 2  # ponytail: halved once; a half cut off again is not judged
                first, second = batch[:half], batch[half:]
                return self._judge_batch(first, halved=True) | self._judge_batch(second, halved=True)
            self._retry_or_skip(AiTask.RELEVANCE_GATE, exc, [item["threat"] for item in batch], first_ask)
            return {}
        if first_ask and (missing := [item for item in batch if item["slot"] not in judged]):
            told = [problem for item in missing for problem in faults.get(item["slot"], ())]
            judged |= self._judge_batch(missing, told)  # ponytail: once; still wrong = not judged
        return judged

    def _retry_or_skip(
        self, check: AiTask, error: Exception, asked: list[str], first_ask: bool = True
    ) -> None:
        """An unreadable reply to a first ask raises Unavailable, so the job asks again later, unless this is
        the job's last attempt; a cut-off reply, one to an ask again, or any on the last attempt, is skipped
        with a warning naming what it asked."""
        if isinstance(error, UnreadableAiAnswer) and first_ask and not self._last_attempt:
            self._unavailable.set()
            raise Unavailable(str(error)) from error
        log.warning(LogEvent.PLANNER_THREATS_NOT_JUDGED, check=check, asked=asked, message=str(error))

    def _gap_threats(self, empty: list[CategoryAudit]) -> dict[StrideCategory, _GapOutcome]:
        """Each empty category's AI threat, or why its proposal was not kept: one gap-fill ask, the library
        checks, then one gate check of every proposal left."""
        proposals = self._proposals(empty)
        outcomes: dict[StrideCategory, _GapOutcome] = {}
        to_judge: list[tuple[StrideCategory, dict[str, Any], LibraryThreatType, dict[str, Any]]] = []
        for kind in (audit.category for audit in empty):
            if (proposal := proposals.get(kind)) is None:  # not answered, or the reply was skipped
                outcomes[kind] = None, _lost("", PlanLoss.NOT_JUDGED)
                continue
            library_type, lost = self._matcher.library_type(kind, proposal)
            outcomes[kind] = None, lost  # a proposal the gate judges gets the gate's outcome below
            if library_type is not None:
                slot, threat_type = f"{ThreatFinding.RECORD_SLOT}{len(to_judge) + 1}", proposal["threat_type"]
                item = _candidate_for_gate(
                    slot, threat_type, proposal["threat"], (kind,), _attackers_for(library_type)
                )
                to_judge.append((kind, proposal, library_type, item))
        judged = self._judge([item for *_, item in to_judge])
        for kind, proposal, library_type, item in to_judge:
            outcomes[kind] = _checked_proposal(kind, proposal, library_type, judged.get(item["slot"]))
        return outcomes

    def _proposals(self, empty: list[CategoryAudit]) -> dict[StrideCategory, dict[str, Any]]:
        """The gap fill's one ask for every empty category, each with the library threats judged not to apply:
        {category: its proposal}; {} when the reply is skipped."""
        kinds = [audit.category for audit in empty]
        rejected = [dict.fromkeys(threat_name_without_code(r["threat"]) for r in a.rejected) for a in empty]
        asked = [
            (a.category, len(a.judged_ids), list(names)) for a, names in zip(empty, rejected, strict=True)
        ]
        read = functools.partial(_read_proposals, asked=kinds, aliases=self._landscape.system_ids)
        try:
            proposals: dict[StrideCategory, dict[str, Any]] = _ask_reusing(
                self._chat, AiTask.GAP_FILL, gap_fill_prompt(self._landscape.text, asked), read
            )
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            self._retry_or_skip(AiTask.GAP_FILL, exc, [str(kind) for kind in kinds])
            return {}
        return proposals


class _ProposalMatcher:
    """A gap-fill proposal against the run's library snapshot: a repeat of a threat judged, or the library
    type it is planned under."""

    def __init__(
        self, rerank: RerankModel, snapshot: LibrarySnapshot, allowed_types: Collection[str]
    ) -> None:
        self._rerank, self._snapshot, self._allowed_types = rerank, snapshot, allowed_types

    def library_type(
        self, kind: StrideCategory, proposal: dict[str, Any]
    ) -> tuple[LibraryThreatType | None, dict[str, Any] | None]:
        """The library type an applying proposal is planned under: it is no library threat already judged,
        and its type matches one that links an attacker; else why it was not kept (None: none proposed)."""
        if not proposal["applies"]:
            return None, None
        threat = proposal["threat"]
        if self._is_library_threat(threat, kind):
            return None, _lost(threat, PlanLoss.LIBRARY_REPEAT)
        (types,) = self._snapshot.find_threat_types(
            [proposal["threat_type"]], top_k=ThreatFinding.LIBRARY_MATCH_CANDIDATES, category=kind
        )
        matched = self._best_match(proposal["threat_type"], [(found, found.name) for found, _ in types])
        if matched is None:
            return None, _lost(threat, PlanLoss.TYPE_UNMATCHED, proposal["threat_type"])
        if not matched.linked_actors:
            log.info(LogEvent.PLANNER_THREAT_NOT_PLANNED, category=kind, type_id=matched.type_id)
            return None, _lost(threat, PlanLoss.NO_LINKED_ACTOR, matched.name)
        return matched, None

    def _is_library_threat(self, threat: str, category: StrideCategory) -> bool:
        """Whether a proposal is a library threat of the category this run judged (and found not to apply)."""
        (hits,) = self._snapshot.find_threats(
            [(threat, category)],
            top_k=ThreatFinding.LIBRARY_MATCH_CANDIDATES,
            allowed_types=self._allowed_types,
        )
        return (
            self._best_match(threat, [(found, threat_name_without_code(found.name)) for found, _ in hits])
            is not None
        )

    def _best_match[Row](self, text: str, candidates: list[tuple[Row, str]]) -> Row | None:
        """The candidate the reranker scores highest for `text`, if it reaches THREAT_SIMILARITY_THRESHOLD."""
        if not candidates:
            return None
        scores = self._rerank.score_relevance(text, [label for _, label in candidates])
        best = max(range(len(candidates)), key=scores.__getitem__)
        return candidates[best][0] if scores[best] >= get_settings().threat_similarity_threshold else None


def _ai_threat(
    category: StrideCategory, proposal: dict[str, Any], verdict: Verdict, library_type: LibraryThreatType
) -> PlannedThreat:
    """The proposal as a planned threat of the library type it matched, with the gate's attacker pick."""
    return PlannedThreat(
        key=f"ai:{name_match_key(proposal['threat'])}",  # one AI threat under two categories is one
        catalogue_id=None,
        type_id=library_type.type_id,
        type_name=library_type.name,
        name=proposal["threat"],
        categories=(category,),
        systems=verdict.systems,
        impact=verdict.impact,
        confidence=verdict.confidence,
        reason=verdict.reason,
        kind_places=((category, _place_of(verdict)),),
        actor_pick=verdict.actor_pick,
        actions=verdict.actions,
    )


def _library_threat(category: StrideCategory, threat: LibraryThreat, verdict: Verdict) -> PlannedThreat:
    """An accepted library threat as the plan holds it, before its attacker is chosen."""
    return PlannedThreat(
        key=f"lib:{threat.catalogue_id}",
        catalogue_id=threat.catalogue_id,
        type_id=threat.type_id,
        type_name=threat.type_name,
        name=threat.name,
        categories=(category,),
        systems=verdict.systems,
        impact=verdict.impact,
        confidence=verdict.confidence,
        reason=verdict.reason,
        kind_places=((category, _place_of(verdict)),),
        actor_pick=verdict.actor_pick,
        actions=verdict.actions,
    )


def _place_of(verdict: Verdict) -> KindPlace:
    """Where and how strongly a verdict says its threat applies, and its attacker pick."""
    return KindPlace(
        verdict.systems, verdict.impact, verdict.confidence, verdict.actor_pick, verdict.entry_points
    )


#: What the library holds under a name: the outcome, the type id and the threat id (None when rejected).
_NamedRecord = tuple[PromotionOutcome, int | None, int | None]


def library_threats_named(library: ThreatLibrary, name: str) -> _NamedRecord | None:
    """What the library holds under a threat name (normalised, codes left out): a live threat, then one
    pending a curator (both existing), then a wording a curator rejected; None for a new name."""
    key = name_match_key(threat_name_without_code(name))

    def named_alike(other: str) -> bool:
        """Whether `other` is the looked-up name."""
        return name_match_key(threat_name_without_code(other)) == key

    for threat in library.threats:
        if named_alike(threat.name):
            return PromotionOutcome.EXISTING, threat.type_id, threat.catalogue_id
    for row in library.pending:
        if row.kind == LibraryRowKind.THREAT and named_alike(row.name):
            return PromotionOutcome.EXISTING, row.type_id, row.row_id
    if any(named_alike(row.name) for row in library.curator_rejected):
        return PromotionOutcome.CURATOR_REJECTED, None, None
    return None


# --- code's check on the verdicts: the asset-type fit


def _run_asset_types(context: FrozenContext) -> frozenset[str]:
    """The AssetType values a library threat must fit to be judged: the asset's or a chosen system's."""
    return compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in context.systems)
    )


def _place_on_matching_systems(found: list[CategoryFindings], context: FrozenContext) -> None:
    """Each accepted library threat keeps only the ways in (systems, or the asset itself) its AssetType fits,
    and every system it involves; with no way in that fits, it is refused."""
    asset_fits, system_fits = _place_fits(context)
    for result in found:
        kept = []
        for threat, verdict in result.accepted:
            placed = _placed(threat, verdict, asset_fits, system_fits)
            if placed is None:
                detail = f"asset type {threat.asset_type}"
                mismatch = _rejected(threat, CandidateRejection.ASSET_TYPE_MISMATCH, detail)
                result.audit.rejected.append(mismatch)
            else:
                kept.append((threat, placed))
        result.accepted[:] = kept


def _keep_on_matching_systems(
    threats: list[PlannedThreat], library: Sequence[LibraryThreat], context: FrozenContext
) -> tuple[list[PlannedThreat], list[dict[str, Any]]]:
    """After a merge (an AI twin's kinds folded in), each library threat keeps each kind only through the ways
    in its type fits; a kind with none is dropped, and a threat left with no kind. The threats, the drops."""
    by_id = {threat.catalogue_id: threat for threat in library}
    asset_fits, system_fits = _place_fits(context)
    kept, drops = [], []
    for threat in threats:
        own = by_id.get(threat.catalogue_id) if threat.catalogue_id is not None else None
        if own is None:
            kept.append(threat)
            continue
        places: dict[str, KindPlace] = {}
        for kind, place in places_by_kind(threat).items():
            entry_points = _fitting(own.asset_type, ways_in(place), asset_fits, system_fits)
            if entry_points is None:
                reason = CandidateRejection.ASSET_TYPE_MISMATCH
                drops.append(plan_drop(threat.key, threat.name, kind, PlanStage.MERGE, reason))
            else:
                places[kind] = dataclasses.replace(place, entry_points=entry_points)
        if places:
            kept.append(_with_places(threat, places))
    return kept, drops


def _with_places(threat: PlannedThreat, places: dict[str, KindPlace]) -> PlannedThreat:
    """The threat on only these kinds' places: its categories (first kept first), systems, impact, confidence
    and attacker pick follow them, so a kind dropped never speaks for the threat."""
    if places == places_by_kind(threat):
        return threat
    return dataclasses.replace(
        threat,
        categories=tuple(category for category in threat.categories if category in places),
        systems=tuple(sorted({system for place in places.values() for system in place.systems})),
        impact=max(place.impact for place in places.values()),
        confidence=max(place.confidence for place in places.values()),
        actor_pick=functools.reduce(_named_pick_first, (place.actor_pick for place in places.values()), None),
        kind_places=tuple(places.items()),
    )


def _fitting(
    asset_type: str | None,
    systems: tuple[int, ...],
    asset_fits: Collection[str],
    system_fits: dict[int, frozenset[str]],
) -> tuple[int, ...] | None:
    """The places (systems, or () for the asset itself) a library type fits; None when it fits none. Asked of
    the ways in only: the other systems a threat involves may be of any type."""
    if not systems:
        return () if asset_type_fits(asset_type, asset_fits) else None
    fitting = tuple(s for s in systems if asset_type_fits(asset_type, system_fits.get(s, frozenset())))
    return fitting or None


def _place_fits(context: FrozenContext) -> tuple[frozenset[str], dict[int, frozenset[str]]]:
    """The AssetType values the asset fits, and those each system fits (the asset's code when it has none)."""
    asset_code = context.asset.get("category_code")
    system_fits = {
        system["id"]: place_asset_types(asset_code, (system.get("category_code"),))
        for system in context.systems
    }
    return place_asset_types(asset_code, ()), system_fits


def _placed(
    threat: LibraryThreat,
    verdict: Verdict,
    asset_fits: Collection[str],
    system_fits: dict[int, frozenset[str]],
) -> Verdict | None:
    """The verdict through only the ways in its threat's type fits, every system it involves kept; None when
    no way in fits."""
    entry_points = _fitting(threat.asset_type, ways_in(verdict), asset_fits, system_fits)
    if entry_points is None:
        return None
    return (
        verdict
        if entry_points == verdict.entry_points
        else dataclasses.replace(verdict, entry_points=entry_points)
    )


# --- one threat per threat


def merge_two_threats(kept: PlannedThreat, other: PlannedThreat) -> PlannedThreat:
    """One threat for both: every category and system, the higher impact and confidence, the kept one's
    reason, each category's own reason and place, and an attacker pick that names one over one that names
    none. Another threat folded in never moves the kept one's first category."""
    union = set(kept.categories) | set(other.categories)
    lead = (kept.categories[0],) if kept.key != other.key else ()
    return dataclasses.replace(
        kept,
        categories=(*lead, *in_stride_order(union - set(lead))),
        systems=tuple(sorted(set(kept.systems) | set(other.systems))),
        impact=max(kept.impact, other.impact),
        confidence=max(kept.confidence, other.confidence),
        actor_pick=_named_pick_first(kept.actor_pick, other.actor_pick),
        actions=kept.actions or other.actions,
        kind_reasons=tuple((threat_reasons_by_kind(other) | threat_reasons_by_kind(kept)).items()),
        kind_places=tuple((places_by_kind(other) | places_by_kind(kept)).items()),
    )


def _named_pick_first(kept: ActorPick | None, other: ActorPick | None) -> ActorPick | None:
    """A pick naming an attacker, else one saying none fits, else none; the kept one's on a tie. So one kind's
    "none fits" never vetoes the attacker another kind named."""
    return min((kept, other), key=lambda pick: 2 if pick is None else 0 if pick.name else 1)


def _name_key(name: str) -> str:
    """What a name match compares: the name without its library code, normalised."""
    return name_match_key(threat_name_without_code(name))


def merge_same_threats(
    threats: list[PlannedThreat], folded: dict[str, str] | None = None
) -> list[PlannedThreat]:
    """One threat per key, and an AI threat named like a library threat of the same type folded into it (the
    library record is canonical); in key order. `folded` records each AI threat folded: key -> the kept."""
    by_key: dict[str, PlannedThreat] = {}
    for threat in threats:
        seen = by_key.get(threat.key)
        by_key[threat.key] = threat if seen is None else merge_two_threats(seen, threat)
    library_names = {(_name_key(t.name), t.type_id): t.key for t in by_key.values() if threat_from_library(t)}
    for threat in sorted(by_key.values(), key=lambda t: t.key):
        twin = (
            None
            if threat_from_library(threat)
            else library_names.get((_name_key(threat.name), threat.type_id))
        )
        if twin is not None:
            by_key[twin] = merge_two_threats(by_key[twin], by_key.pop(threat.key))
            if folded is not None:
                folded[threat.key] = twin
    return [by_key[key] for key in sorted(by_key)]


def merge_reworded_threats(
    threats: list[PlannedThreat],
    embeddings: EmbeddingModel,
    asset_name: str,
    folded: dict[str, str] | None = None,
) -> list[PlannedThreat]:
    """An AI threat whose name means what a library threat's or an earlier AI threat's of the same type means
    (cosine at least AI_DUPLICATE_COSINE, the asset's name left out) is folded into it; one embedding call.
    `folded` records each AI threat folded: its key -> the kept."""
    ai_threats = [threat for threat in threats if not threat_from_library(threat)]
    if not ai_threats:
        return threats
    labels = {
        t.key: remove_asset_name(threat_name_without_code(t.name), asset_name) or t.name for t in threats
    }
    texts = list(dict.fromkeys(labels.values()))
    vectors = dict(zip(texts, embeddings.embed_texts_to_compare(texts), strict=True))
    by_key = {threat.key: threat for threat in threats}
    compared = [t.key for t in threats if threat_from_library(t)]  # library threats, then each AI threat kept
    for threat in ai_threats:
        vector = vectors[labels[threat.key]]
        twin = next(
            (
                key
                for key in compared
                if by_key[key].type_id == threat.type_id
                and float(vector @ vectors[labels[key]]) >= ThreatFinding.AI_DUPLICATE_COSINE
            ),
            None,
        )
        if twin is None:
            compared.append(threat.key)
        else:
            by_key[twin] = merge_two_threats(by_key[twin], by_key.pop(threat.key))
            if folded is not None:
                folded[threat.key] = twin
    return [by_key[t.key] for t in threats if t.key in by_key]


# --- who carries out each threat


def assign_attackers(snapshot: LibrarySnapshot, threats: list[PlannedThreat]) -> list[PlannedThreat]:
    """Every threat with its acting attacker: the gate's pick among its linked actors, else none."""
    library = snapshot.library.threat_library
    by_threat = {threat.catalogue_id: threat.linked_actors for threat in library.threats}
    by_type = linked_actors_by_type(library)
    linked = [
        by_threat.get(t.catalogue_id, ()) if t.catalogue_id is not None else by_type.get(t.type_id, ())
        for t in threats
    ]
    return [choose_actor(threat, actors) for threat, actors in zip(threats, linked, strict=True)]


def choose_actor(threat: PlannedThreat, linked: Sequence[LibraryActor]) -> PlannedThreat:
    """The threat with the linked actor the gate picked acting (chosen), else none (none fits)."""
    pick = threat.actor_pick or ActorPick(None, "")
    acting = next((actor for actor in linked if actor.name == pick.name), None)
    return dataclasses.replace(
        threat,
        actors=() if acting is None else (PlannedActor(acting.actor_id, acting.name, ActorRole.ACTING),),
        attacker_check=AttackerCheck.NONE_FITS if acting is None else AttackerCheck.CHOSEN,
        attacker_check_reason=pick.reason,
        actor_pick=None,
    )


# --- threat finding, whole


class ThreatFinder:
    """Finds every threat that applies to a run's asset; holds no run's state."""

    def __init__(
        self, chat: ChatModel, search: LibrarySearch, rerank: RerankModel, embeddings: EmbeddingModel
    ) -> None:
        self._chat, self._search, self._rerank, self._embeddings = chat, search, rerank, embeddings

    def find_threats(
        self, context: FrozenContext, country: str = "", last_attempt: bool = False
    ) -> ThreatFindings:
        """Every threat that applies, one per threat, each with its acting attacker, from one library
        snapshot. `country`: a fact of the landscape while intelligence is on. `last_attempt`: the job's last
        try, when a broken reply is skipped instead of retried."""
        snapshot = self._search.snapshot()
        library = snapshot.library.threat_library
        if not any(threat.linked_actors for threat in library.threats):  # refused before any AI call
            raise PlanRefused(ErrorCode.ACTOR_LIBRARY_EMPTY, PlanMessage.ACTOR_LIBRARY_EMPTY)
        landscape = describe_asset_for_ai(context, self._chat.max_prompt_chars // 2, country)
        found, drops = self._judge_categories(snapshot, context, landscape, last_attempt)
        threats, later_drops = self._one_per_threat(snapshot, found, context, landscape)
        return ThreatFindings(
            [_named_threat(threat, landscape) for threat in threats],
            [result.audit for result in found],
            landscape=landscape,
            library_stamp={
                table: digest.hex() if digest else None for table, digest in snapshot.library.stamp
            },
            category_ids={name.strip().lower(): row_id for row_id, name in library.category_ids},
            drops=drops + later_drops,
            library_threats=len(library.threats),
            ai_threats=sum(result.ai_threat is not None for result in found),
        )

    def _one_per_threat(
        self,
        snapshot: LibrarySnapshot,
        found: list[CategoryFindings],
        context: FrozenContext,
        land: Landscape,
    ) -> tuple[list[PlannedThreat], list[dict[str, Any]]]:
        """The accepted threats merged into one per threat, each kind on the places its type fits, each with
        its acting attacker; the threats left with an attacker, and every drop on the way."""
        accepted = [
            _library_threat(result.audit.category, threat, verdict)
            for result in found
            for threat, verdict in result.accepted
        ]
        # an AI threat's name says systems by name before any merge, so no drop shows an alias
        ai_threats = [
            _named_threat(result.ai_threat, land) for result in found if result.ai_threat is not None
        ]
        names = {threat.key: threat.name for threat in accepted + ai_threats}
        folded: dict[str, str] = {}
        main_first = {f"lib:{t.catalogue_id}": v.kinds for result in found for t, v in result.accepted}
        threats = merge_same_threats(accepted + ai_threats, folded)
        threats = [_main_category_first(threat, main_first.get(threat.key, ())) for threat in threats]
        threats = merge_reworded_threats(threats, self._embeddings, context.asset["name"], folded)
        threats, drops = _keep_on_matching_systems(threats, snapshot.library.threat_library.threats, context)
        threats = [_main_and_two_others(threat, main_first.get(threat.key, ())) for threat in threats]
        for key, kept in folded.items():
            drops.append(plan_drop(key, names[key], None, PlanStage.MERGE, PlanLoss.MERGED, f"into {kept}"))
        threats = assign_attackers(snapshot, threats)
        for threat in (threat for threat in threats if not threat.actors):  # no listed attacker fits
            detail = replace_codes_with_names(threat.attacker_check_reason, land.system_names)
            stage, reason = PlanStage.ATTACKER, AttackerCheck.NONE_FITS
            drops.append(plan_drop(threat.key, threat.name, None, stage, reason, detail))
        return [threat for threat in threats if threat.actors], drops

    def _judge_categories(
        self, snapshot: LibrarySnapshot, context: FrozenContext, landscape: Landscape, last_attempt: bool
    ) -> tuple[list[CategoryFindings], list[dict[str, Any]]]:
        """Every judgeable threat judged once for all its own categories, the gate calls in one pool; the
        asset-type fit; then one gap fill for the categories left empty. One result per category in STRIDE
        order, with the threats left out before the gate. A threat whose type links no attacker is never
        judged; gate batches asked and not one answered: Unavailable."""
        allowed = _run_asset_types(context)
        fitting, drops = _judgeable(snapshot.library.threat_library.threats, allowed)
        matcher = _ProposalMatcher(self._rerank, snapshot, allowed)
        with ThreadPoolExecutor(ThreatFinding.AI_BATCHES_AT_ONCE, thread_name_prefix="gate-batch") as pool:
            judge = _ThreatJudge(self._chat, matcher, landscape, fitting, pool, last_attempt)
            found = judge.judge_all()
            if fitting and not any(result.audit.judged_ids for result in found):
                raise Unavailable(PlanMessage.AI_COULD_NOT_ANSWER)  # nothing checked is never "none apply"
            _place_on_matching_systems(found, context)  # before any gap fill: these may empty a category
            return judge.fill_gaps(found), drops


def _judgeable(
    threats: Sequence[LibraryThreat], allowed: Collection[str]
) -> tuple[list[LibraryThreat], list[dict[str, Any]]]:
    """The library threats the gate is asked about: their type fits the asset or a chosen system and links an
    attacker, and they sit in a STRIDE category. Those threats, and a drop for each one left out (one in
    custom categories only never reaches a scenario, so it is left out without one)."""
    fitting, drops = [], []
    for threat in threats:
        key, stage = f"lib:{threat.catalogue_id}", PlanStage.PRE_FILTER
        if not asset_type_fits(threat.asset_type, allowed):
            detail = f"asset type {threat.asset_type}"
            drops.append(plan_drop(key, threat.name, None, stage, PlanLoss.TYPE_FITS_NO_PLACE, detail))
        elif not threat.linked_actors:
            drops.append(plan_drop(key, threat.name, None, stage, PlanLoss.NO_LINKED_ACTOR))
        elif threat.categories:
            fitting.append(threat)
    if unlinked := [drop["threat_key"] for drop in drops if drop["reason"] == PlanLoss.NO_LINKED_ACTOR]:
        log.info(LogEvent.PLANNER_THREAT_NOT_PLANNED, threat_keys=unlinked)
    return fitting, drops


def _main_category_first(threat: PlannedThreat, gate_order: Sequence[StrideCategory]) -> PlannedThreat:
    """The threat told as the category the gate put first among those it kept (the one its own action most
    directly causes), with that category's reason; the others after it, as they were."""
    lead = next((kind for kind in gate_order if kind in threat.categories), threat.categories[0])
    return dataclasses.replace(
        threat,
        categories=(lead, *(kind for kind in threat.categories if kind != lead)),
        reason=threat_reason_for(threat, lead),
    )


def _main_and_two_others(threat: PlannedThreat, gate_order: Sequence[StrideCategory]) -> PlannedThreat:
    """The threat with its main category and at most two others, those the gate named earliest (a kind it did
    not order last), kept in their own order: a card's "also" list stays short when the AI names every
    kind."""
    main, *others = threat.categories
    if len(others) < ThreatFinding.MAX_CATEGORIES_PER_THREAT:
        return threat
    rank = {kind: n for n, kind in enumerate(gate_order)}
    room = ThreatFinding.MAX_CATEGORIES_PER_THREAT - 1
    chosen = sorted(others, key=lambda kind: rank.get(kind, len(rank)))[:room]
    return dataclasses.replace(threat, categories=(main, *(kind for kind in others if kind in chosen)))


def _named_threat(threat: PlannedThreat, landscape: Landscape) -> PlannedThreat:
    """A threat whose reasons and actions (an AI threat's names too) name systems, never by their aliases."""
    names = landscape.system_names
    threat = dataclasses.replace(
        threat,
        reason=replace_codes_with_names(threat.reason, names),
        kind_reasons=tuple((kind, replace_codes_with_names(why, names)) for kind, why in threat.kind_reasons),
        attacker_check_reason=replace_codes_with_names(threat.attacker_check_reason, names),
        actions=tuple(replace_codes_with_names(action, names) for action in threat.actions),
    )
    if threat_from_library(threat):
        return threat
    return dataclasses.replace(
        threat,
        name=replace_codes_with_names(threat.name, names),
        type_name=replace_codes_with_names(threat.type_name, names),
    )


# --- the plan: one asset-level path per threat, ranked

#: A path's scope when it is on no listed system: the asset itself.
_ASSET_ITSELF = "asset"
_STRIDE_ORDER = list(STRIDE_DEFINITIONS)


def threat_paths(threats: Sequence[PlannedThreat]) -> list[AttackPath]:
    """One path per threat (owner D6: one card per threat; scenarios at asset level), told as its main
    category through that category's own systems, impact and confidence; its other categories follow it as
    contributing ones. Two threats never share a path, and one is never split per system."""
    paths = []
    for threat in threats:
        kind = threat.categories[0]
        place = place_for(threat, kind)
        step = dataclasses.replace(threat, impact=place.impact, confidence=place.confidence)
        paths.append(path_on(step, place.systems, kind))
    return paths


def path_on(
    threat: PlannedThreat, systems: tuple[int, ...], kind: StrideCategory | None = None
) -> AttackPath:
    """A one-step path told around `threat` as the `kind` of attack (its own first category when None) on
    `systems`, or on the asset itself when there is none; its scope, and so its id, names both."""
    systems = tuple(sorted(systems))
    kind = kind or threat.categories[0]
    categories = (kind, *(category for category in threat.categories if category != kind))
    scope = _ASSET_ITSELF if not systems else "system" + ("s" if len(systems) > 1 else "") + ":"
    if systems:
        scope += ",".join(map(str, systems))
    step = dataclasses.replace(threat, systems=systems, categories=categories)
    return AttackPath((step,), scope=f"{kind}@{scope}")


def _path_strength(path: AttackPath) -> tuple[Any, ...]:
    """Impact, confidence, the STRIDE order of the kind, then the tie-break: library before AI, the lowest
    library id, the path id."""
    return (
        -attack_path_impact(path),
        -attack_path_confidence(path),
        _STRIDE_ORDER.index(attack_path_categories(path)[0]),
        *attack_path_tie_break(path),
    )


def rank_paths(paths: Iterable[AttackPath]) -> list[AttackPath]:
    """The most relevant path first, the same order on every run."""
    return sorted(paths, key=_path_strength)


def take_turns(records: list[dict[str, Any]], order: Sequence[int]) -> list[dict[str, Any]]:
    """The ranked path records dealt in turns over the systems in `order`, then the asset itself: each turn
    takes the best record left that an attacker could get in through that system, which becomes its
    `entry_system`; a system with none left is skipped."""
    left, dealt = list(records), []
    turns = (*order, None)
    while left:
        before = len(left)
        for position, system in enumerate(turns):
            taken = _best_through(system, turns[position + 1 :], left)
            if taken is not None:
                left.remove(taken)
                dealt.append(taken | {"entry_system": system})
        if len(left) == before:  # ponytail: a way in outside `order`; the gate names listed systems only
            dealt += [record | {"entry_system": (record["entry_points"] or [None])[0]} for record in left]
            break
    return dealt


def _best_through(
    system: int | None, later: tuple[int | None, ...], left: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The best record left that gets in through `system`, passing over one that a system still to play this
    round has no other way to take while `system` has another; None when none gets in through it."""
    through = [record for record in left if _enters_through(record, system)]
    scarce = [other for other in later if sum(_enters_through(record, other) for record in left) == 1]
    spare = next((record for record in through if not any(_enters_through(record, s) for s in scarce)), None)
    return spare or next(iter(through), None)


def _enters_through(record: dict[str, Any], system: int | None) -> bool:
    """Whether an attacker could get in through `system` on this path; None: whether it is on the asset."""
    return system in record["entry_points"] if system is not None else not record["systems"]


def select_up_to_target(paths: list[dict[str, Any]], max_scenarios: int) -> list[dict[str, Any]]:
    """The paths by rank, the `max_scenarios` best selected (0 = all), the rest set aside (target_reached)."""
    ranked = sorted(paths, key=lambda path: path["rank"])
    keep = len(ranked) if max_scenarios == 0 else max_scenarios
    return [
        {**path, "selected": True}
        if position < keep
        else {**path, "selected": False, "unselected_reason": UnselectedReason.TARGET_REACHED}
        for position, path in enumerate(ranked)
    ]


def build_plan(findings: ThreatFindings, target: int) -> dict[str, Any]:
    """The plan the run freezes: every threat once, one path per threat, dealt in turns over the
    systems, and the `target` (TOTAL_SCENARIO_COUNT, 0 = no cap) best selected; the asset's other sessions
    never take a path away (D15)."""
    threats = [
        planned_threat_record(threat)
        | {"category_id": findings.category_ids.get(threat.categories[0].lower())}
        for threat in findings.threats
    ]
    paths = rank_paths(threat_paths(findings.threats))
    ranked = [_path_record(path, 0, findings.category_ids) for path in paths]
    fresh = take_turns(ranked, list(findings.landscape.system_ids.values()))
    for rank, record in enumerate(fresh, start=1):
        record["rank"] = rank
    return {
        "prompt_version": PromptVersion.PLANNER,
        "threats": threats,
        "paths": select_up_to_target(fresh, target),
        "target": target,
        "not_assessed": [],  # ponytail: old pods read it during a rolling update; drop next release
    }


def _path_record(path: AttackPath, rank: int, category_ids: dict[str, int]) -> dict[str, Any]:
    """A path as the plan holds it: its threats by key, the card's category with its library id."""
    category = path.steps[-1].categories[0]
    return {
        "path_id": attack_path_id(path),
        "rank": rank,
        "served": None,
        "attempts": 0,
        "abandoned": False,
        "steps": [step.key for step in path.steps],
        "category": category,
        "category_id": category_ids.get(category.lower()),
        "categories": list(attack_path_categories(path)),
        "systems": list(attack_path_systems(path)),
        "entry_points": list(ways_in(place_for(path.steps[0], category))),
        "entry_system": None,  # take_turns: the system this path's turn gets in through; None: the asset
        "impact": attack_path_impact(path),
        "confidence": attack_path_confidence(path),
        "also_applies": [],  # stored field: two threats never share a path (owner 2026-10-19)
    }


# --- a frozen plan's progress: open paths, next sets and reserves


def is_still_to_write(path: dict[str, Any], reopen: bool = False) -> bool:
    """Not written yet, and not given up unless `reopen`."""
    return not path["served"] and (reopen or not path["abandoned"])


def next_set_paths(paths: Iterable[dict[str, Any]], size: int) -> list[str]:
    """The ids of the next `size` selected, still-open paths, best rank first."""
    left = sorted(
        (path for path in paths if path["selected"] and is_still_to_write(path)),
        key=lambda path: path["rank"],
    )
    return [path["path_id"] for path in left[:size]]


def set_and_first_batch(paths: Iterable[dict[str, Any]], size: int) -> tuple[list[str], list[dict[str, Any]]]:
    """The next set of `size` paths and its first batch to write: for the plan job and a next-set call."""
    paths = list(paths)
    asked = next_set_paths(paths, size)
    return asked, next_paths_to_write(path for path in paths if path["path_id"] in asked)


def next_paths_to_write(paths: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The next paths to write, never-tried ones first, best rank first; at most Generation.WRITER_BATCH."""
    left = sorted(
        (path for path in paths if path["selected"] and is_still_to_write(path)),
        key=lambda path: (path["attempts"] > 0, path["rank"]),
    )
    return [{"path_id": path["path_id"], "replaces": None} for path in left[: Generation.WRITER_BATCH]]


def plan_counts(paths: Iterable[dict[str, Any]]) -> dict[str, int]:
    """The plan's figures; `remaining` is what a next set can still write, `outage_cards` the paths given up
    for an AI outage whose card a regenerate can still write (a replaced one too)."""
    paths = list(paths)
    selected = [path for path in paths if path["selected"]]
    replaced = UnselectedReason.REPLACED_AFTER_FAILURE
    return {
        "planned": len(selected),
        "remaining": sum(is_still_to_write(path) for path in selected),
        "abandoned": sum(bool(path["abandoned"]) for path in selected),
        "replaced": sum(path.get("unselected_reason") == replaced for path in paths),
        # ponytail: a path given up before its give-up named the AI outage reads "unavailable" and is not
        # counted (its run reads complete), though its card regenerates; backfill from the cards if needed.
        "outage_cards": sum(
            bool(path["abandoned"]) and not path["served"] and path.get("abandoned_reason") in AiOutage
            for path in paths
        ),
    }


def why_no_path_left(paths: Iterable[dict[str, Any]]) -> ConflictReason:
    """Why no path is left to write: some given up, some left out by the scenario count, or all written."""
    paths = list(paths)
    if any(path["selected"] and path["abandoned"] for path in paths):
        return ConflictReason.SCENARIOS_ABANDONED
    replaced = (
        UnselectedReason.REPLACED_AFTER_FAILURE
    )  # a spare took its place: no scenario count left it out
    if any(not path["selected"] and path.get("unselected_reason") != replaced for path in paths):
        return ConflictReason.TARGET_REACHED
    return ConflictReason.NOTHING_LEFT


def set_summary(in_set: list[dict[str, Any]], paths: list[dict[str, Any]], outcome: str) -> dict[str, Any]:
    """A finished next set: its outcome, how many of its selected paths are written, why it fell short or was
    the last, and what a next set can still write."""
    remaining = plan_counts(paths)["remaining"]
    reason: ConflictReason | None = None
    if plan_counts(in_set)["abandoned"]:
        reason = ConflictReason.SCENARIOS_ABANDONED
    elif not remaining:
        reason = why_no_path_left(paths)
    delivered = sum(bool(path["served"]) for path in in_set if path["selected"])
    return {"outcome": outcome, "delivered": delivered, "reason": reason, "remaining": remaining}


def best_reserve(
    paths: Iterable[dict[str, Any]], threats: dict[str, dict[str, Any]], in_set: Collection[str]
) -> dict[str, Any] | None:
    """The best-ranked path to write in a failed path's place, only one whose attacker is supported: one the
    scenario count left out, else a later set's open path (selected, not in `in_set`)."""
    writable = [path for path in paths if _attributable(_threat_of(path, threats))]
    left_out = [
        path
        for path in writable
        if not path["selected"] and path.get("unselected_reason") == UnselectedReason.TARGET_REACHED
    ]
    later = [
        path
        for path in writable
        if path["selected"] and is_still_to_write(path) and path["path_id"] not in in_set
    ]
    return min(left_out or later, key=lambda path: path["rank"], default=None)


def budget_left(set_paths: Iterable[dict[str, Any]]) -> bool:
    """Whether the set may still write a replacement: its write calls stay under its own paths x
    MAX_PATH_ATTEMPTS (a replacement brings no budget of its own)."""
    paths = list(set_paths)
    own = sum(not path.get("replaces") for path in paths)
    spent = sum(path["attempts"] + (1 if path["served"] else 0) for path in paths)
    return spent < own * Generation.MAX_PATH_ATTEMPTS


def _threat_of(path: dict[str, Any], threats: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The plan threat a path is told around ({} when it has none)."""
    return (threats.get(path["steps"][0]) or {}) if path["steps"] else {}


def _attributable(threat: dict[str, Any]) -> bool:
    """Whether some check supports the threat's acting attacker."""
    return not attacker_unsupported(threat.get("attacker_check"), (threat.get("actors") or [{}])[0])


# --- the run's frozen context: the procedure's rows as the facts every step reads, checked first

#: Coded columns holding one saved option value, and the option code that names it.
SINGLE_SELECT_CODES: Final = {
    "accessability_channel": "acc-channel",
    "hosting_location": "hosting-location",
    "network_connectivity_primary_dr": "network-connectivity",
    "dr_drill_frequency": "dr-drill",
    "managed_by": "managed-by",
}
#: Coded columns holding a JSON array of saved option values, or the names the procedure already joined.
MULTI_SELECT_CODES: Final = {
    "technology_used": "technology-used",
    "database_platforms": "database-platforms",
    "targeted_users": "targeted-users",
    "saas_platform_list": "saas-platforms",
    "public_cloud_platforms": "pub-c-platforms",
}
_SINGLE_CODES: Final = {**SINGLE_SELECT_CODES, "asset_priority": "priority"}
_NAME_FACTS: Final = ("critical_service", "sector", "sub_sector")
_NEVER_TESTED_YEAR: Final = 1900  # SQL Server's minimum date: "never", not a real date
#: Names a fact column may not have: the app's own (alias) and the keys every prompt drops.
_RESERVED_NAMES: Final = (frozenset(ContextProperties.ALWAYS_USED) | DATABASE_KEYS) - set(
    ContextProperties.HEAD
)
_ASSET_SETTING, _SYSTEM_SETTING = "ASSET_PROPERTIES_REQUIRED", "SYSTEM_PROPERTIES_REQUIRED"
_ALWAYS_REQUIRED: Final = frozenset({"name"})  # every prompt, card and search names the asset and its systems


def freeze_context(request: StartRunRequest, rows: AssetContextRows) -> FrozenContext:
    """The run's frozen context from the procedure's rows: 403/404/422 for the request, 500 for a procedure
    set up wrong."""
    _check_procedure_columns(rows)
    _check_ownership(request, rows)
    assert rows.asset is not None
    _check_sector(request, rows.sector)
    _warn_unlinked_service(request, rows.services)
    options = _option_names_by_code(rows.options)
    systems_by_id = {row["id"]: row for row in rows.systems}
    asset_facts = _facts_of_row(rows.asset, options)
    systems = [
        _frozen_system(systems_by_id[system_id], f"{ThreatFinding.SYSTEM_ALIAS}{position}", options)
        for position, system_id in enumerate(request.supporting_system_ids, start=1)
    ]
    asset = _head_columns(rows.asset)
    check_required(request, {"name": asset["name"], **asset_facts}, systems)
    linked = _asset_systems(request.supporting_system_ids, systems_by_id)
    return FrozenContext(asset, asset_facts, systems, _missing_facts(systems), linked)


def _asset_systems(asked: list[int], rows_by_id: dict[int, Row]) -> list[dict[str, Any]]:
    """Every system linked to the asset, once, as {id, name, category_code}: the asked ones in request order,
    then the others by id; a name an earlier one already has gets its id, so a name the AI gives back finds
    one system. Nothing else of the others is kept, and nothing about them refuses a run."""
    linked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for system_id in [*asked, *sorted(set(rows_by_id) - set(asked))]:
        name = _display_name(rows_by_id[system_id]["name"] or "")
        name = name or ContextProperties.UNNAMED_SYSTEM.format(id=system_id)
        unique = f"{name} ({system_id})" if name_match_key(name) in seen else name
        linked.append(
            {"id": system_id, "name": unique, "category_code": rows_by_id[system_id]["category_code"]}
        )
        seen.add(name_match_key(name))
    return linked


def _display_name(value: Any) -> Any:
    """A name as prompts and cards show it: runs of whitespace collapsed to one space."""
    return " ".join(value.split()) if isinstance(value, str) else value


def _check_procedure_columns(rows: AssetContextRows) -> None:
    """500 setup_error when a row lacks a head column, a fact has a reserved name, or the dropdown names
    lack code, name and value (or id)."""
    for kind, found in (("asset", [rows.asset] if rows.asset else []), ("supporting system", rows.systems)):
        if not found:
            continue
        if any(column not in row for row in found for column in ContextProperties.HEAD):
            columns = ", ".join(ContextProperties.HEAD)
            raise SetupError(PropertyMessage.HEAD_MISSING.format(columns=columns, rows=kind))
        facts = set(found[0]) - set(ContextProperties.HEAD)  # one result set: every row has its columns
        # A reserved name would replace SYS1..n, or count as recorded while the AI never saw it.
        if reserved := sorted(facts & _RESERVED_NAMES):
            raise SetupError(PropertyMessage.RESERVED.format(columns=", ".join(reserved), rows=kind))
    if rows.options and not _option_key(rows.options[0]):
        raise SetupError(PropertyMessage.OPTIONS_OUT_OF_DATE.format(found=", ".join(rows.options[0])))


def _check_ownership(request: StartRunRequest, rows: AssetContextRows) -> None:
    """403 an asset the entity does not own or a system not linked; 404 an unknown service or sector."""
    if rows.asset is None:
        raise Forbidden(
            SessionMessage.ASSET_NOT_OWNED.format(asset_id=request.asset_id),
            reason=ConflictReason.ASSET_NOT_OWNED,
        )
    linked = {row["id"] for row in rows.systems}
    unlinked = [system_id for system_id in request.supporting_system_ids if system_id not in linked]
    if unlinked:
        message = SessionMessage.SYSTEMS_NOT_LINKED.format(system_ids=unlinked, asset_id=request.asset_id)
        raise Forbidden(message, reason=ConflictReason.SYSTEM_NOT_LINKED, details={"system_ids": unlinked})
    if request.service_id is not None and not any(row["id"] == request.service_id for row in rows.services):
        raise NotFound(SessionMessage.SERVICE_NOT_FOUND.format(service_id=request.service_id))
    asked_sector = request.subsector_id or request.sector_id
    if asked_sector is not None and rows.sector is None:
        raise NotFound(SessionMessage.SECTOR_NOT_FOUND.format(sector_id=asked_sector))


def _check_sector(request: StartRunRequest, row: Row | None) -> None:
    """422 when a sector_id sent with a sub-sector is not its parent."""
    if row is None or request.subsector_id is None or request.sector_id is None:
        return
    top_id = row["parent_id"] if row["parent_id"] is not None else row["id"]
    if top_id != request.sector_id:
        message = SessionMessage.SECTOR_NOT_PARENT.format(
            sector_id=request.sector_id, subsector_id=request.subsector_id, parent_id=top_id
        )
        raise Invalid(message, errors=[{"field": f"{request.FIELD_PREFIX}.sector_id", "message": message}])


def _warn_unlinked_service(request: StartRunRequest, rows: list[Row]) -> None:
    """Logs an asked service the asset is not linked to; it is used anyway."""
    if request.service_id is not None and not any(row["linked"] for row in rows):
        log.warning(
            LogEvent.CONTEXT_SERVICE_NOT_LINKED, asset_id=request.asset_id, service_id=request.service_id
        )


def _option_names_by_code(rows: list[Row]) -> dict[str, dict[int, str]]:
    """{option code in lower case (SQL compares codes case-insensitively): {saved number: name}}."""
    names: dict[str, dict[int, str]] = {}
    key = _option_key(rows[0]) if rows else None
    for row in rows:
        if key and (row["name"] or "").strip():  # a blank option name names nothing: reads as unanswered
            names.setdefault(str(row["code"]).strip().lower(), {})[row[key]] = row["name"]
    return names


def _option_key(row: Row) -> str | None:
    """The column a dropdown-names row holds its number in (value or id), when it has code and name."""
    if any(column not in row for column in ContextProperties.OPTION_COLUMNS):
        return None
    return next((key for key in ContextProperties.OPTION_KEYS if key in row), None)


def _single_select_name(raw: int | str | None, code: str, options: dict[str, dict[int, str]]) -> str | None:
    """The saved option's name, or the name the procedure already gave; None when unanswered (NULL or the
    form's 0) or unknown (logged)."""
    if isinstance(raw, str):
        number = _whole_number(raw)
        if number is None:
            return _display_name(raw) or None
        raw = number
    if not raw:
        return None
    name = options.get(code, {}).get(raw)
    if name is None:
        log.warning(LogEvent.CONTEXT_OPTION_VALUE_NOT_FOUND, code=code, value=raw)
    return name


def _multi_select_names(raw: str | None, code: str, options: dict[str, dict[int, str]]) -> list[str] | None:
    """Names of a JSON array of saved values (an unknown item dropped alone, as SQL's TRY_CAST); a broken
    array is none; a text that is no array is the names the procedure already joined."""
    text = (raw or "").strip()
    try:
        items = json.loads(text) if text else []
    except ValueError:
        if text.startswith("["):
            return None
        return [name for name in (part.strip() for part in text.split(",")) if name] or None
    known = options.get(code, {})
    values = map(_whole_number, items if isinstance(items, list) else [])
    return [known[value] for value in values if value in known] or None


def _whole_number(item: Any) -> int | None:
    """6 or "6" -> 6; null, true, 6.5 or "x" -> None (as SQL's TRY_CAST(... AS INT))."""
    try:
        return int(str(item))
    except ValueError:
        return None


def _stored_value(value: Any) -> Any:
    """A column's value as MongoDB stores it and a prompt reads it: a DECIMAL as a number, a date as ISO text
    (SQL Server's minimum date as None), binary as None, any other type as text."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, date):  # a datetime too
        return None if value.year <= _NEVER_TESTED_YEAR else value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return None
    return str(value)


def _fact_value(column: str, value: Any, options: dict[str, dict[int, str]]) -> Any:
    """One column's fact: option names for a coded column, collapsed spaces for a name, else its value."""
    if column in _SINGLE_CODES:
        return _single_select_name(value, _SINGLE_CODES[column], options)
    if column in MULTI_SELECT_CODES:
        return _multi_select_names(value, MULTI_SELECT_CODES[column], options)
    if column in _NAME_FACTS:
        return _display_name(value)
    return _stored_value(value)


def _facts_of_row(row: Row, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    """Every column of a procedure row but its head, in the procedure's order."""
    return {
        column: _fact_value(column, value, options)
        for column, value in row.items()
        if column not in ContextProperties.HEAD
    }


def _head_columns(row: Row) -> dict[str, Any]:
    """A row's id, display name and category code."""
    return {"id": row["id"], "name": _display_name(row["name"]), "category_code": row["category_code"]}


def _frozen_system(row: Row, alias: str, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    """A supporting system as the run freezes it: id, alias, head and facts."""
    return {"id": row["id"], "alias": alias, **_head_columns(row), **_facts_of_row(row, options)}


def _missing_facts(systems: list[dict[str, Any]]) -> list[str]:
    """The system facts not one system in scope records: shown to the reviewer, never a reason to refuse."""
    first = systems[0] if systems else {}  # one result set: every system has the same columns
    columns = [column for column in first if column not in ContextProperties.ALWAYS_USED]
    return sorted(
        column
        for column in columns
        if not any(facts_safe_for_prompt({"fact": system.get(column)}) for system in systems)
    )


def check_required(
    request: StartRunRequest, asset_facts: dict[str, Any], systems: list[dict[str, Any]]
) -> None:
    """500 when a required name is no column of the procedure; else 422 naming every required fact not
    recorded (as the AI would be shown it), the asset's first, then each system's in request order."""
    settings = get_settings()
    required_asset = settings.required_asset_properties | _ALWAYS_REQUIRED
    required_system = settings.required_system_properties | _ALWAYS_REQUIRED
    _check_returned(_ASSET_SETTING, required_asset, asset_facts)
    for system in systems[:1]:  # every system row has the procedure's same columns
        _check_returned(_SYSTEM_SETTING, required_system, system)
    gaps: list[tuple[str, str, list[str]]] = []  # (field, owner, names)
    by_field: dict[str, list[str]] = {}
    for name in _not_recorded(asset_facts, required_asset):  # sector & co come from the request's own fields
        field = ContextProperties.REQUEST_FIELDS.get(name, "asset_id")
        by_field.setdefault(f"{request.FIELD_PREFIX}.{field}", []).append(name)
    gaps += [(field, f"asset {request.asset_id}", names) for field, names in by_field.items()]
    for index, system in enumerate(systems):
        if names := _not_recorded(system, required_system):
            gaps.append(
                (f"{request.FIELD_PREFIX}.supporting_system_id.{index}", f"system {system['id']}", names)
            )
    if gaps:
        _refuse_missing_facts(gaps)


def _check_returned(setting: str, required: frozenset[str], facts: dict[str, Any]) -> None:
    """500 setup_error naming the required names the procedure does not return."""
    if absent := sorted(required - facts.keys()):
        raise SetupError(PropertyMessage.NOT_RETURNED.format(setting=setting, names=", ".join(absent)))


def _not_recorded(facts: dict[str, Any], required: frozenset[str]) -> list[str]:
    """The required names, in the facts' order, whose value the AI would not be shown."""
    return [name for name in facts if name in required and not facts_safe_for_prompt({"fact": facts[name]})]


def _refuse_missing_facts(gaps: list[tuple[str, str, list[str]]]) -> None:
    """422 required_facts_missing with one error per field: names and ids, never a value."""
    errors = [
        {"field": field, "message": PropertyMessage.NOT_RECORDED.format(owner=owner, names=", ".join(names))}
        for field, owner, names in gaps
    ]
    detail = PropertyMessage.REQUIRED_MISSING.format(
        gaps="; ".join(f"{owner}: {', '.join(names)}" for _, owner, names in gaps)
    )
    raise Invalid(detail, reason=ConflictReason.REQUIRED_FACTS_MISSING, errors=errors)


def request_fingerprint(request: StartRunRequest) -> str:
    """SHA-256 of the request's canonical JSON (systems as a set): what a replayed key must match."""
    canonical = request.model_dump(mode="json") | {
        "supporting_system_ids": sorted(request.supporting_system_ids)
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def check_same_start_request(earlier: dict[str, Any], request: StartRunRequest) -> None:
    """409 idempotency_key_conflict when the run that took the key is hand-written or another request's."""
    fingerprint = request_fingerprint(request)
    if (
        earlier.get("kind") == RunKind.MANUAL
        or earlier["asset_id"] != request.asset_id
        or earlier.get("request_hash", fingerprint) != fingerprint
    ):
        message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
        raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)


def check_intel_has_data(active_snapshot: dict[str, Any]) -> None:
    """409 intel_no_data when the active intelligence snapshot indexes nothing."""
    if not (active_snapshot.get("counts") or {}).get("indexed"):
        raise Conflict(IntelMessage.NO_DATA_YET, reason=ConflictReason.INTEL_NO_DATA)


#: The message of each reason a next set has no path left to write.
_NONE_LEFT: Final = {
    ConflictReason.NOTHING_LEFT: ReviewMessage.NOTHING_LEFT,
    ConflictReason.TARGET_REACHED: ReviewMessage.TARGET_REACHED,
    ConflictReason.SCENARIOS_ABANDONED: ReviewMessage.SCENARIOS_ABANDONED,
}


def nothing_left_to_write(session_id: str, paths: Iterable[dict[str, Any]]) -> Conflict:
    """409 naming why a next set has no path left: all written, the scenario count reached, or given up."""
    reason = why_no_path_left(paths)
    return Conflict(_NONE_LEFT[reason].format(session_id=session_id), reason=reason)
