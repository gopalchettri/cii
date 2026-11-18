"""Planning a run: which threats apply to the asset, each attacker, and which attack paths in which order."""

import dataclasses
import functools
import hashlib
import itertools
import json
import math
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Final

import structlog

from app.ai import ChatModel, EmbeddingModel, RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core import constants as c
from app.core.asset_types import asset_type_fits, compatible_asset_types, find_fitting_entry_points
from app.core.config import get_settings
from app.core.exceptions import PlanRefused, Unavailable
from app.core.prompts import PROMPTS
from app.core.redaction import redact
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
    threat_name_key,
    threat_name_without_code,
)
from app.domain.shared.parallel import run_in_parallel
from app.domain.shared.prompt_redaction import facts_safe_for_prompt
from app.schemas.library import LibraryActor, LibraryThreat, LibraryThreatType
from app.schemas.scenario_internal import (
    ActorPick,
    AttackPlace,
    Drop,
    FrozenContext,
    GapFillResponse,
    Landscape,
    PlannedActor,
    PlannedThreat,
    ThreatFindings,
    Verdict,
)
from app.search.service import LibrarySearch
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)


_LEADING_ASSET_FACT_KEYS = ("sector", "sub_sector", "critical_service", "asset_priority")


def describe_asset_for_ai(context: FrozenContext, budget: int, country: str = "") -> Landscape:
    """The asset and each system by alias and quoted name with its facts, the longest fact cut to `budget`."""
    own_facts, organisation_facts = context.own_and_organisation_facts()
    lead = {key: own_facts[key] for key in _LEADING_ASSET_FACT_KEYS if key in own_facts}
    systems = [facts_safe_for_prompt(FrozenContext.read_system_facts(system)) for system in context.systems]
    parts = [facts_safe_for_prompt({**lead, **own_facts}), facts_safe_for_prompt(organisation_facts), *systems]
    listed: list[dict[str, Any]] = [
        {key: facts[key] for key in ("name", "asset_type") if key in facts} for facts in systems
    ]
    text = _write_asset_and_systems_text(context, country, listed, parts)
    if over := max(len(text) - budget, 0):
        cut = cut_to_fit(parts, sum(len(as_json(part)) for part in parts) - over)
        text = _write_asset_and_systems_text(context, country, listed, cut)
    return Landscape(
        # ponytail: names, aliases and lists are never cut; past them the text is cut, never a system's line
        text=shorten_text(text, budget),
        system_ids={system["alias"]: system["id"] for system in context.systems},
        system_names={system["alias"]: system["name"] for system in context.systems},
        is_cut=over > 0,
    )


def _write_asset_and_systems_text(
    context: FrozenContext, country: str, listed: list[dict[str, Any]], parts: list[dict[str, Any]]
) -> str:
    asset_facts, organisation, *systems = parts
    where = {c.ContextProperties.COUNTRY_KEY: country} if country else {}
    described = {
        "asset": redact(context.asset["name"]),
        **where,
        "asset_context": asset_facts,
        "supporting_systems": listed,
    }
    lines = ["ASSET: " + as_json(described)]
    if organisation:
        lines.append(c.ThreatFinding.ORGANISATION_LABEL + as_json(organisation))
    for system, facts in zip(context.systems, systems, strict=True):
        name = quoted_for_prompt(shorten_text(system["name"], c.ThreatFinding.SYSTEM_NAME_CHARS))
        lines.append(f"{system['alias']} {name}: {as_json(facts)}")
    return "\n".join(lines)


_GATE_RULES: str = PROMPTS["scenario"]["gate"]["text"]
_GATE_FOLLOW_UP: str = PROMPTS["scenario"]["gate"]["follow_up"]
_GAP_FILL_RULES: str = PROMPTS["scenario"]["gap_fill"]["text"]
_PLANNER_SYSTEM: str = PROMPTS["scenario"]["gate"]["system"]


def _build_threat_finding_prompt(
    landscape: str, categories: Iterable[c.StrideCategory], rules: str, label: str, items: Sequence[dict[str, Any]]
) -> ChatPrompt:
    stride = "STRIDE CATEGORIES:\n" + "".join(
        f"- {category}: {c.STRIDE_DEFINITIONS[category]}.\n" for category in categories
    )
    return _PLANNER_SYSTEM, f"LANDSCAPE:\n{landscape}\n\n{stride}{rules}\n\n{label}:\n" + json.dumps(
        list(items), ensure_ascii=False
    )


_STRIDE_BY_KEY: Final = {name_match_key(category): category for category in c.StrideCategory}
_STRIDE_ORDER = list(c.STRIDE_DEFINITIONS)


def _read_which_apply_answer(
    answer: dict[str, Any], asked: dict[str, dict[str, Any]], landscape: Landscape
) -> tuple[tuple[dict[str, Verdict], dict[str, list[str]]], list[str]]:
    items, problems = answers_for_asked_slots(answer, "verdicts", set(asked))
    judged: dict[str, Verdict] = {}
    faults: dict[str, list[str]] = {}
    for item in items:
        candidate = asked[item["slot"]]
        named, item_problems = _find_problems_in_threat_answer(item, candidate, landscape.system_ids)
        problems += item_problems
        if item_problems:
            faults[item["slot"]] = item_problems
        else:
            judged[item["slot"]] = _read_one_threat_answer(item, candidate, named, landscape)
    return (judged, faults), [] if judged else problems  # the problems re-ask only when none read well


def _find_problems_in_threat_answer(
    item: dict[str, Any], candidate: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[c.StrideCategory, tuple[int, str]], list[str]]:
    slot, relevant, systems = item["slot"], item.get("relevant"), item.get("systems") or []
    entry_points = (item.get("entry_points") or []) if relevant is True else None
    confidence, needs = item.get("confidence"), item.get("needs") or []
    problems = _find_problems_in_answer_systems(slot, systems, entry_points, aliases)
    if threat_name_key(str(item.get("threat") or "")) != threat_name_key(candidate["threat"]):
        problems.append(f"{slot}: threat must be this slot's own threat, copied exactly")
    if not isinstance(relevant, bool):
        problems.append(f"{slot}: relevant must be true or false")
    named, category_problems = _read_answer_categories(slot, item.get("categories"), candidate["categories"])
    if relevant is True:
        problems += category_problems
        if isinstance(confidence, bool) or not isinstance(confidence, int | float) or not 0 <= confidence <= 100:
            problems.append(f"{slot}: confidence must be a number from 0 to 100")
        if str(item.get("likelihood") or "").upper() not in c.ThreatFinding.LIKELIHOOD_RANK:
            problems.append(f"{slot}: likelihood must be HIGH, MEDIUM or LOW")
    elif not str(item.get("reason") or "").strip():
        problems.append(f"{slot}: a threat that does not apply needs its reason")
    if not isinstance(needs, list) or any(not isinstance(need, str) for need in needs):
        problems.append(f"{slot}: needs must be a list of names ([] when everything it needs is recorded)")
    return (named if relevant is True else {}), problems


def _find_problems_in_answer_systems(slot: str, systems: Any, entry_points: Any, aliases: dict[str, int]) -> list[str]:
    if not isinstance(systems, list) or any(not isinstance(alias, str) or alias not in aliases for alias in systems):
        return [f"{slot}: systems must be listed aliases only (SYS1, SYS2 ...)"]
    if entry_points is None:
        return []
    if not isinstance(entry_points, list) or any(alias not in systems for alias in entry_points):
        return [f"{slot}: entry_points must be aliases from its own systems"]
    if systems and not entry_points:
        return [f"{slot}: entry_points must name the systems among its own an attacker could get in through"]
    return []


def _read_answer_categories(
    slot: str, named: Any, own: Sequence[str]
) -> tuple[dict[c.StrideCategory, tuple[int, str]], list[str]]:
    if not isinstance(named, list) or not named:
        return {}, [f"{slot}: categories must list the slot's own categories it belongs to, the main first"]
    categories: dict[c.StrideCategory, tuple[int, str]] = {}
    problems = []
    for entry in named:
        entry = entry if isinstance(entry, dict) else {}
        category = _STRIDE_BY_KEY.get(name_match_key(str(entry.get("name") or "")))
        impact, reason = str(entry.get("impact") or "").upper(), str(entry.get("reason") or "").strip()
        if category is None:
            listed = ", ".join(own)
            problems.append(f"{slot}: {entry.get('name')!r} is no STRIDE category: copy its own: {listed}")
        elif impact not in c.ThreatFinding.IMPACT_RANK or not reason:
            problems.append(f"{slot}: {category} needs its impact (HIGH, MEDIUM or LOW) and its reason")
        else:
            categories.setdefault(
                category, (c.ThreatFinding.IMPACT_RANK[impact], reason[: c.ThreatFinding.REASON_MAX_CHARS])
            )
    if not problems and not set(categories) & set(own):
        problems.append(f"{slot}: categories must name at least one of its own: {', '.join(own)}")
    return categories, problems


def _read_one_threat_answer(
    item: dict[str, Any],
    candidate: dict[str, Any],
    named: dict[c.StrideCategory, tuple[int, str]],
    landscape: Landscape,
) -> Verdict:
    relevant, names, aliases = item["relevant"], landscape.system_names, landscape.system_ids
    needs = [" ".join(need.split())[: c.ThreatFinding.NEED_MAX_CHARS] for need in item.get("needs") or []]
    needs = [need for need in needs if need][: c.ThreatFinding.NEEDS_MAX_ITEMS]
    reason = str(item.get("reason") or "").strip()[: c.ThreatFinding.REASON_MAX_CHARS]
    refusal = None
    if needs:
        refusal = c.CandidateRejection.NEEDS_UNRECORDED, replace_codes_with_names("; ".join(needs), names)
    elif not relevant:
        refusal = c.CandidateRejection.NOT_RELEVANT, replace_codes_with_names(reason, names)
    pick = None
    if relevant:
        by_key = {name_match_key(name): name for name in candidate["attackers"]}
        pick_reason = str(item.get("attacker_reason") or "").strip()[: c.ThreatFinding.REASON_MAX_CHARS]
        pick = ActorPick(
            by_key.get(name_match_key(str(item.get("attacker") or ""))), replace_codes_with_names(pick_reason, names)
        )
    listed: list[Any] = item["actions"] if relevant and isinstance(item.get("actions"), list) else []
    actions = (" ".join(action.split()) for action in listed if isinstance(action, str) and action.strip())
    return Verdict(
        named_categories={
            category: (impact, replace_codes_with_names(category_reason, names))
            for category, (impact, category_reason) in named.items()
        },
        refusal=refusal,
        systems=tuple(sorted({aliases[alias] for alias in item.get("systems") or ()})),
        entry_points=tuple(sorted({aliases[alias] for alias in item.get("entry_points") or () if relevant})),
        confidence=float(item.get("confidence") or 0) if relevant else 0.0,
        likelihood=c.ThreatFinding.LIKELIHOOD_RANK[str(item["likelihood"]).upper()] if relevant else 0,
        actor_pick=pick,
        actions=tuple(replace_codes_with_names(action, names) for action in actions),
    )


def _read_ai_proposed_threats(
    answer: dict[str, Any], asked: Sequence[c.StrideCategory], aliases: dict[str, int]
) -> tuple[dict[c.StrideCategory, dict[str, Any]], list[str]]:
    items = answer.get("proposals")
    if not isinstance(items, list):
        return {}, ['the reply must be {"proposals": [...]}']
    by_key = {name_match_key(category): category for category in asked}
    proposals: dict[c.StrideCategory, dict[str, Any]] = {}
    problems = []
    for item in items:
        named = str(item.get("category") or "") if isinstance(item, dict) else ""
        category = by_key.get(name_match_key(named))
        if category is None or category in proposals:
            problems.append(f"category {named or '?'} is not listed or answered twice")
            continue
        proposal, item_problems = _read_one_ai_proposed_threat(item, aliases)
        problems += [f"{category}: {problem}" for problem in item_problems]
        if proposal is not None:
            proposals[category] = proposal
    return proposals, [] if proposals else problems


def _read_one_ai_proposed_threat(
    answer: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(answer.get("applies"), bool):
        return None, ['the reply must be {"applies": true|false, ...}']
    checked = answer if answer["applies"] else {"reason": "", **answer}  # "none applies" needs no reason
    if problems := answer_item_problems(GapFillResponse, checked, "the reply"):
        return None, problems
    if not answer["applies"]:
        return {"applies": False}, []
    fields = {name: str(answer.get(name) or "").strip() for name in ("threat_type", "threat", "reason")}
    problems = [f"{name} is required" for name, value in fields.items() if not value]
    if len(fields["threat_type"]) + len(fields["threat"]) > c.ThreatFinding.GAP_FILL_MAX_CHARS:
        problems.append("the proposal is too long")
    systems = answer.get("systems") or []
    if not isinstance(systems, list) or any(not isinstance(alias, str) or alias not in aliases for alias in systems):
        problems.append("systems must be listed aliases only (SYS1, SYS2 ...)")
    return (None, problems) if problems else ({**fields, "applies": True, "systems": systems}, [])


_GateQuestion = tuple[str, str, Sequence[c.StrideCategory], Sequence[LibraryActor]]
_NOT_JUDGED: Final = Verdict({}, (c.PlanLoss.NOT_JUDGED, ""), (), (), 0.0, 0, None, ())


@dataclasses.dataclass
class _ThreatFindingCalls:
    """One run's planner AI calls: the models, the snapshot, the landscape and a stop flag."""

    chat: ChatModel
    rerank: RerankModel
    snapshot: LibrarySnapshot
    allowed_types: frozenset[str]  # the AssetType values a library threat must fit to be judged
    landscape: Landscape
    is_last_attempt: bool
    stopped: threading.Event = dataclasses.field(default_factory=threading.Event)  # no new gate call starts

    def ask_which_threats_apply(self, questions: Sequence[_GateQuestion]) -> list[Verdict | None]:
        """The gate's verdict on each question (None: not judged), in even batches run at the same time."""
        items: list[dict[str, Any]] = [
            {
                "slot": f"{c.ThreatFinding.RECORD_SLOT}{number}",
                "threat_type": threat_name_without_code(threat_type),
                "threat": threat_name_without_code(threat),
                "categories": [str(category) for category in categories],
                "attackers": [actor.name for actor in actors],
            }
            for number, (threat_type, threat, categories, actors) in enumerate(questions, start=1)
        ]
        if not items:
            return []
        size = math.ceil(len(items) / math.ceil(len(items) / c.ThreatFinding.THREATS_PER_QUESTION))
        prompt_of = functools.partial(
            _build_threat_finding_prompt, self.landscape.text, c.StrideCategory, _GATE_RULES, "CANDIDATES"
        )
        batches = [
            list(part)
            for batch in itertools.batched(items, size)
            for part in within_call_limit(batch, prompt_of, self.chat, c.AiTask.RELEVANCE_GATE)
        ]
        answered = run_in_parallel(
            self._ask_one_batch_which_apply, batches, c.ThreatFinding.AI_BATCHES_AT_ONCE, "gate-batch"
        )
        judged = {slot: verdict for batch in answered for slot, verdict in batch.items()}
        return [judged.get(item["slot"]) for item in items]

    def _ask_one_batch_which_apply(
        self, batch: list[dict[str, Any]], problems: list[str] | None = None, halved: bool = False
    ) -> dict[str, Verdict]:
        if self.stopped.is_set():
            return {}
        first_ask, rules = problems is None, _GATE_RULES
        if problems:
            cap, most = c.AiLimits.REASK_PROBLEM_CHARS, c.AiLimits.REASK_MAX_PROBLEMS
            rules += _GATE_FOLLOW_UP.replace("{problems}", "; ".join(p[:cap] for p in problems[:most]))
        prompt = _build_threat_finding_prompt(self.landscape.text, c.StrideCategory, rules, "CANDIDATES", batch)
        asked = {item["slot"]: item for item in batch}
        read = functools.partial(_read_which_apply_answer, asked=asked, landscape=self.landscape)
        may_halve = first_ask and not halved and len(batch) > 1
        try:
            answer = self.ask_ai_reusing_earlier_answer(
                c.AiTask.RELEVANCE_GATE, prompt, read, [item["threat"] for item in batch], first_ask, may_halve
            )
        except TruncatedAiAnswer:
            half = (len(batch) + 1) // 2  # ponytail: halved once; a half cut off again is not judged
            return self._ask_one_batch_which_apply(batch[:half], halved=True) | self._ask_one_batch_which_apply(
                batch[half:], halved=True
            )
        if answer is None:
            return {}
        judged, faults = answer
        if first_ask and (missing := [item for item in batch if item["slot"] not in judged]):
            told = [problem for item in missing for problem in faults.get(item["slot"], ())]
            # ponytail: once; still wrong = not judged
            judged |= self._ask_one_batch_which_apply(missing, told)
        return judged

    def ask_ai_reusing_earlier_answer(
        self,
        task: c.AiTask,
        prompt: ChatPrompt,
        read: Callable[[dict[str, Any]], tuple[Any, list[str]]],
        asked: list[str],
        first_ask: bool = True,
        may_halve: bool = False,
    ) -> Any:
        """One planner ask reusing a job's earlier answer: an outage or bad first reply raises, else None."""
        try:
            return ask_ai_and_check(self.chat, task, prompt, read, reuse_earlier_answer=True)
        except Unavailable:
            self.stopped.set()
            raise
        except (UnreadableAiAnswer, TruncatedAiAnswer) as error:
            if may_halve and isinstance(error, TruncatedAiAnswer):
                raise
            if isinstance(error, UnreadableAiAnswer) and first_ask and not self.is_last_attempt:
                self.stopped.set()
                raise Unavailable(str(error)) from error
            log.warning(c.LogEvent.PLANNER_THREATS_NOT_JUDGED, check=task, asked=asked, message=str(error))
            return None


def _list_threats_to_check(
    library: Sequence[LibraryThreat], allowed_types: frozenset[str], drops: list[Drop]
) -> list[LibraryThreat]:
    fitting: list[LibraryThreat] = []
    for threat in library:
        key, stage = f"lib:{threat.catalogue_id}", c.PlanStage.PRE_FILTER
        if not asset_type_fits(threat.asset_type, allowed_types):
            detail = f"asset type {threat.asset_type}"
            drops.append(Drop(key, threat.name, None, stage, c.PlanLoss.TYPE_FITS_NO_PLACE, detail))
        elif not threat.linked_actors:
            drops.append(Drop(key, threat.name, None, stage, c.PlanLoss.NO_LINKED_ACTOR))
        elif threat.categories:  # one in custom categories only never reaches a scenario: left out silently
            fitting.append(threat)
    return fitting


def _find_library_threats_that_apply(
    calls: _ThreatFindingCalls, fitting: Sequence[LibraryThreat], context: FrozenContext, drops: list[Drop]
) -> list[PlannedThreat]:
    candidates = [
        (
            PlannedThreat(
                f"lib:{threat.catalogue_id}",
                threat.catalogue_id,
                threat.type_id,
                threat.type_name,
                threat.name,
                threat.categories,
                linked_actors=threat.linked_actors,
                asset_type=threat.asset_type,
            ),
            (threat.type_name, threat.name, threat.categories, threat.linked_actors),
        )
        for threat in fitting
    ]
    system_codes = {system["id"]: system.get("category_code") for system in context.systems}
    kept = []
    for accepted in _keep_threats_the_ai_accepts(calls, candidates, c.PlanStage.GATE, drops):
        entry_points = find_fitting_entry_points(
            accepted.asset_type, accepted.main_place.entry_points, context.asset.get("category_code"), system_codes
        )
        if entry_points is None:
            reason, detail = c.CandidateRejection.ASSET_TYPE_MISMATCH, f"asset type {accepted.asset_type}"
            drops.extend(
                Drop(accepted.key, accepted.name, category, c.PlanStage.CHECKS, reason, detail)
                for category in accepted.categories
            )
        else:
            main_place = dataclasses.replace(accepted.main_place, entry_points=entry_points)
            kept.append(dataclasses.replace(accepted, main_place=main_place))
    return kept


def _keep_threats_the_ai_accepts(
    calls: _ThreatFindingCalls,
    candidates: Sequence[tuple[PlannedThreat, _GateQuestion]],
    stage: c.PlanStage,
    drops: list[Drop],
) -> list[PlannedThreat]:
    verdicts = calls.ask_which_threats_apply([question for _, question in candidates])
    if stage == c.PlanStage.GATE and candidates and all(verdict is None for verdict in verdicts):
        raise Unavailable(c.PlanMessage.AI_COULD_NOT_ANSWER)  # nothing checked is never "none apply"
    accepted = []
    for (candidate, _), verdict in zip(candidates, verdicts, strict=True):
        verdict = verdict or _NOT_JUDGED
        named, own = verdict.named_categories, candidate.categories
        kept = [] if verdict.refusal else [category for category in named if category in own]
        other_categories = c.PlanMessage.OTHER_KINDS.format(kinds=", ".join(kept))
        refusal = verdict.refusal or (c.CandidateRejection.NOT_RELEVANT, other_categories)
        for category in (category for category in own if category not in kept):
            drops.append(Drop(candidate.key, candidate.name, category, stage, *refusal))
        if not kept:
            continue
        impacts = [named[category][0] for category in kept]
        accepted.append(
            dataclasses.replace(
                candidate,
                categories=tuple(kept),
                reasons={category: named[category][1] for category in kept},
                main_place=AttackPlace(verdict.systems, verdict.entry_points, verdict.confidence),
                systems=verdict.systems,
                impact=max(impacts),
                confidence=verdict.confidence,
                likelihood=verdict.likelihood,
                actor_pick=verdict.actor_pick,
                actions=verdict.actions,
            )
        )
    return accepted


def _add_ai_threats_for_empty_categories(
    calls: _ThreatFindingCalls, fitting: Sequence[LibraryThreat], kept: Sequence[PlannedThreat], drops: list[Drop]
) -> list[PlannedThreat]:
    items: list[dict[str, Any]] = []
    for category in c.StrideCategory:  # the categories with no threat kept and every answer read
        lost = [
            drop for drop in drops if drop.kind == category and drop.stage in (c.PlanStage.GATE, c.PlanStage.CHECKS)
        ]
        if any(category in threat.categories for threat in kept) or any(
            drop.reason == c.PlanLoss.NOT_JUDGED for drop in lost
        ):
            continue
        rejected = dict.fromkeys(threat_name_without_code(drop.threat_name) for drop in lost)
        judged = sum(category in threat.categories for threat in fitting)
        items.append({"category": category, "judged": judged, "rejected": list(rejected)})
    if not items:
        return []
    categories = [item["category"] for item in items]
    prompt = _build_threat_finding_prompt(calls.landscape.text, categories, _GAP_FILL_RULES, "EMPTY CATEGORIES", items)
    read = functools.partial(_read_ai_proposed_threats, asked=categories, aliases=calls.landscape.system_ids)
    proposals = calls.ask_ai_reusing_earlier_answer(c.AiTask.GAP_FILL, prompt, read, list(map(str, categories))) or {}
    applying = [found for found in map(proposals.get, categories) if found and found["applies"]]
    threats, types = [found["threat"] for found in applying], [found["threat_type"] for found in applying]
    calls.snapshot.embed_gap_fill_queries(threats, types)  # each category's search reads its stored vector
    candidates: list[tuple[PlannedThreat, _GateQuestion]] = []
    for category in categories:
        proposal = proposals.get(category)
        if proposal is None:  # not answered, or the reply was skipped
            drops.append(Drop("ai:", "", category, c.PlanStage.GAP_FILL, c.PlanLoss.NOT_JUDGED))
        elif proposal["applies"] and (candidate := _build_ai_threat_candidate(calls, category, proposal, drops)):
            candidates.append(candidate)
    return _keep_threats_the_ai_accepts(calls, candidates, c.PlanStage.GAP_FILL, drops)


def _build_ai_threat_candidate(
    calls: _ThreatFindingCalls, category: c.StrideCategory, proposal: dict[str, Any], drops: list[Drop]
) -> tuple[PlannedThreat, _GateQuestion] | None:
    names = calls.landscape.system_names
    raw_name = proposal["threat"]
    key, name = (f"ai:{name_match_key(raw_name)}", replace_codes_with_names(raw_name, names))
    matched = _find_library_type_of_ai_threat(calls, category, proposal)
    if isinstance(matched, tuple):
        reason, detail = matched
        drops.append(Drop(key, name, category, c.PlanStage.GAP_FILL, reason, replace_codes_with_names(detail, names)))
        return None
    type_name = replace_codes_with_names(matched.name, names)
    candidate_threat = PlannedThreat(
        key, None, matched.type_id, type_name, name, (category,), linked_actors=matched.linked_actors
    )
    return candidate_threat, (proposal["threat_type"], raw_name, (category,), matched.linked_actors)


def _find_library_type_of_ai_threat(
    calls: _ThreatFindingCalls, category: c.StrideCategory, proposal: dict[str, Any]
) -> LibraryThreatType | tuple[str, str]:
    threat, threat_type = proposal["threat"], proposal["threat_type"]
    threshold = get_settings().threat_similarity_threshold
    (hits,) = calls.snapshot.find_threats(
        [(threat, category)], top_k=c.ThreatFinding.LIBRARY_MATCH_CANDIDATES, allowed_types=calls.allowed_types
    )
    if hits:
        scores = calls.rerank.score_relevance(threat, [threat_name_without_code(hit.name) for hit, _ in hits])
        if max(scores) >= threshold:
            return c.PlanLoss.LIBRARY_REPEAT, ""
    (types,) = calls.snapshot.find_threat_types(
        [threat_type], top_k=c.ThreatFinding.LIBRARY_MATCH_CANDIDATES, category=category
    )
    scores = calls.rerank.score_relevance(threat_type, [found.name for found, _ in types]) if types else []
    best = max(range(len(scores)), key=scores.__getitem__, default=None)
    if best is None or scores[best] < threshold:
        return c.PlanLoss.TYPE_UNMATCHED, threat_type
    matched = types[best][0]
    if not matched.linked_actors:
        return c.PlanLoss.NO_LINKED_ACTOR, matched.name
    return matched


def _merge_duplicate_threats(
    threats: list[PlannedThreat], embeddings: EmbeddingModel, context: FrozenContext, drops: list[Drop]
) -> list[PlannedThreat]:
    by_key: dict[str, PlannedThreat] = {}
    for threat in threats:  # one AI name under two categories: the STRIDE-first is kept
        earlier = by_key.get(threat.key)
        by_key[threat.key] = threat if earlier is None else _merge_threat_into_another(earlier, threat, context, drops)
    library = sorted(
        (threat for threat in by_key.values() if threat.catalogue_id is not None),
        key=lambda threat: min(map(_STRIDE_ORDER.index, threat.categories)),
    )
    library_by_name = {(threat_name_key(threat.name), threat.type_id): threat.key for threat in library}
    for key in sorted(key for key, threat in by_key.items() if threat.catalogue_id is None):
        library_key = library_by_name.get((threat_name_key(by_key[key].name), by_key[key].type_id))
        if library_key is not None:
            twin = by_key.pop(key)
            by_key[library_key] = _merge_threat_into_another(by_key[library_key], twin, context, drops)
            drops.append(Drop(key, twin.name, None, c.PlanStage.MERGE, c.PlanLoss.MERGED, f"into {library_key}"))
    return _merge_reworded_threats([by_key[key] for key in sorted(by_key)], embeddings, context, drops)


def _merge_reworded_threats(
    threats: list[PlannedThreat], embeddings: EmbeddingModel, context: FrozenContext, drops: list[Drop]
) -> list[PlannedThreat]:
    if len({threat.type_id for threat in threats}) == len(threats):
        return threats  # no two threats of one type: nothing to compare
    asset = context.asset["name"]
    labels = {
        threat.key: remove_asset_name(threat_name_without_code(threat.name), asset) or threat.name for threat in threats
    }
    texts = list(dict.fromkeys(labels.values()))
    vectors = dict(zip(texts, embeddings.embed_texts_to_compare(texts), strict=True))
    by_key = {threat.key: threat for threat in threats}
    library = sorted(
        (threat for threat in threats if threat.catalogue_id is not None),
        key=lambda threat: _build_path_record(threat, {})[0],  # the plan's own rank
    )
    kept_as: dict[str, str] = {}  # each threat compared so far: the key it is kept under (joined: another's)
    for threat in [*library, *(threat for threat in threats if threat.catalogue_id is None)]:
        vector = vectors[labels[threat.key]]
        twin = next(
            (
                into
                for key, into in kept_as.items()  # a library threat joined meets only AI threats, by its name
                if (threat.catalogue_id is None or key == into)
                and _is_same_threat(threat, by_key[into], float(vector @ vectors[labels[key]]))
            ),
            None,
        )
        if twin is None or threat.catalogue_id is not None:
            kept_as[threat.key] = twin or threat.key
        if twin is None:
            continue
        by_key[twin] = _merge_threat_into_another(by_key[twin], by_key.pop(threat.key), context, drops)
        drops.append(Drop(threat.key, threat.name, None, c.PlanStage.MERGE, c.PlanLoss.MERGED, f"into {twin}"))
    return [by_key[threat.key] for threat in threats if threat.key in by_key]


def _is_same_threat(threat: PlannedThreat, kept: PlannedThreat, cosine: float) -> bool:
    if threat.catalogue_id is None:
        return threat.type_id == kept.type_id and cosine >= c.ThreatFinding.AI_DUPLICATE_COSINE
    same_kind = (threat.type_id, threat.asset_type) == (kept.type_id, kept.asset_type)
    return same_kind and cosine >= c.ThreatFinding.LIBRARY_DUPLICATE_COSINE


def _merge_threat_into_another(
    kept: PlannedThreat, twin: PlannedThreat, context: FrozenContext, drops: list[Drop]
) -> PlannedThreat:
    added = tuple(category for category in twin.categories if category not in kept.categories)
    merged = dataclasses.replace(
        kept, likelihood=max(kept.likelihood, twin.likelihood), actions=kept.actions or twin.actions
    )
    system_codes = {system["id"]: system.get("category_code") for system in context.systems}
    if (
        added
        and kept.catalogue_id is not None
        and find_fitting_entry_points(
            kept.asset_type, twin.main_place.entry_points, context.asset.get("category_code"), system_codes
        )
        is None
    ):
        reason = c.CandidateRejection.ASSET_TYPE_MISMATCH
        drops.extend(Drop(kept.key, kept.name, category, c.PlanStage.MERGE, reason) for category in added)
        return merged
    return dataclasses.replace(
        merged,
        categories=(*kept.categories, *added),
        reasons=twin.reasons | kept.reasons,
        systems=tuple(sorted({*kept.systems, *twin.systems})),
        impact=max(kept.impact, twin.impact),
        confidence=max(kept.confidence, twin.confidence),
        actor_pick=min(
            (kept.actor_pick, twin.actor_pick), key=lambda pick: 2 if pick is None else 0 if pick.name else 1
        ),
    )


def _set_main_category_and_attacker(threats: list[PlannedThreat], drops: list[Drop]) -> list[PlannedThreat]:
    picked_threats = []
    for threat in threats:
        main, *others = threat.categories
        pick = threat.actor_pick or ActorPick(None, "")
        acting = next((actor for actor in threat.linked_actors if actor.name == pick.name), None)
        if acting is None:  # no listed attacker fits
            drops.append(
                Drop(threat.key, threat.name, None, c.PlanStage.ATTACKER, c.AttackerCheck.NONE_FITS, pick.reason)
            )
            continue
        picked_threats.append(
            dataclasses.replace(
                threat,
                categories=(main, *(category for category in _STRIDE_ORDER if category in others)),
                actors=(PlannedActor(acting.actor_id, acting.name, c.ActorRole.ACTING),),
                attacker_check=c.AttackerCheck.CHOSEN,
                attacker_check_reason=pick.reason,
                actor_pick=None,
            )
        )
    return picked_threats


def find_threats(
    chat: ChatModel,
    search: LibrarySearch,
    rerank: RerankModel,
    embeddings: EmbeddingModel,
    context: FrozenContext,
    country: str = "",
    is_last_attempt: bool = False,
) -> ThreatFindings:
    """Every threat that applies, one record each with its attacker, from one library snapshot."""
    snapshot = search.snapshot()
    library = snapshot.library.threat_library
    if not any(threat.linked_actors for threat in library.threats):  # refused before any AI call
        raise PlanRefused(c.ErrorCode.ACTOR_LIBRARY_EMPTY, c.PlanMessage.ACTOR_LIBRARY_EMPTY)
    landscape = describe_asset_for_ai(context, chat.max_prompt_chars // 2, country)
    allowed = compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in context.systems)
    )
    drops: list[Drop] = []
    calls = _ThreatFindingCalls(chat, rerank, snapshot, allowed, landscape, is_last_attempt)
    fitting = _list_threats_to_check(library.threats, allowed, drops)
    kept = _find_library_threats_that_apply(calls, fitting, context, drops)
    ai_threats = _add_ai_threats_for_empty_categories(calls, fitting, kept, drops)
    threats = _set_main_category_and_attacker(
        _merge_duplicate_threats([*kept, *ai_threats], embeddings, context, drops), drops
    )
    return ThreatFindings(
        threats,
        landscape=landscape,
        category_ids={name.strip().lower(): row_id for row_id, name in library.category_ids},
        drops=drops,
        library_threats=len(library.threats),
        gate_asked=sum(len(threat.categories) for threat in fitting),
        ai_threats=len(ai_threats),
    )


_DROP_REPORT_ORDER = (
    (c.PlanStage.ATTACKER, c.AttackerCheck.NONE_FITS),
    (c.PlanStage.MERGE, c.CandidateRejection.ASSET_TYPE_MISMATCH),
    (c.PlanStage.MERGE, c.PlanLoss.MERGED),
    (c.PlanStage.CHECKS, c.CandidateRejection.ASSET_TYPE_MISMATCH),
    *((c.PlanStage.GAP_FILL, reason) for reason in (c.PlanLoss.TYPE_UNMATCHED, c.PlanLoss.NO_LINKED_ACTOR)),
    *((c.PlanStage.GAP_FILL, reason) for reason in (c.CandidateRejection.NEEDS_UNRECORDED, c.PlanLoss.NOT_JUDGED)),
    *((c.PlanStage.GAP_FILL, reason) for reason in (c.CandidateRejection.NOT_RELEVANT, c.PlanLoss.LIBRARY_REPEAT)),
    (c.PlanStage.GATE, c.CandidateRejection.NEEDS_UNRECORDED),
    (c.PlanStage.GATE, c.PlanLoss.NOT_JUDGED),
    (c.PlanStage.GATE, c.CandidateRejection.NOT_RELEVANT),
    (c.PlanStage.PRE_FILTER, c.PlanLoss.NO_LINKED_ACTOR),
    (c.PlanStage.PRE_FILTER, c.PlanLoss.TYPE_FITS_NO_PLACE),
)
_DROP_REPORT_RANK: Final[dict[tuple[str, str], int]] = {
    pair: position for position, pair in enumerate(_DROP_REPORT_ORDER)
}


def build_plan(findings: ThreatFindings, target: int) -> dict[str, Any]:
    """The plan the run freezes: one path per threat, ranked, dealt in turns, the `target` best selected."""
    ranked = sorted(
        (_build_path_record(threat, findings.category_ids) for threat in findings.threats), key=lambda pair: pair[0]
    )
    dealt = spread_paths_across_systems([record for _, record in ranked], list(findings.landscape.system_ids.values()))
    keep = len(dealt) if target == 0 else target
    paths = [
        record
        | {"rank": rank}
        | (
            {"selected": True}
            if rank <= keep
            else {"selected": False, "unselected_reason": c.UnselectedReason.TARGET_REACHED}
        )
        for rank, record in enumerate(dealt, start=1)
    ]
    return {
        "threats": [threat.to_record(findings.category_ids) for threat in findings.threats],
        "paths": paths,
        "target": target,
    }


def _build_path_record(threat: PlannedThreat, category_ids: dict[str, int]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    category, main_place = threat.categories[0], threat.main_place
    systems = tuple(sorted(main_place.systems))
    scope = ("systems:" if len(systems) > 1 else "system:") + ",".join(map(str, systems)) if systems else "asset"
    path_id = hashlib.sha256(f"{threat.key}@{category}@{scope}".encode()).hexdigest()[:16]
    record = {
        "path_id": path_id,
        "served": None,
        "attempts": 0,
        "abandoned": False,
        "steps": [threat.key],
        "category": category,
        "category_id": category_ids.get(category.lower()),
        "categories": list(threat.categories),
        "systems": list(systems),
        "entry_points": list(main_place.entry_points),
        "impact": threat.impact,  # its worst harm
        "confidence": main_place.confidence,
        "also_applies": [],  # stored field: two threats never share a path
    }
    risk = threat.impact * threat.likelihood  # its worst harm, never only its main kind's
    strength = (
        -risk,
        -threat.impact,
        -main_place.confidence,
        _STRIDE_ORDER.index(category),
        threat.catalogue_id is None,
    )
    return (*strength, threat.catalogue_id or 0, path_id), record


def spread_paths_across_systems(records: list[dict[str, Any]], order: Sequence[int]) -> list[dict[str, Any]]:
    """Deals the ranked records in turns over the systems in `order`, then the asset, each turn the best."""
    left = [(record, {*record["entry_points"], *(() if record["systems"] else (None,))}) for record in records]
    dealt: list[dict[str, Any]] = []
    turns = (*order, None)
    while left:
        before = len(left)
        for position, system in enumerate(turns):
            through = [pair for pair in left if system in pair[1]]
            scarce = {other for other in turns[position + 1 :] if sum(other in ways for _, ways in left) == 1}
            taken = next((pair for pair in through if not pair[1] & scarce), None) or next(iter(through), None)
            if taken is not None:
                left.remove(taken)
                dealt.append(taken[0] | {"entry_system": system})
        if len(left) == before:  # ponytail: a way in outside `order`; the gate names listed systems only
            dealt += [record | {"entry_system": (record["entry_points"] or [None])[0]} for record, _ in left]
            break
    return dealt


def build_plan_trace(findings: ThreatFindings, plan: dict[str, Any], first_set: int) -> dict[str, Any]:
    """The trace saved with the plan: every stage's counts, the landscape cut, and the most telling drops."""
    drops_by_report_rank = sorted(
        findings.drops,
        key=lambda drop: (
            _DROP_REPORT_RANK.get((drop.stage, drop.reason), len(_DROP_REPORT_RANK)),
            drop.threat_key,
            drop.kind or "",
        ),
    )
    drops = [
        drop._asdict()
        | {
            "threat_name": threat_name_without_code(drop.threat_name),
            "detail": shorten_text(redact(" ".join(drop.detail.split())), c.PlanTraceLimits.DETAIL_MAX_CHARS),
        }
        for drop in drops_by_report_rank[: c.PlanTraceLimits.MAX_DROPS]
    ]
    counts = _count_threats_per_planning_step(findings, plan) | {"first_set": first_set}
    return {
        "counts": counts,
        "landscape_cut": findings.landscape.is_cut,
        "drops": drops,
        "drops_total": len(drops_by_report_rank),
    }


def _count_threats_per_planning_step(findings: ThreatFindings, plan: dict[str, Any]) -> dict[str, int]:
    counted = Counter((str(drop.stage), str(drop.reason)) for drop in findings.drops)
    gate = {
        "not_judged": counted[(c.PlanStage.GATE, c.PlanLoss.NOT_JUDGED)],
        "not_relevant": counted[(c.PlanStage.GATE, c.CandidateRejection.NOT_RELEVANT)],
        "needs_unrecorded": counted[(c.PlanStage.GATE, c.CandidateRejection.NEEDS_UNRECORDED)],
        "asset_type_mismatch": counted[(c.PlanStage.CHECKS, c.CandidateRejection.ASSET_TYPE_MISMATCH)],
        "needs_unrecorded_elsewhere": 0,  # one verdict per threat: a need refuses it under every category
    }
    selected = sum(bool(path["selected"]) for path in plan["paths"])
    return {
        "library_threats": findings.library_threats,
        "type_fits_no_place": counted[(c.PlanStage.PRE_FILTER, c.PlanLoss.TYPE_FITS_NO_PLACE)],
        "no_linked_actor": counted[(c.PlanStage.PRE_FILTER, c.PlanLoss.NO_LINKED_ACTOR)],
        "gate_asked": findings.gate_asked,
        **gate,
        "gate_accepted": findings.gate_asked - sum(gate.values()),
        "ai_threats": findings.ai_threats,
        "gap_fill_lost": sum(count for (stage, _), count in counted.items() if stage == c.PlanStage.GAP_FILL),
        "merged": counted[(c.PlanStage.MERGE, c.PlanLoss.MERGED)],
        "unfit_after_merge": counted[(c.PlanStage.MERGE, c.CandidateRejection.ASSET_TYPE_MISMATCH)],
        "no_attacker": counted[(c.PlanStage.ATTACKER, c.AttackerCheck.NONE_FITS)],
        "threats": len(plan["threats"]),
        "not_selected": len(plan["paths"]) - selected,
        "selected": selected,
        "paths": len(plan["paths"]),
        "already_held": 0,  # the asset's other sessions never take a path away
    }
