"""The writer's brief for one attack path (approved prompts, BUILD_PLAN): built by code from the frozen
plan and context, no AI call. Only this path's systems, each by name with its recorded facts; the acting
attacker; the relevance check's reason. No database id reaches it, and every text is redacted. A path that
lacks what its scenario needs is refused here, so no AI is asked to invent the fact."""

import json
import re
from typing import Any

from app.core.config import get_settings
from app.core.constants import (
    ActorRole,
    ContextProperties,
    ErrorCode,
    PathProblem,
    StrideCategory,
    WriterStyle,
    Writing,
)
from app.core.exceptions import PathNotWritable
from app.core.tracing import traced
from app.engine.scenarios.finding.asset_landscape import raw_system_facts
from app.engine.shared.names import find_name_mentions, shorten_text, threat_name_without_code
from app.engine.shared.prompt_redaction import facts_safe_for_prompt, redact
from app.models.asset_context import FrozenContext
from app.models.writing import BriefSystem, LiveLibrary, WriterBrief

#: The asset facts under the names the approved brief shows; every other fact keeps its own name.
_ASSET_FACT_NAMES = {
    "cii_asset_description": "description",
    "asset_type": "type",
    "asset_priority": "priority",
}


@traced("writing.brief")
def build_brief(
    threats: dict[str, dict[str, Any]],
    path: dict[str, Any],
    context: FrozenContext,
    budget: int,
    live: LiveLibrary,
    other_scenarios: tuple[str, ...] = (),
    style: WriterStyle = WriterStyle.ORIGINAL,
) -> WriterBrief:
    """The brief for `path`; `threats` = the plan's threats by key, `budget` = the most characters its facts
    may use (half the model input, as the landscape's: the asset at most a quarter, the path's systems
    sharing the rest equally); `live` = what the library holds active now; `style` = how it is written (only
    an evidence story reads the threat's evidence); `other_scenarios` = the path's versions a regenerate
    must differ from, oldest first (the newest kept within a quarter of the budget).
    Raises PathNotWritable for a path missing a fact or whose threat or acting attacker was retired."""
    threat = _path_threat(threats, path)
    _check_still_live(threat, path["path_id"], live)
    in_path = _path_systems(path, context)
    asset = _cut_to_fit(_named_facts(context.asset["name"], _asset_facts(context, style)), budget // 4)
    share = (budget - _json_length(asset)) // max(len(in_path), 1)
    systems = tuple(
        _cut_to_fit(_named_facts(system["name"], raw_system_facts(system)), share) for system in in_path
    )
    return WriterBrief(
        asset=asset,
        asset_name=asset["name"],
        critical_service=_critical_service(context),
        category=StrideCategory(path["category"]),
        attacker=threat["actors"][0]["name"],
        threat_type=threat_name_without_code(threat["type"]["name"]),
        threat=threat_name_without_code(threat["name"]),
        why_it_applies=redact(_reason_on_path(threat["reason"], path, context)),
        systems=systems,
        other_systems=_other_systems(path, context),
        other_scenarios=_newest_within(other_scenarios, budget // 4),
        style=style,
        evidence=_evidence_of(threat, style),
        supporting_systems=_brief_systems(path, context),
    )


def _other_systems(path: dict[str, Any], context: FrozenContext) -> tuple[str, ...]:
    """The run's systems this scenario is not on, by name (redacted): never part of its story."""
    return tuple(redact(system["name"]) for system in context.systems if system["id"] not in path["systems"])


def _brief_systems(path: dict[str, Any], context: FrozenContext) -> tuple[BriefSystem, ...]:
    """Every supporting system of the run, in its order: applicable when the scenario's route goes through
    it (code decides, G216); the writer gives each a one-sentence reason. Names as the prompt may show
    them."""
    return tuple(
        BriefSystem(system["id"], redact(system["name"]), system["id"] in path["systems"])
        for system in context.systems
    )


def _evidence_of(threat: dict[str, Any], style: WriterStyle) -> tuple[dict[str, Any], ...]:
    """Only an evidence story reads the threat's saved evidence: the original writer's brief never
    carries it."""
    return tuple(threat.get("evidence") or ()) if style is WriterStyle.EVIDENCE_STORY else ()


def _asset_facts(context: FrozenContext, style: WriterStyle) -> dict[str, Any]:
    """The asset's own facts under the names the approved brief shows; the organisation's (entity_...) kept
    apart under one key that says they are background, never this asset's (G208). An evidence story also
    reads the deployment's country (G232); the original writer's brief is as it was."""
    own, organisation = context.own_and_organisation_facts()
    facts = {_ASSET_FACT_NAMES.get(key, key): value for key, value in own.items()}
    if style is WriterStyle.EVIDENCE_STORY:
        facts[ContextProperties.COUNTRY_KEY] = get_settings().context_country
    background = "; ".join(str(value) for value in organisation.values() if value)
    return facts | ({ContextProperties.ORGANISATION_BRIEF_KEY: background} if background else {})


def _reason_on_path(reason: str, path: dict[str, Any], context: FrozenContext) -> str:
    """The relevance check's reason without the names of the run's systems this path is not on (each has its
    own path: G208), so neither the writer nor the card tells another system's story here."""
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
            reason, edge = reason[:start] + Writing.OTHER_SYSTEM + reason[end:], start
    repeated = rf"{Writing.OTHER_SYSTEM}(?:,? (?:and |or )?{Writing.OTHER_SYSTEM})+"
    return re.sub(repeated, Writing.OTHER_SYSTEMS, reason)


def _path_systems(path: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The path's own systems as the run froze them: the system its kind of attack is on (owner 2026-10-12),
    or every system of a scenario merged from the same attack through several systems (G213); never every
    system its threat involves. PathNotWritable when one is not in the run."""
    by_id = {system["id"]: system for system in context.systems}
    if any(system_id not in by_id for system_id in path["systems"]):
        raise PathNotWritable(path["path_id"], PathProblem.SYSTEM_NOT_IN_RUN)
    return [by_id[system_id] for system_id in path["systems"]]


def _critical_service(context: FrozenContext) -> str | None:
    """The critical service(s) the asset supports, as the procedure's asset row gives them, redacted."""
    service = context.asset_context.get("critical_service")
    return redact(service) if service else None


def _newest_within(statements: tuple[str, ...], budget: int) -> tuple[str, ...]:
    """The newest of a path's versions (given oldest first) that fit `budget` characters together, redacted,
    oldest first: a path regenerated many times never pushes the prompt past the model input."""
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
    """The path's one threat (one threat = one path, G114), checked whole before any AI call."""
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
    """A part's name first, then its recorded facts cleaned for a prompt (no id, no empty or placeholder
    value, secrets redacted). The name is set apart so a placeholder-like name is never dropped."""
    return {"name": redact(" ".join(str(name).split())), **facts_safe_for_prompt(facts | {"name": None})}


def _json_length(facts: dict[str, Any]) -> int:
    return len(json.dumps(facts, ensure_ascii=False, default=str))


def _cut_to_fit(facts: dict[str, Any], limit: int) -> dict[str, Any]:
    """`facts` within `limit` JSON characters: the longest text fact (never the name) is cut first, so the
    brief stays one valid JSON object."""
    # ponytail: lists (technology, platforms) are never cut: they hold the platform's short option names.
    kept = dict(facts)
    while (over := _json_length(kept) - limit) > 0:
        texts = [(len(value), key) for key, value in kept.items() if key != "name" and isinstance(value, str)]
        length, key = max(texts, default=(0, ""))
        if length <= 1:
            break
        kept[key] = shorten_text(kept[key], max(length - over, 1))
    return kept
