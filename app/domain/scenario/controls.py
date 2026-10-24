"""A written scenario's controls: library controls that fit its asset and systems, searched by its scenario
and risk statements, scored by the reranker and kept by the threshold rule; never written by an AI."""

import re
from collections.abc import Collection
from dataclasses import replace
from typing import Any

from app.ai import RerankModel
from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
from app.core.config import Settings, get_settings
from app.core.constants import (
    EMBEDDING_SOURCE_TABLE,
    QUERY_TASKS,
    REAL_WORLD_USER,
    ControlMatch,
    ControlMessage,
    Controls,
    EmbeddingCorpus,
    ErrorCode,
    ErrorMessage,
)
from app.core.exceptions import ControlsNotMapped
from app.core.redaction import redact
from app.domain.scenario.library_rules import place_asset_types
from app.domain.scenario.plan import raw_system_facts
from app.domain.shared.names import name_match_key, shorten_text
from app.domain.shared.prompt_redaction import facts_safe_for_prompt
from app.models.library.library import LibraryControl
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.controls import ControlMapping, ControlQuery, ControlRule, MappedControl
from app.search.snapshot import LibrarySnapshot
from app.search.texts import describe_control

_ABOUT_AI = re.compile(Controls.AI_THREAT_WORDS)
_REAL_WORLD_USER = re.compile(REAL_WORLD_USER)
_Scored = list[tuple[LibraryControl, float]]


class ControlMapper:
    """Maps scenarios to library controls with one reranker."""

    def __init__(self, rerank: RerankModel) -> None:
        self._rerank = rerank

    def map_controls(
        self, scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
    ) -> ControlMapping:
        """Every fitting control at or above CONTROL_SIMILARITY_THRESHOLD, best first, at most MAX_CONTROLS,
        topped up with the nearest to MIN_CONTROLS; none strong, the NEAREST_CONTROLS nearest, flagged. No
        control of the scenario's type: the nearest of any type, flagged. ControlsNotMapped only when the
        library is empty; an outage is raised."""
        if not snapshot.library.control_library:
            raise ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, ErrorMessage.CONTROL_LIBRARY_EMPTY)
        rule = _control_rule()
        scored, query, other_type, about_ai = self._scored_candidates(scenario, context, snapshot, rule)
        mapping = select_controls(scored, rule, query.text, other_type)
        return replace(
            mapping,
            query_shortened=query.shortened,
            mitigations=query.mitigations,
            ai_controls=about_ai,
            shortlist=tuple((control.control_id, score) for control, score in scored),
        )

    def find_alternatives(
        self,
        scenario: dict[str, Any],
        context: FrozenContext,
        snapshot: LibrarySnapshot,
        identified: Collection[int],
        count: int,
        mapped: dict[str, Any] | None = None,
    ) -> _Scored:
        """The `count` best-scored library controls for the scenario that are not `identified` nor one's twin:
        what a remediation plan may put in place of an identified control that does not fit its risk.
        `mapped`: the scenario's controls record, whose reranked shortlist is reused when it still applies."""
        if not snapshot.library.control_library:
            return []
        scored = _stored_shortlist(mapped or {}, scenario, context, snapshot)
        if scored is None:
            scored, _, _, _ = self._scored_candidates(scenario, context, snapshot, _control_rule())
        taken = {
            name_match_key(describe_control(control))
            for control in snapshot.library.control_library
            if control.control_id in identified
        }
        ranked = _without_twins(sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)))
        return [pair for pair in ranked if name_match_key(describe_control(pair[0])) not in taken][:count]

    def _scored_candidates(
        self, scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot, rule: ControlRule
    ) -> tuple[_Scored, ControlQuery, str | None, bool]:
        """(the shortlist the reranker scored 0-100, the query it was searched by, the other-type warning,
        whether the threat is about AI): the scenario's own place decides the asset types searched."""
        content = scenario["content"]
        systems = _scenario_systems(content, context)
        allowed = place_asset_types(
            context.asset.get("category_code"), (system.get("category_code") for system in systems)
        )
        query = control_query(content, context, systems)
        about_ai = is_about_ai(content)
        found, other_type = _compatible_else_nearest(snapshot, query.text, rule, allowed, about_ai)
        candidates = [control for control, _ in found]
        scores = self._rerank.score_relevance(
            query.text, [describe_control(control) for control in candidates]
        )
        return list(zip(candidates, scores, strict=True)), query, other_type, about_ai


def _compatible_else_nearest(
    snapshot: LibrarySnapshot, query: str, rule: ControlRule, allowed: frozenset[str], about_ai: bool
) -> tuple[list[tuple[LibraryControl, float]], str | None]:
    """The fitting shortlist; when no control of the scenario's types exists, every control's, with the
    warning that says so."""
    (found,) = snapshot.find_controls([query], rule.candidates, allowed, ai_controls=about_ai)
    if found:
        return found, None
    types = ", ".join(sorted(allowed)) or "none recorded"
    (nearest,) = snapshot.find_controls([query], rule.candidates, ai_controls=about_ai)
    return nearest, ControlMessage.OTHER_TYPE.format(types=types)


def is_about_ai(content: dict[str, Any]) -> bool:
    """Whether a card is about AI, by its threat's type and name or its scenario text: only such a card may
    get an AI control. The real-world attackers its evidence names (an "AI-orchestrated Campaign") never
    count."""
    threat, statement = content.get("threat") or {}, content.get("statement") or ""
    for entry in content.get("evidence") or []:
        for fact in entry.get("facts") or []:
            if user := _REAL_WORLD_USER.fullmatch(str(fact)):
                statement = statement.replace(user["name"] or user["campaign"], "")
    return bool(_ABOUT_AI.search(f"{threat.get('type') or ''} {threat.get('name') or ''} {statement}"))


def _scenario_systems(content: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The scenario's own systems, as the run froze them."""
    ids = {system["id"] for system in content.get("systems") or []}
    return [system for system in context.systems if system["id"] in ids]


def _control_library_stamp(snapshot: LibrarySnapshot) -> dict[str, str | None]:
    """The control library table's version, as a mapping record keeps it."""
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.CONTROL]
    return {
        name: digest.hex() if digest else None for name, digest in snapshot.library.stamp if name == table
    }


def control_query_instruction(settings: Settings) -> str | None:
    """What the control query is embedded after (None: sent plain), as the embedding gateway sends it."""
    profile = find_model_profile(EMBEDDING_MODEL_PROFILES, settings.embedding_model)
    return profile.instruction_for(QUERY_TASKS[EmbeddingCorpus.CONTROL])


def _stored_shortlist(
    mapped: dict[str, Any], scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
) -> _Scored | None:
    """The mapping's reranked shortlist when it was searched by the same query (as embedded: its instruction
    too), library, models, candidate count and AI rule the scenario has now; None otherwise, or when the
    record keeps none."""
    shortlist = mapped.get("shortlist")
    if not shortlist:
        return None
    settings, content = get_settings(), scenario["content"]
    searched_now = {
        "rerank_model": settings.rerank_model,
        "embedding_model": settings.embedding_model,
        "query_instruction": control_query_instruction(settings),
        "library": _control_library_stamp(snapshot),
        "candidates": settings.control_candidates,
        "ai_controls": is_about_ai(content),
    }
    made_with = mapped.get("made_with") or {}
    if any(made_with.get(key) != value for key, value in searched_now.items()):
        return None
    if mapped.get("query") != control_query(content, context, _scenario_systems(content, context)).text:
        return None
    by_id = {control.control_id: control for control in snapshot.library.control_library}
    return [(by_id[entry["control_id"]], entry["score"]) for entry in shortlist]


def controls_record(mapping: ControlMapping, snapshot: LibrarySnapshot) -> dict[str, Any]:
    """What a scenario keeps of its mapping: the controls, the warning, every candidate reranked with its
    score, and what was searched with what (the query, the models, the library version and the rule)."""
    settings = get_settings()
    return {
        "items": [item.to_record() for item in mapping.items],
        "warning": mapping.warning,
        "shortfall": mapping.shortfall,
        "left_out_over_max": mapping.left_out,
        "query": mapping.query,
        "shortlist": [{"control_id": control_id, "score": score} for control_id, score in mapping.shortlist],
        "made_with": {
            "rerank_model": settings.rerank_model,
            "embedding_model": settings.embedding_model,
            "query_instruction": control_query_instruction(settings),
            "library": _control_library_stamp(snapshot),
            "threshold": settings.control_similarity_threshold,
            "candidates": settings.control_candidates,
            "min_controls": settings.min_controls,
            "max_controls": settings.max_controls,
            "nearest_controls": settings.nearest_controls,
            "query_shortened": list(mapping.query_shortened),
            "mitigations": list(mapping.mitigations),
            "ai_controls": mapping.ai_controls,
        },
    }


# --- which reranked candidates a scenario keeps


def _control_rule() -> ControlRule:
    """The rule the settings give: CONTROL_SIMILARITY_THRESHOLD, CONTROL_CANDIDATES, MIN_, MAX_ and
    NEAREST_CONTROLS."""
    settings = get_settings()
    return ControlRule(
        settings.control_similarity_threshold,
        settings.control_candidates,
        settings.min_controls,
        settings.max_controls,
        settings.nearest_controls,
    )


def select_controls(
    scored: _Scored, rule: ControlRule, query: str, other_type: str | None = None
) -> ControlMapping:
    """Best first, twins folded: every control at or above the threshold ("strong", at most MAX_CONTROLS);
    fewer than MIN_CONTROLS strong, the nearest below it added as "fallback" up to it; none strong, the
    NEAREST_CONTROLS nearest. `other_type`: the shortlist is of another asset type (that warning), so none is
    strong, whatever its score. `scored`: 0-100 scores."""
    unique = _without_twins(sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)))
    strong = [] if other_type else [(control, score) for control, score in unique if score >= rule.cutoff]
    kept = strong[: rule.most]
    target = min(rule.least if kept else rule.nearest, rule.most)
    below = unique if other_type else [(control, score) for control, score in unique if score < rule.cutoff]
    fallback = below[: max(target - len(kept), 0)]
    chosen = [_mapped(c, s, ControlMatch.EXACT, rule, bool(kept)) for c, s in kept]
    chosen += [_mapped(c, s, ControlMatch.NEAREST, rule, bool(kept), other_type) for c, s in fallback]
    items = tuple(replace(item, rank=rank) for rank, item in enumerate(chosen, 1))
    nearest_only = ControlMessage.NEAREST_ONLY.format(cutoff=rule.cutoff, nearest=target)
    warning = other_type or (None if kept else nearest_only)
    short = ControlMessage.SHORTFALL.format(kept=len(items), least=target) if len(items) < target else None
    return ControlMapping(items, query, warning, short, len(strong) - len(kept))


def _without_twins(ordered: _Scored) -> _Scored:
    """The best of each control: the same id, then the same text (an IT and an OT copy), once."""
    seen: set[object] = set()
    unique: _Scored = []
    for control, score in ordered:
        keys = {control.control_id, name_match_key(describe_control(control))}
        if not keys & seen:
            seen |= keys
            unique.append((control, score))
    return unique


def _mapped(
    control: LibraryControl,
    score: float,
    match: ControlMatch,
    rule: ControlRule,
    any_strong: bool,
    other_type: str | None = None,
) -> MappedControl:
    """A kept control with its score and why it was kept: strong, a top-up to the minimum, a nearest, or a
    nearest of another asset type."""
    if other_type:
        asset_type = control.asset_type or "none recorded"
        reason = ControlMessage.OTHER_TYPE_REASON.format(
            score=score, asset_type=asset_type, nearest=rule.nearest
        )
    elif match is ControlMatch.EXACT:
        reason = ControlMessage.STRONG_REASON.format(score=score, cutoff=rule.cutoff)
    elif any_strong:
        reason = ControlMessage.FALLBACK_REASON.format(score=score, cutoff=rule.cutoff, least=rule.least)
    else:
        reason = ControlMessage.NEAREST_REASON.format(score=score, cutoff=rule.cutoff, nearest=rule.nearest)
    fields = (control.control_id, control.code, control.name, control.domain, control.asset_type)
    return MappedControl(*fields, 0, score, match, control.description, reason)


# --- the text a scenario's controls are searched and reranked by


def control_query(
    content: dict[str, Any], context: FrozenContext, systems: list[dict[str, Any]]
) -> ControlQuery:
    """The query within Controls.QUERY_MAX_CHARS: a head never cut (category, threat, attacker, title, asset,
    cited mitigations), then each system, the asset's facts, the scenario and the risk sharing the rest
    fairly; with the labels of the parts shortened. Redacted."""
    threat = content.get("threat") or {}
    acting = next((a["name"] for a in content.get("actors") or [] if a.get("role") == "acting"), "")
    asset = _named_with_type(context.asset.get("name"), context.asset_context.get("asset_type"))
    mitigations = _cited_mitigations(content)
    head = redact(
        "\n".join(
            [
                f"Category: {content.get('category') or ''}",
                f"Threat: {threat.get('type') or ''}: {threat.get('name') or ''}",
                f"Attacker: {acting}",
                f"Title: {content.get('title') or ''}",
                f"Asset: {asset}",
                *([f"Mitigations (MITRE ATT&CK): {'; '.join(mitigations)}"] if mitigations else []),
            ]
        )
    )
    labelled = [
        *((f"system {s['id']}", f"System {s['name']}: {_facts_line(raw_system_facts(s))}") for s in systems),
        ("asset facts", f"Asset facts: {_facts_line(context.own_and_organisation_facts()[0])}"),
        ("scenario", f"Scenario: {content.get('statement') or ''}"),
        ("risk", f"Risk: {content.get('risk_statement') or ''}"),
    ]
    texts = [redact(text) for _, text in labelled]
    room = Controls.QUERY_MAX_CHARS - len(head) - len(texts)  # one line break before each part
    shares = _fair_shares([len(text) for text in texts], max(room, 0))
    fitted = [shorten_text(text, share) for text, share in zip(texts, shares, strict=True)]
    shortened = tuple(
        label for (label, _), text, share in zip(labelled, texts, shares, strict=True) if len(text) > share
    )
    query = "\n".join([shorten_text(head, Controls.QUERY_MAX_CHARS), *(text for text in fitted if text)])
    return ControlQuery(query, shortened, mitigations)


def _cited_mitigations(content: dict[str, Any]) -> tuple[str, ...]:
    """The mitigations of the evidence the scenario cites, each once, at most Controls.QUERY_MITIGATIONS."""
    names = (str(name) for item in content.get("evidence") or [] for name in item.get("mitigations") or ())
    return tuple(dict.fromkeys(name for name in names if name.strip()))[: Controls.QUERY_MITIGATIONS]


def _fair_shares(lengths: list[int], room: int) -> list[int]:
    """Each part's room: shortest first, each takes what it needs up to an equal share of what is left."""
    shares = [0] * len(lengths)
    for position, index in enumerate(sorted(range(len(lengths)), key=lambda i: (lengths[i], i))):
        shares[index] = min(lengths[index], room // (len(lengths) - position))
        room -= shares[index]
    return shares


def _facts_line(facts: dict[str, Any]) -> str:
    """Every recorded fact as `name: value` (a list joined by commas), cleaned as a prompt's."""
    shown = facts_safe_for_prompt({key: value for key, value in facts.items() if key != "name"})
    return "; ".join(
        f"{key}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
        for key, value in shown.items()
    )


def _named_with_type(name: str | None, asset_type: str | None) -> str:
    """The asset's name and type, e.g. "Grid Centre (Control system)", or the name alone (never "()")."""
    recorded = facts_safe_for_prompt({"type": asset_type}).get("type")  # "N/A", blanks: not a type
    return f"{name or ''} ({recorded})" if recorded else name or ""
