"""A written scenario's controls: library controls that fit its asset and systems, searched by its scenario
and risk statements, scored by the reranker and kept by the threshold rule; never written by an AI."""

import re
from dataclasses import replace
from typing import Any

from app.ai import RerankModel
from app.core.config import get_settings
from app.core.constants import (
    EMBEDDING_SOURCE_TABLE,
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
_Scored = list[tuple[LibraryControl, float]]


class ControlMapper:
    """Maps scenarios to library controls with one reranker."""

    def __init__(self, rerank: RerankModel) -> None:
        self._rerank = rerank

    def map_controls(
        self, scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
    ) -> ControlMapping:
        """Every fitting control at or above CONTROL_SIMILARITY_THRESHOLD, best first, at most MAX_CONTROLS;
        else the nearest up to MIN_CONTROLS, flagged. No control of the scenario's type: the nearest of any
        type, flagged. ControlsNotMapped only when the library is empty; an outage is raised."""
        content = scenario["content"]
        if not snapshot.library.control_library:
            raise ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, ErrorMessage.CONTROL_LIBRARY_EMPTY)
        systems = _scenario_systems(content, context)
        # The scenario's own place decides: its systems' category codes, the asset's when it is on the asset.
        allowed = place_asset_types(
            context.asset.get("category_code"), (system.get("category_code") for system in systems)
        )
        rule = _control_rule()
        query = control_query(content, context, systems)
        about_ai = is_about_ai(content.get("threat") or {})
        found, other_type = _compatible_else_nearest(snapshot, query.text, rule, allowed, about_ai)
        candidates = [control for control, _ in found]
        scores = self._rerank.score_relevance(
            query.text, [describe_control(control) for control in candidates]
        )
        mapping = select_controls(list(zip(candidates, scores, strict=True)), rule, query.text)
        if other_type:  # never a strong set of another type: the nearest only, flagged as such
            mapping = replace(mapping, items=mapping.items[: rule.least], warning=other_type, left_out=0)
        return replace(
            mapping, query_shortened=query.shortened, mitigations=query.mitigations, ai_controls=about_ai
        )


def _compatible_else_nearest(
    snapshot: LibrarySnapshot, query: str, rule: ControlRule, allowed: frozenset[str], about_ai: bool
) -> tuple[list[tuple[LibraryControl, float]], str | None]:
    """The fitting shortlist; when no control of the scenario's types exists, every control's, with the
    warning that says so."""
    (found,) = snapshot.find_controls([query], rule.candidates, allowed, ai_controls=about_ai)
    if found:
        return found, None
    types = ", ".join(sorted(allowed)) or "none recorded"
    (nearest,) = snapshot.find_controls([query], rule.candidates)
    return nearest, ControlMessage.OTHER_TYPE.format(types=types)


def is_about_ai(threat: dict[str, Any]) -> bool:
    """Whether a card's threat is about AI, by its type and name: only such a card may get an AI control."""
    return bool(_ABOUT_AI.search(f"{threat.get('type') or ''} {threat.get('name') or ''}"))


def _scenario_systems(content: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The scenario's own systems, as the run froze them."""
    ids = {system["id"] for system in content.get("systems") or []}
    return [system for system in context.systems if system["id"] in ids]


def controls_record(mapping: ControlMapping, snapshot: LibrarySnapshot) -> dict[str, Any]:
    """What a scenario keeps of its mapping: the controls, the warning, and what was searched with what (the
    query, the models, the library version and the rule)."""
    settings = get_settings()
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.CONTROL]
    stamp = {
        name: digest.hex() if digest else None for name, digest in snapshot.library.stamp if name == table
    }
    return {
        "items": [item.to_record() for item in mapping.items],
        "warning": mapping.warning,
        "shortfall": mapping.shortfall,
        "left_out_over_max": mapping.left_out,
        "query": mapping.query,
        "made_with": {
            "rerank_model": settings.rerank_model,
            "embedding_model": settings.embedding_model,
            "library": stamp,
            "threshold": settings.control_similarity_threshold,
            "candidates": settings.control_candidates,
            "min_controls": settings.min_controls,
            "max_controls": settings.max_controls,
            "query_shortened": list(mapping.query_shortened),
            "mitigations": list(mapping.mitigations),
            "ai_controls": mapping.ai_controls,
        },
    }


# --- which reranked candidates a scenario keeps


def _control_rule() -> ControlRule:
    """The rule the settings give: CONTROL_SIMILARITY_THRESHOLD, CONTROL_CANDIDATES, MIN_/MAX_CONTROLS."""
    settings = get_settings()
    return ControlRule(
        settings.control_similarity_threshold,
        settings.control_candidates,
        settings.min_controls,
        settings.max_controls,
    )


def select_controls(scored: _Scored, rule: ControlRule, query: str) -> ControlMapping:
    """Best first, twins folded: every control at or above the threshold ("strong", at most MAX_CONTROLS),
    and fewer than MIN_CONTROLS strong, the nearest below it added as "fallback". `scored`: 0-100 scores."""
    unique = _without_twins(sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)))
    strong = [(control, score) for control, score in unique if score >= rule.cutoff]
    kept = strong[: rule.most]
    room = max(min(rule.least, rule.most) - len(kept), 0)
    fallback = [(control, score) for control, score in unique if score < rule.cutoff][:room]
    chosen = [_mapped(c, s, ControlMatch.EXACT, rule) for c, s in kept]
    chosen += [_mapped(c, s, ControlMatch.NEAREST, rule) for c, s in fallback]
    items = tuple(replace(item, rank=rank) for rank, item in enumerate(chosen, 1))
    warning = None if kept else ControlMessage.NEAREST_ONLY.format(cutoff=rule.cutoff, least=rule.least)
    short = (
        ControlMessage.SHORTFALL.format(kept=len(items), least=rule.least)
        if len(items) < rule.least
        else None
    )
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


def _mapped(control: LibraryControl, score: float, match: ControlMatch, rule: ControlRule) -> MappedControl:
    """A kept control with its score and why it was kept."""
    reason = (
        ControlMessage.STRONG_REASON.format(score=score, cutoff=rule.cutoff)
        if match is ControlMatch.EXACT
        else ControlMessage.FALLBACK_REASON.format(score=score, cutoff=rule.cutoff, least=rule.least)
    )
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
