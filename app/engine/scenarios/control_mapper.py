"""A written scenario's controls: only library controls
compatible with its asset and systems, found by meaning from its scenario AND risk statements, scored by the
reranker, never written by an AI."""

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
from app.core.tracing import ranked, record_detail, step_detail_enabled, traced
from app.engine.scenarios.finding.asset_landscape import raw_system_facts
from app.engine.shared.names import name_match_key, shorten_text
from app.engine.shared.prompt_redaction import facts_safe_for_prompt
from app.models.asset_context import FrozenContext
from app.models.controls import ControlMapping, MappedControl
from app.models.library import LibraryControl, place_asset_types
from app.search.snapshot import LibrarySnapshot
from app.search.texts import describe_control


class ControlMapper:
    def __init__(self, rerank: RerankModel) -> None:
        self._rerank = rerank

    @traced("controls.map")
    def map_controls(
        self, scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
    ) -> ControlMapping:
        """Every compatible control at or above the reranker's cut-off, best first; else the single nearest,
        with a warning. ControlsNotMapped when the library is empty or nothing fits; an outage is raised."""
        content = scenario["content"]
        if not snapshot.library.control_library:
            raise ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, ErrorMessage.CONTROL_LIBRARY_EMPTY)
        systems = _scenario_systems(content, context)
        # The scenario's own place decides, as for its threat (owner 2026-10-12, G211): its systems' category
        # codes (IT, OT, IT\OT), the asset's when it is on the asset itself. The asset's code, never its
        # free-text `asset_context.asset_type` ("Control system"), which names no type (review 2026-10-11).
        allowed = place_asset_types(
            context.asset.get("category_code"), (system.get("category_code") for system in systems)
        )
        query = control_search_text(content, context, systems)
        (found,) = snapshot.find_controls([query], Controls.SHORTLIST, allowed)
        threat = (content.get("threat") or {}).get("name")
        if step_detail_enabled():
            _trace_shortlist(threat, context, systems, allowed, len(query), len(found))
        if not found:  # no control fits: never one of another type in its place
            types = ", ".join(sorted(allowed)) or "none recorded"
            message = ErrorMessage.NO_COMPATIBLE_CONTROL.format(types=types)
            raise ControlsNotMapped(ErrorCode.NO_COMPATIBLE_CONTROL, message)
        candidates = [control for control, _ in found]
        scores = self._rerank.score_relevance(query, [describe_control(control) for control in candidates])
        threshold = get_settings().control_similarity_threshold  # CONTROL_SIMILARITY_THRESHOLD
        return _controls_above_cutoff(candidates, scores, threshold, query, threat)


def control_search_text(
    content: dict[str, Any], context: FrozenContext, systems: list[dict[str, Any]]
) -> str:
    """What one scenario's controls are searched and reranked by: its category, threat and attacker, then its
    title, scenario and risk statements (both required: spec v4.0 §7.5.1), then the asset, then every recorded
    fact of the scenario's systems and of the asset (owner 2026-10-11: every column the asset procedure
    returns, none picked by name); cut at Controls.QUERY_MAX_CHARS from the end, so what matters most is kept.
    Redacted, as every prompt is."""
    threat = content.get("threat") or {}
    acting = next(
        (actor["name"] for actor in content.get("actors") or [] if actor.get("role") == "acting"), ""
    )
    parts = [
        f"Category: {content.get('category') or ''}",
        f"Threat: {threat.get('type') or ''}: {threat.get('name') or ''}",
        f"Attacker: {acting}",
        f"Title: {content.get('title') or ''}",
        f"Scenario: {content.get('statement') or ''}",
        f"Risk: {content.get('risk_statement') or ''}",
        f"Asset: {_named_with_type(context.asset.get('name'), context.asset_context.get('asset_type'))}",
        *(f"System {system['name']}: {_facts_line(raw_system_facts(system))}" for system in systems),
        f"Asset facts: {_facts_line(context.own_and_organisation_facts()[0])}",  # never the organisation's
    ]
    return shorten_text(redact("\n".join(parts)), Controls.QUERY_MAX_CHARS)


def _facts_line(facts: dict[str, Any]) -> str:
    """Every recorded fact as `name: value` (a list joined by commas), as the AI would be shown it: no id, no
    placeholder, no unanswered value; the line itself says whose facts they are."""
    shown = facts_safe_for_prompt({key: value for key, value in facts.items() if key != "name"})
    return "; ".join(
        f"{key}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
        for key, value in shown.items()
    )


def _named_with_type(name: str | None, asset_type: str | None) -> str:
    """The asset's name and type, e.g. "Grid Centre (Control system)", or the name alone when no type is
    recorded or it is excluded (G197): never empty brackets in the text the reranker scores."""
    recorded = facts_safe_for_prompt({"type": asset_type}).get("type")  # "N/A", blanks: not a type
    return f"{name or ''} ({recorded})" if recorded else name or ""


def _scenario_systems(content: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The scenario's own systems, as the run froze them (their type and technology)."""
    ids = {system["id"] for system in content.get("systems") or []}
    return [system for system in context.systems if system["id"] in ids]


def _controls_above_cutoff(
    candidates: list[LibraryControl], scores: list[float], cutoff: float, query: str, threat: str | None
) -> ControlMapping:
    """Every candidate at or above `cutoff`, else the single best as `nearest`; twins folded (the same id,
    then the same text, an IT and an OT copy), keeping the higher score; ranked 1..n, best first, then id.
    `threat`: the scenario's threat name, for the step trace only."""
    ordered = sorted(zip(candidates, scores, strict=True), key=lambda pair: (-pair[1], pair[0].control_id))
    exact = [(control, score) for control, score in ordered if score >= cutoff]
    kept, match = (exact, ControlMatch.EXACT) if exact else (ordered[:1], ControlMatch.NEAREST)
    seen: set[object] = set()
    items: list[MappedControl] = []
    twins: list[str] = []
    for control, score in kept:
        keys = {control.control_id, name_match_key(describe_control(control))}
        if keys & seen:
            twins.append(control.code)
            continue
        seen |= keys
        rank = len(items) + 1
        fields = (control.control_id, control.code, control.name, control.domain, control.asset_type)
        items.append(MappedControl(*fields, rank, score, match, control.description))
    if step_detail_enabled():
        _trace_rerank_and_cutoff(threat, ordered, cutoff, len(exact), items, twins)
    warning = None if exact else ControlMessage.NEAREST_ONLY.format(cutoff=cutoff)
    return ControlMapping(tuple(items), query, warning)


def _trace_shortlist(
    threat: str | None,
    context: FrozenContext,
    systems: list[dict[str, Any]],
    allowed: frozenset[str],
    query_chars: int,
    shortlist: int,
) -> None:
    system_types = ", ".join(sorted({str(system.get("category_code")) for system in systems})) or "none"
    record_detail(
        "allowed types + query",
        threat,
        given={"asset_category": context.asset.get("category_code"), "system_categories": system_types},
        produced={"allowed": ", ".join(sorted(allowed)), "query_chars": query_chars, "shortlist": shortlist},
    )


def _trace_rerank_and_cutoff(
    threat: str | None,
    ordered: list[tuple[LibraryControl, float]],
    cutoff: float,
    exact: int,
    items: list[MappedControl],
    twins: list[str],
) -> None:
    labelled = ((f"{control.code} {control.name}", score) for control, score in ordered)
    record_detail("rerank", threat, given={"candidates": len(ordered)}, produced=ranked(labelled))
    produced = {
        "exact": exact,
        "match": str(ControlMatch.EXACT if exact else ControlMatch.NEAREST),
        "kept": ", ".join(item.code for item in items),
        "skipped_twins": ", ".join(twins) or "none",
    }
    record_detail("cut-off", threat, given={"threshold": cutoff}, produced=produced)


def controls_record(mapping: ControlMapping, snapshot: LibrarySnapshot) -> dict[str, Any]:
    """What the scenario keeps of its mapping, whoever mapped it (the controls job or a plan request's
    top-up): the controls, the warning, what was searched and with what: traceable to the
    query, the models and the library version)."""
    settings = get_settings()
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.CONTROL]
    stamp = {
        name: digest.hex() if digest else None for name, digest in snapshot.library.stamp if name == table
    }
    return {
        "items": [item.to_record() for item in mapping.items],
        "warning": mapping.warning,
        "query": mapping.query,
        "made_with": {
            "rerank_model": settings.rerank_model,
            "embedding_model": settings.embedding_model,
            "library": stamp,
            "threshold": settings.control_similarity_threshold,  # what "exact" meant for this mapping
        },
    }
