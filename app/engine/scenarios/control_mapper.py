"""A written scenario's controls: only library controls
compatible with its asset and systems, found by meaning from its scenario AND risk statements, scored by the
reranker, never written by an AI."""

from dataclasses import replace
from typing import Any

from app.ai import RerankModel
from app.core.config import get_settings
from app.core.constants import (
    CONTROL_TIERS,
    EMBEDDING_SOURCE_TABLE,
    EmbeddingCorpus,
    ErrorCode,
    ErrorMessage,
)
from app.core.exceptions import ControlsNotMapped
from app.core.tracing import ranked, record_detail, step_detail_enabled, traced
from app.engine.scenarios.control_query import control_query
from app.engine.scenarios.control_selection import control_rule, select_controls
from app.models.asset_context import FrozenContext
from app.models.controls import ControlMapping, ControlRule
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
        """Every compatible control at or above CONTROL_SIMILARITY_THRESHOLD, best first, at most
        MAX_CONTROLS; else the nearest up to MIN_CONTROLS, with a warning (never zero, G227).
        ControlsNotMapped when the library is empty or no control fits the asset type; an outage is raised."""
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
        rule = control_rule()  # CONTROL_CANDIDATES, the threshold, MIN/MAX_CONTROLS (G225, G227)
        query = control_query(content, context, systems)
        (found,) = snapshot.find_controls([query.text], rule.candidates, allowed)
        threat = (content.get("threat") or {}).get("name")
        if step_detail_enabled():
            _trace_shortlist(threat, context, systems, allowed, len(query.text), len(found))
        if not found:  # no control fits: never one of another type in its place
            types = ", ".join(sorted(allowed)) or "none recorded"
            message = ErrorMessage.NO_COMPATIBLE_CONTROL.format(types=types)
            raise ControlsNotMapped(ErrorCode.NO_COMPATIBLE_CONTROL, message)
        candidates = [control for control, _ in found]
        scores = self._rerank.score_relevance(
            query.text, [describe_control(control) for control in candidates]
        )
        scored = list(zip(candidates, scores, strict=True))
        mapping, twins = select_controls(scored, rule, query.text)
        if step_detail_enabled():
            _trace_rerank_and_cutoff(threat, scored, rule, mapping, twins)
        return replace(mapping, query_shortened=query.shortened)


def _scenario_systems(content: dict[str, Any], context: FrozenContext) -> list[dict[str, Any]]:
    """The scenario's own systems, as the run froze them (their type and technology)."""
    ids = {system["id"] for system in content.get("systems") or []}
    return [system for system in context.systems if system["id"] in ids]


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
    scored: list[tuple[LibraryControl, float]],
    rule: ControlRule,
    mapping: ControlMapping,
    twins: list[str],
) -> None:
    labelled = ((f"{control.code} {control.name}", score) for control, score in scored)
    record_detail("rerank", threat, given={"candidates": len(scored)}, produced=ranked(labelled))
    produced = {
        "kept": ", ".join(f"{item.code} ({CONTROL_TIERS[item.match]})" for item in mapping.items),
        "left_out_over_max": mapping.left_out,
        "shortfall": mapping.shortfall or "none",
        "skipped_twins": ", ".join(twins) or "none",
    }
    given = {"threshold": rule.cutoff, "candidates": rule.candidates, "min": rule.least, "max": rule.most}
    record_detail("cut-off", threat, given=given, produced=produced)


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
        "shortfall": mapping.shortfall,  # fewer than MIN_CONTROLS kept, and why (G225)
        "left_out_over_max": mapping.left_out,  # strong controls MAX_CONTROLS did not keep
        "query": mapping.query,
        "made_with": {
            "rerank_model": settings.rerank_model,
            "embedding_model": settings.embedding_model,
            "library": stamp,
            "threshold": settings.control_similarity_threshold,  # what "strong" meant for this mapping
            "candidates": settings.control_candidates,
            "min_controls": settings.min_controls,
            "max_controls": settings.max_controls,
            "query_shortened": list(mapping.query_shortened),  # labels only (G227)
        },
    }
