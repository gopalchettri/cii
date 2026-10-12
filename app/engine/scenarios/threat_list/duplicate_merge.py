"""One threat per threat (v1 threat_identification/paths.merge and dedupe):

a. the same key found under several categories is ONE threat, its categories and systems united;
b. an AI threat named like a library threat OF THE SAME TYPE is that library threat (the library record is
   canonical); named alike but of another type, both are kept and noted (a canonical type is never
   overwritten);
c. an AI threat whose meaning vector is at least AI_DUPLICATE_COSINE close to a library threat or to an AI
   threat kept before it, of the same type, is a rewording of it, the first one wins. Library threats are
   never folded this way: the curator vouched for them being different.
Every fold is returned, never silent. The AI same-attack check (d) is same_attack_check.py."""

import dataclasses

import numpy as np

from app.ai import EmbeddingModel
from app.core.constants import FoldReason, PlanMessage, ThreatFinding
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.shared.names import name_match_key, remove_asset_name, threat_name_without_code
from app.models.threats import FoldedThreat, PlannedThreat, in_stride_order


def merge_two_threats(kept: PlannedThreat, other: PlannedThreat) -> PlannedThreat:
    """One threat for both: every category and system of either, the higher impact and confidence, and ONE
    reason, the kept one's. A different threat folded in never moves the kept one's primary category (a
    category/record pairing the library never made); its categories join as contributing ones."""
    union = set(kept.categories) | set(other.categories)
    lead = (kept.categories[0],) if kept.key != other.key else ()
    return dataclasses.replace(
        kept,
        categories=(*lead, *in_stride_order(union - set(lead))),
        systems=tuple(sorted(set(kept.systems) | set(other.systems))),
        impact=max(kept.impact, other.impact),
        confidence=max(kept.confidence, other.confidence),
    )


def _name_key(name: str) -> str:
    """What a name match compares: a library name keeps its code ("AML.T0036 Data from ..."), an AI one has
    none."""
    return name_match_key(threat_name_without_code(name))


@traced("threats.merge")
def merge_same_threats(
    threats: list[PlannedThreat],
) -> tuple[list[PlannedThreat], list[FoldedThreat], list[str]]:
    """Rules a and b: (the threats in key order, the folds, a note for each same name of another type)."""
    by_key: dict[str, PlannedThreat] = {}
    for threat in threats:
        seen = by_key.get(threat.key)
        by_key[threat.key] = threat if seen is None else merge_two_threats(seen, threat)
    library_names = {_name_key(t.name): t for t in by_key.values() if t.from_library}
    folded: list[FoldedThreat] = []
    notes: list[str] = []
    for threat in sorted(by_key.values(), key=lambda t: t.key):
        twin = None if threat.from_library else library_names.get(_name_key(threat.name))
        if twin is None:
            continue
        if twin.type_id != threat.type_id:
            notes.append(_type_conflict_note(threat, twin))
            continue
        by_key[twin.key] = merge_two_threats(by_key[twin.key], threat)
        folded.append(FoldedThreat(threat, twin.key, FoldReason.SAME_NAME))
    gone = {fold.threat.key for fold in folded}
    if step_detail_enabled():
        _trace_same_threats(len(threats) - len(by_key), folded, by_key, len(notes))
    return [by_key[key] for key in sorted(by_key) if key not in gone], folded, notes


def _trace_same_threats(
    key_merges: int, folded: list[FoldedThreat], by_key: dict[str, PlannedThreat], kept_apart: int
) -> None:
    """Rules a and b: how many same-key finds were united, which AI threats became a library one."""
    same_name = " | ".join(f"{fold.threat.name} -> {by_key[fold.kept_key].name}" for fold in folded)
    record_detail(
        "same key / same name",
        given={"threats": key_merges + len(by_key)},
        produced={"key_merges": key_merges, "same_name_folds": same_name or "none", "kept_apart": kept_apart},
    )


def _type_conflict_note(ai_threat: PlannedThreat, library_twin: PlannedThreat) -> str:
    return PlanMessage.TYPE_CONFLICT_KEPT_APART.format(
        threat=threat_name_without_code(ai_threat.name),
        threat_type=ai_threat.type_name,
        library_threat=threat_name_without_code(library_twin.name),
        library_type=library_twin.type_name,
    )


@traced("threats.fold_rewordings")
def merge_reworded_threats(
    threats: list[PlannedThreat], embeddings: EmbeddingModel, asset_name: str
) -> tuple[list[PlannedThreat], list[FoldedThreat]]:
    """Rule c, with one embedding call for every name. Names are compared with the asset's name taken out:
    every name may end in "... of <asset>", which says "same asset", not "same threat"."""
    ai_threats = [threat for threat in threats if not threat.from_library]
    if not ai_threats:
        return threats, []
    labels = {
        t.key: remove_asset_name(threat_name_without_code(t.name), asset_name) or t.name for t in threats
    }
    texts = list(dict.fromkeys(labels.values()))
    vectors = dict(zip(texts, embeddings.embed_search_queries(texts), strict=True))
    by_key = {threat.key: threat for threat in threats}
    compared = [t.key for t in threats if t.from_library]  # library threats, then each AI threat kept
    folded: list[FoldedThreat] = []
    closest: dict[str, str] = {}  # the step trace's best cosine per AI threat (DEBUG_STEP_DETAIL only)
    for threat in ai_threats:  # in order: a twin is always earlier, so already final
        same_type = [key for key in compared if by_key[key].type_id == threat.type_id]  # G109
        if step_detail_enabled():
            closest[threat.name] = _closest_for_trace(vectors, labels, threat, same_type, by_key)
        twin, score = _closest_kept(
            vectors[labels[threat.key]], [(key, vectors[labels[key]]) for key in same_type]
        )
        if twin is None:
            compared.append(threat.key)
            continue
        del by_key[threat.key]
        by_key[twin] = merge_two_threats(by_key[twin], threat)
        folded.append(FoldedThreat(threat, twin, FoldReason.SAME_WORDING, score=score))
    if closest:
        record_detail("rewording cosine", given={"ai_threats": len(ai_threats)}, produced=closest)
    return [by_key[t.key] for t in threats if t.key in by_key], folded


def _closest_for_trace(
    vectors: dict[str, np.ndarray],
    labels: dict[str, str],
    threat: PlannedThreat,
    same_type: list[str],
    by_key: dict[str, PlannedThreat],
) -> str:
    """The kept threat of the same type closest in meaning, as "<name> <cosine>"; "none" without one."""
    vector = vectors[labels[threat.key]]
    scored = [(float(vector @ vectors[labels[key]]), key) for key in same_type]
    if not scored:
        return "none"
    cosine, key = max(scored, key=lambda pair: pair[0])
    return f"{by_key[key].name} {cosine:.4f}"


def _closest_kept(vector: np.ndarray, kept: list[tuple[str, np.ndarray]]) -> tuple[str | None, float | None]:
    """The first kept threat at least AI_DUPLICATE_COSINE close, with its cosine (vectors are normalised)."""
    for key, other in kept:
        score = float(vector @ other)
        if score >= ThreatFinding.AI_DUPLICATE_COSINE:
            return key, score
    return None, None
