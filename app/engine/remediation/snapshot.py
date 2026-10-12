"""A plan version's frozen input (BLUEPRINT M11 R4, BUILD_PLAN S48; v1 treatment_input.py): the scenario
half (the asset, its systems, the threat, the scenario, its mapped controls with their library details)
joined to the register half (app/engine/remediation/register.py) in one fixed key order. Whether the
register already covers a mapped control is decided here, in code; the AI only judges the register's free
text. Every free text passes the one door (`clip`). Pure, no IO: the library is in memory."""

from collections.abc import Mapping
from typing import Any

from app.core.constants import ControlMatch, Remediation, SnapshotWarning
from app.engine.remediation.register import clip
from app.engine.scenarios.finding.asset_landscape import raw_system_facts
from app.engine.shared.names import name_match_key
from app.engine.shared.prompt_redaction import facts_safe_for_prompt
from app.models.asset_context import FrozenContext
from app.models.library import LibraryControl
from app.search.texts import describe_control


def build_snapshot(
    scenario: dict[str, Any],
    context: FrozenContext,
    register_part: dict[str, Any],
    controls_by_id: Mapping[int, LibraryControl],
) -> dict[str, Any]:
    """The snapshot; its keys and their order are part of the stored record (a regenerate and the AI read
    it)."""
    content = scenario.get("content") or {}
    mapped, retired = _library_mapped(scenario, controls_by_id)
    covered = _register_covers(register_part["register_controls"], controls_by_id)
    library_mapped = [{**item, "covered_by_register": twin in covered} for item, twin in mapped]
    return {
        "asset": clip(context.asset["name"]),
        "asset_context": _capped(facts_safe_for_prompt(context.asset_context)),
        "supporting_systems": [
            _capped(facts_safe_for_prompt(raw_system_facts(system))) for system in context.systems
        ],
        "threat": _threat(content),
        "scenario": _scenario(content),
        "existing_controls": {
            "library_mapped": library_mapped,
            "library_mapped_count": len(library_mapped),
            "register_controls": register_part["register_controls"],
            "register_matched_count": sum(item["covered_by_register"] for item in library_mapped),
            "applied_to_all_subsystems": register_part["applied_to_all_subsystems"],
            "applied_to_all_subsystems_justification": register_part[
                "applied_to_all_subsystems_justification"
            ],
        },
        "risk_assessment": register_part["risk_assessment"],
        "treatment_strategy": Remediation.STRATEGY,
        "register": register_part["register"],
        "warnings": register_part["warnings"] + retired,
    }


def _threat(content: dict[str, Any]) -> dict[str, Any]:
    threat = content.get("threat") or {}
    return {
        "category": clip(content.get("category")),
        "type": clip(threat.get("type")),
        "name": clip(threat.get("name")),
        "actors": [
            {"name": clip(actor.get("name")), "role": actor.get("role")}
            for actor in content.get("actors") or []
        ],
    }


def _scenario(content: dict[str, Any]) -> dict[str, Any]:
    """The scenario as written, with ITS systems: the AI judges `applicable_to_all_subsystems` against
    them, not against every system of the run."""
    return {
        "title": clip(content.get("title")),
        "statement": clip(content.get("statement")),
        "risk_statement": clip(content.get("risk_statement")),
        "supporting_systems_involved": [
            {"supporting_system": clip(system.get("name")), "is_entry_point": bool(system.get("entry_point"))}
            for system in content.get("systems") or []
        ],
        "route_status": (content.get("route") or {}).get("status"),
    }


def _library_mapped(
    scenario: dict[str, Any], controls_by_id: Mapping[int, LibraryControl]
) -> tuple[list[tuple[dict[str, Any], str]], list[str]]:
    """The scenario's mapped controls with their library details, best rank first, each with its twin key; one
    retired since mapping is left out with a warning (its row is no longer active)."""
    kept, retired = [], []
    for item in (scenario.get("controls") or {}).get("items") or []:
        row = controls_by_id.get(item["control_id"])
        if row is None:
            retired.append(SnapshotWarning.CONTROL_RETIRED.format(code=item.get("code")))
            continue
        shown = {
            "control_id": row.control_id,
            "control_code": row.code,
            "asset_type": row.asset_type,
            "domain": row.domain,
            "control_name": row.name,
            "control_description": clip(row.description),
            "mapping_relevance": None if item.get("score") is None else round(item["score"]),
            # A control the person named for a hand-written scenario met their own bar: the AI reads it as an
            # exact match (the approved prompt knows exact and nearest only).
            "match": ControlMatch.EXACT if item.get("match") == ControlMatch.GIVEN else item.get("match"),
        }
        kept.append((shown, _twin_key(row)))
    return kept, retired


def _register_covers(register_controls: list[Any], controls_by_id: Mapping[int, LibraryControl]) -> set[str]:
    """The controls the register names, as twin keys: an IT and an OT copy of one control (the same text)
    are one control, so naming either covers both (the control mapping folds twins the same way)."""
    covered = set()
    for entry in register_controls:
        row = controls_by_id.get(entry["control_id"]) if isinstance(entry, dict) else None
        if row is not None:
            covered.add(_twin_key(row))
    return covered


def _twin_key(row: LibraryControl) -> str:
    return name_match_key(describe_control(row))


def _capped(value: Any) -> Any:
    """Every text inside a facts block through the one door's cut (facts_safe_for_prompt already redacted
    it)."""
    if isinstance(value, str):
        return clip(value)
    if isinstance(value, dict):
        return {key: _capped(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_capped(inner) for inner in value]
    return value
