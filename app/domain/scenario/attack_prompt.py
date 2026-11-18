"""The prompt of a run the AI writes from its MITRE ATT&CK knowledge, built per request from the facts it has."""

from collections.abc import Collection, Sequence
from typing import Any, Final

from app.core import constants as c
from app.core.asset_types import asset_type_label, compatible_asset_types
from app.core.config import get_settings
from app.core.prompts import PROMPTS
from app.domain.scenario import write
from app.domain.shared.ask_ai import ChatPrompt
from app.domain.shared.names import as_json, name_match_key
from app.domain.shared.prompt_redaction import drop_database_ids
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import FrozenContext

_PROMPT: Final[dict[str, Any]] = PROMPTS["scenario"]["attack"]
_LISTED: Final = "<listed>"  # in a piece's text: the phrases of the inputs the request has
_MIXED: Final = "mixed"  # the prompt's side when more than one ATT&CK source fits
_SOURCE_OF_TYPE: Final = {c.AssetType.IT: c.IntelSource.ATTACK_ENTERPRISE, c.AssetType.OT: c.IntelSource.ATTACK_ICS}


def find_attack_sources_of_asset(context: FrozenContext) -> frozenset[str]:
    """The ATT&CK sources that fit the asset and its systems: Enterprise for IT, ICS for OT, both when unknown."""
    types = compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in context.systems)
    )
    fitting = frozenset(source.value for kind, source in _SOURCE_OF_TYPE.items() if kind in types)
    return fitting or frozenset(source.value for source in _SOURCE_OF_TYPE.values())


def list_threat_choices(library: ThreatLibrary) -> tuple[list[c.StrideCategory], list[tuple[int, str]]]:
    """The STRIDE categories and the threat types (id, name) a prompt lists and an answer may copy."""
    live = {name_match_key(name) for _, name in library.category_ids}
    categories = [kind for kind in c.STRIDE_DEFINITIONS if not live or name_match_key(kind) in live]
    types = [(kind.type_id, kind.name) for kind in library.types]
    types = types or [(threat.type_id, threat.type_name) for threat in library.threats]
    named: dict[str, tuple[int, str]] = {}
    for type_id, name in types:
        named.setdefault(name, (type_id, name))
    return categories, list(named.values())


def build_attack_facts(context: FrozenContext, room: int) -> dict[str, Any]:
    """The service, the asset and each system with every recorded fact, redacted, within `room` characters."""
    asset, systems = write.shorten_facts_to_fit(context, context.systems, False, room)  # the writer's own facts
    service = asset.pop("critical_service", None)
    kind = asset_type_label(context.asset.get("category_code"))
    if kind and asset_type_label(str(asset.get("type") or "")) == kind:  # the platform's own type says the same
        del asset["type"]
    named = {"name": asset.pop("name")} | ({"asset_type": kind.value} if kind else {})
    facts = {"service": service, "asset": named | asset, "supporting_systems": systems}
    return {part: value for part, value in facts.items() if value}


def build_attack_prompt(
    context: FrozenContext,
    slots: Sequence[dict[str, Any]],
    titles_used: Sequence[str],
    list_other_risks: bool,
    library: ThreatLibrary,
    room: int,
) -> ChatPrompt:
    """One call's (system, user) prompt, naming only what this request has, the facts within `room` characters."""
    facts = build_attack_facts(context, room)
    categories, types = list_threat_choices(library)
    asked: dict[str, Any] = {
        "threat_categories": {str(kind): c.STRIDE_DEFINITIONS[kind] for kind in categories},
        "threat_types": [name for _, name in types],
        "titles_used": list(titles_used),
        "slots": drop_database_ids(slots),
    }
    lines = [f"{name.upper()}: {as_json(value)}" for name, value in (facts | asked).items()]
    lines.insert(-1, _PROMPT["list_other_risks"][list_other_risks])
    return _build_system_prompt(context, facts, slots), "\n".join(lines)


def _build_system_prompt(context: FrozenContext, facts: dict[str, Any], slots: Sequence[dict[str, Any]]) -> str:
    asset = facts["asset"]
    present = {*facts, *asset, *(f"slot_{key}" for slot in slots for key in slot)}
    sides = find_attack_sources_of_asset(context)
    side = _PROMPT["sides"][next(iter(sides)) if len(sides) == 1 else _MIXED]
    settings = get_settings()
    filled = {
        **{f"<{name}>": _fill_piece(piece, present, asset) for name, piece in _PROMPT["pieces"].items()},
        **{f"<{name}>": text for name, text in side.items()},
        c.Writing.SCENARIO_WORDS_SLOT: "{} to {}".format(*settings.scenario_words),
        c.Writing.RISK_WORDS_SLOT: "{} to {}".format(*settings.risk_words),
    }
    prompt: str = _PROMPT["text"]
    for slot, text in filled.items():
        prompt = prompt.replace(slot, text)
    return prompt


def _fill_piece(piece: dict[str, Any], present: Collection[str], asset: dict[str, Any]) -> str:
    phrases = [phrase for name, phrase in piece["phrases"].items() if name in present]
    if piece.get("names_other_facts"):
        phrases += [name.replace("_", " ").title() for name in asset if name not in piece["phrases"]]
    if not phrases:
        return ""
    *first, last = phrases
    separator: str = _PROMPT["separator"]
    listed = separator.join(first) + piece.get("last", separator) + last if first else last
    return str(piece["text"]).replace(_LISTED, listed)
