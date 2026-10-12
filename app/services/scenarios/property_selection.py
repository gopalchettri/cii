"""Required asset and supporting-system facts (owner 2026-10-11; ASSET_/SYSTEM_PROPERTIES_REQUIRED): a run,
or a hand-written scenario, starts only when each is recorded for the asset and for every supporting system it
names. Which facts exist at all is dbo.tsg_GetAssetContext's columns (services/scenarios/context.py)."""

from typing import Any

from app.core.config import get_settings
from app.core.constants import ConflictReason, ContextProperties, PropertyMessage
from app.core.exceptions import Invalid, SetupError
from app.engine.shared.prompt_redaction import facts_safe_for_prompt
from app.models.scenarios import StartRunRequest

_ASSET_SETTING, _SYSTEM_SETTING = "ASSET_PROPERTIES_REQUIRED", "SYSTEM_PROPERTIES_REQUIRED"
#: Always required, whatever the settings say: every prompt, card and search names the asset and its systems.
_ALWAYS_REQUIRED = frozenset({"name"})


def check_required(
    request: StartRunRequest, asset_facts: dict[str, Any], systems: list[dict[str, Any]]
) -> None:
    """500 setup_error when a required name is no column of the procedure (every run would be refused); else
    422 required_facts_missing naming every required fact not recorded, all at once: the asset's, then each
    system's in request order, each in the procedure's column order. Recorded means what the AI would be
    shown: 0 and False are facts; None, a blank or placeholder ("N/A"), an empty list and an unanswered code
    are not. The refusal carries names and ids, never a value."""
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
        _refuse(gaps)


def _check_returned(setting: str, required: frozenset[str], facts: dict[str, Any]) -> None:
    if absent := sorted(required - facts.keys()):
        raise SetupError(PropertyMessage.NOT_RETURNED.format(setting=setting, names=", ".join(absent)))


def _not_recorded(facts: dict[str, Any], required: frozenset[str]) -> list[str]:
    """The required names, in the facts' order, whose value the AI would not be shown."""
    return [name for name in facts if name in required and not facts_safe_for_prompt({"fact": facts[name]})]


def _refuse(gaps: list[tuple[str, str, list[str]]]) -> None:
    errors = [
        {"field": field, "message": PropertyMessage.NOT_RECORDED.format(owner=owner, names=", ".join(names))}
        for field, owner, names in gaps
    ]
    detail = PropertyMessage.REQUIRED_MISSING.format(
        gaps="; ".join(f"{owner}: {', '.join(names)}" for _, owner, names in gaps)
    )
    raise Invalid(detail, reason=ConflictReason.REQUIRED_FACTS_MISSING, errors=errors)
