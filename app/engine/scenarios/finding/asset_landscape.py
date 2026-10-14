"""What threat finding reads (v1 threat_identification/landscape.py, BLUEPRINT M10 T1-T2): the landscape,
the asset and every supporting system as one text held to its budget, and each category's search queries."""

import json
import re
from typing import Any

from app.core.constants import (
    STRIDE_DEFINITIONS,
    ContextProperties,
    ErrorCode,
    PlanMessage,
    Search,
    StrideCategory,
    ThreatFinding,
)
from app.core.exceptions import PlanRefused
from app.core.tracing import traced
from app.engine.shared.names import quoted_for_prompt, shorten_text
from app.engine.shared.prompt_redaction import facts_safe_for_prompt, redact
from app.models.asset_context import FrozenContext
from app.models.threats import Landscape

#: The asset facts every threat-finding step weighs; they lead the asset's text, so a long description is what
#: gets clipped, never them.
_SECTOR_KEYS = ("sector", "sub_sector", "critical_service")
_LEAD_KEYS = (*_SECTOR_KEYS, "asset_priority")
#: A frozen system's keys that are not facts (core/constants/context_properties.py); every other key is one,
#: in the procedure's column order, so a column added to tsg_GetAssetContext is shown with no code change.
_NOT_SYSTEM_FACTS = frozenset(ContextProperties.ALWAYS_USED)
#: A date as the context stores it (ISO, from any date column the procedure returns): not words to search by.
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(T[0-9:.+\-Z]*)?")


def raw_system_facts(system: dict[str, Any]) -> dict[str, Any]:
    """A system's recorded facts as the run froze them, its category shown as its asset type, NOT yet safe for
    an AI: every caller passes them through facts_safe_for_prompt (secrets, personal data, placeholders and
    database ids out)."""
    return {
        "name": system["name"],
        **{
            "asset_type" if key == "category_name" else key: value
            for key, value in system.items()
            if key not in _NOT_SYSTEM_FACTS
        },
    }


def _joined_text(values: list[Any]) -> str:
    words = []
    for value in values:
        for item in value if isinstance(value, list | tuple) else [value]:
            text = str(item).strip() if item is not None else ""
            if text:
                words.append(text)
    return " ".join(words)


def sector_text(asset_context: dict[str, Any]) -> str:
    """The asset's sector, sub-sector and critical service as one line ('' when none is set)."""
    return _joined_text([asset_context.get(key) for key in _SECTOR_KEYS])


def _asset_part(context: FrozenContext, budget: int, country: str) -> str:
    """The asset, its lead facts first, then the organisation's own facts on a line of their own (never read
    as this asset's: G208), in at most max(budget // 4, ASSET_SHARE_MIN_CHARS) characters; a long part is cut
    from its end, the organisation's line first."""
    own_facts, organisation_facts = context.own_and_organisation_facts()
    lead = {key: own_facts[key] for key in _LEAD_KEYS if key in own_facts}
    own, organisation = (
        facts_safe_for_prompt({**lead, **own_facts}),
        facts_safe_for_prompt(organisation_facts),
    )
    where = {ContextProperties.COUNTRY_KEY: country} if country else {}  # G232: intelligence on only
    described = {
        "asset": redact(context.asset["name"]),
        **where,
        "asset_context": own,
        "supporting_systems": [],
    }
    text = json.dumps(described, ensure_ascii=False, default=str)
    if organisation:
        line = ThreatFinding.ORGANISATION_LABEL + json.dumps(organisation, ensure_ascii=False, default=str)
        text = f"{text}\n{line}"
    limit = max(budget // 4, ThreatFinding.ASSET_SHARE_MIN_CHARS)
    return "ASSET: " + shorten_text(text, limit)


def _system_heads_and_facts(systems: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Each system's head (its alias and quoted name) and its recorded facts as JSON, cleaned for a prompt."""
    heads = [
        f"{s['alias']} {quoted_for_prompt(shorten_text(s['name'], ThreatFinding.SYSTEM_NAME_CHARS))}: "
        for s in systems
    ]
    facts = [
        json.dumps(facts_safe_for_prompt(raw_system_facts(s)), ensure_ascii=False, default=str)
        for s in systems
    ]
    return heads, facts


@traced("threats.build_landscape")
def describe_asset_for_ai(context: FrozenContext, budget: int, country: str = "") -> Landscape:
    """The landscape within `budget` characters: every system keeps its alias and quoted name, and their
    recorded facts share what the asset leaves equally, so no system is clipped away by another's long text.
    Raises PlanRefused when facts had to be shortened below MIN_SYSTEM_FACT_CHARS each: a system judged by its
    name alone is never planned in silence."""
    systems = context.systems
    asset_part = _asset_part(context, budget, country)
    heads, facts = _system_heads_and_facts(systems)
    share = (budget - len(asset_part) - sum(len(head) + 1 for head in heads)) // max(len(systems), 1)
    too_long = [len(text) for text in facts if len(text) > share]
    if too_long and share < ThreatFinding.MIN_SYSTEM_FACT_CHARS:
        message = PlanMessage.SYSTEMS_DO_NOT_FIT.format(
            systems=len(systems),
            share=max(share, 0),
            budget=budget,
            minimum=ThreatFinding.MIN_SYSTEM_FACT_CHARS,
        )
        raise PlanRefused(ErrorCode.PLAN_REFUSED, message)
    note = (
        PlanMessage.FACTS_SHORTENED.format(
            clipped=len(too_long), systems=len(systems), share=share, longest=max(too_long)
        )
        if too_long
        else None
    )
    text = "\n".join(
        [asset_part] + [head + shorten_text(fact, share) for head, fact in zip(heads, facts, strict=True)]
    )
    return Landscape(
        text=text,
        facts_shortened_note=note,
        system_ids={s["alias"]: s["id"] for s in systems},
        system_names={s["alias"]: s["name"] for s in systems},
        sector=sector_text(context.asset_context),
    )


def _search_text(facts: dict[str, Any]) -> str:
    """The words of a part's text facts (strings and lists of strings): no numbers, yes/no flags or dates."""
    return _joined_text(
        [
            value
            for value in facts.values()
            if (isinstance(value, str) and not _ISO_DATE.fullmatch(value))
            or (isinstance(value, list) and all(isinstance(v, str) for v in value))
        ]
    )


@traced("threats.search_queries")
def library_search_queries(context: FrozenContext, category: StrideCategory) -> list[str]:
    """One library search query per supporting system plus one for the asset (its name and its OWN text facts,
    never the organisation's: G208), each led by the category, its definition and the asset's sector, so
    sector-typical threats rank higher (T2). Cleaned as every prompt is: a query goes to the embedding model,
    so no secret, personal data or placeholder rides in it."""
    head = " ".join(
        part
        for part in (f"{category}.", STRIDE_DEFINITIONS[category], sector_text(context.asset_context))
        if part
    )
    parts = [_search_text(facts_safe_for_prompt(raw_system_facts(system))) for system in context.systems]
    own_facts, _ = context.own_and_organisation_facts()
    parts.append(_search_text(facts_safe_for_prompt({"name": context.asset["name"], **own_facts})))
    return [shorten_text(f"{head} {text}", Search.QUERY_MAX_CHARS) for text in parts if text]
