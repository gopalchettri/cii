"""A stored threat and the run's frozen context as the evidence engine's neutral request (the engine never
imports the planner or the asset context). The search text is the threat's type, name and reason ONLY,
redacted and cut from the end: the asset is not in it (it dilutes the match) and enters through the IT / OT
filter and the products it records."""

import dataclasses
from collections.abc import Iterable, Iterator
from typing import Any

from app.core.config import get_settings
from app.core.constants import ActorRole, EvidenceLimits, RecordedFields
from app.core.redaction import redact
from app.engine.external_intelligence.place_words import sectors_in
from app.engine.shared.names import shorten_text
from app.models.asset_context import FrozenContext
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    RecordedProduct,
    RecordedProducts,
)
from app.models.external_intelligence.known_groups import Nearness
from app.models.library import compatible_asset_types


def nearness_of(context: FrozenContext) -> Nearness:
    """What makes a real group near this asset (G232): the deployment's country and the asset's sectors."""
    facts = context.asset_context
    sector_facts = " ".join(str(facts.get(key) or "") for key in ("sector", "sub_sector", "critical_service"))
    return Nearness(get_settings().context_country, frozenset(sectors_in(sector_facts)))


class EvidenceRequestBuilder:
    def __init__(self, context: FrozenContext) -> None:
        self._context = context
        self._near = nearness_of(context)

    def build(self, threat: dict[str, Any]) -> EvidenceRequest:
        """The request for one stored threat of the plan."""
        systems = self._systems_of(threat)
        types = compatible_asset_types(
            self._context.asset.get("category_code"), (system.get("category_code") for system in systems)
        )
        rows = (self._context.asset_context, *systems)
        products = RecordedProducts(tuple(_recorded(row) for row in rows))
        acting = (
            a.get("name") or "" for a in threat.get("actors") or () if a.get("role") == ActorRole.ACTING
        )
        return EvidenceRequest(_query_of(threat), types, products, next(acting, ""), self._near)

    def alternative(self, threat: dict[str, Any], attempt: int) -> EvidenceRequest:
        """The same request in other words, for a threat whose search found nothing usable (G229): first the
        kind of attack, the threat and the technology its systems record; then a short keyword form. The
        filter and the recorded products are the same; no AI call."""
        request = self.build(threat)
        rows = (self._context.asset_context, *self._systems_of(threat))
        products = dict.fromkeys(text for row in rows for text in _recorded(row).products)
        technology = ", ".join(products) or "not recorded"
        asset_type = str(self._context.asset_context.get("asset_type") or "")
        kind, threat_type = threat.get("category") or "", threat["type"]["name"]
        forms = (
            f"Attack: {threat_type}: {threat['name']}\nKind of attack: {kind}\nTechnology: {technology}\n"
            f"Asset type: {asset_type}",
            f"{kind} {threat_type} {asset_type} {technology}",
        )
        text = shorten_text(redact(forms[min(attempt, len(forms) - 1)]), EvidenceLimits.QUERY_MAX_CHARS)
        return dataclasses.replace(request, text=text)

    def _systems_of(self, threat: dict[str, Any]) -> list[dict[str, Any]]:
        """The systems the threat concerns; every system of the run when none of them is known."""
        wanted = set(threat.get("systems") or ())
        own = [system for system in self._context.systems if system.get("id") in wanted]
        return own or list(self._context.systems)


def _query_of(threat: dict[str, Any]) -> str:
    parts = [f"Threat: {threat['type']['name']}: {threat['name']}", f"Reason: {threat['reason']}"]
    return shorten_text(redact("\n".join(parts)), EvidenceLimits.QUERY_MAX_CHARS)


def _recorded(row: dict[str, Any]) -> RecordedProduct:
    """What one record of the asset (the asset itself, or a system) says of its vendor, products and versions,
    as written: the engine reads each version only with the product recorded beside it."""

    def values(keys: Iterable[str]) -> tuple[str, ...]:
        return tuple(text for key in keys for text in _texts(row.get(key)))

    return RecordedProduct(
        values(RecordedFields.VENDOR_KEYS),
        values(RecordedFields.PRODUCT_KEYS),
        values(RecordedFields.VERSION_KEYS),
    )


def _texts(value: Any) -> Iterator[str]:
    for item in value if isinstance(value, list | tuple) else [value]:
        if item is not None and str(item).strip():
            yield str(item).strip()
