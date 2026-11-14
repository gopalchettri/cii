"""Whether a vulnerability or an advisory concerns the asset, by its recorded vendors and products."""

import re
from collections.abc import Iterable
from typing import Any

from app.core.constants import Applicability, EvidenceReason
from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.evidence_request import RecordedProducts

_WORD = re.compile(r"[a-z0-9]+")
#: Words that name no vendor or product on their own ("Acme Inc", "Foo Server Software").
_GENERIC = frozenset(
    {"a", "an", "and", "the", "of", "for", "inc", "llc", "ltd", "corp", "corporation", "co", "company"}
    | {"group", "system", "systems", "software", "server", "servers", "product", "products", "service"}
    | {"services", "solutions", "technology", "technologies"}
)
Words = frozenset[str]
Verdict = tuple[Applicability, str]


def _name_words(values: Iterable[str]) -> Words:
    """The lower-case words of these names, generic words left out."""
    found: set[str] = set()
    for text in values:
        found.update(_WORD.findall(text.casefold()))
    return frozenset(found - _GENERIC)


def _entry_words(entry: dict[str, Any]) -> tuple[Words, Words]:
    """The vendor words and the product words of one affected entry."""
    return _name_words([str(entry.get("vendor") or "")]), _name_words([str(entry.get("product") or "")])


def _vendor_and_product(record: dict[str, Any]) -> dict[str, str]:
    """The entry's vendor and product as written, to fill in a reason."""
    return {"vendor": str(record.get("vendor") or ""), "product": str(record.get("product") or "")}


def _entries_to_compare(hit: IntelHit) -> list[dict[str, Any]]:
    """The record's `affected` entries, or the record itself (its vendor and product) when it states none."""
    affected = hit.data.get("affected")
    entries = [entry for entry in affected if isinstance(entry, dict)] if isinstance(affected, list) else []
    return entries or [hit.data]


class ProductLinkChecker:
    """Compares product records with one request's recorded products; made per request, nothing shared."""

    def __init__(self, recorded: RecordedProducts) -> None:
        self._vendors: Words = _name_words(text for row in recorded.rows for text in row.vendors)
        self._products: Words = _name_words(text for row in recorded.rows for text in row.products)

    def has_no_link(self, hit: IntelHit) -> bool:
        """True when nothing ties a product-specific record to the asset: the asset records no vendor or
        product at all, or the record names no vendor or product to compare."""
        named: Words = frozenset().union(
            *(_entry_words(entry)[0] | _entry_words(entry)[1] for entry in _entries_to_compare(hit))
        )
        return not (self._vendors | self._products) or not named

    def judge(self, hit: IntelHit) -> Verdict:
        """NOT_APPLICABLE with the reason when no affected vendor or product is the asset's, else UNKNOWN."""
        relations = [(entry, self._relation(*_entry_words(entry))) for entry in _entries_to_compare(hit)]
        if all(why is not None for _, why in relations):  # no affected vendor / product is the asset's
            entry, why = relations[0]
            reason = (why or EvidenceReason.DIFFERENT_PRODUCT).format(**_vendor_and_product(entry))
            return Applicability.NOT_APPLICABLE, reason
        return Applicability.UNKNOWN, ""

    def _relation(self, vendor: Words, product: Words) -> EvidenceReason | None:
        """Why a record's vendor and product are NOT the asset's, or None when they may be."""
        known = self._vendors | self._products
        if not known or not (vendor | product):  # nothing recorded, or the record names nothing
            return None
        vendor_seen, product_seen = bool(vendor & known), bool(product & known)
        if not vendor_seen and not product_seen:  # neither named: the asset runs something else
            return EvidenceReason.DIFFERENT_PRODUCT
        if vendor_seen and product and not product_seen and self._products:  # the maker, its other product
            return EvidenceReason.OTHER_PRODUCT_OF_VENDOR
        return None
