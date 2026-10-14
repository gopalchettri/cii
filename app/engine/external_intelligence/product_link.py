"""Does a known-exploited vulnerability or an advisory concern the asset? Unknown stays unknown.

With the record's `affected` list ({vendor, product, versions, fixed}) the asset's vendor, product and version
are compared with it: no overlap with any entry is NOT_APPLICABLE (left out, with the reason); an overlap with
no usable asset version is UNKNOWN; CONFIRMED needs the asset's product to be named in full, ONE recorded
version beside it, and that version inside an affected range and not at or after a fix; a version outside
every range is NOT_APPLICABLE. A record with no `affected` list is compared by vendor and product alone
(never CONFIRMED). A technique has no applicability. One checker is made per request: it holds that request's
recorded products and nothing is shared."""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from app.core.constants import Applicability, EvidenceReason
from app.engine.external_intelligence.version_match import affected_state
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


def _words(values: Iterable[str]) -> Words:
    found: set[str] = set()
    for text in values:
        found.update(_WORD.findall(text.casefold()))
    return frozenset(found - _GENERIC)


def _entry_words(entry: dict[str, Any]) -> tuple[Words, Words]:
    return _words([str(entry.get("vendor") or "")]), _words([str(entry.get("product") or "")])


def _names(record: dict[str, Any]) -> dict[str, str]:
    return {"vendor": str(record.get("vendor") or ""), "product": str(record.get("product") or "")}


@dataclass(frozen=True)
class _Row:
    """What one record of the asset (the asset itself, or a system) says about its products."""

    vendors: Words
    products: Words
    version: str | None

    @property
    def named(self) -> Words:
        return self.vendors | self.products


def _version_of(versions: Iterable[str]) -> str | None:
    """The row's one recorded version; None when it records none, or more than one different one."""
    found = {text.strip() for text in versions}
    found.discard("")
    return found.pop() if len(found) == 1 else None


def _affected_entries(hit: IntelHit) -> list[dict[str, Any]]:
    affected = hit.data.get("affected")
    return [entry for entry in affected if isinstance(entry, dict)] if isinstance(affected, list) else []


def _entries(hit: IntelHit) -> list[dict[str, Any]]:
    return _affected_entries(hit) or [hit.data]


class ProductLinkChecker:
    def __init__(self, recorded: RecordedProducts) -> None:
        self._rows = tuple(
            _Row(_words(row.vendors), _words(row.products), _version_of(row.versions))
            for row in recorded.rows
        )
        self._vendors: Words = frozenset().union(*(row.vendors for row in self._rows))
        self._products: Words = frozenset().union(*(row.products for row in self._rows))

    def has_no_link(self, hit: IntelHit) -> bool:
        """True when nothing ties a product-specific record to the asset: the asset records no vendor or
        product at all, or the record names no vendor or product to compare."""
        named: Words = frozenset().union(
            *(_entry_words(entry)[0] | _entry_words(entry)[1] for entry in _entries(hit))
        )
        return not (self._vendors | self._products) or not named

    def judge(self, hit: IntelHit) -> Verdict:
        """The applicability of a vulnerability or advisory hit and, when NOT_APPLICABLE, the reason."""
        affected = _affected_entries(hit)
        relations = [(entry, self._relation(*_entry_words(entry))) for entry in _entries(hit)]
        same = [entry for entry, why in relations if why is None]
        if not same:  # no affected vendor / product is one the asset records
            entry, why = relations[0]
            reason = (why or EvidenceReason.DIFFERENT_PRODUCT).format(**_names(entry))
            return Applicability.NOT_APPLICABLE, reason
        return self._by_version(same) if affected else (Applicability.UNKNOWN, "")

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

    def _by_version(self, entries: list[dict[str, Any]]) -> Verdict:
        found = list(self._states(entries))
        if any(state is True for state in found):
            return Applicability.CONFIRMED, ""
        if found and all(state is False for state in found):
            reason = EvidenceReason.VERSION_NOT_AFFECTED.format(**_names(entries[0]))
            return Applicability.NOT_APPLICABLE, reason
        return Applicability.UNKNOWN, ""

    def _states(self, entries: list[dict[str, Any]]) -> Iterator[bool | None]:
        """For every (entry, row) that share a word: True affected, False not, None not known."""
        for entry in entries:
            vendor, product = _entry_words(entry)
            for row in self._rows:
                if not (vendor | product) & row.named:
                    continue
                # the whole product name must be there (not one shared word like "windows"), and the maker
                strong = bool(product) and product <= row.named and (not vendor or bool(vendor & row.named))
                yield affected_state(row.version, entry) if strong and row.version else None
