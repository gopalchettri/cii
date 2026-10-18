"""Whether a vulnerability or an advisory concerns the asset, by the vendors, products and versions it
records: confirmed, not applicable, or unknown, never a guess. Versions compare by PEP 440 (packaging)."""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from app.core.constants import Applicability, EvidenceReason, TextCleaning
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


@dataclass(frozen=True)
class _RecordedRow:
    """What one record of the asset (the asset itself, or a system) says about its products."""

    vendors: Words
    products: Words
    version: str | None

    @property
    def named(self) -> Words:
        """Every vendor and product word of the row."""
        return self.vendors | self.products


def _one_version(versions: Iterable[str]) -> str | None:
    """The row's one recorded version; None when it records none, or more than one different one."""
    found = {text.strip() for text in versions}
    found.discard("")
    return found.pop() if len(found) == 1 else None


def _affected_entries(hit: IntelHit) -> list[dict[str, Any]]:
    """The record's `affected` entries ({vendor, product, versions, fixed}); [] when it states none."""
    affected = hit.data.get("affected")
    return [entry for entry in affected if isinstance(entry, dict)] if isinstance(affected, list) else []


def _entries_to_compare(hit: IntelHit) -> list[dict[str, Any]]:
    """The affected entries, or the record itself (its own vendor and product) when it states none."""
    return _affected_entries(hit) or [hit.data]


class ProductLinkChecker:
    """Compares product records with one request's recorded products; made per request, nothing shared."""

    def __init__(self, recorded: RecordedProducts) -> None:
        self._rows = tuple(
            _RecordedRow(_name_words(row.vendors), _name_words(row.products), _one_version(row.versions))
            for row in recorded.rows
        )
        self._vendors: Words = frozenset().union(*(row.vendors for row in self._rows))
        self._products: Words = frozenset().union(*(row.products for row in self._rows))

    def has_no_link(self, hit: IntelHit) -> bool:
        """True when nothing ties a product-specific record to the asset: the asset records no vendor or
        product at all, or the record names no vendor or product to compare."""
        named: Words = frozenset().union(
            *(_entry_words(entry)[0] | _entry_words(entry)[1] for entry in _entries_to_compare(hit))
        )
        return not (self._vendors | self._products) or not named

    def judge(self, hit: IntelHit) -> Verdict:
        """The applicability of a vulnerability or advisory hit and, when NOT_APPLICABLE, the reason. A record
        with no `affected` list is compared by vendor and product alone (never CONFIRMED)."""
        affected = _affected_entries(hit)
        relations = [(entry, self._relation(*_entry_words(entry))) for entry in _entries_to_compare(hit)]
        same = [entry for entry, why in relations if why is None]
        if not same:  # no affected vendor / product is one the asset records
            entry, why = relations[0]
            reason = (why or EvidenceReason.DIFFERENT_PRODUCT).format(**_vendor_and_product(entry))
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
        """CONFIRMED when a recorded version is affected, NOT_APPLICABLE when every one is outside, else
        UNKNOWN."""
        found = list(self._version_states(entries))
        if any(state is True for state in found):
            return Applicability.CONFIRMED, ""
        if found and all(state is False for state in found):
            reason = EvidenceReason.VERSION_NOT_AFFECTED.format(**_vendor_and_product(entries[0]))
            return Applicability.NOT_APPLICABLE, reason
        return Applicability.UNKNOWN, ""

    def _version_states(self, entries: list[dict[str, Any]]) -> Iterator[bool | None]:
        """For every (entry, row) that share a word: True affected, False not, None not known. CONFIRMED needs
        the product named in full, its maker, and one recorded version."""
        for entry in entries:
            vendor, product = _entry_words(entry)
            for row in self._rows:
                if not (vendor | product) & row.named:
                    continue
                # the whole product name must be there (not one shared word like "windows"), and the maker
                strong = bool(product) and product <= row.named and (not vendor or bool(vendor & row.named))
                yield affected_state(row.version, entry) if strong and row.version else None


def affected_state(version: Any, entry: dict[str, Any]) -> bool | None:
    """Whether `version` is affected by one advisory entry ({versions: [...], fixed: [...]}): True, False, or
    None when that cannot be said for certain. Inside a range but at or after a fixed version is a record
    that contradicts itself (a fix on another branch, say): None, never a guess."""
    target, ranges, fixed = _parsed_version(version), entry.get("versions"), entry.get("fixed") or []
    if target is None or not isinstance(ranges, list) or not ranges or not isinstance(fixed, list):
        return None  # no version, or the record does not state which versions
    states = [_in_range(target, version_range) for version_range in ranges]
    if any(state is True for state in states):
        return True if _reaches_fix(target, fixed) is False else None
    return None if any(state is None for state in states) else False


def _parsed_version(value: Any) -> Version | None:
    """`value` as a PEP 440 version; None when it is not a short readable version string."""
    if not isinstance(value, str) or not value.strip() or len(value) > TextCleaning.VERSION_CHARS:
        return None
    try:
        return Version(value.strip())
    except InvalidVersion:
        return None


def _in_range(target: Version, version_range: Any) -> bool | None:
    """True / False when the range is read with certainty; None otherwise. Both bounds stated as none is
    every version; a missing start_inclusive is True."""
    if not isinstance(version_range, dict):
        return None
    start, end = version_range.get("start"), version_range.get("end")
    if start is None and end is None:  # both bounds stated as none: every version; absent keys: not stated
        return True if {"start", "end"} <= version_range.keys() else None
    inside = True
    for bound, inclusive, is_start in (
        (start, version_range.get("start_inclusive", True), True),  # a start that says nothing is inclusive
        (end, version_range.get("end_inclusive"), False),
    ):
        if bound is None:
            continue
        key = _parsed_version(bound)
        if key is None or not isinstance(inclusive, bool):
            return None
        beyond = target > key if is_start else target < key  # on the inner side of this bound
        inside = inside and (beyond or (target == key and inclusive))
    return inside


def _reaches_fix(target: Version, fixed: list[Any]) -> bool | None:
    """True when the version is at or after a fixed version; None when a fixed version cannot be read."""
    keys = [_parsed_version(item) for item in fixed]
    if any(key is not None and target >= key for key in keys):
        return True
    return None if any(key is None for key in keys) else False
