"""One CISA CSAF 2.0 advisory as one ADVISORY record: the advisory's products and versions come from its
product_tree and from the product_status of its vulnerabilities, its fixes from the `fixed` status.

Every product, vendor, version wording, title, note and mitigation is sanitised; an advisory with unsafe text
raises UnsafeSourceText and the caller quarantines it. Ids, CVE ids and dates are accepted only in their own
shape, so a sentence cannot ride in them."""

import re
from typing import Any, Final

from app.core.constants import AssetType, IcsReading, IntelKind, IntelSource, SourceHosts, TextSafety
from app.engine.external_intelligence.name_grammar import as_name
from app.models.external_intelligence.intel_record import IntelRecord
from app.services.external_intelligence.sources.ics_version_ranges import parse_versions
from app.services.external_intelligence.sources.text_guard import SourceTextGuard, flat_strings

_MITIGATION_CATEGORIES: Final = {"mitigation", "workaround", "vendor_fix"}
_VERSION_LEVELS: Final = {"product_version", "product_version_range"}
_ALL_VERSIONS: Final = "vers:all/*"
_CVSS_KEYS: Final = ("cvss_v4", "cvss_v3", "cvss_v2")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?")
_ADVISORY_ID = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,40}")

Product = tuple[str, str, str | None]  # vendor, product, version wording (None: the leaf names no version)


def _items(value: Any) -> list[dict[str, Any]]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _cut(text: str, room: int) -> str:
    """`text` cut at the last sentence end, else the last space, that fits `room` characters."""
    if len(text) <= room:
        return text
    head = text[:room]
    end = max(head.rfind(". "), head.rfind("! "), head.rfind("? "))
    return head[: end + 1] if end > room // 2 else head[: head.rfind(" ")].rstrip(" ,;:")


def _cvss_max(vulns: list[dict[str, Any]]) -> float | None:
    scores = [
        s[key]["baseScore"]
        for v in vulns
        for s in _items(v.get("scores"))
        for key in _CVSS_KEYS
        if isinstance(s.get(key), dict) and isinstance(s[key].get("baseScore"), int | float)
    ]
    return float(max(scores)) if scores else None


def _words(wording: str) -> str:
    return "all versions" if wording == _ALL_VERSIONS else wording


class IcsAdvisoryReader:
    def __init__(self, guard: SourceTextGuard) -> None:
        self._guard = guard

    def read_advisory(self, doc: dict[str, Any], path: str) -> IntelRecord | None:
        """The record for a parsed CSAF document; None when it has no valid id, title or release date.
        Raises UnsafeSourceText when any of its text reads as instructions to an AI."""
        head = _dict(doc.get("document"))
        tracking = _dict(head.get("tracking"))
        advisory_id = _s(tracking.get("id")).upper()
        modified = _s(tracking.get("current_release_date"))
        if not (_ADVISORY_ID.fullmatch(advisory_id) and _DATE.fullmatch(modified) and _s(head.get("title"))):
            return None
        title = self._guard.clean(head.get("title"), TextSafety.MAX_TITLE_CHARS)
        vulns = _items(doc.get("vulnerabilities"))
        groups = self._groups(self._products(_items(_dict(doc.get("product_tree")).get("branches"))), vulns)
        mitigations = self._mitigations(vulns)
        published = _s(tracking.get("initial_release_date"))
        data = {
            "advisory_id": advisory_id,
            "vendor": next((g["vendor"] for g in groups if g["vendor"]), ""),
            "cves": list(
                dict.fromkeys(c for c in (_s(v.get("cve")).upper() for v in vulns) if _CVE.fullmatch(c))
            ),
            "cvss_max": _cvss_max(vulns),
            "published": published if _DATE.fullmatch(published) else None,
            "affected": [self._affected(group) for group in groups[: TextSafety.MAX_DATA_ITEMS]],
            "mitigations": mitigations,
        }
        text = self._text(advisory_id, title, self._summary(head, vulns), groups, mitigations)
        self._guard.screen_together([title, text, *flat_strings(data)])
        page = self._page(head) or SourceHosts.CISA_ADVISORY_PAGE.format(advisory_id=advisory_id.lower())
        return IntelRecord(
            IntelSource.CISA_ICS, advisory_id, IntelKind.ADVISORY, AssetType.OT.value, title, text, page,
            modified, modified, data,
        )  # fmt: skip

    @staticmethod
    def _affected(group: dict[str, Any]) -> dict[str, Any]:
        """The group without its raw wording; version ranges and fixed lists capped."""
        return {
            "vendor": group["vendor"],
            "product": group["product"],
            "versions": group["versions"][: TextSafety.MAX_DATA_ITEMS],
            "fixed": group["fixed"][: TextSafety.MAX_DATA_ITEMS],
        }

    def _page(self, head: dict[str, Any]) -> str:
        """The advisory's own web page, from the document references: an https address on cisa.gov."""
        urls = [_s(r.get("url")) for r in _items(head.get("references")) if r.get("category") == "self"]
        links = (self._guard.clean_link(u, SourceHosts.CISA_PAGES) for u in urls)
        return next((link for link in links if link), "")

    def _products(
        self, branches: list[dict[str, Any]], vendor: str = "", product: str = ""
    ) -> dict[str, Product]:
        """product_id -> (vendor, product, version wording or None), from the nested branches."""
        found: dict[str, Product] = {}
        for branch in branches:
            if len(found) >= IcsReading.MAX_PRODUCTS:
                break
            name = self._guard.clean(branch.get("name"), IcsReading.NAME_CHARS)
            level = branch.get("category")
            leaf = _dict(branch.get("product"))
            if _s(leaf.get("product_id")):
                label = product or as_name(self._guard.clean(leaf.get("name"), IcsReading.NAME_CHARS))
                found[_s(leaf["product_id"])] = (
                    vendor,
                    label or as_name(name),
                    name if level in _VERSION_LEVELS else None,
                )
            found |= self._products(
                _items(branch.get("branches")),
                as_name(name) if level == "vendor" else vendor,
                as_name(name) if level in ("product_name", "product_family") else product,
            )
        return found

    @staticmethod
    def _groups(products: dict[str, Product], vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The affected shape: one entry per vendor and product, `raw` holding the unparsed wording."""
        status = [s for v in vulns if isinstance(s := v.get("product_status"), dict)]
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for key in ("known_affected", "fixed"):
            for pid in dict.fromkeys(p for s in status for p in s.get(key, []) if isinstance(p, str)):
                if pid not in products:
                    continue
                vendor, product, wording = products[pid]
                if key == "fixed" and (vendor, product) not in groups:
                    continue
                group = groups.setdefault(
                    (vendor, product),
                    {"vendor": vendor, "product": product, "versions": [], "fixed": [], "raw": []},
                )
                _add_wording(group, key, wording)
        return list(groups.values())

    def _mitigations(self, vulns: list[dict[str, Any]]) -> list[str]:
        found = (
            self._guard.clean(r.get("details"), IcsReading.MITIGATION_CHARS)
            for v in vulns
            for r in _items(v.get("remediations"))
            if r.get("category") in _MITIGATION_CATEGORIES
        )
        return list(dict.fromkeys(d for d in found if d))[: IcsReading.MAX_MITIGATIONS]

    def _summary(self, head: dict[str, Any], vulns: list[dict[str, Any]]) -> str:
        notes = _items(head.get("notes")) + [n for v in vulns for n in _items(v.get("notes"))]
        wanted = [n for n in notes if n.get("category") in ("summary", "description")]
        return self._guard.clean(wanted[0].get("text"), IcsReading.SUMMARY_CHARS * 2) if wanted else ""

    def _text(
        self, advisory_id: str, title: str, summary: str, groups: list[dict], mitigations: list[str]
    ) -> str:
        names = [
            g["product"] if g["product"].startswith(g["vendor"]) else f"{g['vendor']} {g['product']}"
            for g in groups
        ]
        shown = "; ".join(names[:8]) + (f"; and {len(names) - 8} more" if len(names) > 8 else "")
        affected = "; ".join(f"{g['product']} {_words(w)}" for g in groups for w in g["raw"])
        fixed = "; ".join(f"{g['product']} {v}" for g in groups for v in g["fixed"])
        parts = [
            f"{advisory_id} {title}.",
            f"Affected products: {shown}." if shown else "",
            _cut(summary, IcsReading.SUMMARY_CHARS),
            f"Affected versions: {_cut(affected, 350)}." if affected else "",
            f"Fixed in: {_cut(fixed, 250)}." if fixed else "",
            f"Mitigations: {_cut('; '.join(mitigations), 300)}." if mitigations else "",
        ]
        return self._guard.clean(" ".join(p for p in parts if p), TextSafety.MAX_TEXT_CHARS)


def _add_wording(group: dict[str, Any], key: str, wording: str | None) -> None:
    if not wording or (wording == _ALL_VERSIONS and key == "fixed"):
        return
    if key == "fixed":
        if wording not in group["fixed"]:
            group["fixed"].append(wording)
        return
    group["raw"].append(wording)
    group["versions"] += [r for r in parse_versions(wording) if r not in group["versions"]]
