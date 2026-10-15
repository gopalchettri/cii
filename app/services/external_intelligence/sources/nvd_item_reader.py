"""NVD API 2.0 CVE item -> one VULNERABILITY_DETAIL record, joined to the KEV vulnerability by CVE id.

`data.affected` is a contract shared with the advisory reader: one entry per (vendor, product), taken from the
`vulnerable: true` cpeMatch entries of `configurations`:
    {vendor, product, versions: [{start, start_inclusive, end, end_inclusive}], fixed: [version, ...]}
- `versions` entries are uniform. A bound that is None is open, and its `*_inclusive` is then True.
- NVD's versionStartIncluding/Excluding and versionEndIncluding/Excluding map to the bound and its flag.
- A cpe naming one version and no range is {start: v, end: v} with both flags True. The cpe's update field
  (beta9, sp1) is not part of the bound: the version is the NVD's text before it.
- A cpe with version `*` or `-` and no range means "every version": `versions` is then [] (not stated).
- `fixed` holds each versionEndExcluding: the first version outside the range, i.e. a fixed release.
The description is the one free text; it and every cpe field are sanitised, and an item with unsafe text is
quarantined whole."""

import re
from typing import Any, Final

from app.core.constants import AssetType, IntelKind, IntelLimits, IntelRejection, IntelSource, TextSafety
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of
from app.services.external_intelligence.sources.text_guard import (
    SourceTextGuard,
    UnsafeSourceText,
    flat_strings,
    plain_id,
)

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d{1,6}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?")
_VECTOR = re.compile(r"[A-Za-z0-9:/._-]{1,120}")
_SEVERITIES: Final = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_SPLIT = re.compile(r"(?<!\\):")  # a cpe 2.3 field separator is a colon not escaped by a backslash
_UNSPECIFIED: Final = {"*", "-", ""}
_METRICS: Final = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")
_PAGE = "https://nvd.nist.gov/vuln/detail/{cve}"
_RANGE_KEYS: Final = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


class NvdItemReader:
    def __init__(self, guard: SourceTextGuard) -> None:
        self._guard = guard

    def read_item(self, item: Any) -> IntelRecord | RejectedRecord:
        """The record for one `vulnerabilities[]` element, or the rejection of a malformed or unsafe one."""
        cve = item.get("cve") if isinstance(item, dict) else None
        cve_id = cve.get("id") if isinstance(cve, dict) else None
        modified = cve.get("lastModified") if isinstance(cve, dict) else None
        if not (
            isinstance(cve, dict)
            and isinstance(cve_id, str)
            and _CVE.fullmatch(cve_id)
            and isinstance(modified, str)
            and _DATE.fullmatch(modified)
        ):
            plain = plain_id(cve_id)
            return RejectedRecord(
                IntelSource.NIST_NVD, plain, IntelRejection.NVD_BAD_ITEM, content_hash_of(item)
            )
        try:
            return self._build(cve, cve_id, modified)
        except UnsafeSourceText as unsafe:
            return self._guard.quarantine(cve_id, item, unsafe.reason)

    def _build(self, cve: dict[str, Any], cve_id: str, modified: str) -> IntelRecord:
        score, vector, severity = _cvss(cve.get("metrics"))
        published = cve.get("published")
        data = {
            "cve": cve_id,
            "cvss": score,
            "cvss_vector": vector,
            "severity": severity,
            "cwes": _cwes(cve.get("weaknesses")),
            "published": published if isinstance(published, str) and _DATE.fullmatch(published) else None,
            "affected": self._affected(cve.get("configurations")),
            "references_patch": self._patch_urls(cve.get("references")),
        }
        text = self._summary(cve_id, score, severity, cve.get("descriptions"))
        self._guard.screen_together([text, *flat_strings(data)])
        return IntelRecord(
            IntelSource.NIST_NVD,
            cve_id,
            IntelKind.VULNERABILITY_DETAIL,
            AssetType.IT.value,
            cve_id,
            text,
            _PAGE.format(cve=cve_id),
            modified,
            modified,
            data,
        )

    def _summary(self, cve: str, score: float | None, severity: str | None, descriptions: Any) -> str:
        rating = f" CVSS {score} {severity}." if score is not None else ""
        english = [
            d.get("value") for d in descriptions or [] if isinstance(d, dict) and d.get("lang") == "en"
        ]
        # G237: the description alone is screened by sentence (its own id and rating are never "a clean
        # sentence" that keeps a poisoned description alive), then the whole once more.
        limit = IntelLimits.NVD_SUMMARY_MAX_CHARS
        description = self._guard.clean_sentences(english[0], limit) if english else ""
        return self._guard.clean(f"{cve}.{rating} {description}", IntelLimits.NVD_SUMMARY_MAX_CHARS)

    def _patch_urls(self, references: Any) -> list[str]:
        urls = [
            r["url"]
            for r in references or []
            if isinstance(r, dict) and isinstance(r.get("url"), str) and "Patch" in (r.get("tags") or [])
        ]
        clean = (self._guard.clean_link(url) for url in dict.fromkeys(urls))
        return [url for url in clean if url][: IntelLimits.NVD_MAX_PATCH_URLS]

    def _affected(self, configurations: Any) -> list[dict[str, Any]]:
        """One entry per (vendor, product) from the vulnerable cpeMatch entries; see the module docstring."""
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for config in configurations or []:
            for node in config.get("nodes") or [] if isinstance(config, dict) else []:
                for match in node.get("cpeMatch") or [] if isinstance(node, dict) else []:
                    if isinstance(match, dict) and match.get("vulnerable") is True:
                        self._add(groups, match)
        return [
            {
                "vendor": vendor,
                "product": product,
                "versions": [] if group["any"] else group["versions"][: TextSafety.MAX_DATA_ITEMS],
                "fixed": group["fixed"][: TextSafety.MAX_DATA_ITEMS],
            }
            for (vendor, product), group in list(groups.items())[: TextSafety.MAX_DATA_ITEMS]
        ]

    def _add(self, groups: dict[tuple[str, str], dict[str, Any]], match: dict[str, Any]) -> None:
        parts = [p.replace("\\", "") for p in _SPLIT.split(str(match.get("criteria") or ""))]
        if len(parts) < 6 or not parts[3] or not parts[4]:
            return
        key = (self._guard.clean_token(parts[3]), self._guard.clean_token(parts[4]))
        group = groups.setdefault(key, {"versions": [], "fixed": [], "any": False})
        bounded = any(match.get(name) for name in _RANGE_KEYS)
        if not bounded and parts[5] in _UNSPECIFIED:
            group["any"] = True
            return
        version = self._bounds(match) if bounded else self._exact(self._guard.clean_token(parts[5]))
        if version not in group["versions"]:
            group["versions"].append(version)
        fixed = match.get("versionEndExcluding")
        if isinstance(fixed, str) and (clean := self._guard.clean_token(fixed)) not in group["fixed"]:
            group["fixed"].append(clean)

    def _bounds(self, match: dict[str, Any]) -> dict[str, Any]:
        start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
        end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
        return {
            "start": self._guard.clean_token(start) if start else None,
            "start_inclusive": not match.get("versionStartExcluding"),
            "end": self._guard.clean_token(end) if end else None,
            "end_inclusive": not match.get("versionEndExcluding"),
        }

    @staticmethod
    def _exact(version: str) -> dict[str, Any]:
        return {"start": version, "start_inclusive": True, "end": version, "end_inclusive": True}


def _cvss(metrics: Any) -> tuple[float | None, str | None, str | None]:
    """Score, vector and severity of the newest CVSS version present, the NVD's own (Primary) rating first."""
    for name in _METRICS:
        entries = [m for m in (metrics or {}).get(name) or [] if isinstance(m, dict)]
        for entry in sorted(entries, key=lambda m: m.get("type") != "Primary"):
            body = entry.get("cvssData") or {}
            score = body.get("baseScore")
            if isinstance(score, int | float) and not isinstance(score, bool):
                severity = str(
                    body.get("baseSeverity") or entry.get("baseSeverity") or ""
                ).upper()  # v2: outside
                vector = body.get("vectorString")
                return (
                    float(score),
                    vector if isinstance(vector, str) and _VECTOR.fullmatch(vector) else None,
                    severity if severity in _SEVERITIES else None,
                )
    return None, None, None


def _cwes(weaknesses: Any) -> list[str]:
    found = [
        d.get("value")
        for w in weaknesses or []
        if isinstance(w, dict)
        for d in w.get("description") or []
        if isinstance(d, dict)
    ]
    return list(dict.fromkeys(v for v in found if isinstance(v, str) and _CWE.fullmatch(v)))
