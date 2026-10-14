"""Affected and fixed versions said in plain words, from the structured `affected` entries of a record."""

import re
from typing import Any

from app.core.constants import EvidenceFact, EvidenceLimits, NameGrammar, VersionWords
from app.engine.external_intelligence.text_cleaner import TextCleaner

_SAFE_VERSION = re.compile(r"^[\w.+\-]+(?: [\w.+\-]+)*$")  # no markup, ids or links


class VersionFacts:
    def __init__(self, cleaner: TextCleaner) -> None:
        self._cleaner = cleaner

    def sentences(self, data: dict[str, Any]) -> list[str]:
        """The affected versions and the fixed ones, from the first entry that states any."""
        for entry in data.get("affected") or []:
            if not isinstance(entry, dict):
                continue
            ranges = [self._range_words(r) for r in _listed(entry.get("versions"))]
            fixed = [self._version(v) for v in _listed(entry.get("fixed"))]
            said, fixes = ", ".join(r for r in ranges if r), ", ".join(v for v in fixed if v)
            if said and fixes:
                return [EvidenceFact.VERSIONS_AND_FIXED.format(ranges=said, fixed=fixes)]
            if said or fixes:
                if said:
                    return [EvidenceFact.VERSIONS_ONLY.format(ranges=said)]
                return [EvidenceFact.FIXED_ONLY.format(fixed=fixes)]
        return []

    def _version(self, value: Any) -> str | None:
        """A version safe to put in a sentence: short, a few words, with a digit, only letters, digits and
        . _ + - characters."""
        text = value.strip() if isinstance(value, str) else ""
        if not text or len(text) > EvidenceLimits.VERSION_MAX_CHARS or not _SAFE_VERSION.match(text):
            return None
        if len(text.split()) > NameGrammar.MAX_VERSION_WORDS or not any(char.isdigit() for char in text):
            return None
        return self._cleaner.clean(text, EvidenceLimits.VERSION_MAX_CHARS)

    def _range_words(self, version_range: Any) -> str | None:
        """One range in plain words; None when a bound is not safe to say or the range has no bound."""
        if not isinstance(version_range, dict):
            return None
        start, end = version_range.get("start"), version_range.get("end")
        low, high = self._version(start), self._version(end)
        if (start is not None and low is None) or (end is not None and high is None):
            return None
        start_in, end_in = version_range.get("start_inclusive", True), version_range.get("end_inclusive")
        upper = (VersionWords.UP_TO if end_in else VersionWords.BEFORE).format(version=high) if high else ""
        if low and high:
            return f"{(VersionWords.FROM if start_in else VersionWords.AFTER).format(version=low)} {upper}"
        if low:
            return (VersionWords.AND_LATER if start_in else VersionWords.AFTER).format(version=low)
        return upper or None


def _listed(value: Any) -> list[Any]:
    return value[: EvidenceLimits.RANGES_SAID] if isinstance(value, list) else []
