"""The plain sentences of the three kinds of evidence record, made ONLY from structured fields (tactics,
mitigations, real-world users, vendor, product, dates, scores, ranges, fixes). A record's free text is never
used: it is the channel a poisoned source would use. Every string put in a sentence went through TextCleaner;
a sentence missing a string it needs is left out whole (G248: the owner undid G233's "how it works" facts)."""

import re
from itertools import islice
from typing import Any

from app.core.constants import (
    ACTOR_KIND_WORDS,
    SEVERITY_BANDS,
    EvidenceFact,
    EvidenceLimits,
    FactWordLimits,
)
from app.engine.external_intelligence.fact_versions import VersionFacts
from app.engine.external_intelligence.fact_words import PlainFactWords
from app.engine.external_intelligence.name_grammar import is_tactic
from app.engine.external_intelligence.text_cleaner import TextCleaner

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_KNOWN = "a known attacker"  # an actor of no kind ACTOR_KIND_WORDS names


class FactSentences:
    def __init__(self, cleaner: TextCleaner) -> None:
        self._cleaner = cleaner
        self._versions = VersionFacts(cleaner)

    def technique(self, data: dict[str, Any]) -> list[str]:
        tactics = self._tactics(data.get("tactics"))
        users = islice(
            filter(None, map(self._used_by, _items(data.get("real_world_use")))),
            EvidenceLimits.REAL_WORLD_USERS,
        )
        return [
            *([PlainFactWords.TACTICS.format(tactics=", ".join(tactics))] if tactics else []),
            *users,
            *self._mitigation(data),
        ]

    def vulnerability(self, data: dict[str, Any]) -> list[str]:
        vendor, product = self._name(data.get("vendor")), self._name(data.get("product"))
        date = data.get("date_added")
        facts: list[str] = []
        if isinstance(date, str) and _DATE.fullmatch(date):
            named = EvidenceFact.KEV_LISTED.format(vendor=vendor, product=product, date=date)
            facts.append(named if vendor and product else EvidenceFact.KEV_LISTED_UNNAMED.format(date=date))
        if data.get("known_ransomware_use") is True:
            facts.append(EvidenceFact.RANSOMWARE.value)
        facts += _likelihood(data.get("epss"))
        facts += _severity(data.get("cvss"), data.get("severity"))
        return [*facts, *self._versions.sentences(data)]

    def advisory(self, data: dict[str, Any]) -> list[str]:
        first = next((e for e in data.get("affected") or [] if isinstance(e, dict)), {})
        parts = (self._name(first.get("vendor") or data.get("vendor")), self._name(first.get("product")))
        named = " ".join(part for part in parts if part)
        impact = EvidenceFact.ADVISORY_IMPACT.value
        opening = (
            EvidenceFact.ADVISORY.format(product=named, impact=impact)
            if named
            else EvidenceFact.ADVISORY_UNNAMED.format(impact=impact)
        )
        return [
            opening,
            *self._versions.sentences(data),
            *_severity(data.get("cvss_max"), None),
            *self._mitigation(data),
        ]

    def _name(self, value: Any) -> str:
        """A name field (a group, vendor, product, mitigation): plain words in the shape of a name."""
        return self._cleaner.clean_name(value) or ""

    def _names(self, values: Any, limit: int) -> list[str]:
        """Up to `limit` of the cleaned names; one that fails the cleaning is passed over."""
        return list(islice(filter(None, map(self._name, _items(values))), limit))

    def _tactics(self, values: Any) -> list[str]:
        """Up to MAX_TACTICS tactics ("initial-access" -> "initial access"); one not shaped like a tactic
        name is passed over."""
        tactics = (v.replace("-", " ") for v in _items(values) if isinstance(v, str) and is_tactic(v))
        cleaned = (self._cleaner.clean(tactic, FactWordLimits.MAX_NAME_CHARS) for tactic in tactics)
        return list(islice(filter(None, cleaned), FactWordLimits.MAX_TACTICS))

    def mitigation_names(self, data: dict[str, Any]) -> list[str]:
        """The record's mitigations that read as names, at most EvidenceLimits.MITIGATIONS: the ones its
        facts say, and the ones the control search reads (G234)."""
        return self._names(data.get("mitigations"), EvidenceLimits.MITIGATIONS)

    def _mitigation(self, data: dict[str, Any]) -> list[str]:
        names = self.mitigation_names(data)
        return [EvidenceFact.MITIGATED_BY.format(mitigations=", ".join(names))] if names else []

    def _used_by(self, use: Any) -> str:
        if not isinstance(use, dict):
            return ""
        name = self._name(use.get("name"))
        if not name:
            return ""
        kind = use.get("kind")
        if kind == "campaign":
            label = name if name.casefold().endswith("campaign") else f"{name} campaign"  # one "campaign"
            return EvidenceFact.CAMPAIGN_USED.format(name=label)
        words = ACTOR_KIND_WORDS.get(kind, _KNOWN) if isinstance(kind, str) else _KNOWN
        return EvidenceFact.USED_BY.format(name=name, what=words)


def _items(value: Any) -> list[Any]:
    return value[:50] if isinstance(value, list) else []


def _likelihood(epss: Any) -> list[str]:
    if isinstance(epss, bool) or not isinstance(epss, int | float) or not 0 <= epss <= 1:
        return []
    percent = epss * 100
    return [EvidenceFact.LIKELIHOOD.format(percent=f"{percent:.1f}" if percent < 10 else f"{percent:.0f}")]


def _severity(score: Any, word: Any) -> list[str]:
    """ "Rated critical (9.8 of 10)": the score's band (the source's own word when it gives no score)."""
    if isinstance(score, int | float) and not isinstance(score, bool) and 0 <= score <= 10:
        band = next((name for floor, name in SEVERITY_BANDS if score >= floor), None)
        return [EvidenceFact.SEVERITY.format(severity=band, score=f"{score:.1f}")] if band else []
    known = {name for _, name in SEVERITY_BANDS}
    if isinstance(word, str) and word.strip().casefold() in known:
        return [EvidenceFact.SEVERITY_WORD.format(severity=word.strip().casefold())]
    return []
