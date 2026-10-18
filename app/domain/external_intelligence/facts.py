"""The plain sentences a scenario writer may use from one intelligence record, built from its structured
fields only (never its free text), every string cleaned, and never holding an id or a link."""

import re
from itertools import islice
from typing import Any

from app.core.constants import (
    ACTOR_KIND_WORDS,
    SEVERITY_BANDS,
    EvidenceFact,
    EvidenceLimits,
    FactWordLimits,
    IntelKind,
    NameGrammar,
    TextSafety,
    VersionWords,
)
from app.domain.external_intelligence.text_cleaner import TextCleaner, is_tactic
from app.domain.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.models.external_intelligence.evidence import IntelHit

_LINK_SCHEMES = ("https://", "http://")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_SAFE_VERSION = re.compile(r"^[\w.+\-]+(?: [\w.+\-]+)*$")  # no markup, ids or links
_ANY_ACTOR_WORDS = "a known attacker"  # an actor of no kind ACTOR_KIND_WORDS names
_MAX_LIST_ITEMS = 50  # the most items of one record list a fact is built from


class PlainFactWriter:
    """Writes an evidence entry's facts, title, link and mitigations, each a cleaned string or nothing."""

    def __init__(self, sanitiser: UntrustedTextSanitiser | None = None) -> None:
        self._cleaner = TextCleaner(sanitiser)
        self._sentences = _Sentences(self._cleaner)

    def write_facts(self, hit: IntelHit) -> tuple[str, ...]:
        """Up to EvidenceLimits.MAX_FACTS clean sentences, none with an id or a link."""
        data = hit.data if isinstance(hit.data, dict) else {}
        builders = {
            IntelKind.TECHNIQUE: self._sentences.technique,
            IntelKind.ADVISORY: self._sentences.advisory,
            IntelKind.VULNERABILITY: self._sentences.vulnerability,
        }
        build = builders.get(hit.kind)
        if build is None:
            return ()
        cleaned = (self._cleaner.clean(sentence, TextSafety.MAX_FACT_CHARS) for sentence in build(data))
        return tuple(dict.fromkeys(sentence for sentence in cleaned if sentence))[: EvidenceLimits.MAX_FACTS]

    def safe_mitigations(self, hit: IntelHit) -> tuple[str, ...]:
        """An ATT&CK technique's mitigations by the names its facts use (the control search labels them
        MITRE ATT&CK, so no other kind's remediation is ever given)."""
        if hit.kind != IntelKind.TECHNIQUE or not isinstance(hit.data, dict):
            return ()
        return tuple(self._sentences.mitigation_names(hit.data))

    def safe_title(self, hit: IntelHit) -> str:
        """The record's title when it is plain words; its own id otherwise (the id is shown, not said)."""
        return self._cleaner.clean(hit.title, TextSafety.MAX_TITLE_CHARS) or hit.external_id

    def safe_reason(self, reason: str) -> str:
        """A reason for leaving a record out (it holds the record's vendor and product names): empty when
        those are not plain words; the decision itself stays recorded."""
        return self._cleaner.clean(reason, TextSafety.MAX_FACT_CHARS * 2) or ""

    def safe_url(self, hit: IntelHit) -> str:
        """The record's link when it is an ordinary web address of a sane length; empty otherwise."""
        url = hit.url if isinstance(hit.url, str) else ""
        ok = url.startswith(_LINK_SCHEMES) and len(url) <= TextSafety.MAX_URL_CHARS and url.isprintable()
        return url if ok and not any(char in url for char in " <>\"'`\\") else ""


class _Sentences:
    """The sentences of the three kinds of evidence record; every string in one went through TextCleaner."""

    def __init__(self, cleaner: TextCleaner) -> None:
        self._cleaner = cleaner

    def technique(self, data: dict[str, Any]) -> list[str]:
        """A technique's tactics, who used it, and what mitigates it."""
        tactics = self._tactics(data.get("tactics"))
        users = islice(
            filter(None, map(self._used_by, _first_items(data.get("real_world_use")))),
            EvidenceLimits.REAL_WORLD_USERS,
        )
        return [
            *([EvidenceFact.TACTICS.format(tactics=", ".join(tactics))] if tactics else []),
            *users,
            *self._mitigation(data),
        ]

    def vulnerability(self, data: dict[str, Any]) -> list[str]:
        """A known-exploited vulnerability's listing, ransomware use, likelihood, severity and versions."""
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
        return [*facts, *self._versions(data)]

    def advisory(self, data: dict[str, Any]) -> list[str]:
        """An advisory's opening (the product it concerns), versions, severity and mitigations."""
        first = next((e for e in data.get("affected") or [] if isinstance(e, dict)), {})
        parts = (self._name(first.get("vendor") or data.get("vendor")), self._name(first.get("product")))
        named = " ".join(part for part in parts if part)
        impact = EvidenceFact.ADVISORY_IMPACT.value
        opening = (
            EvidenceFact.ADVISORY.format(product=named, impact=impact)
            if named
            else EvidenceFact.ADVISORY_UNNAMED.format(impact=impact)
        )
        severity = _severity(data.get("cvss_max"), None)
        return [opening, *self._versions(data), *severity, *self._mitigation(data)]

    def mitigation_names(self, data: dict[str, Any]) -> list[str]:
        """The record's mitigations that read as names, at most EvidenceLimits.MITIGATIONS."""
        names = filter(None, map(self._name, _first_items(data.get("mitigations"))))
        return list(islice(names, EvidenceLimits.MITIGATIONS))

    def _name(self, value: Any) -> str:
        """A name field (a vendor, product, mitigation, actor): plain words in the shape of a name."""
        return self._cleaner.clean_name(value) or ""

    def _tactics(self, values: Any) -> list[str]:
        """Up to MAX_TACTICS tactics ("initial-access" -> "initial access"); one not shaped like a tactic
        name is passed over."""
        tactics = (v.replace("-", " ") for v in _first_items(values) if isinstance(v, str) and is_tactic(v))
        cleaned = (self._cleaner.clean(tactic, FactWordLimits.MAX_NAME_CHARS) for tactic in tactics)
        return list(islice(filter(None, cleaned), FactWordLimits.MAX_TACTICS))

    def _mitigation(self, data: dict[str, Any]) -> list[str]:
        """The "mitigated by" sentence, when the record names any mitigation."""
        names = self.mitigation_names(data)
        return [EvidenceFact.MITIGATED_BY.format(mitigations=", ".join(names))] if names else []

    def _used_by(self, use: Any) -> str:
        """The sentence naming one group, software or campaign that used the technique; '' when unnamed."""
        name = self._name(use.get("name")) if isinstance(use, dict) else ""
        if not name:
            return ""
        kind = use.get("kind")
        if kind == "campaign":
            label = name if name.casefold().endswith("campaign") else f"{name} campaign"  # one "campaign"
            return EvidenceFact.CAMPAIGN_USED.format(name=label)
        words = ACTOR_KIND_WORDS.get(kind, _ANY_ACTOR_WORDS) if isinstance(kind, str) else _ANY_ACTOR_WORDS
        return EvidenceFact.USED_BY.format(name=name, what=words)

    def _versions(self, data: dict[str, Any]) -> list[str]:
        """The affected versions and the fixed ones, from the first `affected` entry that states any."""
        for entry in data.get("affected") or []:
            if not isinstance(entry, dict):
                continue
            ranges = [self._range_words(r) for r in _first_ranges(entry.get("versions"))]
            fixed = [self._version(v) for v in _first_ranges(entry.get("fixed"))]
            said, fixes = ", ".join(r for r in ranges if r), ", ".join(v for v in fixed if v)
            if said and fixes:
                return [EvidenceFact.VERSIONS_AND_FIXED.format(ranges=said, fixed=fixes)]
            if said:
                return [EvidenceFact.VERSIONS_ONLY.format(ranges=said)]
            if fixes:
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


def _first_items(value: Any) -> list[Any]:
    """The first _MAX_LIST_ITEMS items of a record list; [] for anything else."""
    return value[:_MAX_LIST_ITEMS] if isinstance(value, list) else []


def _first_ranges(value: Any) -> list[Any]:
    """The first EvidenceLimits.RANGES_SAID versions or ranges of a record list; [] for anything else."""
    return value[: EvidenceLimits.RANGES_SAID] if isinstance(value, list) else []


def _likelihood(epss: Any) -> list[str]:
    """The EPSS sentence (the likelihood of exploitation) for a score between 0 and 1; [] otherwise."""
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
