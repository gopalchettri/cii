"""Mandatory evidence, checked in code (G229, owner 2026-10-13: "every finalized threat scenario must contain
at least one valid, relevant, traceable evidence item ... a mandatory validation rule, not an optional prompt
instruction"). An evidence story must cite at least one entry; every cited marker needs the claim it supports
(the writer's evidence_links); and a citation counts only when its sentence states something the cited entry
itself states: the group, software or campaign it names, the vendor or product it concerns. "Attackers have
done this before [1]" names none of it and does not count (run 03276384: 6 of 9 citations were such). The
entries' facts are code-built from fixed sentences (EvidenceFact), so what each names is read exactly. An
entry naming nothing (a technique with only its goals) counts when the sentence shares two of its terms.

G232 (owner 2026-10-14): only a sentence that says something HAPPENED ("X has used this", "in 2015", "a past
incident") needs the cited entry's name; a sentence that says how the attack works may cite the technique it
describes ("could flood the wireless links [1]"): the AI plan check, which sees the technique's name, judges
it. A sentence that says something happened in the deployment's country (THREAT_CONTEXT_COUNTRY) must cite a
source that tells of that country (scope "country"): regional or global intelligence is never presented as a
local incident. Each finding is final: the scenario is not finished, and no AI call is spent on it."""

import re
from collections.abc import Iterator
from typing import Any

from app.core.config import get_settings
from app.core.constants import EvidenceFact, EvidenceScope, FindingCode, FindingMessage
from app.engine.external_intelligence.place_words import places_in
from app.models.external_intelligence.evidence_view import markers_of
from app.models.writing import Finding, ScenarioDraft, WriterBrief

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
#: A word with at least one letter, ids such as C0017 or FIN13 included.
_TOKEN = re.compile(r"\b[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*\b")
#: Words in a campaign, group or product name that name nothing on their own.
_GENERIC = frozenset({
    "the", "and", "for", "operation", "attack", "attacks", "campaign", "compromise", "exploitation",
    "system", "systems", "safety", "instrumented", "electric", "power", "team", "group", "inc",
    "corporation", "software",
})  # fmt: skip
_STOP = frozenset({
    "about", "after", "also", "attacker", "attackers", "been", "before", "could", "from", "goals", "have",
    "into", "known", "real", "such", "that", "their", "these", "this", "used", "uses", "were", "what",
    "when", "which", "with", "would", "technique", "techniques", "reduced",
})  # fmt: skip


#: A sentence that says something happened: a perfect tense ("has used", "have done", "has been"), a past
#: action that is not a passive of what can be ("used" but not "be used"), a year, a past incident.
_PRECEDENT = re.compile(
    r"\b(?:has|have|had)\s+(?:\w+\s+){0,2}?\w+(?:ed|en|ne|wn)\b"
    r"|(?<!\bbe )(?<!\bis )(?<!\bare )(?<!\bbeing )\b(?:used|exploited|targeted|deployed|attacked|compromised"
    r"|abused|leveraged|employed|conducted)\b"
    r"|\b(?:previously|historically|precedents?|incidents?)\b|\bin the past\b|\bin (?:19|20)\d{2}\b"
    r"|\bknown to\b|\breal[- ]world\b",
    re.IGNORECASE,
)


def _template(fact: EvidenceFact, *named: str) -> tuple[re.Pattern[str], tuple[str, ...]]:
    """One fact sentence as a pattern: the named fields captured, every other field any text."""
    pattern = re.escape(str(fact))
    for field in re.findall(r"\{(\w+)\}", str(fact)):
        group = f"(?P<{field}>.+?)" if field in named else ".+?"
        pattern = pattern.replace(re.escape("{" + field + "}"), group)
    return re.compile(pattern), named


#: The fact sentences that name something, and which of their fields name it.
_NAMING_FACTS = (
    _template(EvidenceFact.USED_BY, "name"),
    _template(EvidenceFact.CAMPAIGN_USED, "name"),
    _template(EvidenceFact.KEV_LISTED, "vendor", "product"),
    _template(EvidenceFact.ADVISORY, "product"),
)


def evidence_findings(draft: ScenarioDraft, brief: WriterBrief) -> list[Finding]:
    """An evidence story's evidence faults: none cited; a cited marker without its claim; a citation its
    entry does not support. A marker outside the evidence is the story rules' (UNKNOWN_MARKER)."""
    text = f"{draft.statement}\n{draft.risk}"
    count = len(brief.evidence)
    cited = sorted({number for number in markers_of(text) if 1 <= number <= count})
    if not cited:
        return [Finding(FindingCode.NO_EVIDENCE_CITED, FindingMessage.NO_EVIDENCE_CITED.format(count=count))]
    claims = {number: claim for number, claim in draft.evidence_links if claim.strip()}
    findings = []
    if missing := [number for number in cited if number not in claims]:
        markers = ", ".join(f"[{number}]" for number in missing)
        findings.append(
            Finding(
                FindingCode.EVIDENCE_LINK_MISSING,
                FindingMessage.EVIDENCE_LINK_MISSING.format(markers=markers),
            )
        )
    unsupported = [
        number
        for number in cited
        if not any(supports(sentence, brief.evidence[number - 1]) for sentence in _citing(text, number))
    ]
    if unsupported:
        markers = ", ".join(f"[{number}]" for number in unsupported)
        findings.append(
            Finding(
                FindingCode.CITATION_UNSUPPORTED, FindingMessage.CITATION_UNSUPPORTED.format(markers=markers)
            )
        )
    return findings + _country_claims(text, brief)


def supports(sentence: str, entry: dict[str, Any]) -> bool:
    """The sentence states what the entry states: one of the names it gives, or (it names none) two of its
    terms. A sentence saying how the attack works, not that something happened, is the plan check's (G232)."""
    said = {token.casefold() for token in _TOKEN.findall(sentence) if len(token) >= 3}
    names = named_by(entry)
    if names & said or not _PRECEDENT.search(sentence):
        return True
    if names:
        return False
    terms = {token.casefold() for fact in entry.get("facts") or () for token in _TOKEN.findall(fact)}
    return len((terms - _STOP) & said) >= 2


def _country_claims(text: str, brief: WriterBrief) -> list[Finding]:
    """G232: the markers of sentences saying something happened in the deployment's country that cite no
    source telling of it."""
    country = get_settings().context_country
    count, unsupported = len(brief.evidence), []
    for sentence in _SENTENCE_END.split(text):
        cited = [number for number in markers_of(sentence) if 1 <= number <= count]
        if not cited or country not in places_in(sentence) or not _PRECEDENT.search(sentence):
            continue
        if all(brief.evidence[number - 1].get("scope") != EvidenceScope.COUNTRY for number in cited):
            unsupported += [number for number in cited if number not in unsupported]
    if not unsupported:
        return []
    markers = ", ".join(f"[{number}]" for number in unsupported)
    message = FindingMessage.COUNTRY_CLAIM_UNSUPPORTED.format(country=country, markers=markers)
    return [Finding(FindingCode.COUNTRY_CLAIM_UNSUPPORTED, message)]


def named_by(entry: dict[str, Any]) -> set[str]:
    """What the entry's facts name: a group, software or campaign that used it, the vendor and product a
    weakness or advisory concerns; "ransomware" when ransomware groups used it. Lower case words."""
    names: set[str] = set()
    for fact in entry.get("facts") or ():
        fact = fact.strip()
        if fact == EvidenceFact.RANSOMWARE:
            names.add("ransomware")
        for pattern, fields in _NAMING_FACTS:
            if found := pattern.fullmatch(fact):
                names |= {word for field in fields for word in _name_words(found[field])}
    return names


def _name_words(name: str) -> Iterator[str]:
    for token in _TOKEN.findall(name):
        if len(token) >= 3 and token.casefold() not in _GENERIC:
            yield token.casefold()


def _citing(text: str, number: int) -> Iterator[str]:
    return (sentence for sentence in _SENTENCE_END.split(text) if number in markers_of(sentence))
