"""The exact checks of an evidence story: no ids in the prose, only
markers [n] of evidence the plan holds, a real-world name from the evidence only with its marker, an
"unknown" vulnerability never stated as the asset's, no echoed instruction, a story of the right length with
its beats. Code checks only what is exact; the AI plan check judges meaning."""

import re

from app.core.constants import (
    FindingCode,
    FindingMessage,
    StoryFindingCode,
    StoryFindingMessage,
    StoryLimits,
)
from app.engine.external_intelligence.injection_patterns import ECHO_PATTERNS
from app.engine.external_intelligence.text_cleaner import ID_IN_TEXT
from app.engine.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.models.external_intelligence.evidence_view import markers_of
from app.models.writing import Finding, WriterBrief

_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
#: A fact that states real-world use: only its names must carry a marker when the story says them.
_REAL_USE = re.compile(
    r"\b(?:used|uses|attributed|campaigns?|observed|deployed|exploited|targeted|groups?|actors?|malware|"
    r"ransomware)\b",
    re.IGNORECASE,
)
_PROPER_NAME = re.compile(r"\b[A-Z][A-Za-z0-9-]{2,}\b")
#: The asset stated as vulnerable, exploitable or affected, as a fact (not "could be", "if it runs ...").
WEAKNESS_CLAIM = re.compile(
    r"\b(?:is|are|was|were|remains?|stays?)\s+(?:currently\s+|already\s+|still\s+)?"
    r"(?:vulnerable|exploitable|affected|unpatched|exposed)\b"
    r"|\b(?:runs?|running|uses?|using|has|have)\s+(?:an?\s+|the\s+)?(?:vulnerable|unpatched|exploitable)\b",
    re.IGNORECASE,
)
CONDITIONAL = re.compile(r"\b(?:if|whether|unless|assuming|provided|in case|should|were)\b", re.IGNORECASE)
#: Capitalised words that name no one (they open a sentence, or stand for any attacker or defender).
_NOT_A_NAME = frozenset({
    "the", "this", "that", "these", "those", "some", "many", "most", "attackers", "adversaries", "actors",
    "groups", "threat", "threats", "malware", "ransomware", "defenders", "operators", "organisations",
    "organizations", "devices", "systems", "vendors",
})  # fmt: skip
_UNKNOWN = "unknown"
_ECHO_SANITISER = UntrustedTextSanitiser(ECHO_PATTERNS, (), ())


def without_ids(text: str) -> str:
    """`text` without any public number or link, for what the model reads (it cannot copy what it never
    sees)."""
    return " ".join(_URL.sub("", ID_IN_TEXT.sub("", text)).replace("()", "").split())


def story_findings(text: str, statement: str, risk: str, brief: WriterBrief) -> list[Finding]:
    """Every exact fault of the story. `text`: every text of the draft (title and assumptions too, for the ids
    and the echo); `statement`: the story itself."""
    findings = [*_id_findings(text, brief), *_marker_findings(text, len(brief.evidence))]
    both = f"{statement}\n{risk}"
    findings += _precedent_findings(both, brief) + _claim_findings(both, brief)
    return findings + _echo_findings(text) + _shape_findings(statement)


def _finding(code: StoryFindingCode, **fields: object) -> Finding:
    return Finding(code, StoryFindingMessage[code.name].format(**fields))


def _id_findings(text: str, brief: WriterBrief) -> list[Finding]:
    """Ids the story's own parts (the asset's and systems' recorded names) did not supply."""
    named = " ".join((brief.asset_name, *brief.entry_point_options, brief.attacker)).casefold()
    found = dict.fromkeys(m[0] for m in ID_IN_TEXT.finditer(text) if m[0].casefold() not in named)
    if not found:
        return []
    message = FindingMessage.UNCITED_ADVISORY_ID.format(ids=", ".join(found))
    return [Finding(FindingCode.UNCITED_ADVISORY_ID, message)]


def _marker_findings(text: str, count: int) -> list[Finding]:
    """A marker must name an evidence entry of the plan (1..count); with no evidence, none is valid."""
    unknown = dict.fromkeys(f"[{n}]" for n in markers_of(text) if not 1 <= n <= count)
    if not unknown:
        return []
    return [_finding(StoryFindingCode.UNKNOWN_MARKER, markers=", ".join(unknown), count=count)]


def _precedent_names(brief: WriterBrief) -> dict[str, set[int]]:
    """Each real-world name the evidence facts state (a group, a malware, a product used in an attack), with
    the numbers of the evidence that states it. A name the asset side of the brief has is its own, not one."""
    text = " ".join(map(str, (brief.asset, brief.systems, brief.attacker, brief.threat))).casefold()
    own = set(re.findall(r"\w+", text))
    names: dict[str, set[int]] = {}
    for number, item in enumerate(brief.evidence, start=1):
        for fact in item["facts"]:
            if not _REAL_USE.search(fact):
                continue
            for match in _PROPER_NAME.finditer(fact):
                if match[0].casefold() not in own | _NOT_A_NAME:
                    names.setdefault(match[0], set()).add(number)
    return names


def _precedent_findings(text: str, brief: WriterBrief) -> list[Finding]:
    """A sentence naming such a real-world name must carry the marker of the evidence that states it."""
    names = _precedent_names(brief)
    unmarked: dict[str, None] = {}
    for sentence in _SENTENCE_END.split(text) if names else ():
        cited = set(markers_of(sentence))
        for name, numbers in names.items():
            if re.search(rf"\b{re.escape(name)}\b", sentence) and not numbers & cited:
                unmarked[name] = None
    if not unmarked:
        return []
    return [_finding(StoryFindingCode.UNMARKED_PRECEDENT, names=", ".join(unmarked))]


def _claim_findings(text: str, brief: WriterBrief) -> list[Finding]:
    """An unconditional "is vulnerable / exploitable / affected" sentence is blocked when the evidence it
    rests on (the entries it cites; with no marker, any entry of the plan) is not known to apply to the
    asset."""
    unknown = {n for n, item in enumerate(brief.evidence, start=1) if item.get("applicability") == _UNKNOWN}
    flagged: dict[str, None] = {}
    for sentence in _SENTENCE_END.split(text) if unknown else ():
        if not WEAKNESS_CLAIM.search(sentence) or CONDITIONAL.search(sentence):
            continue
        cited = set(markers_of(sentence))
        if cited & unknown or not cited:
            flagged.update(dict.fromkeys(f"[{n}]" for n in sorted(cited & unknown or unknown)))
    if not flagged:
        return []
    return [_finding(StoryFindingCode.UNKNOWN_APPLICABILITY_CLAIM, markers=", ".join(flagged))]


def _echo_findings(text: str) -> list[Finding]:
    """A draft that repeats an instruction aimed at an AI system is blocked: the evidence it may have been fed
    is untrusted, and its words must not travel into a scenario. Only the phrases that signal an echoed
    instruction decide (ECHO_PATTERNS), not every phrase that is suspect in a stored source text."""
    if _ECHO_SANITISER.sanitise(text, len(text) + 1).unsafe:
        return [_finding(StoryFindingCode.INJECTION_ECHO)]
    return []


def _shape_findings(statement: str) -> list[Finding]:
    """The story has at least four sentences (five beats; the last two may share one). Its length is the
    writers' shared word limit (word_limits.py, G226)."""
    sentences = len([part for part in _SENTENCE_END.split(statement) if part.strip()])
    if sentences < StoryLimits.MIN_SENTENCES:
        return [_finding(StoryFindingCode.BEATS_MISSING, sentences=sentences)]
    return []
