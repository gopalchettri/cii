"""A specific scenario, checked in code (G229, owner 2026-10-13: "Every scenario must describe a specific,
technically plausible threat event rather than a generic security possibility ... An independent reviewer must
be able to identify the target, attack mechanism, relevant preconditions, and potential consequence"). The
writer returns the scenario's parts (anatomy) in its one answer; code checks each part is there, the target is
the asset or one of its systems and the scenario names it, the mechanism names something of this asset (its
vocabulary, not a word count), no generic line stands in for the action, and no weakness is stated as fact on
nothing recorded or cited. Every finding but a system left unnamed (a warning) is final: no AI call is spent
repairing it. Empty preconditions are allowed."""

import re
from collections.abc import Iterator

from app.core.constants import FindingCode, FindingMessage
from app.engine.external_intelligence.story.evidence_story_rules import CONDITIONAL, WEAKNESS_CLAIM
from app.engine.shared.names import find_name_mentions, name_match_key
from app.models.external_intelligence.evidence_view import markers_of
from app.models.writing import Anatomy, Finding, ScenarioDraft, WriterBrief

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{3,}")
#: Words that name nothing of an asset in particular: a mechanism using only these is not concrete.
_GENERIC = frozenset({
    "system", "systems", "asset", "assets", "data", "network", "networks", "access", "attack", "attacks",
    "attacker", "attackers", "could", "would", "with", "from", "this", "that", "their", "into", "over",
    "using", "used", "through", "platform", "service", "services", "operations",
})  # fmt: skip
#: The narrow set of lines that state no action (a specific "exploit a weakness in the X firmware" passes).
_VAGUE = (
    re.compile(
        r"\b(?:may|might|could)\s+exploit\s+(?:\w+\s+)?vulnerabilit(?:y|ies)\b(?!\s+(?:in|of)\b)", re.I
    ),
    re.compile(r"\bunauthori[sz]ed access (?:could|may|might) (?:occur|happen|be gained)\b", re.I),
    re.compile(r"\bcompromise the system\b", re.I),
    re.compile(r"\bvarious (?:attacks|methods|techniques|vulnerabilities)\b", re.I),
    re.compile(r"\b(?:gain|gains|obtain|obtains) unauthori[sz]ed access\b(?!\s+to\b)", re.I),
)
_PARTS = ("target", "entry_point", "mechanism", "consequence")


def anatomy_findings(draft: ScenarioDraft, brief: WriterBrief) -> list[Finding]:
    """Every specificity fault of `draft`, in the order a reviewer reads them."""
    findings = _part_findings(draft.anatomy, draft.statement, brief)
    text = f"{draft.statement}\n{draft.risk}"
    if phrases := [found[0] for pattern in _VAGUE for found in pattern.finditer(text)]:
        message = FindingMessage.VAGUE_PHRASE.format(phrases=", ".join(f'"{p}"' for p in phrases))
        findings.append(Finding(FindingCode.VAGUE_PHRASE, message))
    if claims := list(_unsupported_weaknesses(text)):
        message = FindingMessage.UNSUPPORTED_WEAKNESS.format(claims=" | ".join(claims))
        findings.append(Finding(FindingCode.UNSUPPORTED_WEAKNESS, message))
    missing = [
        s.name for s in brief.supporting_systems if s.applicable and not _names(s.name, draft.statement)
    ]
    if missing:
        message = FindingMessage.APPLICABLE_SYSTEM_NOT_IN_STORY.format(systems=", ".join(missing))
        findings.append(Finding(FindingCode.APPLICABLE_SYSTEM_NOT_IN_STORY, message))
    return findings


def _part_findings(anatomy: Anatomy | None, statement: str, brief: WriterBrief) -> list[Finding]:
    """The parts given, the target one of this asset's and named, the mechanism concrete."""
    if anatomy is None or (missing := [part for part in _PARTS if not getattr(anatomy, part)]):
        parts = ", ".join(_PARTS if anatomy is None else missing)
        return [Finding(FindingCode.ANATOMY_MISSING, FindingMessage.ANATOMY_MISSING.format(parts=parts))]
    findings = []
    known = (brief.asset_name, *(system.name for system in brief.supporting_systems))
    target = next((name for name in known if _same_thing(name, anatomy.target)), None)
    if target is None or not _names(target, statement):
        findings.append(
            Finding(
                FindingCode.TARGET_NOT_NAMED, FindingMessage.TARGET_NOT_NAMED.format(target=anatomy.target)
            )
        )
    if not _words(anatomy.mechanism) & _vocabulary(brief):
        findings.append(Finding(FindingCode.MECHANISM_NOT_CONCRETE, FindingMessage.MECHANISM_NOT_CONCRETE))
    return findings


def _same_thing(name: str, target: str) -> bool:
    key, given = name_match_key(name), name_match_key(target)
    return bool(key) and (key in given or given in key)


def _names(name: str, text: str) -> bool:
    return bool(find_name_mentions(name, text, halves=True))


def _vocabulary(brief: WriterBrief) -> set[str]:
    """What this asset's brief names: the asset, its systems and their recorded facts, the threat, the entry
    points. A mechanism naming none of it could be about any asset."""
    texts = [brief.asset_name, brief.threat, brief.threat_type, *brief.entry_point_options]
    texts += [str(value) for value in brief.asset.values() if isinstance(value, str | list)]
    for system in brief.systems:
        texts += [str(value) for value in system.values() if isinstance(value, str | list)]
    texts += [system.name for system in brief.supporting_systems]
    return set().union(*(_words(text) for text in texts))


def _words(text: str) -> set[str]:
    return {word.casefold() for word in _WORD.findall(text)} - _GENERIC


def _unsupported_weaknesses(text: str) -> Iterator[str]:
    """A weakness stated as fact (not "could", "if it runs ...") with no marker of evidence beside it: nothing
    recorded or cited supports it (a marked one is the story rules' to judge)."""
    for sentence in _SENTENCE_END.split(text):
        found = WEAKNESS_CLAIM.search(sentence)
        if found and not CONDITIONAL.search(sentence) and not markers_of(sentence):
            yield found[0]
