"""G252 (owner 2026-10-15: "if we need to make the rule a little loose I am okay with it"): a story blocked
ONLY by footnote faults (a citation its source does not support, a marker without its claim, a local incident
told from regional intelligence) is repaired in code instead of thrown away whole. A flagged footnote on a
sentence that says something happened, or that names what its source names, goes with that sentence: a false
real-world claim is never shown. On a plain attack step only the marker goes: the step stays a possibility.
The repaired story is checked by the code rules again (no AI call); still blocked, it is left as it was. Its
remaining footnotes stay; with none left, the card shows the closest source instead (G250). Measured on the
last 14 runs of asset 1166: 22 of 36 lost stories were lost only so."""

import re
from dataclasses import replace

from app.core.constants import FindingCode, FindingMessage, FindingSeverity
from app.engine.scenarios.writing.evidence_checks import named_by, says_it_happened
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.models.external_intelligence.evidence_view import markers_of
from app.models.writing import Finding, ScenarioDraft, WriterBrief, WrittenScenario

#: The faults a repair removes; any other blocker leaves the story as it was.
FOOTNOTE_FAULTS = frozenset(
    {
        FindingCode.CITATION_UNSUPPORTED,
        FindingCode.EVIDENCE_LINK_MISSING,
        FindingCode.COUNTRY_CLAIM_UNSUPPORTED,
    }
)
#: The plan check's own notes: kept as they were (the repair asks no AI call to check again).
_PLAN_NOTES = frozenset({FindingCode.PLAN_CHECK, FindingCode.PLAN_CHECK_NOT_MADE})
_SENTENCE = re.compile(r"[^.!?]*(?:[.!?]+|$)\s*")  # each sentence with the space after it
_MARKER = re.compile(r"(\s?)\[(\d+(?:\s*,\s*\d+)*)\]")
_WORD = re.compile(r"[A-Za-z0-9-]+")


def repair_citations(
    written: WrittenScenario, brief: WriterBrief, attackers: tuple[str, ...]
) -> WrittenScenario:
    """`written` with its flagged footnotes removed when they are its only serious faults and what is left
    passes the code rules; else `written` unchanged."""
    blockers = [finding for finding in written.findings if finding.severity == FindingSeverity.BLOCKER]
    flagged = {number for finding in blockers for number in finding.markers}
    if not flagged or any(finding.code not in FOOTNOTE_FAULTS for finding in blockers):
        return written
    draft = _without(written.draft, flagged, brief)
    findings, route = check_exact_rules(draft, brief, attackers)
    if any(finding.severity == FindingSeverity.BLOCKER for finding in findings):
        return written
    notes = tuple(finding for finding in written.findings if finding.code in _PLAN_NOTES)
    markers = ", ".join(f"[{number}]" for number in sorted(flagged))
    removed = Finding(FindingCode.CITATION_REMOVED, FindingMessage.CITATION_REMOVED.format(markers=markers))
    return replace(written, draft=draft, findings=(*findings, *notes, removed), route=route)


def _without(draft: ScenarioDraft, flagged: set[int], brief: WriterBrief) -> ScenarioDraft:
    """The draft without the flagged footnotes: the sentences claiming a past event with them go, a plain
    step only loses its marker; their claims (evidence_links) go too."""
    names = {n: named_by(brief.evidence[n - 1]) for n in flagged if 1 <= n <= len(brief.evidence)}

    def repaired(text: str) -> str:
        kept = []
        for sentence in filter(None, _SENTENCE.findall(text)):
            marked = set(markers_of(sentence)) & flagged
            if marked and _claims_what_happened(sentence, marked, names):
                continue
            kept.append(_unmarked(sentence, flagged) if marked else sentence)
        return "".join(kept).strip()

    links = tuple((number, claim) for number, claim in draft.evidence_links if number not in flagged)
    return replace(
        draft, statement=repaired(draft.statement), risk=repaired(draft.risk), evidence_links=links
    )


def _claims_what_happened(sentence: str, marked: set[int], names: dict[int, set[str]]) -> bool:
    """The sentence says something happened, or names what one of its flagged sources names."""
    said = {word.casefold() for word in _WORD.findall(sentence)}
    return says_it_happened(sentence) or any(names.get(number, set()) & said for number in marked)


def _unmarked(sentence: str, flagged: set[int]) -> str:
    """The sentence without the flagged numbers ("[1, 2]" with 1 flagged keeps "[2]")."""

    def keep(match: re.Match[str]) -> str:
        left = [n for n in re.split(r"\s*,\s*", match.group(2)) if int(n) not in flagged]
        return f"{match.group(1)}[{', '.join(left)}]" if left else ""

    return _MARKER.sub(keep, sentence)
