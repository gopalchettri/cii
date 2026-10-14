"""The exact checks of a cleaned scenario (approved prompts v2 "Findings").
Code checks only what is exact -- names, labels and numbers -- and the AI plan check judges meaning.
A finding's severity comes from FINDING_SEVERITIES: only an internal label or an uncited
advisory number blocks a scenario.

Not checked here, because they cannot happen:
- another entity's data: the brief holds only this run's frozen facts, checked against the caller's entity
  when the run started, so no other entity's data reaches the writer;
- an empty assumption: the clean-up drops it."""

import re
from collections.abc import Iterable, Sequence

from app.core.constants import FindingCode, FindingMessage, Route, WriterStyle
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.external_intelligence.story.evidence_story_rules import story_findings
from app.engine.scenarios.writing.anatomy_rules import anatomy_findings
from app.engine.scenarios.writing.evidence_checks import evidence_findings
from app.engine.scenarios.writing.word_limits import length_findings
from app.engine.scenarios.writing.writing_prompts import brief_text
from app.engine.shared.names import find_name_mentions
from app.models.writing import Finding, ScenarioDraft, WriterBrief

#: The planner's aliases and slots (SYS1, THR7): never in a brief, so one in a scenario was made up.
_INTERNAL_LABEL = re.compile(r"\b(?:SYS|THR)\d+\b")
#: A public advisory number: CVE, CISA ICS advisory (ICSA, ICSMA), GitHub (GHSA), Microsoft bulletin, CERT/CC.
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3})\b|\bVU#\d+",
    re.IGNORECASE,
)
#: In a sentence naming two of the scenario's systems, a phrase claiming the link the platform never records
#: (approved writer rule 4). Verb forms only, so "password", "router", "routine" or a "protection relay" are
#: never read as a link (S16-S31 review).
_TOWARDS = r"\s+(?:to|from|through|between|into|onto|via)\b"
_LINK_WORD = re.compile(
    r"\b(?:between|connect(?:s|ed|ing|ion|ions)?|link(?:s|ed|ing)?|reach(?:es|ed|ing)?|depend(?:s|ed|ing|ent)?"
    r"\s+on|via|through|pivot(?:s|ed|ing)?|travers(?:e|es|ed|ing)|propagat(?:e|es|ed|ing)"
    rf"|(?:pass(?:es|ed|ing)?|relay(?:s|ed|ing)?|rout(?:e|es|ed|ing)|bridg(?:e|es|ed|ing)|spread(?:s|ing)?){_TOWARDS}"
    r"|mov(?:e|es|ed|ing)\s+(?:from|to|into|onto))\b",
    re.IGNORECASE,
)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")

Span = tuple[int, int]


@traced("writing.rules")
def check_exact_rules(
    draft: ScenarioDraft, brief: WriterBrief, attackers: Iterable[str]
) -> tuple[tuple[Finding, ...], Route]:
    """Every exact finding of `draft`, and its route: `unknown` when it claims a link between two of its
    systems, else `standalone`. `attackers`: every library attacker's name."""
    text = "\n".join((draft.title, draft.statement, draft.risk, *draft.assumptions))
    findings = [
        *_blockers(text, brief_text(brief).casefold()),
        *_naming_warnings(draft, brief, text, attackers),
        *length_findings(draft),  # both writers: THREAT_SCENARIO / RISK_STATEMENT_WORD_LIMIT (G226)
        *anatomy_findings(draft, brief),  # both writers: specific, its parts stated (G229)
    ]
    findings += _story_findings(draft, brief, text, findings)
    linked = _linked_systems(draft, brief)
    if linked:
        message = FindingMessage.SYSTEM_LINK_CLAIMED.format(systems=" and ".join(linked))
        findings.append(Finding(FindingCode.SYSTEM_LINK_CLAIMED, message))
    route = Route.UNKNOWN if linked else Route.STANDALONE
    if step_detail_enabled():
        _trace_rules(brief.threat, draft.title, findings, route)
    return tuple(findings), route


def _story_findings(
    draft: ScenarioDraft, brief: WriterBrief, text: str, found: list[Finding]
) -> list[Finding]:
    """An evidence story's own exact rules (none for the original writer); an advisory number the base rules
    already found is not reported twice."""
    if brief.style is not WriterStyle.EVIDENCE_STORY:
        return []
    already = any(finding.code == FindingCode.UNCITED_ADVISORY_ID for finding in found)
    story = story_findings(text, draft.statement, draft.risk, brief)
    kept = [f for f in story if not (already and f.code == FindingCode.UNCITED_ADVISORY_ID)]
    return kept + evidence_findings(draft, brief)  # G229: mandatory, supported evidence


def _trace_rules(threat: str, title: str, findings: list[Finding], route: Route) -> None:
    shown = ", ".join(f"{finding.code} ({finding.severity})" for finding in findings) or "none"
    record_detail("rules", threat, given={"title": title}, produced={"findings": shown, "route": str(route)})


def _blockers(text: str, given: str) -> list[Finding]:
    """`given`: the brief's own text, case-folded. A label or number found in it was supplied, not made up
    (a system named "MicroSCADA Pro SYS600", a CVE in a system's recorded incidents)."""
    findings = []
    labels = _unsupplied_matches(_INTERNAL_LABEL, text, given)
    if labels:
        findings.append(Finding(FindingCode.UNKNOWN_ID, FindingMessage.UNKNOWN_ID.format(labels=labels)))
    # ponytail: every advisory number the brief does not give is uncited here; the ids of the evidence block
    # are judged by the story rules (engine/external_intelligence/story).
    advisories = _unsupplied_matches(_ADVISORY_ID, text, given)
    if advisories:
        message = FindingMessage.UNCITED_ADVISORY_ID.format(ids=advisories)
        findings.append(Finding(FindingCode.UNCITED_ADVISORY_ID, message))
    return findings


def _naming_warnings(
    draft: ScenarioDraft, brief: WriterBrief, text: str, attackers: Iterable[str]
) -> list[Finding]:
    """The naming warnings: the asset in the statement and the risk, the acting attacker in the statement,
    no other attacker and no system outside the scenario anywhere."""
    findings = []
    if not find_name_mentions(brief.asset_name, draft.statement):
        message = FindingMessage.ASSET_NOT_IN_STATEMENT.format(asset=brief.asset_name)
        findings.append(Finding(FindingCode.ASSET_NOT_IN_STATEMENT, message))
    if not find_name_mentions(brief.asset_name, draft.risk):
        message = FindingMessage.ASSET_NOT_IN_RISK.format(asset=brief.asset_name)
        findings.append(Finding(FindingCode.ASSET_NOT_IN_RISK, message))
    if not find_name_mentions(brief.attacker, draft.statement, halves=True):
        message = FindingMessage.ATTACKER_NOT_NAMED.format(attacker=brief.attacker)
        findings.append(Finding(FindingCode.ATTACKER_NOT_NAMED, message))
    # What the scenario may name: the acting attacker, the asset (it must) and its own systems. Another name
    # only inside one of these is that name, never another attacker or system ("SCADA" in "Plant SCADA").
    own = find_name_mentions(brief.attacker, text, halves=True) + [
        span
        for name in (brief.asset_name, *brief.entry_point_options)
        for span in find_name_mentions(name, text)
    ]
    others = _named_outside([name for name in attackers if name != brief.attacker], text, own)
    if others:
        message = FindingMessage.OTHER_ATTACKER_NAMED.format(names=", ".join(others), attacker=brief.attacker)
        findings.append(Finding(FindingCode.OTHER_ATTACKER_NAMED, message))
    outside = _named_outside(brief.other_systems, text, own)
    if outside:
        message = FindingMessage.SYSTEM_OUT_OF_SCOPE.format(names=", ".join(outside))
        findings.append(Finding(FindingCode.SYSTEM_OUT_OF_SCOPE, message))
    return findings


def _named_outside(names: Sequence[str], text: str, allowed: list[Span]) -> list[str]:
    """The `names` the text says somewhere other than inside an allowed name ("SCADA" within "SCADA server"
    is the scenario's own system, not another one called "SCADA")."""
    return [
        name
        for name in names
        if any(
            not any(a <= start and end <= b for a, b in allowed)
            for start, end in find_name_mentions(name, text)
        )
    ]


def _linked_systems(draft: ScenarioDraft, brief: WriterBrief) -> list[str]:
    """The scenario's systems one sentence names together with a link word; [] when none does."""
    if len(brief.entry_point_options) < 2:
        return []
    for sentence in _SENTENCE_END.split(" ".join((draft.statement, draft.risk, *draft.assumptions))):
        named = [name for name in brief.entry_point_options if find_name_mentions(name, sentence)]
        if len(named) >= 2 and _LINK_WORD.search(sentence):
            return named
    return []


def _unsupplied_matches(pattern: re.Pattern[str], text: str, given: str) -> str:
    """Each match the brief did not supply, once, in order, joined for a message ('' when none)."""
    found = (match[0] for match in pattern.finditer(text) if match[0].casefold() not in given)
    return ", ".join(dict.fromkeys(found))
