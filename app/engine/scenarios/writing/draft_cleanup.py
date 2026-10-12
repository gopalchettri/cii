"""A written scenario cleaned in code, before any check:
- the title loses every framework name or code and every asset, system and attacker name (rule 8);
- "Because X, Y." in the risk statement becomes "Y, because X." (owner, 2026-10-06), or, when it does not
  split cleanly, "This risk exists because X, Y." (the owner-approved fallback);
- technique codes, report hashes and GUIDs leave every text; blank or repeated assumptions go.
Advisory numbers (CVE ...) are left in the text: the rules block a scenario that cites one never supplied."""

import re
from collections.abc import Iterable

from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.scenarios.writing.writing_prompts import brief_text
from app.engine.shared.names import TECHNIQUE_CODE, find_name_mentions, name_variants
from app.models.writing import ScenarioDraft, WriterBrief

#: A framework or library code by its shape: capitals next to digits ("T0839", "CVE-2024-1234", "CIP-007"),
#: or a numbered reference ("800-82", "1.2.3") (v1 naming.FRAMEWORK_CODE_RX, proven on v1's cards).
_FRAMEWORK_CODE = re.compile(
    r"(?<![\w&.-])(?:(?:[A-Za-z0-9]+[.:-])*[A-Z]+[-_/]?\d\w*(?:[-.:/]\w+)*(?:\(\d{1,3}\))?"
    r"|\d+(?:[-:]\d+)+|\d+(?:\.\d+){2,})(?![\w&])"
)
#: Framework names a title never shows, with the version or number after them (v1 naming.FRAMEWORK_NAMES).
#: Case-sensitive, so "FAIR" is the framework and "fair" a word.
_FRAMEWORK_NAMES = (
    "MITRE ATT&CK", "ATT&CK", "MITRE", "ATLAS", "D3FEND", "EMB3D", "CAPEC", "CWE", "CVE", "CVSS", "NVD",
    "KEV", "CISA", "ICS-CERT", "NIST", "CSF", "OWASP Top 10", "OWASP", "ASVS", "SANS", "STRIDE", "DREAD",
    "PASTA", "LINDDUN", "OCTAVE", "FAIR", "CIS Controls", "CIS Benchmarks", "CIS Benchmark", "NERC", "CIP",
    "PCI DSS", "PCI", "HIPAA", "HITRUST", "GDPR", "SOC 2", "COBIT", "ITIL", "CMMC", "FedRAMP",
    "Cyber Kill Chain", "Unified Kill Chain", "Kill Chain", "Diamond Model", "Purdue Model", "Purdue",
    "ENISA", "NCSC", "MISP", "OTX", "AlienVault", "STIX", "TAXII",
)  # fmt: skip
#: Standards bodies are a framework only WITH their standard ("IEC 62443-3-3"): a bare "ISO" may be a grid's
#: Independent System Operator.
_BODIES = "ISO|IEC|ISA|IEEE|ANSI"
_NAMES = "|".join(re.escape(name) for name in sorted(_FRAMEWORK_NAMES, key=len, reverse=True))
_FRAMEWORK_NAME = re.compile(
    rf"(?<![\w&])(?:(?:{_NAMES})(?:\s*[/&]\s*(?:{_NAMES}|{_BODIES}))*(?:\s+SP)?(?:\s+v?\d[\w.:/-]*)?"
    rf"|(?:{_BODIES})(?:\s*[/&]\s*(?:{_BODIES}))*[\s-]+\d[\w.:/-]*)(?![\w&])"
)
#: The words tying a removed name to the title ("theft by an insider", "access via the RTU"), removed with it.
_TIED_BEFORE = re.compile(
    r"(?:\b(?:by|from|via|through|using|with|involving|attributed to|linked to|led by)\s+)?"
    r"(?:\b(?:a|an|the)\s+)?$",
    re.IGNORECASE,
)
#: A word no title ends on once what followed it is gone ("loss of control at").
_DANGLING_WORD = re.compile(
    r"\s+(?:by|from|via|through|using|with|involving|in|of|for|on|at|against|to|into|within|across|per|"
    r"and|or|the|a|an)(?=\s*(?:[,;:)\]–—-]|$))",
    re.IGNORECASE,
)
#: A technique code, a GUID or a report hash: opaque to a reader, never in a scenario's text.
_OPAQUE_CODE = re.compile(
    rf"(?<![\w.-])(?:{TECHNIQUE_CODE}|CAPEC-\d+|TID-\d+"
    r"|[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{32,})(?![\w-])"
)
_EMPTY_BRACKETS = re.compile(r"\s*[(\[][\s,;:]*[)\]]")
_BECAUSE_OPENER = re.compile(r"\s*because\s+", re.IGNORECASE)
#: Words that cannot open a main clause: after one, the first comma was inside the reason.
_NOT_A_MAIN_CLAUSE = frozenset(
    {"which", "who", "whom", "whose", "that", "where", "when", "and", "or", "but", "nor", "including",
    "such", "as", "then"}
)  # fmt: skip
#: The owner-approved opening when "Because X, Y." cannot be turned around cleanly.
_FALLBACK_OPENING = "This risk exists because "


@traced("writing.clean")
def clean_draft(draft: ScenarioDraft, brief: WriterBrief, attackers: Iterable[str]) -> ScenarioDraft:
    """The draft as it is checked and saved. `attackers`: every library attacker's name."""
    names = _names_kept_out_of_titles(brief, attackers)
    given = brief_text(brief).casefold()
    assumptions = (_without_opaque_codes(assumption, given) for assumption in draft.assumptions)
    fallback = clean_title(brief.threat, names, str(brief.category))
    risk = _without_opaque_codes(draft.risk, given)
    cleaned = ScenarioDraft(
        title=clean_title(draft.title, names, fallback),
        statement=_without_opaque_codes(draft.statement, given),
        risk=lead_with_consequence(risk),
        assumptions=tuple(dict.fromkeys(assumption for assumption in assumptions if assumption)),
        entry_point=draft.entry_point,
    )
    if step_detail_enabled():
        _trace_cleanup(brief.threat, draft, cleaned, fallback, risk != cleaned.risk, given)
    return cleaned


def _trace_cleanup(
    threat: str, draft: ScenarioDraft, cleaned: ScenarioDraft, fallback: str, reordered: bool, given: str
) -> None:
    """`given`: the brief's text, case-folded (a code found in it is kept, not removed)."""
    texts = (draft.statement, draft.risk, *draft.assumptions)
    removed = any(code[0].casefold() not in given for text in texts for code in _OPAQUE_CODE.finditer(text))
    produced = {
        "title_before": draft.title,
        "title_after": cleaned.title,
        "title_fallback_used": cleaned.title == fallback,  # ponytail: also true if the title cleans to it
        "risk_reordered": reordered,
        "codes_removed": removed,
    }
    record_detail("clean-up", threat, given={"fallback_title": fallback}, produced=produced)


def title_suffix(brief: WriterBrief, attackers: Iterable[str]) -> str:
    """What a title carries in brackets to tell two same-titled scenarios of a run apart (title_candidates):
    the threat's name cleaned as a title is (no framework, asset, system or attacker name), or the category
    when nothing of the name is left."""
    return clean_title(brief.threat, _names_kept_out_of_titles(brief, attackers), str(brief.category))


def _names_kept_out_of_titles(brief: WriterBrief, attackers: Iterable[str]) -> tuple[str, ...]:
    """The asset, every system of the run, every library attacker, and the acting attacker's halves."""
    return (
        brief.asset_name,
        *brief.entry_point_options,
        *brief.other_systems,
        *attackers,
        *name_variants(brief.attacker, halves=True),
    )


def clean_title(title: str, names: Iterable[str], fallback: str) -> str:
    """`title` without framework names or codes and without any of `names`, each with the words tying it in;
    `fallback` when nothing is left."""
    spans = [match.span() for rx in (_FRAMEWORK_CODE, _FRAMEWORK_NAME) for match in rx.finditer(title)]
    spans += [span for name in names if name for span in find_name_mentions(name, title)]
    text = title
    for start, end in reversed(
        _merge_overlapping_spans(spans)
    ):  # right to left: the spans still to cut keep their offsets
        text = _TIED_BEFORE.sub("", text[:start]) + " " + text[end:]
    text = _tidy_spacing(re.sub(r"(?<!\w)['’]s\b", "", text))
    while (shorter := _DANGLING_WORD.sub("", text)) != text:
        text = shorter
    text = text.strip(" ,;:|.–—-")
    return text[:1].upper() + text[1:] if text else fallback


def lead_with_consequence(risk: str) -> str:
    """ "Because X, Y. Rest" → "Y, because X. Rest"; "This risk exists because X ..." when the first sentence
    does not split cleanly at its first comma (no comma, or one inside the reason: "Because the RTU, which
    ..."). A risk statement not opening with "Because" comes back unchanged."""
    opener = _BECAUSE_OPENER.match(risk)
    if opener is None:
        return risk
    body = risk[opener.end() :]
    stop = re.search(r"[.!?](?=\s|$)", body)
    first, rest = (body[: stop.start()], body[stop.start() :]) if stop else (body.rstrip(), "")
    reason, comma, main = first.partition(",")
    main = main.strip()
    if comma and reason.strip() and main and main.split()[0].lower() not in _NOT_A_MAIN_CLAUSE:
        return f"{main[0].upper()}{main[1:]}, because {reason.strip()}{rest or '.'}"
    return _FALLBACK_OPENING + body


def _without_opaque_codes(text: str, given: str) -> str:
    """`text` without the codes the brief did not supply (`given`: its text, case-folded)."""
    return _tidy_spacing(_OPAQUE_CODE.sub(lambda code: code[0] if code[0].casefold() in given else "", text))


def _tidy_spacing(text: str) -> str:
    """Brackets left empty removed, no space before punctuation, single spaces."""
    text = _EMPTY_BRACKETS.sub("", text)
    text = re.sub(r"([(\[])[\s,;:]+", r"\1", text)
    text = re.sub(r"[\s,;:]+([)\]])", r"\1", text)
    return " ".join(re.sub(r"\s+([,;:.!?)\]])", r"\1", text).split())


def _merge_overlapping_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
