"""How long a scenario's texts are (owner 2026-10-13, G226: "risk statement and threat scenario words should
be configurable"): THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT, for both writers. The prompts ask
for the ranges (their slots are filled here); a text far outside its range is a warning finding, so the
writer rewrites it once, and it is never blocked."""

import math

from app.core.config import get_settings
from app.core.constants import FindingCode, FindingMessage, Writing
from app.models.writing import Finding, ScenarioDraft


def with_word_limits(template: str) -> str:
    """`template` (an approved system prompt) with the configured ranges in its slots: "300 to 400"."""
    settings = get_settings()
    return template.replace(Writing.SCENARIO_WORDS_SLOT, _spoken(settings.scenario_words)).replace(
        Writing.RISK_WORDS_SLOT, _spoken(settings.risk_words)
    )


def length_findings(draft: ScenarioDraft) -> list[Finding]:
    """The scenario statement and the risk statement each within its range, with the margin
    (Writing.WORDS_BELOW_SHARE of the minimum, WORDS_ABOVE_SHARE of the maximum)."""
    settings = get_settings()
    checks = (
        (FindingCode.STATEMENT_LENGTH, "scenario statement", draft.statement, settings.scenario_words),
        (FindingCode.RISK_LENGTH, "risk statement", draft.risk, settings.risk_words),
    )
    findings = []
    for code, text, written, (least, most) in checks:
        words = len(written.split())
        low, high = math.ceil(least * Writing.WORDS_BELOW_SHARE), math.floor(most * Writing.WORDS_ABOVE_SHARE)
        if not low <= words <= high:
            message = FindingMessage.TEXT_LENGTH.format(text=text, words=words, least=least, most=most)
            findings.append(Finding(code, message))
    return findings


def _spoken(limits: tuple[int, int]) -> str:
    return f"{limits[0]} to {limits[1]}"
