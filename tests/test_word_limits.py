"""G226 (owner 2026-10-13: "risk statement and threat scenario words should be configurable"): both writers
ask for THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT; a text far outside its range (under half the
minimum, over the maximum by a tenth) is a warning the writer rewrites once, never a blocker."""

import pytest

from app.core.config import Settings
from app.core.constants import FINDING_SEVERITIES, FindingCode, FindingSeverity, Writing
from app.engine.external_intelligence.story.evidence_story_texts import STORY_WRITER_SYSTEM_PROMPT
from app.engine.scenarios.writing import word_limits
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.engine.scenarios.writing.writing_prompts import WRITER_SYSTEM_PROMPT
from app.models.writing import ScenarioDraft
from tests.test_scenario_writing import _CLEAN, _brief_of, _plan_threat


@pytest.fixture
def owner_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(THREAT_SCENARIO_WORD_LIMIT="300-400", RISK_STATEMENT_WORD_LIMIT="150-200")  # type: ignore[call-arg]
    monkeypatch.setattr(word_limits, "get_settings", lambda: settings)


def _words(count: int) -> str:
    return " ".join(["word"] * count)


@pytest.mark.usefixtures("owner_limits")
def test_both_writers_ask_for_the_configured_lengths() -> None:
    for template in (WRITER_SYSTEM_PROMPT, STORY_WRITER_SYSTEM_PROMPT):
        assert Writing.SCENARIO_WORDS_SLOT in template and Writing.RISK_WORDS_SLOT in template
        filled = word_limits.with_word_limits(template)
        assert "300 to 400 words" in filled and "150 to 200 words" in filled
        assert Writing.SCENARIO_WORDS_SLOT not in filled and Writing.RISK_WORDS_SLOT not in filled


@pytest.mark.usefixtures("owner_limits")
@pytest.mark.parametrize(
    ("statement", "risk", "expected"),
    [
        (300, 150, []),
        (150, 75, []),  # half the minimum: still inside the margin
        (440, 220, []),  # the maximum and a tenth: still inside
        (149, 150, [FindingCode.STATEMENT_LENGTH]),
        (441, 150, [FindingCode.STATEMENT_LENGTH]),
        (300, 74, [FindingCode.RISK_LENGTH]),
        (300, 221, [FindingCode.RISK_LENGTH]),
    ],
)
def test_a_text_far_outside_its_limit_is_a_finding(statement: int, risk: int, expected: list[str]) -> None:
    draft = ScenarioDraft("Loss of control", _words(statement), _words(risk), (), "")
    assert [finding.code for finding in word_limits.length_findings(draft)] == expected


def test_length_is_a_warning_the_writer_rewrites_never_a_blocker() -> None:
    codes = (FindingCode.STATEMENT_LENGTH, FindingCode.RISK_LENGTH)
    assert {FINDING_SEVERITIES[code] for code in codes} == {FindingSeverity.WARNING}


@pytest.mark.usefixtures("owner_limits")
def test_the_writers_rules_check_it() -> None:
    findings, _ = check_exact_rules(_CLEAN, _brief_of(_plan_threat()), [])
    codes = {finding.code for finding in findings}
    assert {FindingCode.STATEMENT_LENGTH, FindingCode.RISK_LENGTH} <= codes  # the clean sample is a few words


@pytest.mark.parametrize("value", ["400-300", "300", "three hundred", "0-10"])
def test_a_word_limit_that_cannot_be_read_stops_start_up(value: str) -> None:
    with pytest.raises(ValueError):
        Settings(THREAT_SCENARIO_WORD_LIMIT=value)  # type: ignore[call-arg]


def test_the_default_limits_are_the_owners() -> None:
    fields = Settings.model_fields
    defaults = (fields["threat_scenario_word_limit"].default, fields["risk_statement_word_limit"].default)
    assert defaults == ("300-400", "150-200")
