"""The writer's prompt asks for THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT in its slots, the
upper number as a hard limit; EVIDENCE_STATEMENT_WORD_LIMIT caps code's own evidence sentence."""

import pytest

from app.core.config import Settings
from app.core.constants import Writing
from app.domain.scenario import write
from app.domain.scenario.write import WRITER_SYSTEM_PROMPT, with_word_limits

KEYS = ("THREAT_SCENARIO_WORD_LIMIT", "RISK_STATEMENT_WORD_LIMIT", "EVIDENCE_STATEMENT_WORD_LIMIT")


def test_the_writer_asks_for_the_configured_lengths(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(  # type: ignore[call-arg]
        THREAT_SCENARIO_WORD_LIMIT="150-200",
        RISK_STATEMENT_WORD_LIMIT="100-150",
        EVIDENCE_STATEMENT_WORD_LIMIT="30-80",
    )
    monkeypatch.setattr(write, "get_settings", lambda: settings)
    slots = (Writing.SCENARIO_WORDS_SLOT, Writing.RISK_WORDS_SLOT)
    assert all(slot in WRITER_SYSTEM_PROMPT for slot in slots)
    filled = with_word_limits(WRITER_SYSTEM_PROMPT)
    assert "150 to 200 WORDS, NEVER MORE" in filled and "100 to 150 WORDS, NEVER MORE" in filled
    assert "30 to 80" not in filled  # D65: the evidence sentence is code's, its limit checked by code
    assert "The upper number of each range is a hard limit." in filled
    assert not any(slot in filled for slot in slots)


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("value", ["400-300", "300", "three hundred", "0-10"])
def test_a_word_limit_that_cannot_be_read_stops_start_up(key: str, value: str) -> None:
    with pytest.raises(ValueError):
        Settings(**{key: value})  # type: ignore[call-arg]


def test_the_default_limits_are_the_owners() -> None:
    """Owner 2026-10-19: 150-200 for the scenario, 100-150 for the risk, 30-80 for the evidence passage."""
    fields = Settings.model_fields
    names = ("threat_scenario_word_limit", "risk_statement_word_limit", "evidence_statement_word_limit")
    assert tuple(fields[name].default for name in names) == ("150-200", "100-150", "30-80")
