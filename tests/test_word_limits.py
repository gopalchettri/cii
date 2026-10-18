"""The writer's prompt asks for THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT in its slots."""

import pytest

from app.core.config import Settings
from app.core.constants import Writing
from app.domain.scenario import write
from app.domain.scenario.write import WRITER_SYSTEM_PROMPT, with_word_limits


def test_the_writer_asks_for_the_configured_lengths(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(THREAT_SCENARIO_WORD_LIMIT="300-400", RISK_STATEMENT_WORD_LIMIT="150-200")  # type: ignore[call-arg]
    monkeypatch.setattr(write, "get_settings", lambda: settings)
    assert (
        Writing.SCENARIO_WORDS_SLOT in WRITER_SYSTEM_PROMPT
        and Writing.RISK_WORDS_SLOT in WRITER_SYSTEM_PROMPT
    )
    filled = with_word_limits(WRITER_SYSTEM_PROMPT)
    assert "300 to 400 words" in filled and "150 to 200 words" in filled
    assert Writing.SCENARIO_WORDS_SLOT not in filled and Writing.RISK_WORDS_SLOT not in filled


@pytest.mark.parametrize("value", ["400-300", "300", "three hundred", "0-10"])
def test_a_word_limit_that_cannot_be_read_stops_start_up(value: str) -> None:
    with pytest.raises(ValueError):
        Settings(THREAT_SCENARIO_WORD_LIMIT=value)  # type: ignore[call-arg]


def test_the_default_limits_are_the_owners() -> None:
    fields = Settings.model_fields
    defaults = (fields["threat_scenario_word_limit"].default, fields["risk_statement_word_limit"].default)
    assert defaults == ("300-400", "150-200")
