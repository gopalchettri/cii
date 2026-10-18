"""G227 (owner 2026-10-13): a scenario's statement and risk reach the remediation plan whole up to
Remediation.STATEMENT_MAX_CHARS (a 300-400-word scenario was cut at 2,000 and lost its impact), every other
free-text value keeps TEXT_MAX_CHARS, a cut is always marked, and a second clip changes nothing."""

import pytest

from app.core.constants import Remediation
from app.domain.remediation.register import clip
from app.domain.remediation.snapshot import _scenario

MARK = Remediation.TRUNCATED_MARK


def _words(size: int) -> str:
    """Ordinary prose of exactly `size` characters (one long run of letters would read as a secret)."""
    return ("the grid could stop " * (size // 20 + 1))[:size]


@pytest.mark.parametrize(("size", "cut"), [(1_999, False), (2_000, False), (2_001, True)])
def test_other_free_text_keeps_its_2000_limit(size: int, cut: bool) -> None:
    clipped = clip(_words(size))
    assert clipped is not None and clipped.endswith(MARK) is cut
    assert len(clipped) == (Remediation.TEXT_MAX_CHARS + len(MARK) if cut else size)


@pytest.mark.parametrize(("size", "cut"), [(3_000, False), (3_999, False), (4_000, False), (4_001, True)])
def test_a_statement_and_a_risk_reach_the_plan_whole_up_to_4000(size: int, cut: bool) -> None:
    text = _words(size)
    shown = _scenario({"title": "t", "statement": text, "risk_statement": text})
    for value in (shown["statement"], shown["risk_statement"]):
        assert value is not None and value.endswith(MARK) is cut
        assert value == (text[: Remediation.STATEMENT_MAX_CHARS] + MARK if cut else text)


def test_a_second_clip_changes_nothing_and_odd_text_is_kept_as_it_is() -> None:
    once = clip("é" * 2_500)
    assert once is not None and clip(once) == once and once.count(MARK) == 1
    assert clip("") == "" and clip("   ") == "   " and clip(None) is None
    assert clip("日本語のテキスト") == "日本語のテキスト"
