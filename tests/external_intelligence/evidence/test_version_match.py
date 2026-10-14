"""The version comparator: understood forms only, never a guess (spec rule: unknown stays unknown)."""

from typing import Any

import pytest

from app.engine.external_intelligence.version_match import affected_state, parse


def rng(
    start: str | None = None, end: str | None = None, si: bool = True, ei: bool = False
) -> dict[str, Any]:
    return {"start": start, "start_inclusive": si, "end": end, "end_inclusive": ei}


def entry(ranges: list[Any], fixed: list[str] | None = None) -> dict[str, Any]:
    return {"vendor": "Siemens", "product": "WinCC", "versions": ranges, "fixed": fixed or []}


def test_versions_compare_numerically_with_simple_suffixes() -> None:
    assert parse("2.10") > parse("2.9") and parse("2.3") == parse("2.3.0") and parse("v1.0") == parse("1")
    assert parse("2.3rc1") < parse("2.3") < parse("2.3 sp1") < parse("2.3.1")
    assert parse("1.0-beta2") < parse("1.0-rc1")


@pytest.mark.parametrize(
    "bad", ["", "latest", "2.3 and earlier", "1.x", "1..2", None, 7, "9" * 70, "1.2-foo"]
)
def test_a_version_not_certainly_understood_is_not_parsed(bad: Any) -> None:
    assert parse(bad) is None


def test_range_ends_can_be_inclusive_or_exclusive() -> None:
    upto, before = entry([rng(end="2.3", ei=True)]), entry([rng(end="2.3", ei=False)])
    assert affected_state("2.3", upto) is True and affected_state("2.3", before) is False
    assert affected_state("2.3.1", upto) is False and affected_state("0.1", before) is True
    between = entry([rng("1.0", "2.0", si=False)])
    assert (affected_state("1.0", between), affected_state("1.5", between)) == (False, True)


def test_a_version_at_or_after_the_fix_is_not_affected() -> None:
    fixed = entry([rng(end="2.4")], ["2.4"])
    assert affected_state("2.3", fixed) is True
    assert affected_state("2.4", fixed) is False and affected_state("2.5", fixed) is False


def test_a_record_that_contradicts_itself_or_cannot_be_read_is_never_guessed() -> None:
    branch = entry([rng("3.0", "3.9"), rng("2.0", "2.4")], ["2.4"])
    assert affected_state("3.0", branch) is None
    assert affected_state("2.3", entry([rng(end="2.4")], ["soon"])) is None
    for bad in (entry([]), entry([{}]), entry([rng(end="n/a")]), {"versions": "all"}, {}):
        assert affected_state("2.3", bad) is None
    assert affected_state("banana", entry([rng(end="9")])) is None and affected_state(None, entry([])) is None
    assert affected_state("2.3", entry(["junk", rng(end="9")])) is True
    assert affected_state("2.3", entry(["junk"])) is None


def test_a_missing_start_flag_is_inclusive_and_no_bounds_means_every_version() -> None:
    from_two = entry([{"start": "2.0", "end": "3.0", "end_inclusive": False}])
    assert affected_state("2.0", from_two) is True and affected_state("3.0", from_two) is False
    every = entry([{"start": None, "end": None, "end_inclusive": False}])
    assert (
        affected_state("9.9", every) is True
        and affected_state("9.9", entry(every["versions"], ["9.0"])) is None
    )
    assert affected_state("9.9", entry(every["versions"], ["10.0"])) is True
