"""A scenario keeps its strong controls (at or above the threshold), at most MAX_CONTROLS, topped up with the
nearest to MIN_CONTROLS; none strong: the NEAREST_CONTROLS nearest, so controls are never zero; each control
carries its tier and its reason; how many candidates are searched is CONTROL_CANDIDATES."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.constants import ControlMatch
from app.domain.scenario.controls import select_controls
from app.models.library.library import LibraryControl
from app.models.scenario.controls import ControlRule

RULE = ControlRule(cutoff=50, candidates=40, least=1, most=10, nearest=1)


def _control(n: int, name: str = "") -> LibraryControl:
    return LibraryControl(n, f"C-{n}", "OT", None, name or f"Control {n}", None)


def test_strong_controls_are_kept_best_first_and_never_more_than_the_maximum() -> None:
    scored = [(_control(n), 90.0 - n) for n in range(1, 15)]  # 14 strong, 89 down to 76
    mapping = select_controls(scored, RULE, "q")
    assert [item.score for item in mapping.items] == [89.0 - n for n in range(10)]
    assert [item.rank for item in mapping.items] == list(range(1, 11))
    assert mapping.left_out == 4 and mapping.warning is None and mapping.shortfall is None
    record = mapping.items[0].to_record()
    assert (record["tier"], record["match"]) == ("strong", ControlMatch.EXACT)
    assert record["rationale"] == "Score 89 is at or above the threshold of 50: strong."


def test_controls_are_never_zero_the_nearest_is_kept_however_low() -> None:
    scored = [(_control(1), 5.0), (_control(2), 3.0)]
    mapping = select_controls(scored, RULE, "q")
    assert [(item.code, item.to_record()["tier"]) for item in mapping.items] == [("C-1", "fallback")]
    assert mapping.warning and mapping.shortfall is None
    assert "below the threshold of 50: fallback" in mapping.items[0].rationale


def test_fallback_reaches_the_minimum_and_never_passes_the_maximum() -> None:
    scored = [(_control(1), 80.0), (_control(2), 45.0), (_control(3), 44.0)]
    two = select_controls(scored, ControlRule(50, 40, 2, 10, 3), "q")
    assert [item.match for item in two.items] == [ControlMatch.EXACT, ControlMatch.NEAREST]
    capped = select_controls(scored, ControlRule(50, 40, 3, 2, 3), "q")  # min above max: max wins
    assert len(capped.items) == 2


def test_fewer_compatible_controls_than_the_minimum_is_recorded() -> None:
    mapping = select_controls([(_control(1), 30.0)], ControlRule(50, 40, 3, 10, 3), "q")
    assert [item.code for item in mapping.items] == ["C-1"]
    assert mapping.shortfall == "1 control(s) kept: the minimum is 3, but only 1 compatible control(s) exist."


def test_twins_are_folded_before_the_maximum() -> None:
    scored = [(_control(1, "Backup"), 90.0), (_control(2, "Backup"), 85.0), (_control(3), 80.0)]
    mapping = select_controls(scored, ControlRule(50, 40, 1, 2, 1), "q")
    assert [item.code for item in mapping.items] == ["C-1", "C-3"]
    assert mapping.left_out == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"CONTROL_SIMILARITY_THRESHOLD": 0.5},  # the owner's 0.50 must be written 50
        {"MIN_CONTROLS": 5, "MAX_CONTROLS": 3},
        {"MIN_CONTROLS": 0},  # controls are never zero
        {"CONTROL_CANDIDATES": 5, "MAX_CONTROLS": 10},  # cannot keep more than are searched
        {"NEAREST_CONTROLS": 6, "MAX_CONTROLS": 5},  # cannot keep more nearest than the maximum
        {"NEAREST_CONTROLS": 0},
    ],
)
def test_control_settings_that_cannot_work_stop_start_up(changes: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        Settings(**changes)  # type: ignore[arg-type]


def test_the_default_rule_is_the_owners_and_the_floor_setting_is_gone() -> None:
    fields = Settings.model_fields
    assert fields["control_similarity_threshold"].default == 50.0
    defaults = (
        fields["min_controls"].default,
        fields["max_controls"].default,
        fields["nearest_controls"].default,
    )
    assert defaults == (3, 5, 3)  # the owner's rule, 2026-10-21
    assert "control_fallback_threshold" not in fields


def test_the_candidates_come_only_from_the_env_file_and_start_up_stops_without_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CONTROL_CANDIDATES in code; the env file's value is the one searched."""
    assert Settings.model_fields["control_candidates"].is_required()
    # No env file is read: the other required settings get placeholders, and dev keeps prod's checks (admin
    # key, CORS) out of the way, so only CONTROL_CANDIDATES decides.
    others = {
        name: "placeholder"
        for name, field in Settings.model_fields.items()
        if field.is_required() and name != "control_candidates"
    } | {"env": "dev"}
    monkeypatch.setenv("CONTROL_CANDIDATES", "12")
    assert Settings(_env_file=None, **others).control_candidates == 12  # type: ignore[call-arg]
    monkeypatch.delenv("CONTROL_CANDIDATES")
    with pytest.raises(ValidationError) as missing:
        Settings(_env_file=None, **others)  # type: ignore[call-arg]
    assert ("CONTROL_CANDIDATES",) in [error["loc"] for error in missing.value.errors()]


OWNERS = ControlRule(cutoff=50, candidates=10, least=3, most=5, nearest=3)  # MIN 3, MAX 5, NEAREST 3


@pytest.mark.parametrize(
    ("strong", "kept", "nearest_kept"), [(0, 3, 3), (1, 3, 2), (3, 3, 0), (4, 4, 0), (7, 5, 0)]
)
def test_the_owners_rule_at_least_three_at_most_five_three_nearest_when_none_is_strong(
    strong: int, kept: int, nearest_kept: int
) -> None:
    """None strong: the 3 nearest; some strong: topped up to 3; never more than 5."""
    scored = [(_control(n), 90.0 - n) for n in range(strong)] + [
        (_control(50 + n), 40.0 - n) for n in range(6)
    ]
    mapping = select_controls(scored, OWNERS, "q")
    tiers = [item.match for item in mapping.items]
    assert len(tiers) == kept and tiers.count(ControlMatch.NEAREST) == nearest_kept
    assert (mapping.warning is not None) == (strong == 0) and mapping.shortfall is None


def test_nearest_controls_is_its_own_setting_apart_from_the_minimum() -> None:
    """NEAREST_CONTROLS 2 with MIN_CONTROLS 3: none strong keeps 2; one strong still tops up to 3."""
    rule = ControlRule(cutoff=50, candidates=10, least=3, most=5, nearest=2)
    weak = [(_control(50 + n), 40.0 - n) for n in range(6)]
    none_strong = select_controls(weak, rule, "q")
    assert len(none_strong.items) == 2 and none_strong.shortfall is None
    assert "the 2 nearest compatible controls are kept" in str(none_strong.warning)
    assert "one of the 2 nearest kept because no control reached it" in none_strong.items[0].rationale
    one_strong = select_controls([(_control(1), 80.0), *weak], rule, "q")
    assert len(one_strong.items) == 3 and "to reach the minimum of 3" in one_strong.items[1].rationale
