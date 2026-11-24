"""A scenario keeps its strong controls (at or above the threshold), at most MAX_CONTROLS, topped up with the
nearest to MIN_CONTROLS; none strong: the NEAREST_CONTROLS nearest, so controls are never zero; each control
carries its tier and its reason; how many candidates are searched is CONTROL_CANDIDATES."""

import os

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.constants import ControlMatch
from app.domain.scenario.write import pick_controls_to_keep
from app.schemas.library import LibraryControl

RULE = (50, 1, 10, 1)  # cutoff, least, most, nearest
_NONE_REACHED = "no control reached it"  # ControlMessage.NEAREST_REASON: none strong, the nearest kept


def _control(n: int, name: str = "") -> LibraryControl:
    return LibraryControl(n, f"C-{n}", "OT", None, name or f"Control {n}", None)


def test_strong_controls_are_kept_best_first_and_never_more_than_the_maximum() -> None:
    scored = [(_control(n), 90.0 - n) for n in range(1, 15)]  # 14 strong, 89 down to 76
    items = pick_controls_to_keep(scored, *RULE)
    assert [item["score"] for item in items] == [89.0 - n for n in range(10)]
    assert [item["rank"] for item in items] == list(range(1, 11))
    assert all(item["match"] is ControlMatch.EXACT for item in items)
    assert (items[0]["tier"], items[0]["match"]) == ("strong", ControlMatch.EXACT)
    assert items[0]["rationale"] == "Score 89 is at or above the threshold of 50: strong."


def test_controls_are_never_zero_the_nearest_is_kept_however_low() -> None:
    scored = [(_control(1), 5.0), (_control(2), 3.0)]
    items = pick_controls_to_keep(scored, *RULE)
    assert [(item["code"], item["tier"]) for item in items] == [("C-1", "fallback")]
    assert "below the threshold of 50: fallback" in items[0]["rationale"]
    assert _NONE_REACHED in items[0]["rationale"]


def test_fallback_reaches_the_minimum_and_never_passes_the_maximum() -> None:
    scored = [(_control(1), 80.0), (_control(2), 45.0), (_control(3), 44.0)]
    two = pick_controls_to_keep(scored, 50, 2, 10, 3)
    assert [item["match"] for item in two] == [ControlMatch.EXACT, ControlMatch.NEAREST]
    capped = pick_controls_to_keep(scored, 50, 3, 2, 3)  # min above max: max wins
    assert len(capped) == 2


def test_fewer_compatible_controls_than_the_minimum_keeps_all_there_are() -> None:
    items = pick_controls_to_keep([(_control(1), 30.0)], 50, 3, 10, 3)
    assert [(item["code"], item["match"]) for item in items] == [("C-1", ControlMatch.NEAREST)]


def test_a_score_at_the_threshold_is_strong() -> None:
    items = pick_controls_to_keep([(_control(1), 50.0)], *RULE)
    assert [(item["match"], item["tier"]) for item in items] == [(ControlMatch.EXACT, "strong")]


def test_twins_are_folded_before_the_maximum() -> None:
    scored = [(_control(1, "Backup"), 90.0), (_control(2, "Backup"), 85.0), (_control(3), 80.0)]
    items = pick_controls_to_keep(scored, 50, 1, 2, 1)
    assert [item["code"] for item in items] == ["C-1", "C-3"]


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
    defaults = (fields["min_controls"].default, fields["max_controls"].default, fields["nearest_controls"].default)
    assert defaults == (3, 5, 3)  # the owner's rule, 2026-10-21
    assert "control_fallback_threshold" not in fields


def test_the_candidates_come_only_from_the_env_file_and_start_up_stops_without_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CONTROL_CANDIDATES in code; the env file's value is the one searched."""
    assert Settings.model_fields["control_candidates"].is_required()
    # No env file is read: the other required settings get placeholders (the MITRE sizes keep the values
    # tests/conftest.py sets), and dev keeps prod's checks (admin key, CORS) out of the way, so only
    # CONTROL_CANDIDATES decides.
    others = {"env": "dev"}
    for name, field in Settings.model_fields.items():
        alias = field.validation_alias
        env_name = alias if isinstance(alias, str) else f"CII_{name.upper()}"
        if field.is_required() and name != "control_candidates" and env_name not in os.environ:
            others[name] = "placeholder"
    monkeypatch.setenv("CONTROL_CANDIDATES", "12")
    assert Settings(_env_file=None, **others).control_candidates == 12  # type: ignore[call-arg]
    monkeypatch.delenv("CONTROL_CANDIDATES")
    with pytest.raises(ValidationError) as missing:
        Settings(_env_file=None, **others)  # type: ignore[call-arg]
    assert ("CONTROL_CANDIDATES",) in [error["loc"] for error in missing.value.errors()]


OWNERS = (50, 3, 5, 3)  # threshold 50, MIN 3, MAX 5, NEAREST 3


@pytest.mark.parametrize(("strong", "kept", "nearest_kept"), [(0, 3, 3), (1, 3, 2), (3, 3, 0), (4, 4, 0), (7, 5, 0)])
def test_the_owners_rule_at_least_three_at_most_five_three_nearest_when_none_is_strong(
    strong: int, kept: int, nearest_kept: int
) -> None:
    """None strong: the 3 nearest; some strong: topped up to 3; never more than 5."""
    scored = [(_control(n), 90.0 - n) for n in range(strong)] + [(_control(50 + n), 40.0 - n) for n in range(6)]
    items = pick_controls_to_keep(scored, *OWNERS)
    tiers = [item["match"] for item in items]
    assert len(tiers) == kept and tiers.count(ControlMatch.NEAREST) == nearest_kept
    assert any(_NONE_REACHED in item["rationale"] for item in items) == (strong == 0)


def test_nearest_controls_is_its_own_setting_apart_from_the_minimum() -> None:
    """NEAREST_CONTROLS 2 with MIN_CONTROLS 3: none strong keeps 2; one strong still tops up to 3."""
    rule = (50, 3, 5, 2)
    weak = [(_control(50 + n), 40.0 - n) for n in range(6)]
    none_strong = pick_controls_to_keep(weak, *rule)
    assert [item["match"] for item in none_strong] == [ControlMatch.NEAREST] * 2
    assert "one of the 2 nearest kept because no control reached it" in none_strong[0]["rationale"]
    one_strong = pick_controls_to_keep([(_control(1), 80.0), *weak], *rule)
    assert len(one_strong) == 3 and "to reach the minimum of 3" in one_strong[1]["rationale"]
