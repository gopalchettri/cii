"""A duplicate is caught before a save: the same threat (key or name) as the same kind on the same systems,
or the very same words.
Another kind, other systems or another threat told in other words is kept."""

from typing import Any

from app.core.constants import FindingCode
from app.domain.scenario.write import duplicate_of

_STATEMENT = "A cybercriminal could push modified firmware to the SCADA server, so breakers open unseen [1]."


def _content(statement: str = _STATEMENT, threat: str = "lib:1", **changes: Any) -> dict[str, Any]:
    content = {
        "statement": statement,
        "threat": {"key": threat},
        "category": "Tampering",
        "systems": [{"id": 1}],
    }
    return content | changes


def _held(content: dict[str, Any], path_id: str = "p2") -> list[dict[str, Any]]:
    return [{"_id": "s-first", "path_id": path_id, "content": content}]


def test_the_same_threat_kind_and_systems_is_a_copy_naming_the_scenario_it_copies() -> None:
    finding = duplicate_of(_content("Told in other words."), "p1", [], _held(_content()))
    assert finding is not None and finding.code == FindingCode.NEAR_DUPLICATE and "s-first" in finding.message
    assert duplicate_of(_content("Told again."), "p1", _held(_content()), []) is not None  # this run's too


def test_another_kind_other_systems_or_another_threat_in_other_words_is_kept() -> None:
    held = _held(_content())
    assert duplicate_of(_content("Other words.", category="Denial of Service"), "p1", [], held) is None
    assert duplicate_of(_content("Other words.", systems=[{"id": 1}, {"id": 2}]), "p1", [], held) is None
    assert duplicate_of(_content("Other words.", threat="lib:2"), "p1", [], held) is None


def test_the_very_same_words_are_a_copy_whatever_the_threat_case_spaces_or_markers() -> None:
    held = _held(_content(threat="lib:2", category="Spoofing"))
    reworded = _STATEMENT.upper().replace(" ", "   ").replace(" [1]", " [2, 3]")
    assert duplicate_of(_content(reworded, threat="lib:9"), "p1", [], held) is not None
    assert duplicate_of(_content(_STATEMENT.replace(" [1]", ""), threat="lib:9"), "p1", [], held) is not None


def test_the_paths_own_versions_are_never_its_copies() -> None:
    assert duplicate_of(_content(), "p1", _held(_content(), path_id="p1"), []) is None


def test_a_hand_written_scenario_of_the_same_live_threat_is_its_threat_and_a_pending_one_is_not() -> None:
    """A hand-written record names its threat by library id alone, "lib:<id>" as the planner keys it; a
    pending row's id is another id space, so it never stands in."""
    hand_written = _content("Hand written.", threat="") | {
        "threat": {"library_id": 1, "library_status": "active"}
    }
    assert duplicate_of(_content(), "p1", [], _held(hand_written)) is not None
    pending = hand_written | {"threat": {"library_id": 1, "library_status": "pending"}}
    assert duplicate_of(_content(), "p1", [], _held(pending)) is None


def test_the_same_threat_name_is_the_same_threat_whatever_its_key() -> None:
    """An AI threat later approved into the library keeps its "ai:" key on old scenarios: its name matches."""
    accepted_ai = _content("Told first.") | {"threat": {"key": "ai:x", "name": "Firmware tampering"}}
    library = _content("Told again.") | {"threat": {"key": "lib:9", "name": "T0839 firmware  TAMPERING"}}
    assert duplicate_of(library, "p1", [], _held(accepted_ai)) is not None
    pending = {"name": "Firmware tampering", "library_id": 3, "library_status": "pending"}
    assert duplicate_of(library, "p1", [], _held(_content("Hand written.") | {"threat": pending})) is not None
    other = _content("Other words.") | {"threat": {"key": "lib:9", "name": "Spoofed commands"}}
    assert duplicate_of(other, "p1", [], _held(accepted_ai)) is None
