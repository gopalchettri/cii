"""G229 (owner 2026-10-13): a near copy needs BOTH much the same text AND the same thing (the same threat, or
the same target, systems and kind told with much the same mechanism and consequence); scenarios that share
words but describe a different attack are kept."""

from typing import Any

from app.core.constants import FindingCode
from app.engine.scenarios.writing.near_copies import near_copy

_STATEMENT = (
    "A cybercriminal could use a stolen vendor VPN account to reach the SCADA server of Grid Control Centre "
    "and push modified firmware to the feeder RTUs, so operators see normal readings while breakers open."
)


def _content(
    statement: str = _STATEMENT, threat: str = "lib:1", target: str = "SCADA server", **anatomy: str
) -> dict[str, Any]:
    parts = {"target": target, "mechanism": "pushes modified firmware to the feeder RTUs"}
    parts |= {"consequence": "operators see normal readings while breakers open"} | anatomy
    return {
        "statement": statement,
        "threat": {"key": threat},
        "category": "Tampering",
        "systems": [{"id": 1}],
        "anatomy": parts,
    }


def _finished(content: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"_id": "s-first", "content": content}]


def test_a_planted_copy_of_another_threat_is_rejected_naming_the_scenario_it_copies() -> None:
    reworded = _STATEMENT.replace("stolen", "borrowed").replace("normal", "ordinary")
    finding = near_copy(_content(reworded, threat="lib:2"), _finished(_content()))
    assert finding is not None and finding.code == FindingCode.NEAR_DUPLICATE
    assert "s-first" in finding.message


def test_the_same_words_about_another_attack_are_kept() -> None:
    """Another target and mechanism, though the story is told with much the same sentence."""
    other = _content(
        _STATEMENT.replace("SCADA server", "historian"), threat="lib:2", target="historian",
        mechanism="deletes the historian archive", consequence="investigators lose the event record",
    )  # fmt: skip
    assert near_copy(other, _finished(_content())) is None


def test_the_same_threat_told_again_is_a_copy_and_a_different_story_of_it_is_not() -> None:
    assert near_copy(_content(_STATEMENT + " Again."), _finished(_content())) is not None
    different = "An insider with an engineering laptop disables alarms on the protection relays overnight."
    assert near_copy(_content(different), _finished(_content())) is None


def test_citation_markers_never_make_two_stories_differ() -> None:
    """A heavily cited copy (a marker every third word) is still the same story: markers are not words."""
    words = _STATEMENT.split()
    marked = " ".join(f"{word} [{n // 3 + 1}]" if n % 3 == 2 else word for n, word in enumerate(words))
    assert near_copy(_content(marked, threat="lib:2"), _finished(_content())) is not None
