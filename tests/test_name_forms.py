"""Two names are compared in every form a text may use them ("PGS" and "Power Generation System" for "Power
Generation System (PGS)") and on whole words only ("ICS" is never the
"ics" of "electronics"): the writer reads a system's reason and its entry point by any of their forms."""

from app.core.constants import Writing
from app.domain.scenario.write import _pick_reason_for_system, _read_scenario_draft
from app.domain.shared.names import is_same_name
from app.models.scenario.write import BriefSystem, WriterBrief

PGS = "Power Generation System (PGS)"
DCS = "Distributed Control System (DCS)"
_YES_DCS, _NO_PGS = BriefSystem(1, DCS, applicable=True), BriefSystem(2, PGS, applicable=False)


def _reasons_by_system(
    written: dict[str, str], systems: tuple[BriefSystem, ...], statement: str
) -> tuple[tuple[str, str], ...]:
    """Each system with the reason the card shows for it."""
    return tuple((system.name, _pick_reason_for_system(system, written, statement)) for system in systems)


def _offered_entry_point(written: str, options: tuple[str, ...]) -> str:
    """The entry point code settles for a slot answering `written`, offered `options`."""
    brief = WriterBrief({}, (), {}, "Threat", (), (), options)
    item = {"threat": "Threat", "scenario_title": "T", "scenario_statement": "S.", "risk_statement": "R."}
    draft, problems = _read_scenario_draft(brief, item | {"assumptions": [], "entry_point": written}, 0)
    assert draft is not None, problems
    return draft.entry_point


def test_every_form_of_a_name_is_the_same_name_and_nothing_else_is() -> None:
    for written in (PGS, "Power Generation System", "PGS", "power  generation SYSTEM", "pgs"):
        assert is_same_name(PGS, written), written
    for written in ("Power Generation", "PGS turbines", "", "System"):
        assert not is_same_name(PGS, written), written
    assert is_same_name("APT41", "APT-41")


def test_the_writer_reads_a_system_and_an_entry_point_by_their_short_form() -> None:
    """A miss here refused the answer: the AI was asked again, then the path failed."""
    assert _reasons_by_system({"DCS": " It runs the turbines. "}, (_YES_DCS,), "") == (
        (DCS, "It runs the turbines."),
    )
    assert _offered_entry_point("DCS", (DCS, "Historian")) == DCS


def test_a_no_system_always_gets_codes_sentence_never_the_writers() -> None:
    """D66: the writer gives no reason for a "no" system; one it gives anyway is not served."""
    written = {"PGS": "It could be shut down too.", "DCS": "It runs the turbines."}
    assert _reasons_by_system(written, (_YES_DCS, _NO_PGS), "") == (
        (DCS, "It runs the turbines."),
        (PGS, Writing.NOT_REACHED_REASON),
    )


def test_a_yes_system_without_a_reason_takes_the_story_sentence_naming_it_else_codes_sentence() -> None:
    """D66: a missing "yes" reason is never a fault: the story's first sentence naming the system (in any of
    its forms), else code's fixed sentence."""
    story = "The attacker could enter the Historian. Then the DCS setpoints could change. The DCS could stop."
    assert _reasons_by_system({"Historian": "Its records."}, (_YES_DCS,), story) == (
        (DCS, "Then the DCS setpoints could change."),
    )
    assert _reasons_by_system({"DCS": "  "}, (_YES_DCS,), "The asset could stop.") == (
        (DCS, Writing.REACHED_REASON),
    )


def test_an_entry_point_not_offered_is_ignored_and_the_first_option_assigned() -> None:
    """D66: the path decides the way in (D14); a written one outside the options is never a fault."""
    assert _offered_entry_point("Engineering laptop", (DCS, "Historian")) == DCS
    assert _offered_entry_point("", (DCS,)) == DCS
    assert _offered_entry_point("DCS", ()) == ""
