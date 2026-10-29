"""Two names are compared in every form a text may use them ("PGS" and "Power Generation System" for "Power
Generation System (PGS)") and on whole words only ("ICS" is never the
"ics" of "electronics"): the writer reads a system's reason and its entry point by any of their forms."""

from app.domain.scenario.write import _offered_entry_point, _reasons_by_system
from app.domain.shared.names import is_same_name

PGS = "Power Generation System (PGS)"
DCS = "Distributed Control System (DCS)"


def test_every_form_of_a_name_is_the_same_name_and_nothing_else_is() -> None:
    for written in (PGS, "Power Generation System", "PGS", "power  generation SYSTEM", "pgs"):
        assert is_same_name(PGS, written), written
    for written in ("Power Generation", "PGS turbines", "", "System"):
        assert not is_same_name(PGS, written), written
    assert is_same_name("APT41", "APT-41")


def test_the_writer_reads_a_system_and_an_entry_point_by_their_short_form() -> None:
    """A miss here refused the answer: the AI was asked again, then the path failed."""
    assert _reasons_by_system({"DCS": " It runs the turbines. "}, (DCS,)) == (
        ((DCS, "It runs the turbines."),),
        [],
    )
    assert _reasons_by_system({"Historian": "Its records."}, (DCS,))[1] == [DCS]
    assert _offered_entry_point("DCS", (DCS, "Historian")) == DCS
    assert _offered_entry_point("Engineering laptop", (DCS, "Historian")) is None
