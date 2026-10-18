"""Citation numbers are the sources the final scenario actually uses, from [1] in the order first cited;
a marker naming no source is dropped; only the cited sources are kept."""

from app.domain.scenario.write import renumber_citations

ENTRIES = [{"ref": "T1078"}, {"ref": "T0839"}, {"ref": "T1566"}]


def test_the_only_source_used_is_cited_as_1_with_its_claim() -> None:
    statement, _, cited = renumber_citations("Credential abuse was used [2].", "", ENTRIES, {2: "abuse"})
    assert statement == "Credential abuse was used [1]."
    assert cited == [{"ref": "T0839", "n": 1, "supports": "abuse"}]


def test_numbers_follow_the_first_citation_and_a_source_keeps_its_number() -> None:
    statement, risk, cited = renumber_citations("A [3], B [1], again A [3].", "Then B [1].", ENTRIES)
    assert (statement, risk) == ("A [1], B [2], again A [1].", "Then B [2].")
    assert [(item["ref"], item["n"]) for item in cited] == [("T1566", 1), ("T1078", 2)]


def test_a_marker_naming_no_source_is_dropped_and_a_combined_one_keeps_the_known() -> None:
    statement, _, cited = renumber_citations("[7] Real [2, 7] and invented [7].", "", ENTRIES)
    assert statement == "Real [1] and invented." and cited == [{"ref": "T0839", "n": 1}]


def test_a_story_citing_nothing_keeps_no_source() -> None:
    assert renumber_citations("No intelligence here.", "None.", ENTRIES) == (
        "No intelligence here.",
        "None.",
        [],
    )
