"""G224 (owner 2026-10-13): citation numbers are the sources the final scenario actually uses, from [1] in the
order first cited; a marker naming no source is dropped; only the cited sources are kept."""

from app.engine.external_intelligence.story.evidence_story_texts import (
    STORY_PLAN_CHECK_SYSTEM_PROMPT,
    STORY_WRITER_SYSTEM_PROMPT,
)
from app.engine.scenarios.writing.evidence_citations import renumber_citations

ENTRIES = [{"ref": "T1078"}, {"ref": "T0839"}, {"ref": "T1566"}]


def test_the_only_source_used_is_cited_as_1() -> None:
    statement, risk, cited = renumber_citations("Credential abuse was used for persistence [2].", "", ENTRIES)
    assert statement == "Credential abuse was used for persistence [1]."
    assert cited == [{"ref": "T0839", "n": 1}]


def test_numbers_follow_the_first_citation_and_a_source_keeps_its_number() -> None:
    statement, risk, cited = renumber_citations("A [3], B [1], again A [3].", "Then B [1].", ENTRIES)
    assert (statement, risk) == ("A [1], B [2], again A [1].", "Then B [2].")
    assert [(item["ref"], item["n"]) for item in cited] == [("T1566", 1), ("T1078", 2)]


def test_a_marker_naming_no_source_is_dropped_and_a_combined_one_keeps_the_known() -> None:
    statement, _, cited = renumber_citations("Real [2, 7] and invented [7].", "", ENTRIES)
    assert statement == "Real [1] and invented."
    assert cited == [{"ref": "T0839", "n": 1}]


def test_the_writer_and_the_check_cite_only_what_directly_supports_the_claim() -> None:
    """Part 3 of the owner's request: never a reference for a shared category. G229: a marker's sentence
    states the entry's own finding, a false citation is worse than none, each marker returns its claim, and
    the plan check names the unsupported ones."""
    writer = STORY_WRITER_SYSTEM_PROMPT
    assert "never because it shares a category" in writer
    assert "it names the group, software, campaign, vendor or product the entry names" in writer
    assert "which is better than a false citation" in writer
    assert "evidence_links" in writer and "When no entry directly fits" not in writer
    assert "not only a shared category" in STORY_PLAN_CHECK_SYSTEM_PROMPT
    assert '"unsupported_citations"' in STORY_PLAN_CHECK_SYSTEM_PROMPT


def test_a_dropped_marker_at_the_start_leaves_no_space_and_punctuation_is_kept() -> None:
    """G227: "[7] Real [2]." with entry 2 known gives "Real [1].", never " Real [1]."."""
    statement, risk, cited = renumber_citations("[7] Real [2].", "Cost rose [3], then fell [2].", ENTRIES)
    assert statement == "Real [1]." and risk == "Cost rose [2], then fell [1]."
    assert [(item["ref"], item["n"]) for item in cited] == [("T0839", 1), ("T1566", 2)]
    assert renumber_citations("Ends with a source [3]", "", ENTRIES)[0] == "Ends with a source [1]"
    assert renumber_citations("", "", ENTRIES) == ("", "", [])


def test_a_story_citing_nothing_keeps_no_source() -> None:
    written = ("No intelligence here.", "None.")
    assert renumber_citations(*written, ENTRIES) == (*written, [])
