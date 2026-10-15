"""G224 (owner 2026-10-13): citation numbers are the sources the final scenario actually uses, from [1] in the
order first cited; a marker naming no source is dropped; only the cited sources are kept."""

from app.engine.external_intelligence.story.evidence_story_texts import (
    STORY_PLAN_CHECK_SYSTEM_PROMPT,
    STORY_WRITER_SYSTEM_PROMPT,
)
from app.engine.scenarios.writing.evidence_checks import named_by, supports
from app.engine.scenarios.writing.evidence_citations import renumber_citations
from app.engine.scenarios.writing.writing_prompts import WRITER_SYSTEM_PROMPT

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
    # G253 (owner 2026-10-15): a step that IS the entry's technique may carry its marker; a named group only
    # in the entry's own words
    assert "either a step that IS the entry's technique (as its title says), adding no detail" in writer
    assert "in the entry's own words; a sentence that says only" in writer
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


def test_the_story_writer_has_no_step_rule_and_real_attackers_are_cited_by_name() -> None:
    """G248 (owner 2026-10-15, "undo the feed-built steps"): with G233's steps, 72% of first cards were set
    aside (28% before): the writer stretched the real-attack accounts onto its own attack. One feed sentence
    per card again: no step rule, and a real attacker is a name the citation check reads."""
    assert "Build the attack's steps" not in STORY_WRITER_SYSTEM_PROMPT
    assert "Build the attack's steps" not in WRITER_SYSTEM_PROMPT
    entry = {
        "facts": [
            "ALLANITE, a threat group, has used this technique.",
            "The Anthropic AI-orchestrated Campaign used this technique.",
        ]
    }
    assert {"allanite", "anthropic"} <= named_by(entry)
    assert supports("ALLANITE has collected credentials this way [1].", entry)
    assert not supports("Attackers have done this before [1].", entry)


def test_a_sentence_saying_how_the_attack_works_is_never_read_as_a_past_event() -> None:
    """G246 (run 5f2e072a): "Incident" in a system's name and a past participle describing a noun read as "it
    happened", so how-it-works sentences needed a group's name and their cards were blocked."""
    entry = {
        "facts": [
            "It is used for these attacker goals: impact.",
            "OnionDuke, a piece of malicious software, has used this technique.",
        ]
    }
    for sentence in (
        "Simultaneously, they could direct resource exhaustion requests against the Incident Detection & "
        "Response Platform, depleting server memory and CPU until incident alerts queue and then fail [1].",
        "The attacker could send a targeted phishing email to an operator [1].",
        "They could log in with compromised credentials through a remote session [1].",
        "Compromised credentials would let the attacker open a trusted session [1].",
        "A tool that can be used to flood the platform could be bought [1].",
    ):
        assert supports(sentence, entry), sentence
    for sentence in (
        "A similar incident disrupted a regional utility [1].",
        "The C0027 campaign used similar access techniques [1].",
        "Attackers previously flooded such platforms [1].",
    ):
        assert not supports(sentence, entry), sentence
    assert supports("OnionDuke has used a Denial of Service module [1].", entry)
