"""G252 (owner 2026-10-15: "if we need to make the rule a little loose I am okay with it"): a story
blocked only by footnote faults is repaired in code, never thrown away whole for them: the sentence
claiming a past event with a flagged footnote goes; on a plain step only the marker goes; any other fault,
or a repair that still fails the code rules, leaves the story as it was. No AI call."""

import dataclasses

import pytest

from app.core.constants import FindingCode, PlanCheckStatus, Route
from app.engine.scenarios.writing import citation_repair
from app.engine.scenarios.writing.citation_repair import repair_citations
from app.models.writing import Finding, PlanCheck, WrittenScenario
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _DRAFT, _story_brief
from tests.test_scenario_writing import _LIBRARY_ATTACKERS

_PAST = "Attackers have used a rogue firmware update to disable substation devices before [1]."
_STEP_MARKED = (
    "With that login they could open a support session and prepare a firmware update that looks genuine [1]."
)
_STEP = "With that login they could open a support session and prepare a firmware update that looks genuine."
_UNSUPPORTED = Finding(FindingCode.CITATION_UNSUPPORTED, "The marker(s) [1] sit by claims …", (1,))
_NOTE = Finding(FindingCode.PLAN_CHECK, "Rule 6: the risk could name the critical service.")


def _written(statement: str, *findings: Finding) -> WrittenScenario:
    draft = dataclasses.replace(_DRAFT, statement=statement)
    return WrittenScenario(draft, findings, PlanCheck(PlanCheckStatus.INCONSISTENT), Route.STANDALONE, False)


def _repair(written: WrittenScenario) -> WrittenScenario:
    return repair_citations(written, _story_brief(TECHNIQUE), _LIBRARY_ATTACKERS)


def test_a_flagged_footnote_on_a_past_event_goes_with_its_sentence_and_the_story_is_kept() -> None:
    repaired = _repair(_written(_DRAFT.statement, _UNSUPPORTED, _NOTE))
    assert (
        not repaired.blocked
        and _PAST not in repaired.draft.statement
        and "[1]" not in repaired.draft.statement
    )
    assert repaired.draft.evidence_links == ()  # its claim goes too
    codes = [finding.code for finding in repaired.findings]
    assert FindingCode.CITATION_REMOVED in codes and FindingCode.PLAN_CHECK in codes  # the AI's notes stay
    assert FindingCode.CITATION_UNSUPPORTED not in codes


def test_a_flagged_footnote_on_a_plain_step_loses_only_its_marker() -> None:
    statement = _DRAFT.statement.replace(_PAST, _PAST.replace(" [1]", "")).replace(_STEP, _STEP_MARKED)
    repaired = _repair(_written(statement, _UNSUPPORTED))
    assert (
        not repaired.blocked and _STEP in repaired.draft.statement and "[1]" not in repaired.draft.statement
    )


def test_a_combined_marker_keeps_the_numbers_not_flagged() -> None:
    assert citation_repair._unmarked("A step [1, 2].", {1}) == "A step [2]."  # noqa: SLF001
    assert citation_repair._unmarked("A step [1].", {1}) == "A step."  # noqa: SLF001


def test_any_other_fault_or_no_flagged_number_leaves_the_story_as_it_was() -> None:
    target = Finding(FindingCode.TARGET_NOT_NAMED, "Its target is not named.")
    other = _written(_DRAFT.statement, _UNSUPPORTED, target)
    assert _repair(other) is other
    unnumbered = _written(_DRAFT.statement, Finding(FindingCode.CITATION_UNSUPPORTED, "no numbers"))
    assert _repair(unnumbered) is unnumbered


def test_a_repair_that_still_fails_the_code_rules_leaves_the_story_as_it_was(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    still = (Finding(FindingCode.VAGUE_PHRASE, "Uses a vague phrase."),)
    monkeypatch.setattr(citation_repair, "check_exact_rules", lambda *_: (still, Route.STANDALONE))
    written = _written(_DRAFT.statement, _UNSUPPORTED)
    assert _repair(written) is written


def test_a_footnote_the_code_check_rejects_is_removed_the_same_way() -> None:
    """The code check's own rejection (a past event naming nothing its source names) is repaired like the AI
    check's: the writer asks no rewrite for it and the story is kept without that sentence."""
    from tests.external_intelligence.worker.test_mandatory_evidence import NAMED
    from tests.test_scenario_writing import _CONSISTENT, _writer

    generic = _DRAFT.statement.replace(
        _PAST, "Attackers have tampered with device firmware this way before [1]."
    )
    writer, _ = _writer([dataclasses.replace(_DRAFT, statement=generic).to_answer()], [_CONSISTENT])
    written = writer.write_scenario(_story_brief(NAMED))
    assert not written.blocked and "[1]" not in written.draft.statement
    assert FindingCode.CITATION_REMOVED in {finding.code for finding in written.findings}
