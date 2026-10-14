"""G229 P7 (owner 2026-10-13): every scenario a specific, plausible threat event, enforced in code with no AI
call: the writer states its parts (anatomy) in its one answer; a missing part, a target that is not the asset
or a named system, a mechanism naming nothing of this asset, a generic line, or a weakness stated as fact on
nothing recorded is final; an applicable system left unnamed is a warning; empty preconditions are fine."""

import dataclasses

from app.core.constants import AiTask, FindingCode, FindingSeverity
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.models.writing import Anatomy, ScenarioDraft
from tests.test_scenario_writing import (
    _CLEAN,
    _CONSISTENT,
    _LIBRARY_ATTACKERS,
    _brief_of,
    _plan_threat,
    _writer,
)

BRIEF = _brief_of(_plan_threat())  # Grid Control Centre, its SCADA server applicable


def _codes(draft: ScenarioDraft, brief: object = BRIEF) -> set[str]:
    findings, _ = check_exact_rules(draft, brief, _LIBRARY_ATTACKERS)  # type: ignore[arg-type]
    return {finding.code for finding in findings}


def _with(anatomy: Anatomy | None = None, **text: str) -> ScenarioDraft:
    return dataclasses.replace(_CLEAN, anatomy=anatomy or _CLEAN.anatomy, **text)


def test_a_specific_scenario_with_its_parts_passes_and_needs_no_preconditions() -> None:
    assert _CLEAN.anatomy is not None and _CLEAN.anatomy.preconditions == ()
    assert _codes(_CLEAN) == set()


def test_a_scenario_without_its_parts_is_not_finished() -> None:
    assert FindingCode.ANATOMY_MISSING in _codes(dataclasses.replace(_CLEAN, anatomy=None))
    gap = dataclasses.replace(_CLEAN.anatomy, mechanism="", consequence="")  # type: ignore[type-var]
    assert FindingCode.ANATOMY_MISSING in _codes(_with(gap))


def test_the_target_must_be_the_asset_or_a_system_the_scenario_names() -> None:
    elsewhere = dataclasses.replace(_CLEAN.anatomy, target="the payroll database")  # type: ignore[type-var]
    assert FindingCode.TARGET_NOT_NAMED in _codes(_with(elsewhere))
    statement = "A cybercriminal could use a vendor session to push firmware to Grid Control Centre."
    assert FindingCode.TARGET_NOT_NAMED in _codes(_with(statement=statement))  # its target, never named


def test_a_mechanism_naming_nothing_of_this_asset_is_not_concrete() -> None:
    """Not a word count: a long mechanism of generic words is still about any asset."""
    generic = "the attacker could gain access to the system through the network and then use that access"
    vague = dataclasses.replace(_CLEAN.anatomy, mechanism=generic)  # type: ignore[type-var]
    assert FindingCode.MECHANISM_NOT_CONCRETE in _codes(_with(vague))


def test_a_generic_line_is_rejected_and_a_specific_one_is_not() -> None:
    lazy = _CLEAN.statement + " An attacker may exploit vulnerabilities and unauthorised access could occur."
    assert FindingCode.VAGUE_PHRASE in _codes(_with(statement=lazy))
    specific = _CLEAN.statement + " It could exploit a vulnerability in the SCADA server firmware."
    assert FindingCode.VAGUE_PHRASE not in _codes(_with(statement=specific))


def test_a_weakness_stated_as_fact_on_nothing_recorded_is_rejected_a_conditional_one_is_not() -> None:
    asserted = _CLEAN.statement + " The SCADA server is unpatched."
    assert FindingCode.UNSUPPORTED_WEAKNESS in _codes(_with(statement=asserted))
    hedged = _CLEAN.statement + " It could succeed if the SCADA server is unpatched."
    assert FindingCode.UNSUPPORTED_WEAKNESS not in _codes(_with(statement=hedged))


def test_a_scenario_over_two_systems_names_both_and_one_left_out_is_a_warning() -> None:
    brief = _brief_of(_plan_threat(systems=(321, 322)))
    both = _CLEAN.statement + " The Historian could then keep the false readings."
    assert _codes(_with(statement=both), brief) == set()
    findings, _ = check_exact_rules(_CLEAN, brief, _LIBRARY_ATTACKERS)
    (missing,) = [f for f in findings if f.code == FindingCode.APPLICABLE_SYSTEM_NOT_IN_STORY]
    assert missing.severity == FindingSeverity.WARNING and "Historian" in missing.message


def test_a_vague_draft_is_final_and_costs_no_rewrite() -> None:
    """No AI call to repair it: the one rewrite is not asked for a G229 finding alone."""
    statement = _CLEAN.statement + " An attacker may exploit vulnerabilities."
    writer, chat = _writer([_CLEAN.to_answer() | {"scenario_statement": statement}], [_CONSISTENT])
    written = writer.write_scenario(BRIEF)
    assert written.blocked and written.final and not chat.asked(AiTask.REWRITE_SCENARIO)
