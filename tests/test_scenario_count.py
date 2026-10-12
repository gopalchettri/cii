"""G208 (owner 2026-10-12, "logically it should not be more than 20-25"; "the identifying the threats are also
weak"): the organisation's own facts reach the AI as background, never as this asset's; a threat that needs a
technology nobody recorded is not relevant; and a scenario is written on its own path's system only."""

import dataclasses

from app.core.constants import ContextProperties, PlanCheckStatus, Route, StrideCategory, ThreatFinding
from app.engine.scenarios.control_mapper import control_search_text
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai, library_search_queries
from app.engine.scenarios.finding.threat_prompts import (
    attacker_fit_prompt,
    gap_fill_prompt,
    relevance_gate_prompt,
)
from app.engine.scenarios.writing.brief_builder import build_brief
from app.engine.scenarios.writing.scenario_record import written_record
from app.models.writing import PlanCheck, WrittenScenario
from tests.planner_samples import CONTEXT
from tests.test_scenario_writing import _CLEAN, _LIVE, _plan_threat

_ORGANISATION_TEXT = "DEWA runs AI-driven customer service, ERP and billing platforms"
_WITH_ORGANISATION = dataclasses.replace(
    CONTEXT, asset_context=CONTEXT.asset_context | {"entity_technology_context": _ORGANISATION_TEXT}
)


def test_no_other_step_reads_the_organisations_facts_as_the_assets() -> None:
    """Review 2026-10-12: the library search, the writer's brief and the control search still took them as
    the asset's: the shortlists were seeded with AI, ERP and billing threats, and a SCADA story could drift
    there."""
    assert all(
        "billing" not in query
        for query in library_search_queries(_WITH_ORGANISATION, StrideCategory.TAMPERING)
    )
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    brief = build_brief({threat["key"]: threat}, path, _WITH_ORGANISATION, 30_000, _LIVE)
    assert brief.asset[ContextProperties.ORGANISATION_BRIEF_KEY] == _ORGANISATION_TEXT
    assert "entity_technology_context" not in brief.asset  # never an asset fact
    content = {"statement": "s", "risk_statement": "r", "systems": [{"id": 321}]}
    assert "billing" not in control_search_text(content, _WITH_ORGANISATION, [_WITH_ORGANISATION.systems[0]])


def test_why_it_applies_never_names_a_system_this_scenario_is_not_on() -> None:
    """Review 2026-10-12: the reason named every system its threat involves, so a SCADA card told the
    Historian's story and the writer's out-of-scope check forced a rewrite."""
    threat = _plan_threat(systems=(321, 322), reason="It reaches the SCADA server and the Historian.")
    on_scada = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    on_asset = on_scada | {"path_id": "p2", "systems": []}
    reason = build_brief({threat["key"]: threat}, on_scada, CONTEXT, 30_000, _LIVE).why_it_applies
    assert reason == "It reaches the SCADA server and another supporting system."
    reason = build_brief({threat["key"]: threat}, on_asset, CONTEXT, 30_000, _LIVE).why_it_applies
    assert reason == "It reaches other supporting systems."


def test_the_organisations_facts_are_a_background_line_never_the_assets() -> None:
    """Live run 2026-10-12: DEWA's whole-estate text sat among the asset's facts, so 32 AI/LLM threats were
    accepted for a SCADA asset. A column named entity_... is the organisation's (the procedure's
    @EntityID)."""
    context = dataclasses.replace(
        CONTEXT, asset_context=CONTEXT.asset_context | {"entity_technology_context": _ORGANISATION_TEXT}
    )
    text = describe_asset_for_ai(context, 30_000).text
    asset_line, organisation_line = text.split("\n")[:2]
    assert _ORGANISATION_TEXT not in asset_line and "entity_technology_context" not in asset_line
    assert (
        organisation_line.startswith(ThreatFinding.ORGANISATION_LABEL)
        and _ORGANISATION_TEXT in organisation_line
    )
    assert "ORGANISATION" not in describe_asset_for_ai(CONTEXT, 30_000).text  # none recorded: no line


def test_the_relevance_and_gap_fill_rules_never_assume_a_technology_or_borrow_the_organisations() -> None:
    """The two sentences the owner approved (Solution A), in both prompts that decide what applies; and
    the 2026-10-04 unknown-facts rule narrowed to details (owner: "fix this also"), in every prompt that
    carries it: its old "do not reject … because a deciding fact is unrecorded" let the AI assume
    engineering workstations, jump servers and radio links into existence (live run e4e70ea7)."""
    gate = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [{"slot": "R1"}])[1]
    gap = gap_fill_prompt("LANDSCAPE", StrideCategory.TAMPERING, 3)[1]
    fit = attacker_fit_prompt("LANDSCAPE", [{"slot": "A1"}])[1]
    for prompt in (gate, gap):
        assert "it may never assume that a technology, component or device exists" in prompt
        assert "an engineering workstation, a jump server, a wireless or radio link" in prompt
        assert "The ORGANISATION line is background only" in prompt
    for prompt in (gate, gap, fit):
        assert "solely because a DETAIL of a recorded technology is unrecorded" in prompt
        assert "because a deciding fact is unrecorded" not in prompt


def test_a_scenario_is_written_on_its_paths_system_only() -> None:
    """A threat on two systems has a path per system (G208): the brief of the path on SYS1 shows that system,
    and lists the other as never part of this scenario."""
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    brief = build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    assert [system["name"] for system in brief.systems] == ["SCADA server"]
    assert brief.other_systems == ("Historian",)
    draft = dataclasses.replace(_CLEAN, entry_point=brief.entry_point_options[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT, ()), Route.STANDALONE, False)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    card = written_record(run, path, threat, brief, written)["content"]["systems"]
    assert card == [{"id": 321, "name": "SCADA server", "entry_point": True}]  # never the Historian
