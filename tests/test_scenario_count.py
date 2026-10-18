"""The organisation's own facts reach the AI as background, never as this asset's; a threat that needs a
technology nobody recorded is not relevant; and a scenario is written on its own path's system only."""

import dataclasses

from app.core.constants import ContextProperties, PlanCheckStatus, Route, StrideCategory, ThreatFinding
from app.domain.scenario.controls import control_query
from app.domain.scenario.plan import describe_asset_for_ai, gap_fill_prompt, relevance_gate_prompt
from app.domain.scenario.write import brief_entry_point_options, build_brief, written_record
from app.models.scenario.write import PlanCheck, WrittenScenario
from tests.planner_samples import CONTEXT
from tests.test_scenario_writing import _CLEAN, _LIVE, _plan_threat

_ORGANISATION_TEXT = "DEWA runs AI-driven customer service, ERP and billing platforms"
_WITH_ORGANISATION = dataclasses.replace(
    CONTEXT, asset_context=CONTEXT.asset_context | {"entity_technology_context": _ORGANISATION_TEXT}
)


def test_no_other_step_reads_the_organisations_facts_as_the_assets() -> None:
    """Neither the writer's brief nor the control search takes them as the asset's."""
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    brief = build_brief({threat["key"]: threat}, path, _WITH_ORGANISATION, 30_000, _LIVE)
    assert brief.asset[ContextProperties.ORGANISATION_BRIEF_KEY] == _ORGANISATION_TEXT
    assert "entity_technology_context" not in brief.asset  # never an asset fact
    content = {"statement": "s", "risk_statement": "r", "systems": [{"id": 321}]}
    assert "billing" not in control_query(content, _WITH_ORGANISATION, [_WITH_ORGANISATION.systems[0]]).text


def test_why_it_applies_never_names_a_system_this_scenario_is_not_on() -> None:
    """The reason never tells another system's story: a name in a list of systems goes with its joiner;
    one alone becomes the placeholder."""
    threat = _plan_threat(systems=(321, 322), reason="It reaches the SCADA server and the Historian.")
    on_scada = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    on_asset = on_scada | {"path_id": "p2", "systems": []}
    reason = build_brief({threat["key"]: threat}, on_scada, CONTEXT, 30_000, _LIVE).why_it_applies
    assert reason == "It reaches the SCADA server."
    reason = build_brief({threat["key"]: threat}, on_asset, CONTEXT, 30_000, _LIVE).why_it_applies
    assert reason == "It reaches another supporting system."


def test_the_organisations_facts_are_a_background_line_never_the_assets() -> None:
    """A column named entity_... is the organisation's (the procedure's @EntityID), never this asset's."""
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
    """Both prompts that decide what applies say a technology nobody recorded is never assumed and the
    organisation's facts are background; an unknown fact may only be a missing detail."""
    gate = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [{"slot": "R1"}])[1]
    gap = gap_fill_prompt("LANDSCAPE", StrideCategory.TAMPERING, 3, ())[1]
    for prompt in (gate, gap):
        assert "it may never assume that a technology, component or device exists" in prompt
        assert "an engineering workstation, a jump server, a wireless or radio link" in prompt
        assert "The ORGANISATION line is background only" in prompt
    for prompt in (gate, gap):
        assert "solely because a DETAIL of a recorded technology is unrecorded" in prompt
        assert "because a deciding fact is unrecorded" not in prompt


def test_a_scenario_is_written_on_its_paths_system_only() -> None:
    """A threat on two systems has a path per system: the brief of the path on SYS1 shows that system, and
    lists the other as never part of this scenario."""
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321]}
    brief = build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    assert [system["name"] for system in brief.systems] == ["SCADA server"]
    assert brief.other_systems == ("Historian",)
    draft = dataclasses.replace(_CLEAN, entry_point=brief_entry_point_options(brief)[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT, ()), Route.STANDALONE, False)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    card = written_record(run, path, threat, brief, written)["content"]["systems"]
    assert card == [{"id": 321, "name": "SCADA server", "entry_point": True}]  # never the Historian


def test_a_system_listed_beside_others_leaves_with_its_joiner() -> None:
    """No placeholder in a list; one standing alone keeps it."""
    from types import SimpleNamespace

    from app.domain.scenario.write import _reason_on_path

    systems = [
        {"id": n, "name": name} for n, name in ((1, "Alpha Platform"), (2, "Beta System"), (3, "Gamma Hub"))
    ]
    context = SimpleNamespace(systems=systems)
    cases = {
        "Spray against the Alpha Platform, Beta System, or Gamma Hub could work.": (
            "Spray against the Alpha Platform, or Gamma Hub could work.",
            [1, 3],
        ),
        "Tampering across Alpha Platform, Beta System, and Gamma Hub is possible.": (
            "Tampering across Beta System is possible.",
            [2],
        ),
        "Movement from Alpha Platform to Beta System is a threat.": (
            "Movement from another supporting system to Beta System is a threat.",
            [2],
        ),
    }
    for reason, (expected, route) in cases.items():
        assert _reason_on_path(reason, {"systems": route}, context) == expected  # type: ignore[arg-type]
