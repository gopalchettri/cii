"""A scenario written as a kind reads that kind's reason; the card's threat block shows the threat's own
category. Each category keeping its reason through a fold: tests/test_threat_quality.py."""

import dataclasses

from app.core.constants import StrideCategory
from app.domain.scenario.session import _build_threat_block, build_scenario_view
from app.domain.scenario.write import build_scenario_card, build_writer_input
from app.models.scenario.write import WrittenScenario
from tests.planner_samples import CONTEXT
from tests.test_scenario_writing import _CLEAN, _LIVE, _plan_threat

S = StrideCategory
SPOOFING_WHY = "A former vendor account still active could be used to log in as an operator."
PRIVILEGE_WHY = "The same account could be added to the operator role and gain engineer rights."


def test_the_brief_reads_the_kinds_own_reason() -> None:
    threat = _plan_threat() | {
        "categories": [S.SPOOFING, S.ELEVATION_OF_PRIVILEGE],
        "reasons": {S.SPOOFING: SPOOFING_WHY, S.ELEVATION_OF_PRIVILEGE: PRIVILEGE_WHY},
    }
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Elevation of Privilege", "systems": [321]}
    brief = build_writer_input({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    assert brief.facts["threat"]["why_it_applies"] == PRIVILEGE_WHY
    assert brief.facts["category"] == S.ELEVATION_OF_PRIVILEGE


def test_the_cards_threat_block_shows_the_threats_own_category() -> None:
    """The scenario block shows the kind it is written as; the threat block the library threat's own."""
    threat = _plan_threat() | {
        "category": S.SPOOFING,
        "category_id": 1,
        "categories": [S.SPOOFING, S.INFORMATION_DISCLOSURE],
    }
    path = {
        "path_id": "p1",
        "steps": [threat["key"]],
        "category": "Information Disclosure",
        "category_id": 2,
        "categories": ["Information Disclosure", "Spoofing"],
        "systems": [321],
        "rank": 1,
    }
    brief = build_writer_input({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    draft = dataclasses.replace(_CLEAN, entry_point=brief.entry_options[0])
    written = WrittenScenario(draft, ())
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    record = build_scenario_card(run, path, threat, brief, written) | {"_id": "s1", "session_id": "run-1"}
    view = build_scenario_view(record)
    assert (view.threat.threat_category, view.threat.threat_category_id) == (S.SPOOFING, 1)
    assert view.scenario is not None and view.scenario.threat_category == "Information Disclosure"


def test_the_threat_blocks_category_id_is_its_own_categorys() -> None:
    """A plan threat stored without its category id: the kind's id never stands beside another category's
    name."""
    old_plan = {
        "category": S.TAMPERING,
        "category_id": 12,
        "threat": {"key": "lib:1", "category": S.SPOOFING},
    }
    block = _build_threat_block(old_plan)
    assert (block.threat_category, block.threat_category_id) == (S.SPOOFING, None)  # before: (Spoofing, 12)
    same_kind = old_plan | {"threat": {"key": "lib:1", "category": S.TAMPERING}}
    assert _build_threat_block(same_kind).threat_category_id == 12
