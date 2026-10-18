"""Each category a threat was accepted for keeps its own reason through every merge, so a scenario written
as a kind reads that kind's reason; the card's threat block shows the threat's own category."""

import dataclasses

from app.core.constants import PlanCheckStatus, Route, StrideCategory
from app.domain.scenario.plan import merge_two_threats, planned_threat_record, threat_reason_for
from app.domain.scenario.write import brief_entry_point_options, build_brief, written_record
from app.models.scenario.plan import PlannedThreat
from app.models.scenario.write import PlanCheck, WrittenScenario
from app.services.scenario.results import _threat_block, build_scenario_view
from tests.planner_samples import CONTEXT, planned
from tests.test_scenario_writing import _CLEAN, _LIVE, _plan_threat

S = StrideCategory
SPOOFING_WHY = "A former vendor account still active could be used to log in as an operator."
PRIVILEGE_WHY = "The same account could be added to the operator role and gain engineer rights."


def _judged(category: S, reason: str, key: str = "lib:233") -> PlannedThreat:
    """A gate verdict: the threat accepted under one category with that category's reason."""
    return planned(key, "Shared, stale or orphaned account misuse", categories=(category,), reason=reason)


def _spoofing_and_privilege() -> PlannedThreat:
    return merge_two_threats(
        _judged(S.SPOOFING, SPOOFING_WHY), _judged(S.ELEVATION_OF_PRIVILEGE, PRIVILEGE_WHY)
    )


def test_a_merge_keeps_each_categorys_own_reason() -> None:
    merged = _spoofing_and_privilege()
    assert merged.categories == (S.SPOOFING, S.ELEVATION_OF_PRIVILEGE)
    assert merged.reason == SPOOFING_WHY  # the threat's own reason
    assert threat_reason_for(merged, S.ELEVATION_OF_PRIVILEGE) == PRIVILEGE_WHY
    assert planned_threat_record(merged)["reasons"] == {
        S.SPOOFING: SPOOFING_WHY,
        S.ELEVATION_OF_PRIVILEGE: PRIVILEGE_WHY,
    }
    folded = merge_two_threats(merged, _judged(S.SPOOFING, "another reworded reason", key="ai:x"))
    assert threat_reason_for(folded, S.SPOOFING) == SPOOFING_WHY  # the kept one's wins a category both have


def test_the_brief_reads_the_kinds_own_reason() -> None:
    threat = _plan_threat() | {
        "categories": [S.SPOOFING, S.ELEVATION_OF_PRIVILEGE],
        "reasons": {S.SPOOFING: SPOOFING_WHY, S.ELEVATION_OF_PRIVILEGE: PRIVILEGE_WHY},
    }
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Elevation of Privilege", "systems": [321]}
    brief = build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    assert brief.why_it_applies == PRIVILEGE_WHY and brief.category == S.ELEVATION_OF_PRIVILEGE


def test_every_paths_reason_belongs_to_its_kind() -> None:
    """The recurrence guard: whatever order verdicts are merged in, each kind reads its own reason."""
    verdicts = [_judged(S.SPOOFING, "s"), _judged(S.TAMPERING, "t"), _judged(S.ELEVATION_OF_PRIVILEGE, "e")]
    for first in range(3):
        order = verdicts[first:] + verdicts[:first]
        merged = order[0]
        for other in order[1:]:
            merged = merge_two_threats(merged, other)
        assert {kind: threat_reason_for(merged, kind) for kind in merged.categories} == {
            S.SPOOFING: "s",
            S.TAMPERING: "t",
            S.ELEVATION_OF_PRIVILEGE: "e",
        }


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
    brief = build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)
    draft = dataclasses.replace(_CLEAN, entry_point=brief_entry_point_options(brief)[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT, ()), Route.STANDALONE, False)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    record = written_record(run, path, threat, brief, written) | {"_id": "s1", "session_id": "run-1"}
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
    block = _threat_block(old_plan)
    assert (block.threat_category, block.threat_category_id) == (S.SPOOFING, None)  # before: (Spoofing, 12)
    same_kind = old_plan | {"threat": {"key": "lib:1", "category": S.TAMPERING}}
    assert _threat_block(same_kind).threat_category_id == 12
