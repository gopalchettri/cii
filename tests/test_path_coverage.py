"""G223 (owner 2026-10-13): TOTAL_SCENARIO_COUNT is a hard limit, and within it scenarios are picked one at
a time for the most coverage (critical risk, then supporting systems, kinds of attack, threats), recomputed
after every pick; the plan records what is covered and why anything is not."""

import random
from datetime import UTC, datetime

from app.core.constants import CoverageGap
from app.engine.scenarios.attack_paths.path_grouping import path_on
from app.engine.scenarios.attack_paths.path_ranking import rank_paths
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.models.coverage import COVERAGE_FIELDS, coverage_record, run_coverage
from app.models.scenarios import SessionStatus
from app.models.threats import AttackPath, ThreatFindings
from tests.planner_samples import S, planned
from tests.test_attack_paths import LANDSCAPE

CC, ITS, TSC, IDR = 1448, 1449, 1450, 1451  # asset 1166's systems (run 82f22cc3)


def _path(key: str, kind: S, systems: tuple[int, ...], *also: S, impact: int = 3) -> AttackPath:
    threat = planned(key, key, systems, categories=(kind, *also), impact=impact, confidence=80.0)
    return path_on(threat, systems, kind)


#: Run 82f22cc3's 17 paths: every threat HIGH; the Spoofing and Tampering threats also fit Repudiation.
RUN_82F22CC3 = [
    _path("lib:1", S.SPOOFING, (ITS, TSC), S.REPUDIATION),
    _path("lib:2", S.DENIAL_OF_SERVICE, (CC, IDR)),
    _path("lib:3", S.ELEVATION_OF_PRIVILEGE, (CC, IDR)),
    _path("lib:4", S.TAMPERING, ()),
    _path("lib:5", S.INFORMATION_DISCLOSURE, (CC, IDR)),
    _path("lib:6", S.TAMPERING, (CC, IDR), S.REPUDIATION),
    _path("lib:7", S.DENIAL_OF_SERVICE, (TSC,)),
    _path("lib:8", S.TAMPERING, (ITS, TSC)),
    _path("lib:9", S.DENIAL_OF_SERVICE, (ITS, TSC)),
    _path("lib:10", S.SPOOFING, (CC, IDR), S.REPUDIATION),
    _path("lib:11", S.ELEVATION_OF_PRIVILEGE, (TSC,)),
    _path("lib:12", S.TAMPERING, (TSC,)),
    _path("lib:13", S.ELEVATION_OF_PRIVILEGE, (ITS, TSC)),
    _path("lib:14", S.INFORMATION_DISCLOSURE, (ITS, TSC)),
    _path("lib:15", S.DENIAL_OF_SERVICE, (ITS,)),
    _path("lib:16", S.REPUDIATION, (ITS, TSC), S.TAMPERING),
    _path("lib:17", S.REPUDIATION, (CC, IDR), S.TAMPERING),
]


def _kinds(paths: list[AttackPath]) -> set[str]:
    return {path.categories[0] for path in paths}


def test_the_first_set_and_the_limit_cover_every_kind_and_every_system() -> None:
    """The first set (6) had 4 scenarios on Command Centre + Incident Response, and the limit of 15 cut both
    Repudiation paths: a Spoofing path counted as covering Repudiation."""
    ranked = [path for path, _ in rank_paths(RUN_82F22CC3)]
    first_set, within_limit = ranked[:6], ranked[:15]
    assert _kinds(first_set) == set(S) and {s for p in first_set for s in p.systems} == {CC, ITS, TSC, IDR}
    assert sum(path.categories[0] == S.REPUDIATION for path in within_limit) == 2
    assert {s for p in within_limit for s in p.systems} == {CC, ITS, TSC, IDR}


def test_a_high_impact_threat_is_never_given_up_for_more_systems() -> None:
    first = _path("lib:1", S.SPOOFING, (CC,))
    another_high = _path("lib:2", S.SPOOFING, (CC,))
    medium_on_a_new_system = _path("lib:3", S.TAMPERING, (ITS,), impact=2)
    ranked = [path for path, _ in rank_paths([medium_on_a_new_system, another_high, first])]
    assert ranked == [first, another_high, medium_on_a_new_system]


def test_the_order_is_the_same_whatever_the_input_order() -> None:
    expected = [path.path_id for path, _ in rank_paths(RUN_82F22CC3)]
    for seed in range(5):
        shuffled = random.Random(seed).sample(RUN_82F22CC3, len(RUN_82F22CC3))  # noqa: S311 — test data
        assert [path.path_id for path, _ in rank_paths(shuffled)] == expected


def _record(
    path_id: str,
    systems: list[int],
    kind: str,
    selected: bool = True,
    abandoned: bool = False,
    **more: object,
) -> dict:
    """A plan path as stored; finished (served) unless it is unselected, abandoned or `served` says not."""
    finished = selected and not abandoned
    return {
        "path_id": path_id,
        "systems": systems,
        "categories": [kind],
        "selected": selected,
        "abandoned": abandoned,
        "served": f"s-{path_id}" if finished else None,
    } | more


def test_the_coverage_record_names_its_paths_and_why_anything_is_not_covered() -> None:
    """G229: only finished scenarios cover; a gap says why: no threat, the limit, failed, not written yet."""
    paths = [
        _record("p2", [CC], S.SPOOFING),
        _record("p1", [CC, ITS], S.SPOOFING),
        _record("p3", [TSC], S.TAMPERING, selected=False),  # the limit kept others
        _record("p4", [IDR], S.REPUDIATION, abandoned=True, abandoned_reason="no_evidence_cited"),
        _record("p5", [], S.DENIAL_OF_SERVICE),
        _record("p6", [10], S.ELEVATION_OF_PRIVILEGE, served=None),  # selected, a next set writes it
    ]
    systems = {
        CC: "Command Centre",
        ITS: "Traffic Systems",
        TSC: "Signal Control",
        IDR: "Incident Response",
        9: "Historian",
        10: "Gateway",
    }
    record = coverage_record(paths, systems, 4)
    figures = ("limit", "candidates", "selected", "finished", "asset_itself")
    assert tuple(record[key] for key in figures) == (4, 6, 4, 3, 1)
    by_name = {system["name"]: system for system in record["systems"]}
    assert by_name["Command Centre"] == {
        "id": CC,
        "name": "Command Centre",
        "finished": 2,
        "path_ids": ["p1", "p2"],
    }
    for system in record["systems"]:
        assert system["finished"] == len(set(system["path_ids"])) == len(system["path_ids"])
    assert record["kinds"][S.SPOOFING] == {"finished": 2, "path_ids": ["p1", "p2"]}
    gaps = {gap.get("system") or gap.get("kind"): gap["reason"] for gap in record["not_covered"]}
    assert gaps["Signal Control"] == gaps[S.TAMPERING] == CoverageGap.LIMIT_REACHED
    assert gaps["Incident Response"] == gaps[S.REPUDIATION] == CoverageGap.SCENARIOS_FAILED
    assert gaps["Historian"] == gaps[S.INFORMATION_DISCLOSURE] == CoverageGap.NO_RELEVANT_THREAT
    assert gaps["Gateway"] == gaps[S.ELEVATION_OF_PRIVILEGE] == CoverageGap.AWAITING_NEXT_SET
    for unfinished in ("p3", "p4", "p6"):
        assert unfinished not in str(record["systems"]) + str(record["kinds"])
    assert record["given_up"] == [{"path_id": "p4", "reason": "no_evidence_cited", "replaced_by": None}]


def test_a_replaced_path_is_listed_with_its_reserve_and_the_reserve_covers_once_written() -> None:
    """G229: p2 failed for good and reserve p3 took its place: p2 is listed with why and by what; p3 covers
    Traffic Systems only once its scenario is finished, until then a next set writes it."""
    failed = _record(
        "p2", [ITS], S.TAMPERING, selected=False, abandoned=True, abandoned_reason="near_duplicate",
        unselected_reason="replaced_after_failure", replaced_by="p3",
    )  # fmt: skip
    reserve = _record("p3", [ITS], S.TAMPERING, served=None, replaces="p2")
    systems = {CC: "Command Centre", ITS: "Traffic Systems"}
    record = coverage_record([_record("p1", [CC], S.SPOOFING), failed, reserve], systems, 2)
    assert record["given_up"] == [{"path_id": "p2", "reason": "near_duplicate", "replaced_by": "p3"}]
    assert (record["selected"], record["finished"]) == (2, 1)
    assert {"system": "Traffic Systems", "reason": CoverageGap.AWAITING_NEXT_SET} in record["not_covered"]
    reserve["served"] = "s-p3"
    record = coverage_record([_record("p1", [CC], S.SPOOFING), failed, reserve], systems, 2)
    assert record["finished"] == 2 and not [gap for gap in record["not_covered"] if "system" in gap]


def test_with_no_limit_a_gap_is_never_put_down_to_the_limit() -> None:
    """TOTAL_SCENARIO_COUNT 0: every valid path is selected, nothing is left out by a limit, so no reserve
    exists; a failed path stays a gap that says it failed."""
    paths = [
        _record("p1", [CC], S.SPOOFING),
        _record("p2", [ITS], S.TAMPERING, abandoned=True, abandoned_reason="evidence_not_found"),
    ]
    record = coverage_record(paths, {CC: "Command Centre", ITS: "Traffic Systems"}, 0)
    reasons = {gap["reason"] for gap in record["not_covered"]}
    assert CoverageGap.LIMIT_REACHED not in reasons and CoverageGap.SCENARIOS_FAILED in reasons
    assert record["given_up"] == [{"path_id": "p2", "reason": "evidence_not_found", "replaced_by": None}]


def _run(plan: dict | None) -> dict:
    record = {
        "_id": "r1",
        "entity_id": 86,
        "asset_id": 1166,
        "status": "done",
        "updated_at": datetime.now(UTC),
    }
    record["context"] = {
        "systems": [{"id": CC, "name": "Command Centre"}, {"id": ITS, "name": "Traffic Systems"}]
    }
    return record | ({"plan": plan} if plan is not None else {})


def test_the_results_work_coverage_out_from_the_plan_on_every_read() -> None:
    """G227: never a stored copy, so an abandoned path is never counted and an older run has it too."""
    plan = {"target": 15, "paths": [_record("p1", [CC], S.SPOOFING), _record("p2", [ITS], S.TAMPERING)]}
    coverage = run_coverage(_run(plan))
    assert coverage is not None and (coverage["selected"], coverage["finished"]) == (2, 2)
    plan["paths"][1] |= {
        "abandoned": True,
        "served": None,
    }  # the same run read again after p2 failed for good
    coverage = run_coverage(_run(plan))
    assert coverage is not None and (coverage["selected"], coverage["finished"]) == (1, 1)
    assert {"system": "Traffic Systems", "reason": CoverageGap.SCENARIOS_FAILED} in coverage["not_covered"]
    assert run_coverage(_run(None)) is None  # no plan yet
    assert {"plan.paths.served", "plan.paths.abandoned", "context.systems.name"} <= set(COVERAGE_FIELDS)


def test_the_status_never_reads_the_plan_paths_or_the_systems() -> None:
    """G228: the status is read on every run check and live update; only the results show the coverage, so
    only they read what it is worked out from."""
    read = SessionStatus.RECORD_FIELDS
    assert not [key for key in read if key.startswith(("plan.paths", "context.systems"))]
    assert "coverage" not in SessionStatus.model_fields


def test_a_path_stored_without_systems_or_categories_never_fails_the_read() -> None:
    """Coverage is worked out on every status read: a path without them counts in the total, in no system
    or kind, and is not taken for one on the asset itself."""
    bare = {"path_id": "p0", "selected": True, "abandoned": False, "served": "s-p0"}
    plan = {"target": 15, "paths": [bare, _record("p1", [CC], S.SPOOFING)]}
    coverage = run_coverage(_run(plan))
    assert coverage is not None and coverage["finished"] == 2 and coverage["asset_itself"] == 0
    assert coverage["kinds"][S.SPOOFING]["path_ids"] == ["p1"]
    assert all("p0" not in row["path_ids"] for row in coverage["systems"])


def test_the_plan_stores_no_copy_of_its_coverage() -> None:
    threat = planned("lib:7", "Phishing", (321,), categories=(S.SPOOFING,), impact=3)
    findings = ThreatFindings(threats=[threat], audits=[], folded=[], notes=[], landscape=LANDSCAPE)
    assert "coverage" not in AttackPathSelector(target=0).build_plan(findings)
