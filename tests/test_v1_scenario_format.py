"""G267 (owner 2026-10-16: "can we have almost similar format?"): a scenario is shown in TSG v1's results
format,
its fields in v1's order under v1's names and words, then v2's own. v1's requires/produces, standards and
moderation stay out (owner decisions 2026-10-09/10, "Keep them out")."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.constants import ControlMatch, Decision, RunKind
from app.domain.scenario.results import build_scenario_view

V1_KEYS = [
    "scenario_id", "scenario", "threat", "actors", "controls", "accepted", "replaces_accepted_version",
    "accepted_by", "accepted_at", "rejected_by", "rejected_at", "validation_status", "validation_errors",
    "validation_notes", "generation_epoch", "scenario_number", "gen_started_at", "gen_finished_at",
    "gen_seconds",
    "scenario_source", "library", "controls_unavailable", "controls_mapped", "controls_mapping_exhausted",
    "controls_mapping_exhaustion_reason", "replaced_scenarios", "scope", "actor", "threat_source",
    "threat_type_source", "review_flags", "control_match_status",
]  # fmt: skip
V2_EXTRAS = [
    "session_id", "version", "status", "failure", "regenerate_error", "created_at", "controls_status",
    "controls_error", "replaced_by",
    "evidence_mode", "evidence", "evidence_search",
]  # fmt: skip
WRITTEN_AT = datetime(2026, 10, 16, 3, 24, 57, tzinfo=UTC)


def _record(**changes: Any) -> dict[str, Any]:
    """A written scenario as the write job saves it (UAT run 936d0207's first scenario, shortened)."""
    content = {
        "title": "Hidden controller logic manipulation",
        "statement": "A nation-state APT group could seek persistent control over the PGS.",
        "risk_statement": "Manipulation of ICS controller logic could impair the PGS.",
        "why_applies": "ICS-specific malware fits the SCADA system and the ICS.",
        "assumptions": ["assumes contractor credentials can reach the SCADA system"],
        "category": "Elevation of Privilege",
        "category_id": 3,
        "contributing_categories": ["Tampering"],
        "threat": {"key": "lib:568", "type": "Malware/Ransomware", "type_id": 4, "library_id": 568,
                   "name": "ICS-specific malware or firmware implant", "ai_generated": False,
                   "confidence": 85,
                   "rank": 2},
        "actors": [{"id": 68, "name": "Nation-state/APT", "role": "acting", "selection": "chosen",
                    "reason": "r"},
                   {"id": 72, "name": "Ransomware affiliate", "role": "alternate"}],
        "systems": [{"id": 214, "name": "SCADA system", "entry_point": True},
                    {"id": 215, "name": "ICS", "entry_point": False}],
        "system_applicability": [
            {"id": 214, "name": "SCADA system", "applicable": True, "entry_point": True,
             "reason": "foothold"},
            {"id": 215, "name": "ICS", "applicable": True, "entry_point": False, "reason": "runs the logic"},
        ],
        "route": {"status": "standalone"},
        "also_applies": ["Unauthorized controller logic change"],
    }  # fmt: skip
    control = {"control_id": 1300, "code": "CID-0006", "asset_type": "OT", "domain": "Asset Management",
               "name": "Automated Unauthorized Component Detection", "description": "d", "rank": 1,
               "score": 92.0, "match": ControlMatch.EXACT, "tier": "strong",
               "rationale": "Score 92 is at or above 50: strong."}  # fmt: skip
    record = {
        "_id": "239f47cd-1144-59d3-88b2-480ff4af10e4",
        "session_id": "936d0207a84f4e649937e2c2ba3fc400",
        "path_id": "p1",
        "version": 1,
        "status": "done",
        "source": RunKind.GENERATED,
        "decision": Decision.PENDING,
        "content": content,
        "controls": {"status": "done", "items": [control]},
        "findings": [],
        "generation": {
            "epoch": 1,
            "started_at": WRITTEN_AT - timedelta(seconds=18.2),
            "finished_at": WRITTEN_AT,
        },
        "created_at": WRITTEN_AT,
    }
    return record | changes


def _content(**changes: Any) -> dict[str, Any]:
    return {"content": _record()["content"] | changes}


def test_a_scenario_is_shown_in_v1s_order_then_v2s_extras() -> None:
    shown = build_scenario_view(_record()).model_dump()
    assert list(shown) == V1_KEYS + V2_EXTRAS
    assert list(shown["scenario"]) == [
        "threat_category", "contributing_categories", "threat_type", "threat_name",
        "supporting_systems_involved",
        "scenario_title", "scenario_statement", "risk_statement", "assumptions", "route_status",
        "also_applies",
    ]  # fmt: skip
    assert list(shown["scenario"]["supporting_systems_involved"][0]) == [
        "supporting_system_id", "supporting_system", "is_entry_point", "justification", "is_applicable",
    ]  # fmt: skip
    assert list(shown["controls"][0]) == [
        "control_id", "control_code", "itot", "domain", "control_name", "control_description", "map_rank",
        "score",
        "mapping_relevance", "match_type", "match_reason", "tier",
    ]  # fmt: skip
    for dropped in (
        "requires",
        "produces",
        "moderation_checked",
        "moderation_flagged",
        "moderation_categories",
    ):
        assert dropped not in shown and dropped not in shown["scenario"]
    assert "standards" not in shown["controls"][0]


def test_a_written_scenario_carries_v1s_fields_with_their_values() -> None:
    view = build_scenario_view(_record())
    assert (view.actor, view.threat_source, view.threat_type_source) == (
        "Nation-state/APT",
        "LIBRARY",
        "LIBRARY",
    )
    assert view.scope is not None and view.scope.model_dump() == {
        "scope_key": "A+214+215",
        "scope_type": "COMBINATION",
        "supporting_system_ids": [214, 215],
        "evidence": [],  # the stored why_applies is never shown
    }
    assert (view.review_flags, view.control_match_status) == ([], "EXACT")
    assert (view.controls_mapped, view.controls_unavailable, view.controls_mapping_exhausted) == (
        True,
        False,
        False,
    )
    assert view.controls_mapping_exhaustion_reason is None
    assert view.controls[0].mapping_relevance == view.controls[0].score == 92.0
    assert (view.scenario_number, view.generation_epoch, view.gen_seconds) == (1, 1, 18.2)
    assert (view.gen_started_at, view.gen_finished_at) == (WRITTEN_AT - timedelta(seconds=18.2), WRITTEN_AT)
    assert view.threat.grounding_status == "verified" and view.library is None
    assert view.scenario is not None and view.scenario.route_status == "STANDALONE"


def test_a_scenario_written_before_shows_no_generation_times() -> None:
    record = _record()
    record.pop("generation")
    view = build_scenario_view(record)
    assert (view.generation_epoch, view.gen_started_at, view.gen_finished_at, view.gen_seconds) == (None,) * 4


@pytest.mark.parametrize(
    ("systems", "scope_type", "scope_key"),
    [([], "ASSET", "A"), ([{"id": 9, "name": "HMI", "entry_point": True}], "SYSTEM", "A+9")],
)
def test_the_scope_is_the_asset_one_system_or_a_combination(
    systems: list[dict[str, Any]], scope_type: str, scope_key: str
) -> None:
    scope = build_scenario_view(_record(**_content(systems=systems))).scope
    assert scope is not None and (scope.scope_type, scope.scope_key) == (scope_type, scope_key)


def test_an_ai_proposed_threat_on_an_assumed_route_with_a_nearest_control_is_flagged() -> None:
    threat = _record()["content"]["threat"] | {"library_id": None, "type_id": None, "ai_generated": True}
    nearest = _record()["controls"]["items"][0] | {"match": ControlMatch.NEAREST, "tier": "fallback"}
    note = {"code": "plan_check", "severity": "note", "message": "The plan check disagreed."}
    record = _record(**_content(threat=threat, route={"status": "unknown"}), findings=[note])
    record["controls"] = {"status": "done", "items": [nearest]}
    view = build_scenario_view(record)
    assert view.review_flags == ["AI_PROPOSED_TYPE", "AI_PROPOSED_THREAT", "ASSUMED_ROUTE", "PLAN_CHECK",
                                 "NEAREST_CONTROL"]  # fmt: skip
    assert (view.threat_source, view.threat_type_source, view.control_match_status) == (
        "AI_PROPOSED", "AI_PROPOSED", "NEAREST_ONLY",
    )  # fmt: skip
    assert view.threat.grounding_status == "unverified"  # v1's word
    assert view.scenario is not None and view.scenario.route_status == "ASSUMED"  # v1's word for "unknown"


@pytest.mark.parametrize(
    ("controls", "mapped", "exhausted", "reason", "match_status"),
    [
        ({"status": "queued", "items": []}, False, False, None, "PENDING"),
        ({"status": "cancelled", "items": []}, False, False, None, "PENDING"),
        ({"status": "failed", "items": []}, False, True, "retry_budget_exhausted", None),
        ({"status": "done", "items": []}, True, False, None, "CONTROL_LIBRARY_GAP"),
    ],
)
def test_the_controls_flags_follow_the_mapping(
    controls: dict[str, Any], mapped: bool, exhausted: bool, reason: str | None, match_status: str | None
) -> None:
    view = build_scenario_view(_record(controls=controls))
    assert (view.controls_mapped, view.controls_mapping_exhausted) == (mapped, exhausted)
    assert (view.controls_mapping_exhaustion_reason, view.control_match_status) == (reason, match_status)
    assert ("CONTROL_LIBRARY_GAP" in view.review_flags) == (match_status == "CONTROL_LIBRARY_GAP")


def test_a_failure_card_is_v1s_null_scenario_with_its_reason() -> None:
    failure = {
        "code": "unavailable",
        "message": "The AI service did not answer for this attack path in 5 tries.",
    }
    record = _record(status="failed", failure=failure)
    record.pop("controls")
    view = build_scenario_view(record)
    assert view.scenario is None and view.failure == failure
    assert (view.validation_status, view.validation_errors) == ("warning", [failure["message"]])
    assert "VALIDATION_EXCEPTION" in view.review_flags and view.control_match_status is None


def test_a_failure_card_whose_attacker_no_check_supports_names_no_v1_actor() -> None:
    """Owner 2026-10-17 ("If attribution cannot be established, use Unknown/Unattributed"): the path was
    refused so that none is attributed, yet v1's flat field named the nearest attacker; its actors keep their
    roles and how the attacker was decided."""
    failure = {"code": "invalid_plan", "message": "Path p1 cannot be written: no attacker fits its threat."}
    acting = {"id": 68, "name": "Nation-state/APT", "role": "acting", "closest": True, "selection": "ranked"}
    record = _record(status="failed", failure=failure) | _content(actors=[acting])
    record.pop("controls")
    view = build_scenario_view(record)
    assert view.actor is None and [actor.role for actor in view.actors] == ["acting"]
    assert build_scenario_view(_record() | _content(actors=[acting])).actor == "Nation-state/APT"


@pytest.mark.parametrize(
    ("library_status", "threat_status", "banner"),
    [
        ("active", "existing", None),
        ("pending", "inserted", "awaiting a curator's review"),
        ("curator_rejected", "rejected_by_curator", "declined it"),
    ],
)
def test_a_hand_written_card_says_where_its_threat_stands_in_the_library(
    library_status: str, threat_status: str, banner: str | None
) -> None:
    threat = {"type": "Drone intrusion", "type_id": 12, "name": "Rogue drone", "library_id": 901,
              "library_status": library_status, "ai_generated": False}  # fmt: skip
    record = _record(source=RunKind.MANUAL, **_content(threat=threat, title=None, why_applies=None))
    view = build_scenario_view(record)
    assert view.library is not None
    assert view.library.threat.model_dump() == {"name": "Rogue drone", "status": threat_status}
    assert view.library.threat_type.model_dump() == {"name": "Drone intrusion", "status": "existing"}
    assert (view.library.message is None) if banner is None else (banner in (view.library.message or ""))
    assert (view.threat_source, view.threat_type_source) == (None, None)  # v1: hand-written cards have none
    verified = library_status == "active"
    assert view.threat.grounding_status == ("verified" if verified else "unverified")
