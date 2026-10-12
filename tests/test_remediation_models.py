"""Remediation request bodies, the plan AI's answer contract and the status shape (Step 16, BUILD_PLAN S45):
T-REM schema limits. Pure models, no store."""

from datetime import UTC, date, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.constants import Decision, RemediationProgress, Status
from app.models.remediation import PlanDraft, RemediationStatus
from app.models.remediation_requests import DecisionRequest, PlanRequest, RegenerateRequest, RegisterData

MANUAL: dict[str, Any] = {
    "asset_id": 103,
    "supporting_system_ids": [321],
    "threat_type": {"name": "Malicious code"},
    "threat": {"id": 5},
    "threat_scenario": "An insider could upload altered logic to the PLC.",
    "risk_statement": "Loss of trusted control could stop the substation.",
}


def test_blank_means_not_given_on_every_register_field() -> None:
    """FR-REM-03: the platform's form sends "" for an empty field; it is never a 422."""
    blank = dict.fromkeys(RegisterData.model_fields, " ")
    assert all(value is None for value in RegisterData.model_validate(blank).model_dump().values())


def test_ratings_are_exact_decimals_within_their_limits() -> None:
    """BR-REM-04: stored as exact decimal strings (2.46 never 2.4599…); ≥ 0, ≤ 15 digits, ≤ 4 places."""
    register = RegisterData.model_validate(
        {"likelihood_rating": 3, "impact_rating": "2.46", "final_risk_rating": 7.38}
    ).register()
    ratings = (register["likelihood_rating"], register["impact_rating"], register["final_risk_rating"])
    assert ratings == ("3", "2.46", "7.38")
    for wrong in ("1234567890123456", "1.23456", -1, "abc"):
        with pytest.raises(ValidationError):
            RegisterData.model_validate({"final_risk_rating": wrong})


def test_the_mitigation_window_keeps_the_calendar_date_written_and_comes_as_a_pair() -> None:
    """A date-time keeps the date as written (an offset never moves it a day); both or neither; end ≥ start;
    the identification time is an instant, kept in UTC."""
    window = RegisterData.model_validate(
        {
            "mitigation_start_date": "2026-10-01T02:00:00+05:30",
            "mitigation_end_date": "2026-12-31T15:38:19.853",
        }
    )
    assert (window.mitigation_start_date, window.mitigation_end_date) == (
        date(2026, 10, 1),
        date(2026, 12, 31),
    )
    for wrong in (
        {"mitigation_start_date": "2026-10-01"},
        {"mitigation_start_date": "2026-10-02", "mitigation_end_date": "2026-10-01"},
    ):
        with pytest.raises(ValidationError):
            RegisterData.model_validate(wrong)
    identified = RegisterData.model_validate({"risk_identification_date": "2026-09-18T15:38:19"})
    assert identified.risk_identification_date == datetime(2026, 9, 18, 15, 38, 19, tzinfo=UTC)


def test_register_controls_take_strings_drop_blanks_and_keep_the_first_of_a_repeat() -> None:
    """A code-shaped string is a code and a name; free text is a name; a repeat (case aside) is dropped; an
    entry naming nothing, an impossible id or a 51st entry is refused."""
    controls = RegisterData.model_validate(
        {
            "existing_controls": [
                "CII-CID-202",
                "",
                "Quarterly phishing simulation",
                "cii-cid-202",
                {"control_id": 7},
            ]
        }
    ).existing_controls
    assert controls is not None
    assert [(c.control_id, c.control_code, c.control_name) for c in controls] == [
        (None, "CII-CID-202", "CII-CID-202"),
        (None, None, "Quarterly phishing simulation"),
        (7, None, None),
    ]
    for wrong in ([{}], [f"control {n}" for n in range(51)], [{"control_id": 0}]):
        with pytest.raises(ValidationError):
            RegisterData.model_validate({"existing_controls": wrong})


def test_a_plan_request_names_exactly_one_scenario() -> None:
    """Either an accepted generated scenario or a hand-written one; the hand-written one has no title,
    names its library rows, and lists each of its controls once; any register label is accepted and echoed."""
    assert PlanRequest.model_validate({"scenario_id": "s1", "risk_level": "Severe"}).risk_level == "Severe"
    assert PlanRequest.model_validate({"manual_scenario": MANUAL}).manual_scenario is not None
    for wrong in (
        {},
        {"scenario_id": "s1", "manual_scenario": MANUAL},
        {"scenario_id": "s1", "strategy": "Accept"},
        {"manual_scenario": MANUAL | {"scenario_title": "x"}},
        {"manual_scenario": MANUAL | {"threat": {}}},
        {"manual_scenario": MANUAL | {"threat_type": {"name": "---"}}},
        {"manual_scenario": MANUAL | {"threat_type": {"name": "t" * 301}}},  # Threat_Type holds 300
        {"manual_scenario": MANUAL | {"threat_category": {"name": "c" * 201}}},
        {"scenario_id": "s1", "existing_controls_all_subsystems": "yes"},
        {"manual_scenario": MANUAL | {"mapped_controls": ["CII-CID-1", {"control_code": "cii-cid-1"}]}},
        {"manual_scenario": MANUAL | {"supporting_system_ids": [321, 321]}},
        {"manual_scenario": MANUAL | {"threat_scenario": "   "}},  # review S56: blank is not a statement
        {"manual_scenario": MANUAL | {"risk_statement": "\n\t "}},
    ):
        with pytest.raises(ValidationError):
            PlanRequest.model_validate(wrong)


def test_decision_and_regenerate_bodies_refuse_unknown_fields() -> None:
    assert DecisionRequest.model_validate({}).version is None
    wrongs: list[tuple[Any, dict[str, Any]]] = [
        (DecisionRequest, {"version": 0}),
        (DecisionRequest, {"comment": "x" * 2001}),
        (DecisionRequest, {"versoin": 2}),
        (RegenerateRequest, {"user_note": "x"}),
    ]
    for model, body in wrongs:
        with pytest.raises(ValidationError):
            model.model_validate(body)


def test_the_plan_answer_contract() -> None:
    """R5: v1's fields and vocabularies; empty text, an unknown priority or a depends_on that is not a list
    is a broken answer (asked again once)."""
    action = {
        "action_id": "A1",
        "action": "Enforce MFA for vendor sessions",
        "owner": "OT Security",
        "priority": "High",
        "dependencies": "None",
        "depends_on": [],
        "duration_days": 14,
        "implements_controls": ["CII-CID-202"],
        "success_criteria": "The access policy requires MFA.",
    }
    answer = {
        "title": "Vendor access hardening",
        "controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
        "remediation_action_plan": [action],
        "action_plan": "A1 runs first.",
        "mitigation_owner": "OT Security",
        "applicable_to_all_subsystems": "Yes",
    }
    assert PlanDraft.model_validate(answer).remediation_action_plan[0].duration_days == 14
    for wrong in (action | {"action": " "}, action | {"priority": "Urgent"}, action | {"depends_on": "A0"}):
        with pytest.raises(ValidationError):
            PlanDraft.model_validate(answer | {"remediation_action_plan": [wrong]})


@pytest.mark.parametrize(
    ("status", "decision", "overall"),
    [
        (Status.FAILED, Decision.ACCEPTED, RemediationProgress.FAILED),
        (Status.RUNNING, Decision.ACCEPTED, RemediationProgress.GENERATING),
        (Status.DONE, Decision.PENDING, RemediationProgress.AWAITING_REVIEW),
        (Status.DONE, Decision.REJECTED, RemediationProgress.REJECTED),
        (Status.DONE, Decision.ACCEPTED, RemediationProgress.ACCEPTED),
    ],
)
def test_overall_progress_takes_the_first_that_applies(
    status: Status, decision: Decision, overall: str
) -> None:
    """R10: failed > generating > awaiting review > the record's decision."""
    record = {
        "_id": "r1",
        "entity_id": 135,
        "scenario_id": "s1",
        "session_id": "run1",
        "status": status,
        "decision": decision,
        "job": {"epoch": 2, "error": None},
        "updated_at": datetime.now(UTC),
    }
    shown = RemediationStatus.from_record(record)
    assert (shown.progress.overall, shown.latest_version) == (overall, 2)
