"""Remediation rules: the request bodies, the plan AI's answer contract, a plan's progress, the shown version
and what a decision changes. Pure, no store."""

import re
from datetime import UTC, date, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.constants import (
    AiOutage,
    ConflictReason,
    Decision,
    Remediation,
    RemediationMessage,
    RemediationProgress,
    Status,
)
from app.core.exceptions import Conflict, NotFound
from app.domain.remediation.rules import decidable_version, decision_change, newest_done_version
from app.models.remediation.plan import PlanDraft, RemediationResult, RemediationStatus, shown_item
from app.models.remediation.requests import (
    PLAN_REQUEST_EXAMPLES,
    PlanRequest,
    RegenerateRequest,
    ReviewRequest,
)

NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
FLAGS = {"all_supporting_systems_applicable": 1, "existing_controls_all_supporting_system_applicable": 1}
GENERATED: dict[str, Any] = {"is_manual": False, "session_id": "r1", "scenario_id": "s1", **FLAGS}
MANUAL: dict[str, Any] = {
    "asset_id": 103,
    "entity_id": 7,
    "supporting_system_ids": [321],
    "threat_type_name": "Malicious code",
    "threat_id": 5,
    "threat_scenario": "An insider could upload altered logic to the PLC.",
    "risk_statement": "Loss of trusted control could stop the substation.",
}
HAND_WRITTEN: dict[str, Any] = {"is_manual": True, "manual_scenario": MANUAL, **FLAGS}
#: The register fields a form may leave blank: all but the two mandatory flags.
REGISTER_FIELDS = set(PlanRequest.model_fields) - {
    "is_manual",
    "session_id",
    "scenario_id",
    "manual_scenario",
    *FLAGS,
}
BY = {"decided_by": "u1", "decided_by_client": "c1"}


def _register(**fields: Any) -> PlanRequest:
    """A generated scenario's plan request with these register fields."""
    return PlanRequest.model_validate(GENERATED | fields)


def test_blank_register_fields_mean_not_given() -> None:
    """The platform's form sends "" for an empty field; it is never a 422."""
    stored = _register(**dict.fromkeys(REGISTER_FIELDS, " ")).register()
    assert stored == dict.fromkeys(REGISTER_FIELDS) | FLAGS


def test_ratings_are_exact_decimals_stored_as_text() -> None:
    """2.46 is never 2.4599…; a rating is 0 or more with at most 15 digits, 4 of them after the point."""
    register = _register(likelihood_rating=3, impact_rating="2.46", final_risk_rating=7.38).register()
    ratings = (register["likelihood_rating"], register["impact_rating"], register["final_risk_rating"])
    assert ratings == ("3", "2.46", "7.38")
    for wrong in ("1234567890123456", "1.23456", -1, "abc"):
        with pytest.raises(ValidationError):
            _register(final_risk_rating=wrong)


def test_the_window_is_a_calendar_pair_in_order() -> None:
    """A date-time keeps the date as written (an offset never moves it a day); both or neither, end on or
    after start; the identification time is an instant, kept in UTC."""
    window = _register(
        mitigation_start_date="2026-10-01T02:00:00+05:30", mitigation_end_date="2026-12-31T15:38:19.853"
    )
    assert (window.mitigation_start_date, window.mitigation_end_date) == (
        date(2026, 10, 1),
        date(2026, 12, 31),
    )
    assert window.register()["mitigation_start_date"] == "2026-10-01"
    wrongs = [
        ({"mitigation_start_date": "2026-10-01"}, RemediationMessage.WINDOW_PAIR),
        (
            {"mitigation_start_date": "2026-10-02", "mitigation_end_date": "2026-10-01"},
            RemediationMessage.WINDOW_ORDER,
        ),
    ]
    for wrong, message in wrongs:
        with pytest.raises(ValidationError, match=re.escape(message)):
            _register(**wrong)
    for written in ("2026-09-18T15:38:19", "2026-09-18T21:08:19+05:30"):
        identified = _register(risk_identification_date=written).risk_identification_date
        assert identified == datetime(2026, 9, 18, 15, 38, 19, tzinfo=UTC)


def test_register_controls_take_plain_strings_drop_blanks_and_keep_the_first_of_a_repeat() -> None:
    """A code-shaped string is a code and a name; free text is a name; a repeat (case aside) is dropped; an
    entry naming nothing, an impossible id or a 51st entry is refused."""
    controls = _register(
        existing_controls=[
            "CII-CID-202",
            "",
            "Quarterly phishing simulation",
            "cii-cid-202",
            {"control_id": 7},
        ]
    ).existing_controls
    assert controls is not None
    assert [(c.control_id, c.control_code, c.control_name) for c in controls] == [
        (None, "CII-CID-202", "CII-CID-202"),
        (None, None, "Quarterly phishing simulation"),
        (7, None, None),
    ]
    too_many = [f"control {n}" for n in range(Remediation.MAX_CONTROL_REFS + 1)]
    for wrong in ([{}], too_many, [{"control_id": 0}]):
        with pytest.raises(ValidationError):
            _register(existing_controls=wrong)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"is_manual": True, **FLAGS}, RemediationMessage.MANUAL_NEEDS_SCENARIO),
        (HAND_WRITTEN | {"scenario_id": "s1"}, RemediationMessage.MANUAL_SENDS_NO_IDS),
        ({"is_manual": False, "scenario_id": "s1", **FLAGS}, RemediationMessage.GENERATED_NEEDS_IDS),
        (GENERATED | {"manual_scenario": MANUAL}, RemediationMessage.GENERATED_SENDS_NO_SCENARIO),
    ],
)
def test_a_request_sends_exactly_one_kind(body: dict[str, Any], message: str) -> None:
    """Each kind sends its own half and never the other's."""
    with pytest.raises(ValidationError, match=re.escape(message)):
        PlanRequest.model_validate(body)


def test_a_hand_written_scenario_names_its_library_rows_and_has_no_title() -> None:
    """The type and the threat each named by id or name, the entity sent, no title, statements not blank,
    every name within its column; any register label is accepted and echoed."""
    assert _register(risk_level="Severe").risk_level == "Severe"
    manual = PlanRequest.model_validate(HAND_WRITTEN).manual_scenario
    assert manual is not None and (manual.threat_type.name, manual.threat.id) == ("Malicious code", 5)
    assert manual.threat_category is None and manual.entity_id == 7
    no_entity = {key: value for key, value in MANUAL.items() if key != "entity_id"}
    for wrong in (
        {"scenario_id": "s1", "session_id": "r1"},  # is_manual is required
        GENERATED | {"strategy": "Accept"},
        GENERATED | {"existing_controls_all_subsystems": "yes"},
        {"is_manual": True, "manual_scenario": no_entity},
        *(
            {"is_manual": True, "manual_scenario": MANUAL | changes}
            for changes in (
                {"scenario_title": "x"},
                {"threat_id": None},  # the threat is not named
                {"threat_type_name": ""},  # nor the type
                {"threat_type_name": "---"},
                {"threat_type_name": "t" * 301},  # Threat_Type holds 300
                {"threat_category_name": "c" * 201},
                {"threat_id": 0},
                {"threat_type": {"name": "the nested shape is gone"}},
                {"supporting_system_ids": [321, 321]},
                {"threat_scenario": "   "},  # blank is not a statement
                {"risk_statement": "\n\t "},
            )
        ),
    ):
        with pytest.raises(ValidationError):
            PlanRequest.model_validate(wrong)


def test_every_published_example_is_valid() -> None:
    """Swagger's two examples (one per kind) can never drift from the model."""
    kinds = [PlanRequest.model_validate(example).is_manual for example in PLAN_REQUEST_EXAMPLES]
    assert kinds == [False, True]


def test_review_and_regenerate_bodies_refuse_unknown_fields() -> None:
    """A review accepts or rejects one version (default: the newest done) with an optional comment; a
    regenerate takes nothing."""
    review = ReviewRequest.model_validate({"decision": "accepted"})
    assert (review.decision, review.version, review.comment) == (Decision.ACCEPTED, None, None)
    assert RegenerateRequest.model_validate({}) == RegenerateRequest()
    wrongs: list[tuple[Any, dict[str, Any]]] = [
        (ReviewRequest, {}),
        (ReviewRequest, {"decision": "pending"}),
        (ReviewRequest, {"decision": "rejected", "versoin": 2}),
        (ReviewRequest, {"decision": "rejected", "version": 0}),
        (ReviewRequest, {"decision": "rejected", "comment": "x" * (Remediation.COMMENT_MAX_CHARS + 1)}),
        (RegenerateRequest, {"user_note": "x"}),
    ]
    for model, body in wrongs:
        with pytest.raises(ValidationError):
            model.model_validate(body)


CONTROL: dict[str, Any] = {
    "control_type": "preventive",
    "control_name": "Multi-factor authentication",
    "description": "MFA on every vendor session.",
    "priority": "High",
    "control_code": "CII-CID-202",
}
ACTION: dict[str, Any] = {
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
ANSWER: dict[str, Any] = {
    "title": "Vendor access hardening",
    "control_validation": [{"control_code": "CII-CID-202", "validation": "retained", "reason": "It fits."}],
    "controls_to_be_implemented": {"control_coverage": "covered", "controls": [CONTROL]},
    "remediation_action_plan": [ACTION],
    "action_plan": "A1 runs first.",
    "mitigation_owner": "OT Security",
    "applicable_to_all_subsystems": "Yes",
}


def test_the_ai_contract_refuses_blank_text() -> None:
    """The answer's {control_coverage, controls} is read as its controls (code sets the coverage); blank text,
    an unknown priority, a depends_on that is not a list or a table without controls is a broken answer."""
    draft = PlanDraft.model_validate(ANSWER)
    assert [control.control_code for control in draft.controls_to_be_implemented] == ["CII-CID-202"]
    assert draft.remediation_action_plan[0].duration_days == 14
    broken = [
        ANSWER | {"title": " "},
        ANSWER | {"remediation_action_plan": [ACTION | {"action": "\n\t"}]},
        ANSWER | {"controls_to_be_implemented": {"controls": [CONTROL | {"control_code": " "}]}},
        ANSWER | {"remediation_action_plan": [ACTION | {"priority": "Urgent"}]},
        ANSWER | {"remediation_action_plan": [ACTION | {"depends_on": "A0"}]},
        ANSWER | {"controls_to_be_implemented": {"control_coverage": "gaps"}},
        {key: value for key, value in ANSWER.items() if key != "control_validation"},
        ANSWER
        | {"control_validation": [{"control_code": "CII-CID-202", "validation": "kept", "reason": "x"}]},
        ANSWER
        | {"control_validation": [{"control_code": "CII-CID-202", "validation": "retained", "reason": " "}]},
    ]
    for answer in broken:
        with pytest.raises(ValidationError):
            PlanDraft.model_validate(answer)


@pytest.mark.parametrize(
    ("status", "decision", "overall"),
    [
        (Status.FAILED, Decision.ACCEPTED, RemediationProgress.FAILED),
        (Status.CANCELLED, Decision.ACCEPTED, RemediationProgress.CANCELLED),
        (Status.QUEUED, Decision.ACCEPTED, RemediationProgress.GENERATING),
        (Status.RUNNING, Decision.REJECTED, RemediationProgress.GENERATING),
        (Status.DONE, Decision.PENDING, RemediationProgress.AWAITING_REVIEW),
        (Status.DONE, Decision.REJECTED, RemediationProgress.REJECTED),
        (Status.DONE, Decision.ACCEPTED, RemediationProgress.ACCEPTED),
    ],
)
def test_overall_progress_takes_the_first_that_applies(
    status: Status, decision: Decision, overall: RemediationProgress
) -> None:
    """Failed, cancelled, generating, awaiting review, then the record's decision; a plan waiting out an AI
    outage says so only while it generates."""
    retry = {"reason": AiOutage.BUSY, "message": "busy", "attempt": 1, "max_attempts": 5, "retry_at": NOW}
    record = {
        "_id": "r1",
        "entity_id": 135,
        "scenario_id": "s1",
        "session_id": "run1",
        "status": status,
        "decision": decision,
        "job": {"epoch": 2, "error": None, "retry": retry},
        "updated_at": NOW,
    }
    shown = RemediationStatus.from_record(record)
    assert (shown.progress.overall, shown.latest_version) == (overall, 2)
    notice = shown.progress.retrying
    assert (notice is not None) is (overall == RemediationProgress.GENERATING)
    assert notice is None or (notice.stage, notice.reason, notice.attempt) == (None, AiOutage.BUSY, 1)
    assert "job.retry" in RemediationStatus.RECORD_FIELDS  # a status read loads the notice


def _read(
    *statuses: Status, decisions: tuple[Decision, ...] = (), accepted: int | None = None
) -> dict[str, Any]:
    """A plan record with one version per status; the latest version's status lives at the top of the record
    (its own item still says queued)."""
    decided = decisions or (Decision.PENDING,) * len(statuses)
    latest = len(statuses)
    versions = [
        {"version": number, "status": Status.QUEUED if number == latest else status, "decision": decision}
        for number, (status, decision) in enumerate(zip(statuses, decided, strict=True), start=1)
    ]
    return {
        "versions": versions,
        "status": statuses[-1],
        "job": {"epoch": latest},
        "accepted_version": accepted,
    }


def test_the_accepted_version_is_shown_else_the_newest_done() -> None:
    """A result builds that version alone; the others only when the history is asked for (a malformed older
    plan proves it is never read)."""
    newest = _read(Status.DONE, Status.DONE, Status.QUEUED)
    reads = (newest, newest | {"accepted_version": 1}, _read(Status.DONE, Status.DONE), _read(Status.FAILED))
    assert [(shown_item(read) or {}).get("version") for read in reads] == [2, 1, 2, None]
    item = {"status": Status.DONE, "decision": Decision.PENDING, "requested_at": NOW, "plan": None,
            "warnings": [], "prompt_version": None}  # fmt: skip
    record = {
        "_id": "r1", "entity_id": 135, "scenario_id": "s1", "session_id": "run1", "status": Status.DONE,
        "decision": Decision.PENDING, "accepted_version": None, "job": {"epoch": 2, "error": None},
        "updated_at": NOW,
        "versions": [item | {"version": 1, "plan": {"not": "a plan"}}, item | {"version": 2}],
    }  # fmt: skip
    result = RemediationResult.from_records(record, None, include_history=False)
    assert (result.shown_version, result.versions) == (2, None)
    with pytest.raises(KeyError):  # the malformed plan is read only for the history
        RemediationResult.from_records(record, None, include_history=True)


def test_accepting_moves_the_one_accepted_version_and_a_repeat_changes_nothing() -> None:
    """Accepting v2 puts the accepted v1 back to pending; accepting the accepted version again, or rejecting a
    rejected one, changes nothing; rejecting the accepted version clears it."""
    read = _read(Status.DONE, Status.DONE, decisions=(Decision.ACCEPTED, Decision.PENDING), accepted=1)
    assert decision_change(read, 2, Decision.ACCEPTED, BY, "Fits the window.", NOW) == {
        "version": 2,
        "decision": Decision.ACCEPTED,
        "stamp": BY | {"decided_at": NOW, "review_comment": "Fits the window."},
        "back_to_pending": 1,
        "accepted_version": 2,
        "record_decision": Decision.ACCEPTED,
    }
    assert decision_change(read, 1, Decision.ACCEPTED, BY, None, NOW) is None
    rejected = _read(Status.DONE, Status.DONE, decisions=(Decision.REJECTED, Decision.PENDING))
    assert decision_change(rejected, 1, Decision.REJECTED, BY, None, NOW) is None
    cleared = decision_change(read, 1, Decision.REJECTED, BY, None, NOW)
    assert cleared is not None and (cleared["accepted_version"], cleared["back_to_pending"]) == (None, None)


@pytest.mark.parametrize(
    ("statuses", "decisions", "record"),
    [
        ((Status.DONE, Status.DONE), (Decision.PENDING, Decision.PENDING), Decision.PENDING),
        ((Status.DONE, Status.QUEUED), (Decision.PENDING, Decision.PENDING), Decision.PENDING),
        ((Status.DONE, Status.DONE), (Decision.PENDING, Decision.REJECTED), Decision.REJECTED),
        (
            (Status.DONE, Status.FAILED, Status.DONE),
            (Decision.PENDING, Decision.PENDING, Decision.REJECTED),
            Decision.REJECTED,
        ),
    ],
)
def test_the_record_decision_waits_while_a_version_is_undecided(
    statuses: tuple[Status, ...], decisions: tuple[Decision, ...], record: Decision
) -> None:
    """Rejecting v1: the record waits while the latest version or a done one is undecided (one being written
    counts); an older failed version waits for nothing."""
    change = decision_change(_read(*statuses, decisions=decisions), 1, Decision.REJECTED, BY, None, NOW)
    assert change is not None and change["record_decision"] == record


def test_the_decided_version_defaults_to_the_newest_done_and_must_be_done() -> None:
    """None asked: the newest done; 404 a version the plan does not have; 409 one not done, or none done."""
    read = _read(Status.DONE, Status.DONE, Status.RUNNING)
    assert newest_done_version(read) == 2
    assert (decidable_version(read, None, "r1"), decidable_version(read, 1, "r1")) == (2, 1)
    with pytest.raises(NotFound) as unknown:
        decidable_version(read, 9, "r1")
    assert unknown.value.reason == ConflictReason.VERSION_NOT_FOUND
    for undecidable, asked in ((read, 3), (_read(Status.FAILED), None)):
        with pytest.raises(Conflict) as refused:
            decidable_version(undecidable, asked, "r1")
        assert refused.value.reason == ConflictReason.NOT_COMPLETE


@pytest.mark.parametrize(
    "flags",
    [
        {},  # both mandatory
        {"all_supporting_systems_applicable": 1},
        {"existing_controls_all_supporting_system_applicable": 1},
        FLAGS | {"all_supporting_systems_applicable": 2},
        FLAGS | {"all_supporting_systems_applicable": "1"},  # an integer, never text
        FLAGS | {"all_supporting_systems_applicable": True},
        FLAGS | {"all_supporting_systems_applicable": 1.0},
        FLAGS | {"existing_controls_all_supporting_system_applicable": ""},
    ],
    ids=["neither", "no-existing-flag", "no-risk-flag", "two", "text", "boolean", "float", "blank"],
)
def test_the_two_flags_are_mandatory_integers_0_or_1(flags: dict[str, Any]) -> None:
    body = {"is_manual": False, "session_id": "r1", "scenario_id": "s1"} | flags
    with pytest.raises(ValidationError):
        PlanRequest.model_validate(body)


def test_existing_controls_name_their_systems_when_not_on_all_and_a_repeat_adds_its_systems() -> None:
    """Flag 0: every existing control lists supporting_system_ids (422 naming the one that does not);
    flag 1: none is needed; one control listed twice is one entry with both lists' systems."""
    by_system = GENERATED | {"existing_controls_all_supporting_system_applicable": 0}
    with pytest.raises(ValidationError) as missing:
        PlanRequest.model_validate(
            by_system
            | {
                "existing_controls": [
                    {"control_code": "CII-CID-1", "supporting_system_ids": [321]},
                    "Backup policy",
                ]
            }
        )
    expected = RemediationMessage.SYSTEMS_REQUIRED.format(position=1, control="Backup policy")
    assert expected in str(missing.value)
    assert _register(existing_controls=["CII-CID-1"]).existing_controls is not None  # flag 1: no ids needed
    twice = [
        {"control_code": "CII-CID-1", "supporting_system_ids": [321]},
        {"control_code": "cii-cid-1", "supporting_system_ids": [322, 321]},
    ]
    request = PlanRequest.model_validate(by_system | {"existing_controls": twice})
    assert request.existing_controls is not None
    assert [entry.supporting_system_ids for entry in request.existing_controls] == [[321, 322]]
    assert request.register()["existing_controls"][0]["supporting_system_ids"] == [321, 322]
