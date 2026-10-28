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
from app.core.exceptions import Conflict, Invalid, NotFound
from app.domain.remediation.rules import (
    check_register_systems,
    decidable_version,
    decision_change,
    newest_done_version,
)
from app.models.remediation.plan import PlanDraft, RemediationResult, RemediationStatus, shown_item
from app.models.remediation.requests import (
    PLAN_REQUEST_EXAMPLES,
    SYSTEM_LISTS,
    PlanRequest,
    RegenerateRequest,
    ReviewRequest,
)

NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
#: The two supporting system lists as stored when none is sent: the risk and the existing controls on none.
NO_SYSTEM = dict.fromkeys(SYSTEM_LISTS, [])
GENERATED: dict[str, Any] = {"is_manual": False, "session_id": "r1", "scenario_id": "s1"}
MANUAL: dict[str, Any] = {
    "asset_id": 103,
    "entity_id": 7,
    "supporting_system_ids": [321],
    "threat_type_name": "Malicious code",
    "threat_id": 5,
    "threat_scenario": "An insider could upload altered logic to the PLC.",
    "risk_statement": "Loss of trusted control could stop the substation.",
}
HAND_WRITTEN: dict[str, Any] = {"is_manual": True, "manual_scenario": MANUAL}
#: The register fields a form may leave blank: all of them.
REGISTER_FIELDS = set(PlanRequest.model_fields) - {
    "is_manual",
    "session_id",
    "scenario_id",
    "manual_scenario",
}
BY = {"decided_by": "u1", "decided_by_client": "c1"}


def _register(**fields: Any) -> PlanRequest:
    """A generated scenario's plan request with these register fields."""
    return PlanRequest.model_validate(GENERATED | fields)


def test_blank_register_fields_mean_not_given() -> None:
    """The platform's form sends "" for an empty field; it is never a 422 (an empty system list is [])."""
    stored = _register(**dict.fromkeys(REGISTER_FIELDS, " ")).register()
    assert stored == dict.fromkeys(REGISTER_FIELDS) | NO_SYSTEM


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
        ({"is_manual": True}, RemediationMessage.MANUAL_NEEDS_SCENARIO),
        (HAND_WRITTEN | {"scenario_id": "s1"}, RemediationMessage.MANUAL_SENDS_NO_IDS),
        ({"is_manual": False, "scenario_id": "s1"}, RemediationMessage.GENERATED_NEEDS_IDS),
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
    assert manual is not None and (manual.threat_type_name, manual.threat_id) == ("Malicious code", 5)
    assert (manual.threat_category_id, manual.threat_category_name, manual.entity_id) == (None, None, 7)
    no_entity = {key: value for key, value in MANUAL.items() if key != "entity_id"}
    for wrong in (
        {"scenario_id": "s1", "session_id": "r1"},  # is_manual is required
        GENERATED | {"strategy": "Accept"},
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
    """Swagger's two examples (one per kind) can never drift from the model; each shows both system lists."""
    requests = [PlanRequest.model_validate(example) for example in PLAN_REQUEST_EXAMPLES]
    assert [request.is_manual for request in requests] == [False, True]
    for request in requests:
        register = request.register()
        assert (
            register["existing_controls"] and register["supporting_systems_applicable_to_existing_controls"]
        )


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
    shown = RemediationStatus.from_record(record, scenario_accepted=True)
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
    result = RemediationResult.from_records(record, None, True, include_history=False)
    assert (result.shown_version, result.versions) == (2, None)
    with pytest.raises(KeyError):  # the malformed plan is read only for the history
        RemediationResult.from_records(record, None, True, include_history=True)


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


BASES = {"generated": GENERATED, "hand-written": HAND_WRITTEN}


@pytest.mark.parametrize("kind", BASES)
@pytest.mark.parametrize(
    ("changes", "loc"),
    [
        ({"supporting_systems_applicable_to_risk": [0]}, ("supporting_systems_applicable_to_risk", 0)),
        (
            {"supporting_systems_applicable_to_existing_controls": [322, 0]},
            ("supporting_systems_applicable_to_existing_controls", 1),
        ),
        (
            {"existing_controls": [{"control_code": "CII-CID-1", "supporting_system_ids": [322]}]},
            ("existing_controls", 0, "supporting_system_ids"),
        ),
    ],
    ids=["bad-risk-id", "bad-existing-id", "systems-inside-a-control"],
)
def test_the_supporting_system_lists_are_refused_when_wrong(
    kind: str, changes: dict[str, Any], loc: tuple[Any, ...]
) -> None:
    """An impossible id in either list and an existing control naming its own systems (an unknown field) are
    refused."""
    with pytest.raises(ValidationError) as refused:
        PlanRequest.model_validate(BASES[kind] | changes)
    assert [error["loc"] for error in refused.value.errors()] == [loc]


#: The old yes/no flags, each with the list a caller sends instead.
OLD_FLAGS = {
    "all_supporting_systems_applicable": "supporting_systems_applicable_to_risk",
    "existing_controls_all_supporting_system_applicable": SYSTEM_LISTS[1],
    "existing_controls_all_subsystems": SYSTEM_LISTS[1],
}


@pytest.mark.parametrize("kind", BASES)
@pytest.mark.parametrize("flag", OLD_FLAGS)
@pytest.mark.parametrize(
    "value", [0, 1, [321], None, "", "Yes"], ids=["0", "1", "list", "null", "blank", "yes"]
)
def test_an_old_supporting_system_flag_is_refused_naming_the_list_to_send(
    kind: str, flag: str, value: Any
) -> None:
    """Any value of an old flag, with the two lists or without them, is refused on that field with a message
    naming the list to send instead."""
    message = RemediationMessage.SYSTEM_FLAG_REMOVED.format(flag=flag, replacement=OLD_FLAGS[flag])
    for lists in ({}, dict.fromkeys(SYSTEM_LISTS, [321])):
        with pytest.raises(ValidationError) as refused:
            PlanRequest.model_validate(BASES[kind] | lists | {flag: value})
        assert [(error["loc"], error["msg"]) for error in refused.value.errors()] == [((flag,), message)]


@pytest.mark.parametrize("kind", BASES)
def test_old_flags_sent_together_are_each_refused_on_their_own_field(kind: str) -> None:
    """All three old flags in one body give three errors, one per flag, each naming its own list."""
    with pytest.raises(ValidationError) as refused:
        PlanRequest.model_validate(BASES[kind] | dict.fromkeys(OLD_FLAGS, 1))
    assert [(error["loc"], error["msg"]) for error in refused.value.errors()] == [
        ((flag,), RemediationMessage.SYSTEM_FLAG_REMOVED.format(flag=flag, replacement=list_to_send))
        for flag, list_to_send in OLD_FLAGS.items()
    ]


MISSING = object()


@pytest.mark.parametrize("kind", BASES)
@pytest.mark.parametrize("none", [None, "", [], MISSING], ids=["null", "blank", "empty", "missing"])
def test_a_list_naming_no_system_is_accepted_and_stored_empty(kind: str, none: Any) -> None:
    """null, "" and [] (or no list) mean no supporting system, for either list, with existing controls named
    or not: accepted and stored as [], never None."""
    for listed, other in (SYSTEM_LISTS, SYSTEM_LISTS[::-1]):
        sent = {} if none is MISSING else {listed: none}
        for existing in (None, ["CII-CID-1"]):
            body = BASES[kind] | {"existing_controls": existing, other: [321]} | sent
            stored = PlanRequest.model_validate(body).register()
            assert (stored[listed], stored[other]) == ([], [321])
    both = {} if none is MISSING else dict.fromkeys(SYSTEM_LISTS, none)
    stored = PlanRequest.model_validate(BASES[kind] | both | {"existing_controls": ["CII-CID-1"]}).register()
    assert {listed: stored[listed] for listed in SYSTEM_LISTS} == NO_SYSTEM


@pytest.mark.parametrize("kind", BASES)
def test_the_lists_drop_repeats_when_stored_and_a_wrong_id_is_named_where_it_was_sent(kind: str) -> None:
    """A repeated system is stored once, in the order given, while a system the asset lacks is named at each
    place the request sent it; no old flag is stored; a repeated control keeps its first entry."""
    lists = {
        "supporting_systems_applicable_to_risk": [324, 321, 324, 322, 321],
        "supporting_systems_applicable_to_existing_controls": [322, 322, 321],
        "existing_controls": [
            {"control_code": "CII-CID-1"},
            {"control_code": "cii-cid-1", "control_name": "x"},
        ],
    }
    request = PlanRequest.model_validate(BASES[kind] | lists)
    stored = request.register()
    assert stored["supporting_systems_applicable_to_risk"] == [324, 321, 322]
    assert stored["supporting_systems_applicable_to_existing_controls"] == [322, 321]
    assert stored["existing_controls"] == [
        {"control_id": None, "control_code": "CII-CID-1", "control_name": None}
    ]
    assert not set(OLD_FLAGS) & set(stored)
    with pytest.raises(Invalid) as refused:
        check_register_systems(request, [321, 322])
    assert [error["field"] for error in refused.value.errors or []] == [
        "body.supporting_systems_applicable_to_risk[0]",
        "body.supporting_systems_applicable_to_risk[2]",
    ]
