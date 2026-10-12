"""Scenario writing (Step 12, BUILD_PLAN S16-S28): T-WRT-01..22, with fake AI models."""

import dataclasses
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.ai import UnreadableAiAnswer
from app.core.constants import (
    CHAT_TEMPERATURES,
    FINDING_SEVERITIES,
    ActorRole,
    AiTask,
    Decision,
    ErrorCode,
    FindingCode,
    FindingSeverity,
    PathProblem,
    PlanCheckStatus,
    Route,
    RunKind,
    ScenarioStatus,
    ValidationStatus,
)
from app.core.database import get_mongodb
from app.core.exceptions import PathNotWritable, Unavailable
from app.data_access.scenarios import ScenarioRepository, TitleTaken
from app.engine.scenarios.writing.ai_plan_check import PlanChecker
from app.engine.scenarios.writing.brief_builder import build_brief
from app.engine.scenarios.writing.draft_cleanup import clean_draft, clean_title, lead_with_consequence
from app.engine.scenarios.writing.exact_rules import check_exact_rules
from app.engine.scenarios.writing.scenario_record import (
    failure_record,
    scenario_id,
    title_candidates,
    written_record,
)
from app.engine.scenarios.writing.scenario_writer import ScenarioWriter
from app.engine.scenarios.writing.writing_prompts import (
    PLAN_CHECK_SYSTEM_PROMPT,
    WRITER_SYSTEM_PROMPT,
    plan_check_prompt,
    writer_prompt,
)
from app.models.scenario_views import ScenarioView
from app.models.threats import PlannedActor
from app.models.writing import (
    Finding,
    LiveLibrary,
    PathFailure,
    PlanCheck,
    PlanCheckAnswer,
    ScenarioAnswer,
    ScenarioDraft,
    WrittenScenario,
)
from tests.fakes import FakeChatModel
from tests.planner_samples import CONTEXT, planned, system_row

_DRAFT = ScenarioDraft("Loss of control integrity", "It could stop.", "Loss of control.", (), "RTU")


def _answer(**changes: object) -> dict[str, object]:
    return _DRAFT.to_answer() | changes


def test_every_finding_code_has_a_severity_and_only_exact_faults_block() -> None:
    assert set(FINDING_SEVERITIES) == set(FindingCode)
    blockers = {code for code, severity in FINDING_SEVERITIES.items() if severity == FindingSeverity.BLOCKER}
    assert blockers == {FindingCode.UNKNOWN_ID, FindingCode.UNCITED_ADVISORY_ID}


def test_a_written_scenario_is_blocked_only_by_a_blocker() -> None:
    def written(*codes: FindingCode) -> WrittenScenario:
        findings = tuple(Finding(code, "m") for code in codes)
        return WrittenScenario(
            _DRAFT, findings, PlanCheck(PlanCheckStatus.CONSISTENT), Route.STANDALONE, False
        )

    assert not written(FindingCode.ASSET_NOT_IN_RISK, FindingCode.PLAN_CHECK).blocked
    assert written(FindingCode.UNCITED_ADVISORY_ID).blocked
    assert Finding(FindingCode.UNKNOWN_ID, "m").to_record() == {
        "code": "unknown_id",
        "severity": "blocker",
        "message": "m",
    }


def test_the_writer_answer_contract_needs_every_text() -> None:
    assert ScenarioAnswer.model_validate(_answer()).entry_point == "RTU"
    for field in ("scenario_title", "scenario_statement", "risk_statement"):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScenarioAnswer.model_validate(_answer(**{field: "  "}))
    with pytest.raises(ValidationError):
        ScenarioAnswer.model_validate(
            {key: value for key, value in _answer().items() if key != "assumptions"}
        )


def test_an_inconsistent_plan_check_must_say_why() -> None:
    assert PlanCheckAnswer.model_validate({"consistent": True, "problems": []}).consistent
    with pytest.raises(ValidationError, match="at least one problem"):
        PlanCheckAnswer.model_validate({"consistent": False, "problems": [" "]})


@pytest.mark.parametrize(
    ("severity", "status"),
    [(FindingSeverity.WARNING, ValidationStatus.WARNING), (FindingSeverity.NOTE, ValidationStatus.OK)],
)
def test_only_a_warning_shows_validation_warning(severity: FindingSeverity, status: ValidationStatus) -> None:
    view = ScenarioView.from_record(
        {
            "_id": "s1",
            "session_id": "r1",
            "version": 1,
            "status": ScenarioStatus.DONE,
            "source": RunKind.GENERATED,
            "decision": Decision.PENDING,
            "findings": [{"code": "x", "severity": severity, "message": "m"}],
            "created_at": datetime.now(UTC),
        },
    )
    assert view.validation_status == status
    assert (view.validation_errors, view.validation_notes) == (
        (["m"], []) if severity == FindingSeverity.WARNING else ([], ["m"])
    )


#: Everything the sample threats name is still active in the library.
_LIVE = LiveLibrary(frozenset({297}), frozenset({1}), frozenset({7, 8}))


def _plan_threat(systems: tuple[int, ...] = (321,), **fields: Any) -> dict[str, Any]:
    """A plan's threat record, as the frozen plan holds it: one acting attacker, one alternate."""
    actors = (
        PlannedActor(7, "Cybercriminal", ActorRole.ACTING),
        PlannedActor(8, "Insider", ActorRole.ALTERNATE),
    )
    threat = planned(
        "lib:297",
        "T0839: Unauthorised firmware update",
        systems=systems,
        actors=actors,
        reason="Vendor sessions on the SCADA server could push firmware. Mail ops@grid.example.",
    )
    return threat.to_record() | fields


def _brief_of(threat: dict[str, Any], budget: int = 30_000, **path: Any) -> Any:
    record = {
        "path_id": "p1",
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    } | path
    return build_brief({threat["key"]: threat}, record, CONTEXT, budget, _LIVE)


def test_the_brief_holds_only_the_paths_systems_and_no_database_id() -> None:
    """T-WRT-01 (S17): only this threat's systems, by name; the run's others listed apart; no id or alias."""
    brief = _brief_of(_plan_threat())
    assert [system["name"] for system in brief.systems] == ["SCADA server"]
    assert brief.entry_point_options == ("SCADA server",) and brief.other_systems == ("Historian",)
    assert (brief.attacker, brief.threat, brief.threat_type) == (
        "Cybercriminal",
        "Unauthorised firmware update",
        "Malware",
    )
    assert brief.asset_name == brief.asset["name"] == "Grid Control Centre"
    assert brief.asset["description"].startswith("Runs the transmission grid")
    sent = json.dumps([brief.asset, *brief.systems, brief.why_it_applies])
    leaked = [
        token for token in ("321", "322", "103", "SYS1", '"id"', "alias", "ops@grid.example") if token in sent
    ]
    assert leaked == []


def test_a_threat_on_the_asset_itself_offers_no_entry_point() -> None:
    brief = _brief_of(_plan_threat(systems=()))
    assert brief.systems == () and brief.entry_point_options == ()
    assert brief.other_systems == ("SCADA server", "Historian")


@pytest.mark.parametrize(
    ("threat_changes", "path_changes", "problem"),
    [
        ({}, {"steps": ["lib:297", "lib:298"]}, PathProblem.NOT_ONE_THREAT),
        ({}, {"steps": ["lib:404"]}, PathProblem.NOT_ONE_THREAT),
        ({}, {"category": "Sabotage"}, PathProblem.CATEGORY_UNKNOWN),
        ({"name": " "}, {}, PathProblem.THREAT_UNNAMED),
        ({"actors": []}, {}, PathProblem.NO_ACTING_ATTACKER),
        ({"systems": [999]}, {}, PathProblem.SYSTEM_NOT_IN_RUN),
    ],
)
def test_a_path_missing_a_fact_is_refused_before_any_ai_call(
    threat_changes: dict[str, Any], path_changes: dict[str, Any], problem: PathProblem
) -> None:
    with pytest.raises(PathNotWritable) as refused:
        _brief_of(_plan_threat(**threat_changes), **path_changes)
    assert refused.value.code == ErrorCode.INVALID_PLAN and problem in refused.value.message


@pytest.mark.parametrize(
    ("live", "threat_changes", "retired"),
    [
        (LiveLibrary(frozenset(), frozenset({1}), frozenset({7})), {}, PathProblem.THREAT_RETIRED),
        (LiveLibrary(frozenset({297}), frozenset({1}), frozenset({8})), {}, PathProblem.ATTACKER_RETIRED),
        (LiveLibrary(frozenset(), frozenset({1}), frozenset({7})), {"library_id": None}, None),
        (
            LiveLibrary(frozenset(), frozenset({2}), frozenset({7})),
            {"library_id": None},
            PathProblem.THREAT_RETIRED,
        ),
    ],
)
def test_a_threat_or_attacker_retired_since_the_plan_is_not_written(
    live: LiveLibrary, threat_changes: dict[str, Any], retired: PathProblem | None
) -> None:
    """Owner, 2026-10-10 (spec v4.0 §7.4.1): a library threat by its own record, an AI-proposed one by its
    library type, and the acting attacker must still be active when the scenario is written."""
    threat = _plan_threat(**threat_changes)
    record = {
        "path_id": "p1",
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    }
    if retired is None:
        assert build_brief({threat["key"]: threat}, record, CONTEXT, 30_000, live).threat
        return
    with pytest.raises(PathNotWritable) as refused:
        build_brief({threat["key"]: threat}, record, CONTEXT, 30_000, live)
    assert refused.value.code == ErrorCode.LIBRARY_RECORD_RETIRED and retired in refused.value.message


def test_long_facts_are_cut_to_the_budget_and_the_brief_stays_json() -> None:
    long_text = "Vendor maintenance window. " * 300
    context = dataclasses.replace(
        CONTEXT,
        asset_context=CONTEXT.asset_context | {"cii_asset_description": long_text},
        systems=[CONTEXT.systems[0] | {"past_incidents": long_text}, CONTEXT.systems[1]],
    )
    threat = _plan_threat()
    record = {
        "path_id": "p1",
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    }
    brief = build_brief({threat["key"]: threat}, record, context, 4_000, _LIVE)
    asset_size = len(json.dumps(brief.asset, ensure_ascii=False))
    assert asset_size <= 1_000 and brief.asset["description"].endswith("…")
    assert len(json.dumps(brief.systems[0], ensure_ascii=False)) <= 4_000 - asset_size
    assert brief.systems[0]["name"] == "SCADA server" and brief.systems[0]["technology_used"]


def test_the_prompts_are_the_owner_approved_text_word_for_word() -> None:
    """S18: the system prompts equal the approved draft's (docs/SCENARIO_PROMPTS_DRAFT.md v2, 2026-10-10):
    an edit to either must go through the owner again."""
    approved = Path(__file__).parents[1] / "docs" / "SCENARIO_PROMPTS_DRAFT.md"
    blocks = re.findall(r"```\n(.*?)```", approved.read_text(encoding="utf-8"), flags=re.S)
    assert blocks[0].rstrip("\n") == WRITER_SYSTEM_PROMPT
    assert blocks[2].rstrip("\n") == PLAN_CHECK_SYSTEM_PROMPT
    rules = ('use "could" or "may"', "as a type of attacker", 'is unknown, not "no"', 'never with "Because"')
    assert [rule for rule in rules if rule not in WRITER_SYSTEM_PROMPT] == []


def test_the_writer_reads_the_brief_as_one_json_object() -> None:
    brief = _brief_of(_plan_threat())
    system, user = writer_prompt(brief)
    assert system == WRITER_SYSTEM_PROMPT and user.startswith("BRIEF:\n")
    sent = json.loads(user.removeprefix("BRIEF:\n"))
    assert sent["entry_point_options"] == ["SCADA server"] and "other_scenarios" not in sent
    assert sent["threat"] == {
        "threat_type": "Malware",
        "threat": "Unauthorised firmware update",
        "why_it_applies": brief.why_it_applies,
    }
    _, regenerated = writer_prompt(dataclasses.replace(brief, other_scenarios=("Before.",)))
    assert json.loads(regenerated.removeprefix("BRIEF:\n"))["other_scenarios"] == ["Before."]


def test_the_plan_check_reads_the_plan_by_names_and_the_scenario_as_written() -> None:
    system, user = plan_check_prompt(_brief_of(_plan_threat()), _DRAFT)
    plan_text, scenario_text = user.removeprefix("PLAN:\n").split("\nSCENARIO:\n")
    plan = json.loads(plan_text)
    assert system == PLAN_CHECK_SYSTEM_PROMPT
    assert (plan["asset"]["name"], [system["name"] for system in plan["systems"]], plan["other_systems"]) == (
        "Grid Control Centre",
        ["SCADA server"],
        ["Historian"],
    )
    # G127: the recorded facts the writer read, so a recorded product is never judged "invented".
    assert plan["systems"][0]["technology_used"] == ["Windows", "Siemens WinCC"]
    assert plan["asset"]["description"].startswith("Runs the transmission grid")
    assert plan["critical_service"] == "Electricity transmission" and plan["attacker"] == "Cybercriminal"
    assert json.loads(scenario_text) == _DRAFT.to_answer()


_ATTACKERS = ("Cybercriminal", "Insider", "Nation-state/APT")


@pytest.mark.parametrize(
    ("title", "cleaned"),
    [
        ("Loss of control integrity via MITRE ATT&CK T0839", "Loss of control integrity"),
        ("Grid Control Centre — loss of control integrity", "Loss of control integrity"),
        ("Firmware tampering by a cybercriminal on the SCADA server", "Firmware tampering"),
        ("Historian data loss (IEC 62443-3-3)", "Data loss"),
        ("APT disruption of telemetry", "Disruption of telemetry"),
        ("ISO market disruption", "ISO market disruption"),
        ("Vendor session compromise", "Vendor session compromise"),
        ("SCADA server", "Unauthorised firmware update"),
    ],
)
def test_the_title_loses_framework_codes_and_every_name(title: str, cleaned: str) -> None:
    """T-WRT-05 (S19): no framework name or code and no asset, system or attacker name in a title, with the
    words that tied them in; a title of names only falls back to the threat's name."""
    brief = _brief_of(_plan_threat())
    names = (brief.asset_name, *brief.entry_point_options, *brief.other_systems, *_ATTACKERS, "APT")
    assert clean_title(title, names, "Unauthorised firmware update") == cleaned


@pytest.mark.parametrize(
    ("risk", "led"),
    [
        (
            "Because vendor sessions are unmonitored, the RTU could accept rogue firmware. Act late.",
            "The RTU could accept rogue firmware, because vendor sessions are unmonitored. Act late.",
        ),
        (
            "Because the RTU, which runs old firmware, is exposed, control could be lost.",
            "This risk exists because the RTU, which runs old firmware, is exposed, control could be lost.",
        ),
        ("because no one watches the logs", "This risk exists because no one watches the logs"),
        ("Loss of control could follow.", "Loss of control could follow."),
    ],
)
def test_a_risk_statement_never_opens_with_because(risk: str, led: str) -> None:
    """T-WRT-06 (S19): "Because X, Y." becomes "Y, because X."; the owner's fallback when it cannot."""
    assert lead_with_consequence(risk) == led


def test_codes_hashes_and_guids_leave_the_text_and_blank_assumptions_go() -> None:
    """T-WRT-07 (S19): opaque codes go; an advisory number stays for the rules to judge."""
    guid, digest = "3f2b8c1e-9d4a-4f6b-8e2c-1a2b3c4d5e6f", "9e107d9d372bb6826bd81d3542a419d6"
    draft = ScenarioDraft(
        "Loss of control integrity",
        f"A cybercriminal could push firmware (T0839) to the SCADA server, per report {digest}.",
        f"Because firmware is unsigned, CVE-2024-1234 could be used (case {guid}).",
        (
            "Assumes vendor access - not recorded in the platform.",
            " ",
            "Assumes vendor access - not recorded in the platform.",
        ),
        "SCADA server",
    )
    cleaned = clean_draft(draft, _brief_of(_plan_threat()), _ATTACKERS)
    assert cleaned.statement == "A cybercriminal could push firmware to the SCADA server, per report."
    assert cleaned.risk == "CVE-2024-1234 could be used (case), because firmware is unsigned."
    assert cleaned.assumptions == ("Assumes vendor access - not recorded in the platform.",)
    assert (cleaned.title, cleaned.entry_point) == ("Loss of control integrity", "SCADA server")


_LIBRARY_ATTACKERS = ("Cybercriminal", "Third-party/Vendor", "APT28", "Malicious insider")
_CLEAN = ScenarioDraft(
    "Loss of control integrity",
    "A cybercriminal could use a vendor session to push firmware to the SCADA server of Grid Control Centre.",
    "Loss of trusted control at Grid Control Centre could interrupt electricity transmission.",
    ("Assumes vendor sessions can update firmware - not recorded in the platform.",),
    "SCADA server",
)


def _codes(draft: ScenarioDraft, systems: tuple[int, ...] = (321,)) -> tuple[list[str], Route]:
    findings, route = check_exact_rules(draft, _brief_of(_plan_threat(systems=systems)), _LIBRARY_ATTACKERS)
    return [finding.code for finding in findings], route


def test_a_clean_scenario_has_no_finding_and_a_standalone_route() -> None:
    """T-WRT-08 (S20): "vendor" alone is no other attacker; only the acting attacker matches by a half."""
    assert _codes(_CLEAN) == ([], Route.STANDALONE)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"statement": _CLEAN.statement + " SYS2 could follow."}, FindingCode.UNKNOWN_ID),
        ({"risk": _CLEAN.risk + " CVE-2024-1234 makes it easy."}, FindingCode.UNCITED_ADVISORY_ID),
        (
            {"statement": "A cybercriminal could push firmware to the SCADA server."},
            FindingCode.ASSET_NOT_IN_STATEMENT,
        ),
        ({"risk": "Loss of trusted control could interrupt transmission."}, FindingCode.ASSET_NOT_IN_RISK),
        (
            {"statement": "An attacker could push firmware to the SCADA server of Grid Control Centre."},
            FindingCode.ATTACKER_NOT_NAMED,
        ),
        ({"assumptions": ("Assumes APT28 targets the sector.",)}, FindingCode.OTHER_ATTACKER_NAMED),
        ({"statement": _CLEAN.statement + " The Historian could log it."}, FindingCode.SYSTEM_OUT_OF_SCOPE),
    ],
)
def test_each_rule_finds_its_fault(changes: dict[str, Any], code: FindingCode) -> None:
    """T-WRT-09 (S20): each exact rule fails on its own fault, with its severity from the table."""
    codes, _ = _codes(dataclasses.replace(_CLEAN, **changes))
    assert codes == [code]


def test_a_system_inside_another_systems_name_is_not_outside() -> None:
    brief = dataclasses.replace(_brief_of(_plan_threat()), other_systems=("SCADA",))
    assert check_exact_rules(_CLEAN, brief, _LIBRARY_ATTACKERS) == ((), Route.STANDALONE)


def test_the_card_keeps_each_systems_recorded_name_and_one_entry_point() -> None:
    """Review 2026-10-11: the card stored the prompt's redacted names (an internal host name became
    [REDACTED]), and two systems redacted alike were both marked the entry point."""
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_brief({threat["key"]: threat}, path, context, 30_000, _LIVE)
    assert brief.entry_point_options == ("[REDACTED]", "[REDACTED]")  # never a host name to the AI
    draft = dataclasses.replace(_CLEAN, entry_point=brief.entry_point_options[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT, ()), Route.UNKNOWN, False)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": context.to_record()}
    record = written_record(run, path, threat, brief, written)
    assert record["content"]["systems"] == [
        {"id": 321, "name": "scada01.plant.local", "entry_point": True},
        {"id": 322, "name": "hist01.plant.local", "entry_point": False},
    ]


def test_the_critical_service_reaches_the_ai_redacted() -> None:
    """Review 2026-10-11: the one fact of the brief that skipped redaction."""
    critical = {"critical_service": "Billing, contact ops@grid.example"}
    context = dataclasses.replace(CONTEXT, asset_context=CONTEXT.asset_context | critical)
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_brief({threat["key"]: threat}, path, context, 30_000, _LIVE)
    assert brief.critical_service is not None and "ops@grid.example" not in brief.critical_service
    assert "ops@grid.example" not in plan_check_prompt(brief, _CLEAN)[1]


def test_a_name_inside_the_assets_name_is_neither_another_system_nor_another_attacker() -> None:
    """Review 2026-10-11: the asset must be named, so a run system "Grid" or a library attacker "Centre"
    inside "Grid Control Centre" was flagged on every scenario, each paying a rewrite that could never fix
    it."""
    brief = dataclasses.replace(_brief_of(_plan_threat()), other_systems=("Grid",))
    assert check_exact_rules(_CLEAN, brief, (*_LIBRARY_ATTACKERS, "Centre")) == ((), Route.STANDALONE)


def test_a_claimed_link_between_two_systems_is_a_warning_and_an_unknown_route() -> None:
    """T-WRT-22 (S20): the platform records no system-to-system link."""
    linked = " The cybercriminal could then pivot from the SCADA server to the Historian."
    codes, route = _codes(dataclasses.replace(_CLEAN, statement=_CLEAN.statement + linked), (321, 322))
    assert (codes, route) == ([FindingCode.SYSTEM_LINK_CLAIMED], Route.UNKNOWN)
    together = " The SCADA server and the Historian could both lose data."
    assert _codes(dataclasses.replace(_CLEAN, statement=_CLEAN.statement + together), (321, 322)) == (
        [],
        Route.STANDALONE,
    )


def _plan_checked(*answers: Any) -> tuple[PlanCheck, tuple[Finding, ...], FakeChatModel]:
    chat = FakeChatModel()
    chat.queue(AiTask.PLAN_CHECK, *answers)
    check, notes = PlanChecker(chat).check_against_plan(_brief_of(_plan_threat()), _CLEAN)
    return check, notes, chat


def test_a_consistent_scenario_gets_no_note() -> None:
    """T-WRT-11 (S21): one call at temperature 0 (CHAT_TEMPERATURES), the plan and the scenario as data."""
    check, notes, chat = _plan_checked({"consistent": True, "problems": []})
    assert (check, notes) == (PlanCheck(PlanCheckStatus.CONSISTENT), ())
    assert len(chat.asked(AiTask.PLAN_CHECK)) == 1 and chat.asked(AiTask.PLAN_CHECK)[0].startswith("PLAN:")
    assert CHAT_TEMPERATURES[AiTask.PLAN_CHECK] == 0.0


def test_each_plan_check_problem_is_a_note() -> None:
    long = "It names " + "a second threat " * 40
    check, notes, _ = _plan_checked({"consistent": False, "problems": ["Adds a second threat.", " ", long]})
    assert check.status == PlanCheckStatus.INCONSISTENT and len(check.problems) == 2
    assert [(note.code, note.severity) for note in notes] == [
        (FindingCode.PLAN_CHECK, FindingSeverity.NOTE)
    ] * 2
    assert notes[0].message == "Adds a second threat." and len(notes[1].message) <= 300


def test_an_unusable_plan_check_is_a_note_never_a_failure() -> None:
    """Re-asked once; a second unusable answer leaves the scenario with the note 'plan check not made'."""
    check, notes, chat = _plan_checked({"consistent": "maybe"}, {"verdict": "fine"})
    assert check == PlanCheck(PlanCheckStatus.UNCHECKED) and len(chat.asked(AiTask.PLAN_CHECK)) == 2
    assert [note.code for note in notes] == [FindingCode.PLAN_CHECK_NOT_MADE]


def test_an_ai_outage_during_the_plan_check_retries_the_job() -> None:
    with pytest.raises(Unavailable):
        _plan_checked(Unavailable("AI down"))


_CONSISTENT = {"consistent": True, "problems": []}


def _writer(
    writes: list[Any], checks: list[Any], rewrites: list[Any] = ()
) -> tuple[ScenarioWriter, FakeChatModel]:
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, *writes)
    chat.queue(AiTask.PLAN_CHECK, *checks)
    chat.queue(AiTask.REWRITE_SCENARIO, *rewrites)
    return ScenarioWriter(chat, _LIBRARY_ATTACKERS), chat


def _calls(chat: FakeChatModel) -> list[AiTask]:
    return [task for task, _ in chat.calls]


def test_a_clean_first_draft_is_kept_after_two_calls() -> None:
    """T-WRT-01: write, then one plan check; nothing found, so no rewrite."""
    writer, chat = _writer([_CLEAN.to_answer()], [_CONSISTENT])
    written = writer.write_scenario(_brief_of(_plan_threat()))
    assert written.draft == _CLEAN and written.findings == () and not written.rewritten
    assert written.route == Route.STANDALONE and _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_an_unreadable_answer_is_asked_once_more() -> None:
    """T-WRT-02: a missing field, then an entry point never offered, are each re-asked once."""
    no_risk = {key: value for key, value in _CLEAN.to_answer().items() if key != "risk_statement"}
    writer, chat = _writer([no_risk, _CLEAN.to_answer()], [_CONSISTENT])
    assert writer.write_scenario(_brief_of(_plan_threat())).draft == _CLEAN
    elsewhere = _CLEAN.to_answer() | {"entry_point": "Historian"}
    writer, chat = _writer([elsewhere, _CLEAN.to_answer() | {"entry_point": "scada  SERVER"}], [_CONSISTENT])
    assert writer.write_scenario(_brief_of(_plan_threat())).draft.entry_point == "SCADA server"
    assert _calls(chat).count(AiTask.WRITE_SCENARIO) == 2


def test_an_answer_unreadable_twice_fails_the_scenario() -> None:
    """T-WRT-03: the worker turns this into a failure card."""
    writer, _ = _writer([{"title": "x"}, {"title": "y"}], [])
    with pytest.raises(UnreadableAiAnswer):
        writer.write_scenario(_brief_of(_plan_threat()))


def test_an_asset_level_threat_has_no_entry_point_whatever_was_written() -> None:
    on_the_asset = {
        "scenario_statement": "A cybercriminal could push firmware to Grid Control Centre.",
        "entry_point": "Grid Control Centre",
    }
    writer, chat = _writer([_CLEAN.to_answer() | on_the_asset], [_CONSISTENT])
    written = writer.write_scenario(_brief_of(_plan_threat(systems=())))
    assert (written.draft.entry_point, written.findings) == ("", ())
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_the_one_rewrite_lists_every_problem_and_a_better_rewrite_is_kept() -> None:
    """T-WRT-15: a code warning and a plan-check note go to ONE rewrite; at most 4 calls."""
    no_asset = _CLEAN.to_answer() | {
        "risk_statement": "Loss of trusted control could interrupt transmission."
    }
    inconsistent = {"consistent": False, "problems": ["The impact does not fit Tampering."]}
    writer, chat = _writer([no_asset], [inconsistent, _CONSISTENT], [_CLEAN.to_answer()])
    written = writer.write_scenario(_brief_of(_plan_threat()))
    assert written.rewritten and written.draft == _CLEAN and written.findings == ()
    assert _calls(chat) == [
        AiTask.WRITE_SCENARIO,
        AiTask.PLAN_CHECK,
        AiTask.REWRITE_SCENARIO,
        AiTask.PLAN_CHECK,
    ]
    rewrite_prompt = chat.asked(AiTask.REWRITE_SCENARIO)[0]
    assert "does not name the asset" in rewrite_prompt and "does not fit Tampering" in rewrite_prompt


def test_a_worse_rewrite_is_dropped_and_a_tie_keeps_the_rewrite() -> None:
    """T-WRT-16: a blocker outweighs any number of warnings; on a tie the rewrite stands."""
    no_asset = _CLEAN.to_answer() | {
        "risk_statement": "Loss of trusted control could interrupt transmission."
    }
    with_cve = _CLEAN.to_answer() | {"scenario_statement": _CLEAN.statement + " CVE-2024-1234 could help."}
    writer, _ = _writer([no_asset], [_CONSISTENT, _CONSISTENT], [with_cve])
    kept = writer.write_scenario(_brief_of(_plan_threat()))
    assert not kept.rewritten and [f.code for f in kept.findings] == [FindingCode.ASSET_NOT_IN_RISK]
    other_fault = _CLEAN.to_answer() | {
        "scenario_statement": "A cybercriminal could push firmware to the SCADA server."
    }
    writer, _ = _writer([no_asset], [_CONSISTENT, _CONSISTENT], [other_fault])
    tie = writer.write_scenario(_brief_of(_plan_threat()))
    assert tie.rewritten and [f.code for f in tie.findings] == [FindingCode.ASSET_NOT_IN_STATEMENT]


def test_an_unusable_rewrite_keeps_the_first_draft() -> None:
    no_asset = _CLEAN.to_answer() | {
        "risk_statement": "Loss of trusted control could interrupt transmission."
    }
    writer, chat = _writer([no_asset], [_CONSISTENT], [{"bad": 1}, {"bad": 2}])
    written = writer.write_scenario(_brief_of(_plan_threat()))
    assert not written.rewritten and [f.code for f in written.findings] == [FindingCode.ASSET_NOT_IN_RISK]
    assert _calls(chat).count(AiTask.REWRITE_SCENARIO) == 2


def _scenarios() -> ScenarioRepository:
    repository = ScenarioRepository(get_mongodb())
    repository.ensure_indexes()
    return repository


def _stored(
    session_id: str, path_id: str, title: str | None = "Loss of control", **fields: Any
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "_id": f"{session_id}:{path_id}",
        "session_id": session_id,
        "entity_id": 86,
        "path_id": path_id,
        "version": 1,
        "source": RunKind.GENERATED,
        "status": ScenarioStatus.DONE,
        "decision": Decision.PENDING,
        "superseded_by": None,
        "content": {"title": title},
        "findings": [],
        "created_at": datetime.now(UTC),
    }
    if title is not None:
        record["title_key"] = title.casefold()
    return record | fields


def test_a_repeated_save_keeps_one_scenario_and_a_success_replaces_a_failure_card() -> None:
    """T-WRT-18 (S23): the same id saves once; a failure or blocked card is replaced by its path's success."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    failure = _stored(session_id, "p1", None, status=ScenarioStatus.FAILED, failure={"code": "x"})
    assert scenarios.save(failure)
    assert scenarios.save(_stored(session_id, "p1"))
    assert not scenarios.save(_stored(session_id, "p1", "Another title"))
    assert scenarios.find_written(session_id, ["p1", "p2"]) == {"p1": f"{session_id}:p1"}
    assert scenarios.find_in_run(session_id, f"{session_id}:p1")["content"]["title"] == "Loss of control"


def test_no_two_written_versions_of_a_run_share_a_title() -> None:
    """T-WRT-17 (S23, G142): the database refuses the clash, even under a race; other runs and blocked cards
    do not count; a replaced version does (the results list still shows one a reviewer decided)."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    assert scenarios.save(_stored(session_id, "p1", "Older", superseded_by="v2", decision=Decision.ACCEPTED))
    with pytest.raises(TitleTaken):
        scenarios.save(_stored(session_id, "p2", "Older"))
    assert scenarios.save(_stored(session_id, "p3"))
    with pytest.raises(TitleTaken):
        scenarios.save(_stored(session_id, "p4"))
    assert scenarios.save(_stored(f"other-{session_id}", "p4"))
    assert scenarios.save(_stored(session_id, "p5", status=ScenarioStatus.BLOCKED))


def test_counts_come_from_one_aggregation_and_a_blocked_scenario_is_never_served() -> None:
    """T-WRT-19 (S23)."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    controls = {"status": "queued", "attempts": 0}
    scenarios.save(_stored(session_id, "p1", "A", controls=controls))
    scenarios.save(_stored(session_id, "p2", "B", decision=Decision.ACCEPTED, controls={"status": "done"}))
    scenarios.save(_stored(session_id, "p3", None, status=ScenarioStatus.FAILED))
    scenarios.save(_stored(session_id, "p4", "C", status=ScenarioStatus.BLOCKED))
    scenarios.save(_stored(session_id, "p5", "D", controls={"status": "failed"}))  # retried later
    assert scenarios.count_for_run(session_id) == {
        "written": 3,
        "failed": 1,
        "accepted": 1,
        "rejected": 0,
        "pending": 2,
        "controls_waiting": 1,
        "controls_failed": 1,
        "controls_cancelled": 0,
    }
    assert scenarios.find_in_run(session_id, f"{session_id}:p4") is None
    assert scenarios.list_for_run(session_id, False, 0, 10)[1] == 4
    assert scenarios.count_for_run(f"empty-{session_id}")["written"] == 0


def test_a_clashing_title_takes_the_threat_name_then_a_number() -> None:
    """T-WRT-17 (S28): owner 2026-10-06; a qualifier the title already says is skipped."""
    titles = title_candidates("Loss of control", "Firmware update")
    assert [next(titles) for _ in range(4)] == [
        "Loss of control",
        "Loss of control (Firmware update)",
        "Loss of control (2)",
        "Loss of control (3)",
    ]
    assert next(title_candidates("Firmware update", "firmware UPDATE")) == "Firmware update"
    assert [
        title
        for _, title in zip(range(2), title_candidates("Firmware update", "Firmware update"), strict=False)
    ] == [
        "Firmware update",
        "Firmware update (2)",
    ]


def test_a_saved_scenario_reads_back_through_the_api_view() -> None:
    """T-WRT-01 (S28): what the job stores is what #3/#9/#10 show: the texts, why it applies, the attackers
    and systems without ids, the entry point, the route, and validation from the findings."""
    brief = _brief_of(_plan_threat())
    written = WrittenScenario(
        _CLEAN,
        (Finding(FindingCode.PLAN_CHECK, "The impact is broad."),),
        PlanCheck(PlanCheckStatus.INCONSISTENT, ("The impact is broad.",)),
        Route.STANDALONE,
        True,
        "Unauthorised firmware update",
    )
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {"path_id": "p1", "category": "Tampering", "categories": ["Tampering", "Denial of Service"]}
    extra = {"rank": 3, "category_id": 5, "systems": [321], "also_applies": ["Logic overwrite"]}
    record = written_record(run, path | extra, _plan_threat(), brief, written)
    view = ScenarioView.from_record(record)
    text = view.scenario
    assert record["_id"] == scenario_id("run-1", "p1", 1) == scenario_id("run-1", "p1", 1)
    assert (text.scenario_title, view.status) == (_CLEAN.title, ScenarioStatus.DONE)
    assert text.scenario_statement == f"{_CLEAN.statement}\n\nWhy this threat applies: {brief.why_it_applies}"
    assert [actor.model_dump() for actor in view.actors] == [
        {"actor_id": 7, "actor_name": "Cybercriminal", "role": "acting", "closest_match": False,
         "below_threshold": False},
        {"actor_id": 8, "actor_name": "Insider", "role": "alternate", "closest_match": False,
         "below_threshold": False},
    ]  # fmt: skip
    assert [system.model_dump() for system in text.supporting_systems_involved] == [
        {"supporting_system_id": 321, "supporting_system": "SCADA server", "is_entry_point": True}
    ]
    assert text.contributing_categories == ["Denial of Service"] and text.route_status == "STANDALONE"
    assert text.also_applies == ["Logic overwrite"]  # the group's other threats, kept with it (G208)
    assert view.validation_status == ValidationStatus.OK and view.validation_notes == ["The impact is broad."]
    assert (view.controls_status, view.controls) == ("queued", [])
    # The threat block v1 tracked (owner 2026-10-12): the library's names never carry a framework code.
    assert view.threat.model_dump() == {
        "threat_id": "lib:297",
        "threat_category": "Tampering",
        "threat_category_id": 5,
        "threat_type": "Malware",
        "threat_name": "Unauthorised firmware update",
        "threat_type_id": 1,
        "library_threat_type": "Malware",
        "library_threat_name": "Unauthorised firmware update",
        "grounding_status": "verified",
        "threat_catalogue_id": 297,
        "is_threat_type_ai_generated": False,
        "is_threat_ai_generated": False,
        "grounding_score": 70.0,
        "score": 70.0,
        "scope_rank": 3,
    }
    assert record["rewritten"]


def test_a_failure_card_is_built_for_a_threat_with_no_name_type_or_attacker() -> None:
    """Review fix 1: before, threat_name_without_code(None) raised inside the job and failed the whole run."""
    threat = {
        "key": "lib:9",
        "type": None,
        "name": None,
        "library_id": 9,
        "ai_generated": False,
        "actors": None,
    }
    path = {"path_id": "p9", "category": "Tampering", "categories": None}
    run = {"_id": "r", "entity_id": 86, "asset_id": 103}
    card = failure_record(run, path, threat, PathFailure(ErrorCode.INVALID_PLAN, "m"))
    assert card["status"] == ScenarioStatus.FAILED and card["content"]["threat"]["name"] == ""
    assert card["content"]["actors"] == [] and card["content"]["contributing_categories"] == []


def test_a_label_or_advisory_the_brief_supplied_is_never_a_blocker() -> None:
    """Review fix 2: a real system named "MicroSCADA Pro SYS600" and a CVE in its recorded incidents were
    blocked as made up; a technique-shaped code in the asset's own name was cut from the text."""
    brief = _brief_of(_plan_threat())
    system = brief.systems[0] | {
        "name": "MicroSCADA Pro SYS600",
        "past_incidents": "CVE-2024-1234 was exploited",
    }
    brief = dataclasses.replace(
        brief, systems=(system,), asset=brief.asset | {"name": "T1100 Gateway"}, asset_name="T1100 Gateway"
    )
    draft = dataclasses.replace(
        _CLEAN,
        statement="A cybercriminal could use CVE-2024-1234 on the MicroSCADA Pro SYS600 of T1100 Gateway.",
        risk="Loss of control at T1100 Gateway could interrupt transmission.",
        entry_point="MicroSCADA Pro SYS600",
    )
    findings, _ = check_exact_rules(draft, brief, _LIBRARY_ATTACKERS)
    assert [finding.code for finding in findings] == []
    assert "T1100 Gateway" in clean_draft(draft, brief, _LIBRARY_ATTACKERS).statement
    made_up = dataclasses.replace(draft, statement=draft.statement + " SYS7 and CVE-2025-0001 help.")
    blockers = [finding.code for finding in check_exact_rules(made_up, brief, _LIBRARY_ATTACKERS)[0]]
    assert blockers == [FindingCode.UNKNOWN_ID, FindingCode.UNCITED_ADVISORY_ID]


@pytest.mark.parametrize(
    ("sentence", "linked"),
    [
        (" An insider could reuse a shared password on the SCADA server and the Historian.", False),
        (" The SCADA server and the Historian sit behind one router used in routine work.", False),
        (" A protection relay near the SCADA server and the Historian could trip.", False),
        (" Commands could pass from the SCADA server to the Historian.", True),
        (" The attacker could pivot from the SCADA server to the Historian.", True),
    ],
)
def test_only_a_real_link_phrase_claims_a_link_between_two_systems(sentence: str, linked: bool) -> None:
    """Review fix 5: "password", "router", "routine" and a "protection relay" are not links."""
    codes, route = _codes(dataclasses.replace(_CLEAN, statement=_CLEAN.statement + sentence), (321, 322))
    assert (FindingCode.SYSTEM_LINK_CLAIMED in codes, route == Route.UNKNOWN) == (linked, linked)
