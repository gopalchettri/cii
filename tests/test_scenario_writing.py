"""Scenario writing (Step 12): the brief, the owner's prompts, the exact safety checks, the reviewer, the one
rewrite, and what is stored and shown. Fake AI models, no network."""

import dataclasses
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app.ai import UnreadableAiAnswer
from app.core.constants import (
    CHAT_TEMPERATURES,
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    ActorRole,
    AiTask,
    Collection,
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
from app.data_access.scenario.scenarios import ScenarioRepository, TitleTaken, find_held_elsewhere
from app.domain.scenario.write import (
    PLAN_CHECK_SYSTEM_PROMPT,
    WRITER_SYSTEM_PROMPT,
    build_brief,
    check_against_plan,
    check_exact_rules,
    failure_record,
    plan_check_prompt,
    scenario_id,
    title_candidates,
    with_word_limits,
    write_scenario,
    writer_prompt,
    written_record,
)
from app.models.scenario.plan import PlannedActor
from app.models.scenario.views import ScenarioView
from app.models.scenario.write import (
    Finding,
    LiveLibrary,
    PathFailure,
    PlanCheck,
    PlanCheckAnswer,
    ScenarioAnswer,
    ScenarioDraft,
    WrittenScenario,
)
from tests.fakes import WHY_APPLIES, FakeChatModel
from tests.planner_samples import CONTEXT, planned, system_row

#: Everything the sample threats name is still active in the library.
_LIVE = LiveLibrary(frozenset({297}), frozenset({1}), frozenset({7, 8}))
_CLEAN = ScenarioDraft(
    "Loss of control integrity",
    "A cybercriminal could use a vendor session to push firmware to the SCADA server of Grid Control Centre.",
    "Loss of trusted control at Grid Control Centre could interrupt electricity transmission.",
    ("Assumes vendor sessions can update firmware - not recorded in the platform.",),
    "SCADA server",
    why_applies=WHY_APPLIES,
)
#: The reasons the fake writer gives an answer that has none (tests/fakes.py): one per system of the brief.
_REASONS = (("SCADA server", "It could affect SCADA server."), ("Historian", "It could affect Historian."))
_READ = dataclasses.replace(_CLEAN, system_reasons=_REASONS)
_CONSISTENT = {"rules": {"1": "holds"}, "same_threat": True, "same_impact": True}
_MISMATCH = {"rules": {"1": "holds"}, "same_threat": False, "same_impact": True}


def _plan_threat(systems: tuple[int, ...] = (321,), **fields: Any) -> dict[str, Any]:
    """A plan's threat record, as the frozen plan holds it: one acting attacker."""
    actors = (PlannedActor(7, "Cybercriminal", ActorRole.ACTING),)
    threat = planned(
        "lib:297",
        "T0839: Unauthorised firmware update",
        systems=systems,
        actors=actors,
        reason="Vendor sessions on the SCADA server could push firmware. Mail ops@grid.example.",
    )
    record = threat.to_record() | fields
    if "reason" in fields and "reasons" not in fields:  # one reason given: every category's
        record["reasons"] = {category: fields["reason"] for category in record["categories"]}
    return record


def _brief_of(threat: dict[str, Any], budget: int = 30_000, **path: Any) -> Any:
    record = {
        "path_id": "p1",
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    }
    return build_brief({threat["key"]: threat}, record | path, CONTEXT, budget, _LIVE)


def _chat_answering(writes: list[Any], checks: list[Any], rewrites: list[Any] = ()) -> FakeChatModel:
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, *writes)
    chat.queue(AiTask.PLAN_CHECK, *checks)
    chat.queue(AiTask.REWRITE_SCENARIO, *rewrites)
    return chat


def _calls(chat: FakeChatModel) -> list[AiTask]:
    return [task for task, _ in chat.calls]


def test_only_a_safety_fault_a_mismatch_no_citation_or_a_copy_blocks_and_three_are_final() -> None:
    """A reviewer's rule verdict is a note, never a blocker; a check not made, a warning."""
    blockers = {code for code, severity in FINDING_SEVERITIES.items() if severity == FindingSeverity.BLOCKER}
    assert {FindingCode.UNKNOWN_ID, FindingCode.UNCITED_ADVISORY_ID} | FINAL_FINDINGS <= blockers
    assert {
        FindingCode.SCENARIO_MISMATCH,
        FindingCode.NO_EVIDENCE_CITED,
        FindingCode.NEAR_DUPLICATE,
    } == FINAL_FINDINGS
    assert FINDING_SEVERITIES[FindingCode.PLAN_CHECK] == FindingSeverity.NOTE
    assert FINDING_SEVERITIES[FindingCode.PLAN_CHECK_NOT_MADE] == FindingSeverity.WARNING
    assert FINDING_SEVERITIES[FindingCode.CITATION_REMOVED] == FindingSeverity.WARNING
    written = WrittenScenario(
        _CLEAN,
        (Finding(FindingCode.PLAN_CHECK, "m"),),
        PlanCheck(PlanCheckStatus.CONSISTENT),
        Route.STANDALONE,
        False,
    )
    assert not written.blocked
    assert Finding(FindingCode.UNKNOWN_ID, "m").to_record() == {
        "code": "unknown_id",
        "severity": "blocker",
        "message": "m",
    }


def test_the_answer_contracts_need_every_text_and_a_verdict_per_rule() -> None:
    assert ScenarioAnswer.model_validate(_CLEAN.to_answer()).entry_point == "SCADA server"
    for field in ("scenario_title", "scenario_statement", "risk_statement"):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScenarioAnswer.model_validate(_CLEAN.to_answer() | {field: "  "})
    verdicts = {"1": "holds", "4": 'broken: "push firmware" - two systems linked'}
    assert PlanCheckAnswer.model_validate({"rules": verdicts, "same_threat": True, "same_impact": True})
    for rules in ({"1": "maybe"}, {}):
        with pytest.raises(ValidationError, match="every numbered rule needs a verdict"):
            PlanCheckAnswer.model_validate({"rules": rules, "same_threat": True, "same_impact": True})


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


def test_the_brief_holds_only_the_paths_systems_and_no_database_id() -> None:
    """Only this threat's systems, by name; the run's others listed apart; no id, alias or secret."""
    brief = _brief_of(_plan_threat())
    assert [system["name"] for system in brief.systems] == ["SCADA server"]
    assert brief.entry_point_options == ("SCADA server",) and brief.other_systems == ("Historian",)
    assert (brief.attacker, brief.threat, brief.threat_type) == (
        "Cybercriminal",
        "Unauthorised firmware update",
        "Malware",
    )
    sent = json.dumps([brief.asset, *brief.systems, brief.why_it_applies])
    leaked = [
        token for token in ("321", "322", "103", "SYS1", '"id"', "alias", "ops@grid.example") if token in sent
    ]
    assert leaked == [] and _brief_of(_plan_threat(systems=())).entry_point_options == ()


@pytest.mark.parametrize(
    ("threat_changes", "path_changes", "problem"),
    [
        ({}, {"steps": ["lib:297", "lib:298"]}, PathProblem.NOT_ONE_THREAT),
        ({}, {"category": "Sabotage"}, PathProblem.CATEGORY_UNKNOWN),
        ({"name": " "}, {}, PathProblem.THREAT_UNNAMED),
        ({"actors": []}, {}, PathProblem.NO_ACTING_ATTACKER),
        ({"attacker_check": "none_fits"}, {}, PathProblem.ATTACKER_UNSUPPORTED),
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
    ("live", "retired"),
    [
        (LiveLibrary(frozenset(), frozenset({1}), frozenset({7})), PathProblem.THREAT_RETIRED),
        (LiveLibrary(frozenset({297}), frozenset({1}), frozenset({8})), PathProblem.ATTACKER_RETIRED),
    ],
)
def test_a_threat_or_attacker_retired_since_the_plan_is_not_written(
    live: LiveLibrary, retired: PathProblem
) -> None:
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    with pytest.raises(PathNotWritable) as refused:
        build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, live)
    assert refused.value.code == ErrorCode.LIBRARY_RECORD_RETIRED and retired in refused.value.message


def test_long_facts_are_cut_to_the_budget_and_the_brief_stays_json() -> None:
    long_text = "Vendor maintenance window. " * 300
    context = dataclasses.replace(
        CONTEXT, asset_context=CONTEXT.asset_context | {"cii_asset_description": long_text}
    )
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_brief({threat["key"]: threat}, path, context, 4_000, _LIVE)
    facts = sum(len(json.dumps(part, ensure_ascii=False)) for part in (brief.asset, *brief.systems))
    assert facts <= 4_000 and brief.asset["description"].endswith("…")


def test_the_writer_and_the_reviewer_read_the_owners_prompts_and_the_brief_as_json() -> None:
    """The owner's text files, the configured word limits in their slots, one line saying no evidence is
    given while intelligence is off; the reviewer's PLAN is the brief plus the critical service."""
    brief = _brief_of(_plan_threat())
    system, user = writer_prompt(brief)
    assert system.startswith(with_word_limits(WRITER_SYSTEM_PROMPT)) and "No EVIDENCE is given" in system
    assert "<scenario words>" not in system
    sent = json.loads(user.removeprefix("BRIEF:\n"))
    assert sent["supporting_systems"] == [
        {"name": "SCADA server", "applicable": "yes"},
        {"name": "Historian", "applicable": "no"},
    ]
    system, user = plan_check_prompt(brief, _CLEAN)
    plan_text, scenario_text = user.removeprefix("PLAN:\n").split("\nSCENARIO:\n")
    assert system.startswith(PLAN_CHECK_SYSTEM_PROMPT) and json.loads(scenario_text) == _CLEAN.to_answer()
    assert json.loads(plan_text)["critical_service"] == "Electricity transmission"
    assert CHAT_TEMPERATURES[AiTask.PLAN_CHECK] == 0.0


def test_a_made_up_label_or_advisory_id_blocks_and_one_the_brief_supplied_does_not() -> None:
    brief = _brief_of(_plan_threat())
    assert check_exact_rules(_CLEAN, brief) == ()
    made_up = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " SYS7 and CVE-2025-0001 help.")
    assert [finding.code for finding in check_exact_rules(made_up, brief)] == [
        FindingCode.UNKNOWN_ID,
        FindingCode.UNCITED_ADVISORY_ID,
    ]
    system = brief.systems[0] | {
        "name": "MicroSCADA Pro SYS600",
        "past_incidents": "CVE-2024-1234 was exploited",
    }
    supplied = dataclasses.replace(brief, systems=(system,))
    told = dataclasses.replace(
        _CLEAN, statement="A cybercriminal could use CVE-2024-1234 on the MicroSCADA Pro SYS600."
    )
    assert check_exact_rules(told, supplied) == ()


def _plan_checked(*answers: Any) -> tuple[PlanCheck, tuple[Finding, ...]]:
    chat = FakeChatModel()
    chat.queue(AiTask.PLAN_CHECK, *answers)
    return check_against_plan(chat, _brief_of(_plan_threat()), _CLEAN)


def test_every_broken_rule_is_a_note_and_a_changed_threat_is_a_mismatch() -> None:
    """Every "broken" verdict is a note for review; same_threat or same_impact false is the one blocker the
    reviewer gives."""
    assert _plan_checked(_CONSISTENT) == (PlanCheck(PlanCheckStatus.CONSISTENT), ())
    rules = {
        "1": "holds",
        "2": 'broken: "APT28 leads" - a named group attacks',
        "4": "broken - systems linked",
    }
    check, notes = _plan_checked({"rules": rules, "same_threat": True, "same_impact": True})
    assert check.status == PlanCheckStatus.INCONSISTENT
    assert [(note.code, note.message) for note in notes] == [
        (FindingCode.PLAN_CHECK, 'Rule 2: "APT28 leads" - a named group attacks'),
        (FindingCode.PLAN_CHECK, "Rule 4: systems linked"),
    ]
    check, notes = _plan_checked(_MISMATCH)
    assert [note.code for note in notes] == [FindingCode.SCENARIO_MISMATCH] and not check.same_threat


def test_an_unusable_plan_check_is_a_warning_and_an_outage_retries_the_job() -> None:
    check, notes = _plan_checked({"consistent": "maybe"}, {"verdict": "fine"})
    assert check == PlanCheck(PlanCheckStatus.UNCHECKED)
    assert [(note.code, note.severity) for note in notes] == [
        (FindingCode.PLAN_CHECK_NOT_MADE, FindingSeverity.WARNING)
    ]
    assert (check.to_record()["same_threat"], check.to_record()["same_impact"]) == (None, None)
    with pytest.raises(Unavailable):
        _plan_checked(Unavailable("AI down"))


def test_a_clean_first_draft_is_kept_after_two_calls_and_a_note_asks_no_rewrite() -> None:
    noted = {"rules": {"5": "broken - the impact is broad"}, "same_threat": True, "same_impact": True}
    chat = _chat_answering([_CLEAN.to_answer()], [noted])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.draft == _READ and not written.rewritten and not written.blocked
    assert [finding.code for finding in written.findings] == [FindingCode.PLAN_CHECK]
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_an_unreadable_answer_is_asked_once_more_and_twice_fails_the_scenario() -> None:
    no_risk = {key: value for key, value in _CLEAN.to_answer().items() if key != "risk_statement"}
    elsewhere = _CLEAN.to_answer() | {"entry_point": "scada  SERVER"}  # an offered option, any spelling
    chat = _chat_answering([no_risk, elsewhere], [_CONSISTENT])
    assert write_scenario(chat, _brief_of(_plan_threat())).draft == _READ
    assert _calls(chat).count(AiTask.WRITE_SCENARIO) == 2
    chat = _chat_answering([{"title": "x"}, {"title": "y"}], [])
    with pytest.raises(UnreadableAiAnswer):
        write_scenario(chat, _brief_of(_plan_threat()))


def test_an_asset_level_threat_has_no_entry_point_whatever_was_written() -> None:
    chat = _chat_answering([_CLEAN.to_answer() | {"entry_point": "Grid Control Centre"}], [_CONSISTENT])
    assert write_scenario(chat, _brief_of(_plan_threat(systems=()))).draft.entry_point == ""


def test_a_mismatch_blocks_then_one_rewrite_listing_it_and_a_better_rewrite_is_kept() -> None:
    chat = _chat_answering([_CLEAN.to_answer()], [_MISMATCH, _CONSISTENT], [_CLEAN.to_answer()])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.rewritten and not written.blocked
    assert _calls(chat) == [
        AiTask.WRITE_SCENARIO,
        AiTask.PLAN_CHECK,
        AiTask.REWRITE_SCENARIO,
        AiTask.PLAN_CHECK,
    ]
    assert "no longer describes the plan's threat" in chat.asked(AiTask.REWRITE_SCENARIO)[0]
    chat = _chat_answering([_CLEAN.to_answer()], [_MISMATCH, _MISMATCH], [_CLEAN.to_answer()])
    kept = write_scenario(chat, _brief_of(_plan_threat()))
    assert kept.blocked and kept.final and kept.rewritten  # a tie keeps the rewrite; still final


def test_a_worse_or_unusable_rewrite_keeps_the_first_draft() -> None:
    labelled = _CLEAN.to_answer() | {"scenario_statement": _CLEAN.statement + " SYS7 helps."}
    worse = labelled | {"risk_statement": _CLEAN.risk + " CVE-2025-0001 too."}
    chat = _chat_answering([labelled], [_CONSISTENT, _MISMATCH], [worse])
    kept = write_scenario(chat, _brief_of(_plan_threat()))
    assert not kept.rewritten and [finding.code for finding in kept.findings] == [FindingCode.UNKNOWN_ID]
    chat = _chat_answering([labelled], [_CONSISTENT], [{"bad": 1}, {"bad": 2}])
    assert not write_scenario(chat, _brief_of(_plan_threat())).rewritten
    assert _calls(chat).count(AiTask.REWRITE_SCENARIO) == 2


def test_every_supporting_system_needs_its_reason_or_the_answer_is_asked_again() -> None:
    """A reason missing for one system is re-asked; a name is matched case and spacing forgiven."""
    half = _CLEAN.to_answer() | {"system_reasons": {"scada  SERVER": "It could stop the server."}}
    whole = _CLEAN.to_answer() | {
        "system_reasons": {"SCADA server": "It could stop it.", "Historian": "Its records stay."}
    }
    chat = _chat_answering([half, whole], [_CONSISTENT])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.draft.system_reasons == (
        ("SCADA server", "It could stop it."),
        ("Historian", "Its records stay."),
    )
    assert _calls(chat).count(AiTask.WRITE_SCENARIO) == 2


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
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    assert scenarios.save(
        _stored(session_id, "p1", None, status=ScenarioStatus.FAILED, failure={"code": "x"})
    )
    assert scenarios.save(_stored(session_id, "p1"))
    assert not scenarios.save(_stored(session_id, "p1", "Another title"))
    assert scenarios.find_written(session_id, ["p1", "p2"]) == {"p1": f"{session_id}:p1"}


def test_no_two_written_versions_of_a_run_share_a_title() -> None:
    """G142: the database refuses the clash, even under a race; other runs and blocked cards do not count."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    assert scenarios.save(_stored(session_id, "p3"))
    with pytest.raises(TitleTaken):
        scenarios.save(_stored(session_id, "p4"))
    assert scenarios.save(_stored(f"other-{session_id}", "p4"))
    assert scenarios.save(_stored(session_id, "p5", status=ScenarioStatus.BLOCKED))


def test_counts_come_from_one_aggregation_and_a_blocked_scenario_is_never_served() -> None:
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    scenarios.save(_stored(session_id, "p1", "A", controls={"status": "queued", "attempts": 0}))
    scenarios.save(_stored(session_id, "p2", "B", decision=Decision.ACCEPTED, controls={"status": "done"}))
    scenarios.save(_stored(session_id, "p3", None, status=ScenarioStatus.FAILED))
    scenarios.save(_stored(session_id, "p4", "C", status=ScenarioStatus.BLOCKED))
    counts = scenarios.count_for_run(session_id)
    assert (counts["written"], counts["failed"], counts["accepted"], counts["pending"]) == (2, 1, 1, 1)
    assert scenarios.find_in_run(session_id, f"{session_id}:p4") is None


def test_the_counts_read_the_run_counts_index_only_and_skip_a_replaced_pending_version() -> None:
    """Every save, mapped control and review recounts the run: the aggregation never fetches a scenario."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    replaced = {"_id": f"{session_id}:p1:v1", "superseded_by": f"{session_id}:p1"}
    scenarios.save(_stored(session_id, "p1", "Old", controls={"status": "queued"}) | replaced)
    scenarios.save(_stored(session_id, "p1", "New", controls={"status": "queued"}))
    counts = scenarios.count_for_run(session_id)
    assert (counts["written"], counts["pending"], counts["controls_waiting"]) == (1, 1, 1)
    asked: list[list[dict[str, Any]]] = []
    spy = ScenarioRepository.__new__(ScenarioRepository)
    spy._scenarios = SimpleNamespace(aggregate=lambda pipeline: asked.append(pipeline) or iter([]))
    spy.count_for_run(session_id)
    command = {"aggregate": Collection.SCENARIOS, "pipeline": asked[0], "cursor": {}}
    explained = get_mongodb().command("explain", command, verbosity="queryPlanner")
    planner = explained.get("queryPlanner") or explained["stages"][0]["$cursor"]["queryPlanner"]
    winning = json.dumps(planner["winningPlan"])
    assert "run_counts" in winning and '"FETCH"' not in winning


def test_the_duplicate_read_of_an_assets_other_runs_examines_that_asset_only() -> None:
    """G268: once per write delivery, never a walk over the entity's whole register."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    asset = int(uuid.uuid4().hex[:12], 16)
    for number in range(20):
        scenarios.save(
            _stored(f"other-{session_id}", f"p{number}", f"T{number}", asset_id=asset + 1 + number)
        )
    scenarios.save(_stored(f"earlier-{session_id}", "p1", asset_id=asset))
    asked: list[dict[str, Any]] = []
    db = {Collection.SCENARIOS: SimpleNamespace(find=lambda query, fields: asked.append(query) or [])}
    find_held_elsewhere(db, 86, asset, session_id)  # type: ignore[arg-type]
    explained = get_mongodb()[Collection.SCENARIOS].find(asked[0]).explain()
    assert explained["executionStats"]["totalDocsExamined"] == 1


def test_a_clashing_title_takes_the_threat_name_then_a_number() -> None:
    titles = title_candidates("Loss of control", "Firmware update")
    assert [next(titles) for _ in range(3)] == [
        "Loss of control",
        "Loss of control (Firmware update)",
        "Loss of control (2)",
    ]
    assert next(title_candidates("Firmware update", "firmware UPDATE")) == "Firmware update"


def test_a_saved_scenario_reads_back_through_the_api_view() -> None:
    """What the job stores is what the API shows: the texts, why it applies, the attackers, every system
    with its reason, the route, and validation from the findings."""
    brief = _brief_of(_plan_threat())
    note = Finding(FindingCode.PLAN_CHECK, "The impact is broad.")
    check = PlanCheck(PlanCheckStatus.INCONSISTENT, ("The impact is broad.",))
    written = WrittenScenario(_READ, (note,), check, Route.STANDALONE, True, "Unauthorised firmware update")
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {
        "path_id": "p1",
        "category": "Tampering",
        "categories": ["Tampering"],
        "rank": 3,
        "systems": [321],
    }
    record = written_record(run, path, _plan_threat(), brief, written)
    view = ScenarioView.from_record(record)
    text = view.scenario
    assert record["_id"] == scenario_id("run-1", "p1", 1) and view.status == ScenarioStatus.DONE
    assert text.scenario_statement == f"{_CLEAN.statement}\n\nWhy this threat applies: {WHY_APPLIES}"
    assert [actor.actor_name for actor in view.actors] == ["Cybercriminal"]
    assert [
        (s.supporting_system, s.is_applicable, s.is_entry_point) for s in text.supporting_systems_involved
    ] == [
        ("SCADA server", True, True),
        ("Historian", False, False),
    ]
    assert view.validation_status == ValidationStatus.OK and view.validation_notes == ["The impact is broad."]
    assert view.threat.threat_name == "Unauthorised firmware update" and view.threat.scope_rank == 3
    assert (view.controls_status, record["rewritten"], view.evidence) == ("queued", True, [])


def test_the_card_keeps_each_systems_recorded_name_and_one_entry_point() -> None:
    """Two systems redacted alike in the prompt are told apart by their place in the brief."""
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_brief({threat["key"]: threat}, path, context, 30_000, _LIVE)
    assert brief.entry_point_options == ("[REDACTED]", "[REDACTED]")
    draft = dataclasses.replace(_CLEAN, entry_point=brief.entry_point_options[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT), Route.STANDALONE, False)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": context.to_record()}
    assert written_record(run, path, threat, brief, written)["content"]["systems"] == [
        {"id": 321, "name": "scada01.plant.local", "entry_point": True},
        {"id": 322, "name": "hist01.plant.local", "entry_point": False},
    ]


def test_a_failure_card_is_built_for_a_threat_with_no_name_type_or_attacker() -> None:
    threat = {
        "key": "lib:9",
        "type": None,
        "name": None,
        "library_id": 9,
        "ai_generated": False,
        "actors": None,
    }
    path = {"path_id": "p9", "category": "Tampering", "categories": None}
    card = failure_record(
        {"_id": "r", "entity_id": 86, "asset_id": 103}, path, threat, PathFailure(ErrorCode.INVALID_PLAN, "m")
    )
    assert card["status"] == ScenarioStatus.FAILED and card["content"]["threat"]["name"] == ""
    assert card["content"]["actors"] == [] and card["failure"] == {
        "code": ErrorCode.INVALID_PLAN,
        "message": "m",
    }
