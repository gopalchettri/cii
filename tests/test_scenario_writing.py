"""Scenario writing (Step 12): the brief, the owner's prompts, the exact safety checks, the reviewer, and
what is stored and shown. Fake AI models, no network."""

import copy
import dataclasses
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app import container
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
    StrideCategory,
    ValidationStatus,
    WriterStyle,
)
from app.core.database import get_mongodb
from app.core.exceptions import PathNotWritable, Unavailable
from app.core.prompts import PROMPTS
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository, TitleTaken
from app.domain.scenario.plan import gap_fill_prompt, planned_threat_record, relevance_gate_prompt
from app.domain.scenario.results import build_scenario_view
from app.domain.scenario.write import (
    PLAN_CHECK_SYSTEM_PROMPT,
    WRITER_SYSTEM_PROMPT,
    brief_entry_point_options,
    build_brief,
    check_against_plan,
    check_exact_rules,
    draft_answer,
    failure_record,
    finding_record,
    finding_severity,
    is_blocked,
    is_final,
    plan_check_prompt,
    plan_check_record,
    scenario_id,
    split_threat_actions,
    title_candidates,
    with_word_limits,
    write_scenario,
    writer_prompt,
    written_record,
)
from app.models.scenario.plan import PlannedActor
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
from app.worker.scenario.path_writing import PathWriter
from tests.fakes import FakeChatModel, truncated
from tests.planner_samples import CONTEXT, planned, system_row

#: Everything the sample threats name is still active in the library.
_LIVE = LiveLibrary(frozenset({297}), frozenset({1}), frozenset({7, 8}))
_SPLIT = PROMPTS["scenario"]["threat_actions"]
_CLEAN = ScenarioDraft(
    "Loss of control integrity",
    "A cybercriminal could use a vendor session to push firmware to the SCADA server of Grid Control Centre.",
    "Loss of trusted control at Grid Control Centre could interrupt electricity transmission.",
    ("Assumes vendor sessions can update firmware - not recorded in the platform.",),
    "SCADA server",
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
    record = planned_threat_record(threat) | fields
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


def _chat_answering(writes: list[Any], checks: list[Any]) -> FakeChatModel:
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, *writes)
    chat.queue(AiTask.PLAN_CHECK, *checks)
    return chat


def _calls(chat: FakeChatModel) -> list[AiTask]:
    return [task for task, _ in chat.calls]


def test_only_a_safety_fault_a_mismatch_or_a_copy_blocks_and_only_a_copy_is_final() -> None:
    """A reviewer's rule verdict is a note, never a blocker; a check not made, a warning."""
    blockers = {code for code, severity in FINDING_SEVERITIES.items() if severity == FindingSeverity.BLOCKER}
    assert {
        FindingCode.UNKNOWN_ID,
        FindingCode.UNCITED_ADVISORY_ID,
        FindingCode.SCENARIO_MISMATCH,
    } | FINAL_FINDINGS <= blockers
    assert {FindingCode.NEAR_DUPLICATE} == FINAL_FINDINGS
    assert FINDING_SEVERITIES[FindingCode.PLAN_CHECK] == FindingSeverity.NOTE
    assert FINDING_SEVERITIES[FindingCode.PLAN_CHECK_NOT_MADE] == FindingSeverity.WARNING
    written = WrittenScenario(
        _CLEAN,
        (Finding(FindingCode.PLAN_CHECK, "m"),),
        PlanCheck(PlanCheckStatus.CONSISTENT),
        Route.STANDALONE,
    )
    assert not is_blocked(written)
    assert finding_record(Finding(FindingCode.UNKNOWN_ID, "m")) == {
        "code": "unknown_id",
        "severity": "blocker",
        "message": "m",
    }


def test_the_answer_contracts_need_every_text_and_a_verdict_per_rule() -> None:
    assert ScenarioAnswer.model_validate(draft_answer(_CLEAN)).entry_point == "SCADA server"
    for field in ("scenario_title", "scenario_statement", "risk_statement"):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScenarioAnswer.model_validate(draft_answer(_CLEAN) | {field: "  "})
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
    view = build_scenario_view(
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
    assert brief_entry_point_options(brief) == ("SCADA server",) and brief.other_systems == ("Historian",)
    assert (brief.attacker, brief.threat, brief.threat_type) == (
        "Cybercriminal",
        "Unauthorised firmware update",
        "Malware",
    )
    sent = json.dumps([brief.asset, *brief.systems, brief.why_it_applies])
    leaked = [
        token for token in ("321", "322", "103", "SYS1", '"id"', "alias", "ops@grid.example") if token in sent
    ]
    assert leaked == [] and brief_entry_point_options(_brief_of(_plan_threat(systems=()))) == ()


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
    assert system.startswith(PLAN_CHECK_SYSTEM_PROMPT) and json.loads(scenario_text) == draft_answer(_CLEAN)
    assert json.loads(plan_text)["critical_service"] == "Electricity transmission"
    assert CHAT_TEMPERATURES[AiTask.PLAN_CHECK] == 0.0


def test_the_impact_comes_from_the_threats_own_action_and_no_prompt_names_the_platform_note() -> None:
    """Every prompt bans an added step and asks why, not how; none names the note code adds to assumptions."""
    gate = relevance_gate_prompt("LANDSCAPE", StrideCategory.TAMPERING, [{"slot": "R1"}])[1]
    gap = gap_fill_prompt("LANDSCAPE", StrideCategory.TAMPERING, 3, ())[1]
    for prompt in (gate, gap):
        assert "directly causes the loss the STRIDE category line describes" in prompt
        assert "only through an added step that is not part of the threat" in prompt
        assert "it never retells the attack steps" in prompt
        assert "An action that only obtains a credential, secret or session" in prompt
        assert "anything later done with it is an added step" in prompt
        assert '"theft" and "phishing" are not use' in prompt
    assert "LIBRARY-GAP BOUNDARY" not in gap and "TSG_SCENARIO_TARGET" not in gap
    writer, reviewer = WRITER_SYSTEM_PROMPT, PLAN_CHECK_SYSTEM_PROMPT
    assert "never add a step that is not part of the threat" in writer
    assert "its primary impact is what the acquisition itself causes" in writer
    assert "never from a later use its name does not state (rule 1)" in writer
    split = "two names for the same act are one action"  # each prompt's own split, used without the list
    assert split in writer and split in reviewer
    assert "naming the threat is not carrying it out" in writer and "is carried out, not only named" in writer
    assert "in your own words and concrete to this asset" in writer and "never copy the list's" in writer
    plain = writer.split("13. PLAIN ENGLISH")[1].split("GENERATOR FINAL CHECK")[0]  # anyone can read them
    assert "who writes for operators, managers and auditors who are not security experts" in writer
    assert "Short sentences, about 20 words at most" in plain and '"pretend to be", not "spoof"' in plain
    assert "each part its own short sentence" in writer and "one or two short sentences" in writer
    assert "Write in plain English (rule 13)" in writer and "- Plain English: short sentences" in writer
    assert "the category's loss (rule 11)" in plain and "locks" not in plain  # plain words keep the category
    assert "in any words (judge the meaning, not the list's wording" in reviewer
    assert "or only named, not carried out as the attacker's action" in reviewer  # a rule 1 note
    stated = "the threat's name does not state"  # a use or objective the name states is the threat's own
    assert f"an objective {stated}" in writer and f"exposed information/access that {stated}" in writer
    assert f"later uses of access or information {stated}" in writer
    assert "an action, use or demand the threat's name states is part of the threat" in reviewer
    assert f"gained access/information that {stated}" in reviewer
    named = ("ransomware", "data theft extortion", "ddos", "wiper", "phishing and mfa")  # no library threat
    prompts = (gate, gap, writer, reviewer, _SPLIT["text"], _SPLIT["system"])
    assert [n for n in named for prompt in prompts if n in prompt.casefold()] == []
    assert "Using access the threat only obtains (a stolen credential, secret or session)" in reviewer
    assert "including using access the threat only obtains" in reviewer
    assert "Add no sentence linking them to this asset or event" in writer and "End with at" not in writer
    assert "It is false for any sentence linking the evidence" in reviewer and "plus at most" not in reviewer
    assert 'List an essential missing detail in assumptions as: "assumes <specific condition>".' in writer
    assert "the primary impact comes from an added step that is not part of the threat" in reviewer
    assert "every action its name states is its own" in gate
    assert [prompt for prompt in (gate, gap, writer, reviewer) if "recorded in the platform" in prompt] == []
    assert "why_applies" not in writer and "why_applies" not in reviewer and '"9"' not in reviewer


def test_the_brief_never_carries_the_platform_note_of_an_older_record() -> None:
    """A stored relevance reason with the note reaches the writer without it."""
    threat = _plan_threat(reason="The SCADA server takes firmware, assumes X - not recorded in the platform.")
    assert _brief_of(threat).why_it_applies == "The SCADA server takes firmware, assumes X."


def test_the_split_and_both_prompts_carry_the_threats_actions() -> None:
    """The split's general rules and five invented examples from other fields; the writer carries out each
    listed action in step 3 and the reviewer answers for each; without the list each splits the name."""
    split, writer, reviewer = _SPLIT["text"], WRITER_SYSTEM_PROMPT, PLAN_CHECK_SYSTEM_PROMPT
    assert "Give no more acts than the name states." in split and 'Return {"actions": ["..."]}.' in split
    assert 'Alternatives joined by "or" are one act: keep them together in one phrase.' in split
    assert "Examples (invented, from other fields):" in split and split.count('\n- "') == 5
    skimming = '"Card skimming with cash-out" -> ["copying card data with a skimmer", "withdrawing cash'
    assert skimming in split and "split a cyber threat's name into the acts" in _SPLIT["system"]
    step3 = "3) Carry out every action in BRIEF.threat.threat_actions (without that list, every action"
    assert f"{step3} of your own split) once, in a realistic order" in writer
    assert "When the list is absent, split the specified threat's name into the actions it states" in writer
    field = '"threat_actions": {"<each item of PLAN.threat.threat_actions, copied>": "carried out" | "only'
    assert field in reviewer and "For each item of PLAN.threat.threat_actions answer in `threat_" in reviewer
    assert 'wording; of alternatives an item joins with "or", one is enough)' in reviewer
    assert "Without that list, answer {} and split PLAN's threat name" in reviewer
    assert "`threat_actions` has one answer for each item of PLAN.threat.threat_actions" in reviewer
    assert "other_scenarios" not in writer and "described in rule 10" in writer and "12. SYSTEM" in writer


def test_the_split_gives_the_actions_and_an_unusable_answer_gives_none() -> None:
    """A usable answer is the tuple; one still unusable after the re-ask, or cut off, gives () (the writer and
    the reviewer split the name); an outage is raised, so the path is retried."""
    chat = FakeChatModel()
    chat.queue(AiTask.THREAT_ACTIONS, {"actions": ["pushing  firmware", "hiding the change"]})
    assert split_threat_actions(chat, "Firmware push") == ("pushing firmware", "hiding the change")
    assert chat.asked(AiTask.THREAT_ACTIONS)[0].endswith('\nTHREAT: "Firmware push"')
    for answers in (({"acts": ["x"]}, {"actions": [" "]}), (truncated(),)):
        chat.queue(AiTask.THREAT_ACTIONS, *answers)
        assert split_threat_actions(chat, "Firmware push") == ()
    chat.queue(AiTask.THREAT_ACTIONS, Unavailable("AI down"))
    with pytest.raises(Unavailable):
        split_threat_actions(chat, "Firmware push")


def _path_writer(chat: FakeChatModel, threat: dict[str, Any]) -> PathWriter:
    """One delivery's writer for a run planning `threat`, every library record still active."""
    run = {"_id": "r1", "context": CONTEXT.to_record(), "plan": {"threats": [threat]}}
    active = SimpleNamespace(catalogue_id=297, type_id=1)
    library = SimpleNamespace(threats=[active], actors=[SimpleNamespace(actor_id=7)])
    return PathWriter(run, chat, library, WriterStyle.ORIGINAL)  # type: ignore[arg-type]


def _sent_threat(prompt: str) -> dict[str, Any]:
    """The threat of the BRIEF or PLAN a writer or reviewer prompt carries."""
    return dict(json.JSONDecoder().raw_decode(prompt.split(":\n", 1)[1])[0]["threat"])


def test_a_delivery_splits_each_threat_once_and_the_brief_and_plan_carry_its_actions() -> None:
    """Two paths of one threat ask for its split once; the writer's BRIEF and the reviewer's PLAN list the
    actions under the threat."""
    threat = _plan_threat()
    chat = FakeChatModel()
    listed = ["pushing firmware", "hiding the change"]
    chat.queue(AiTask.THREAT_ACTIONS, {"actions": listed})
    done = {"threat_actions": dict.fromkeys(listed, "carried out")}
    chat.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN),
        AiTask.PLAN_CHECK: lambda _: _CONSISTENT | done,
    }
    writer = _path_writer(chat, threat)
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    outcomes = [writer.write(path | {"path_id": path_id}) for path_id in ("p1", "p2")]
    assert len(chat.asked(AiTask.THREAT_ACTIONS)) == 1
    assert [outcome[0].threat_actions for outcome in outcomes if isinstance(outcome, tuple)] == [
        tuple(listed)
    ] * 2
    sent = [*chat.asked(AiTask.WRITE_SCENARIO), *chat.asked(AiTask.PLAN_CHECK)]
    assert len(sent) == 4 and all(_sent_threat(prompt)["threat_actions"] == listed for prompt in sent)


def test_a_split_outage_is_raised_to_each_path_of_its_threat_with_one_ask() -> None:
    """The split's outage is kept for the delivery: the threat's other path raises it without asking again."""
    threat = _plan_threat()
    chat = FakeChatModel()
    chat.queue(AiTask.THREAT_ACTIONS, Unavailable("AI down"))
    writer = _path_writer(chat, threat)
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    for path_id in ("p1", "p2"):
        with pytest.raises(Unavailable):
            writer.write(path | {"path_id": path_id})
    assert len(chat.asked(AiTask.THREAT_ACTIONS)) == 1


def test_with_no_list_the_brief_sends_none_and_the_scenario_is_still_written() -> None:
    """An unusable split, like a brief of an old plan path, sends no threat_actions: the writer and the
    reviewer split the name themselves and the scenario is written."""
    threat = _plan_threat()
    chat = _chat_answering([draft_answer(_CLEAN)], [_CONSISTENT])
    chat.queue(AiTask.THREAT_ACTIONS, {"acts": []}, {"acts": []})
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    outcome = _path_writer(chat, threat).write(path)
    assert isinstance(outcome, tuple) and outcome[0].threat_actions == ()
    assert outcome[1].draft == _READ and not is_blocked(outcome[1])
    sent = [*chat.asked(AiTask.WRITE_SCENARIO), *chat.asked(AiTask.PLAN_CHECK)]
    assert len(sent) == 2 and all("threat_actions" not in _sent_threat(prompt) for prompt in sent)


def test_a_made_up_label_blocks_and_with_intelligence_off_any_advisory_id_does() -> None:
    """A label the brief gives is supplied; an advisory id from the asset's own facts blocks while off."""
    brief = _brief_of(_plan_threat())
    assert check_exact_rules(_CLEAN, brief) == ()
    made_up = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " SYS7 and CVE-2025-0001 help.")
    assert [finding.code for finding in check_exact_rules(made_up, brief)] == [
        FindingCode.UNKNOWN_ID,
        FindingCode.UNCITED_ADVISORY_ID,
    ]
    system = brief.systems[0] | {"name": "MicroSCADA Pro SYS600"}
    asset = brief.asset | {"description": "Patched against CVE-2024-1234 last spring."}
    supplied = dataclasses.replace(brief, systems=(system,), asset=asset)
    told = dataclasses.replace(
        _CLEAN, statement="A cybercriminal could use CVE-2024-1234 on the MicroSCADA Pro SYS600."
    )
    (advisory,) = check_exact_rules(told, supplied)
    assert advisory.code == FindingCode.UNCITED_ADVISORY_ID and "CVE-2024-1234" in advisory.message
    story = dataclasses.replace(supplied, style=WriterStyle.EVIDENCE_STORY)
    assert check_exact_rules(told, story) == ()


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


def test_an_action_not_carried_out_is_a_rule_1_note_never_a_blocker() -> None:
    """Each listed action the reviewer finds only named or missing is a rule 1 note and the check is
    inconsistent; none listed ({}) or every action carried out gives no note."""
    actions = {"pushing firmware": "carried out", "hiding the change": "only named", "wiping logs": "missing"}
    check, notes = _plan_checked(_CONSISTENT | {"threat_actions": actions})
    assert check.status == PlanCheckStatus.INCONSISTENT
    assert [(note.code, note.message) for note in notes] == [
        (FindingCode.PLAN_CHECK, 'Rule 1: "hiding the change" is only named, not carried out'),
        (FindingCode.PLAN_CHECK, 'Rule 1: "wiping logs" is missing, not carried out'),
    ]
    assert {finding_severity(note) for note in notes} == {FindingSeverity.NOTE}
    for answered in ({}, {"pushing firmware": " Carried out "}):
        assert _plan_checked(_CONSISTENT | {"threat_actions": answered}) == (
            PlanCheck(PlanCheckStatus.CONSISTENT),
            (),
        )


def test_a_review_that_judges_none_of_the_listed_actions_is_asked_again() -> None:
    """With PLAN listing the threat's actions, an answer judging none of them is asked once more."""
    chat = FakeChatModel()
    chat.queue(AiTask.PLAN_CHECK, _CONSISTENT, _CONSISTENT | {"threat_actions": {"wiping logs": "missing"}})
    brief = dataclasses.replace(_brief_of(_plan_threat()), threat_actions=("wiping logs",))
    check, notes = check_against_plan(chat, brief, _CLEAN)
    assert len(chat.asked(AiTask.PLAN_CHECK)) == 2 and check.status == PlanCheckStatus.INCONSISTENT
    assert [note.message for note in notes] == ['Rule 1: "wiping logs" is missing, not carried out']


def test_an_unusable_plan_check_is_a_warning_and_an_outage_retries_the_job() -> None:
    check, notes = _plan_checked({"consistent": "maybe"}, {"verdict": "fine"})
    assert check == PlanCheck(PlanCheckStatus.UNCHECKED)
    assert [(note.code, finding_severity(note)) for note in notes] == [
        (FindingCode.PLAN_CHECK_NOT_MADE, FindingSeverity.WARNING)
    ]
    assert (plan_check_record(check)["same_threat"], plan_check_record(check)["same_impact"]) == (None, None)
    with pytest.raises(Unavailable):
        _plan_checked(Unavailable("AI down"))


def test_a_clean_draft_is_kept_after_two_calls_and_a_note_blocks_nothing() -> None:
    noted = {"rules": {"5": "broken - the impact is broad"}, "same_threat": True, "same_impact": True}
    chat = _chat_answering([draft_answer(_CLEAN)], [noted])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.draft == _READ and not is_blocked(written)
    assert [finding.code for finding in written.findings] == [FindingCode.PLAN_CHECK]
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_an_unreadable_answer_is_asked_once_more_and_twice_fails_the_scenario() -> None:
    no_risk = {key: value for key, value in draft_answer(_CLEAN).items() if key != "risk_statement"}
    elsewhere = draft_answer(_CLEAN) | {"entry_point": "scada  SERVER"}  # an offered option, any spelling
    chat = _chat_answering([no_risk, elsewhere], [_CONSISTENT])
    assert write_scenario(chat, _brief_of(_plan_threat())).draft == _READ
    assert _calls(chat).count(AiTask.WRITE_SCENARIO) == 2
    chat = _chat_answering([{"title": "x"}, {"title": "y"}], [])
    with pytest.raises(UnreadableAiAnswer):
        write_scenario(chat, _brief_of(_plan_threat()))


def test_an_asset_level_threat_has_no_entry_point_whatever_was_written() -> None:
    chat = _chat_answering([draft_answer(_CLEAN) | {"entry_point": "Grid Control Centre"}], [_CONSISTENT])
    assert write_scenario(chat, _brief_of(_plan_threat(systems=()))).draft.entry_point == ""


def test_a_mismatch_blocks_after_one_write_and_is_not_final() -> None:
    """The blocked draft counts an attempt and its path is given up at once: the writer's own retry is off."""
    chat = _chat_answering([draft_answer(_CLEAN)], [_MISMATCH])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert is_blocked(written) and not is_final(written)
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_a_draft_the_exact_checks_block_makes_no_reviewer_call() -> None:
    labelled = draft_answer(_CLEAN) | {"scenario_statement": _CLEAN.statement + " SYS7 helps."}
    chat = _chat_answering([labelled], [])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert [finding.code for finding in written.findings] == [FindingCode.UNKNOWN_ID]
    assert written.plan_check == PlanCheck(PlanCheckStatus.UNCHECKED) and not is_final(written)
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]


def test_every_supporting_system_needs_its_reason_or_the_answer_is_asked_again() -> None:
    """A reason missing for one system is re-asked; a name is matched case and spacing forgiven."""
    half = draft_answer(_CLEAN) | {"system_reasons": {"scada  SERVER": "It could stop the server."}}
    whole = draft_answer(_CLEAN) | {
        "system_reasons": {"SCADA server": "It could stop it.", "Historian": "Its records stay."}
    }
    chat = _chat_answering([half, whole], [_CONSISTENT])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.draft.system_reasons == (
        ("SCADA server", "It could stop it."),
        ("Historian", "Its records stay."),
    )
    assert _calls(chat).count(AiTask.WRITE_SCENARIO) == 2


def _scenarios() -> ThreatScenarioRepository:
    scenarios = container.get_threat_scenario_repository()
    scenarios.create_indexes()
    return scenarios


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
    assert scenarios.save_scenario(
        _stored(session_id, "p1", None, status=ScenarioStatus.FAILED, failure={"code": "x"})
    )
    assert scenarios.save_scenario(_stored(session_id, "p1"))
    assert not scenarios.save_scenario(_stored(session_id, "p1", "Another title"))
    written = scenarios.list(
        fields="path_id",
        session_id=session_id,
        path_id_in=["p1", "p2"],
        status=ScenarioStatus.DONE,
        newest=True,
    )
    assert {row["path_id"]: row["_id"] for row in written} == {"p1": f"{session_id}:p1"}


def test_no_two_written_versions_of_a_run_share_a_title() -> None:
    """G142: the database refuses the clash, even under a race; other runs and blocked cards do not count."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    assert scenarios.save_scenario(_stored(session_id, "p3"))
    with pytest.raises(TitleTaken):
        scenarios.save_scenario(_stored(session_id, "p4"))
    assert scenarios.save_scenario(_stored(f"other-{session_id}", "p4"))
    assert scenarios.save_scenario(_stored(session_id, "p5", status=ScenarioStatus.BLOCKED))


def test_counts_come_from_one_aggregation_and_a_blocked_scenario_is_never_served() -> None:
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    scenarios.save_scenario(_stored(session_id, "p1", "A", controls={"status": "queued", "attempts": 0}))
    scenarios.save_scenario(
        _stored(session_id, "p2", "B", decision=Decision.ACCEPTED, controls={"status": "done"})
    )
    scenarios.save_scenario(_stored(session_id, "p3", None, status=ScenarioStatus.FAILED))
    scenarios.save_scenario(_stored(session_id, "p4", "C", status=ScenarioStatus.BLOCKED))
    counts = scenarios.count_scenarios_of_session(session_id)
    assert (counts["written"], counts["failed"], counts["accepted"], counts["pending"]) == (2, 1, 1, 1)
    assert scenarios.get(fields="shown", _id=f"{session_id}:p4", session_id=session_id, served=True) is None


def test_the_counts_read_the_run_counts_index_only_and_skip_a_replaced_pending_version() -> None:
    """Every save, mapped control and review recounts the run: the aggregation never fetches a scenario."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    replaced = {"_id": f"{session_id}:p1:v1", "superseded_by": f"{session_id}:p1"}
    scenarios.save_scenario(_stored(session_id, "p1", "Old", controls={"status": "queued"}) | replaced)
    scenarios.save_scenario(_stored(session_id, "p1", "New", controls={"status": "queued"}))
    counts = scenarios.count_scenarios_of_session(session_id)
    assert (counts["written"], counts["pending"], counts["controls_waiting"]) == (1, 1, 1)
    asked: list[list[dict[str, Any]]] = []
    spy = copy.copy(scenarios)  # the instance's named conditions, on a collection that records the pipeline
    spy._collection = SimpleNamespace(aggregate=lambda pipeline: asked.append(pipeline) or iter([]))
    spy.count_scenarios_of_session(session_id)
    command = {"aggregate": Collection.SCENARIOS, "pipeline": asked[0], "cursor": {}}
    explained = get_mongodb().command("explain", command, verbosity="queryPlanner")
    planner = explained.get("queryPlanner") or explained["stages"][0]["$cursor"]["queryPlanner"]
    winning = json.dumps(planner["winningPlan"])
    assert "run_counts" in winning and '"FETCH"' not in winning


def test_the_duplicate_read_examines_the_runs_own_scenarios_only() -> None:
    """D15 (owner 2026-10-20): once per duplicate check, the run's own finished scenarios only; the asset's
    other sessions are never read, so none of their scenarios, pending or accepted, blocks one."""
    scenarios, session_id = _scenarios(), f"run-{uuid.uuid4().hex}"
    asset = int(uuid.uuid4().hex[:12], 16)
    for number, decision in enumerate([Decision.PENDING, Decision.ACCEPTED] * 10):
        stored = _stored(f"other-{session_id}", f"p{number}", f"T{number}", asset_id=asset, decision=decision)
        scenarios.save_scenario(stored)
    scenarios.save_scenario(_stored(session_id, "p1", asset_id=asset))
    asked: list[dict[str, Any]] = []
    spy = ThreatScenarioRepository(SimpleNamespace(find=lambda query, fields, **_: asked.append(query) or []))  # type: ignore[arg-type]
    spy.list_scenarios_for_duplicate_check(session_id)
    explained = get_mongodb()[Collection.SCENARIOS].find(asked[0]).explain()
    assert explained["executionStats"]["totalDocsExamined"] == 1
    held = scenarios.list_scenarios_for_duplicate_check(session_id)
    assert [row["_id"] for row in held] == [f"{session_id}:p1"]


def test_a_clashing_title_takes_the_threat_name_then_a_number() -> None:
    titles = title_candidates("Loss of control", "Firmware update")
    assert [next(titles) for _ in range(3)] == [
        "Loss of control",
        "Loss of control (Firmware update)",
        "Loss of control (2)",
    ]
    assert next(title_candidates("Firmware update", "firmware UPDATE")) == "Firmware update"


def test_a_saved_scenario_reads_back_through_the_api_view() -> None:
    """What the job stores is what the API shows: the texts, the attackers, every system with its reason,
    the route, and validation from the findings."""
    brief = _brief_of(_plan_threat())
    note = Finding(FindingCode.PLAN_CHECK, "The impact is broad.")
    check = PlanCheck(PlanCheckStatus.INCONSISTENT, ("The impact is broad.",))
    written = WrittenScenario(_READ, (note,), check, Route.STANDALONE, "Unauthorised firmware update")
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {
        "path_id": "p1",
        "category": "Tampering",
        "categories": ["Tampering"],
        "rank": 3,
        "systems": [321],
    }
    record = written_record(run, path, _plan_threat(), brief, written)
    view = build_scenario_view(record)
    text = view.scenario
    assert record["_id"] == scenario_id("run-1", "p1", 1) and view.status == ScenarioStatus.DONE
    assert text.scenario_statement == _CLEAN.statement
    assert view.scope is not None and view.scope.evidence == []
    assert "why_applies" not in record["content"] and "why_applies" not in ScenarioAnswer.model_fields
    assert [actor.actor_name for actor in view.actors] == ["Cybercriminal"]
    assert [
        (s.supporting_system, s.is_applicable, s.is_entry_point) for s in text.supporting_systems_involved
    ] == [
        ("SCADA server", True, True),
        ("Historian", False, False),
    ]
    assert view.validation_status == ValidationStatus.OK and view.validation_notes == ["The impact is broad."]
    assert view.threat.threat_name == "Unauthorised firmware update" and view.threat.scope_rank == 3
    assert (view.controls_status, record["rewritten"], view.evidence) == ("queued", False, [])


def test_the_card_keeps_each_systems_recorded_name_and_one_entry_point() -> None:
    """Two systems redacted alike in the prompt are told apart by their place in the brief."""
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_brief({threat["key"]: threat}, path, context, 30_000, _LIVE)
    assert brief_entry_point_options(brief) == ("[REDACTED]", "[REDACTED]")
    draft = dataclasses.replace(_CLEAN, entry_point=brief_entry_point_options(brief)[0])
    written = WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT), Route.STANDALONE)
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": context.to_record()}
    assert written_record(run, path, threat, brief, written)["content"]["systems"] == [
        {"id": 321, "name": "scada01.plant.local", "entry_point": True},
        {"id": 322, "name": "hist01.plant.local", "entry_point": False},
    ]


def test_the_writer_gets_in_through_its_turns_system_and_the_card_marks_that_one() -> None:
    """A path whose turn is the Historian's offers only the Historian as the way in: a reply naming the SCADA
    server is asked again, and the card marks the Historian, though it is the path's second system, even when
    the two names are redacted alike. A plan made before paths took turns offers any of its systems."""
    threat = _plan_threat(systems=(321, 322))
    brief = _brief_of(threat, entry_system=322)
    assert brief_entry_point_options(brief) == ("Historian",)
    chat = _chat_answering(
        [draft_answer(_CLEAN), draft_answer(_CLEAN) | {"entry_point": "Historian"}], [_CONSISTENT]
    )
    written = write_scenario(chat, brief)
    assert written.draft.entry_point == "Historian" and _calls(chat).count(AiTask.WRITE_SCENARIO) == 2
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321, 322]}
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    assert written_record(run, path | {"entry_system": 322}, threat, brief, written)["content"][
        "systems"
    ] == [
        {"id": 321, "name": "SCADA server", "entry_point": False},
        {"id": 322, "name": "Historian", "entry_point": True},
    ]
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    alike = build_brief({threat["key"]: threat}, path | {"entry_system": 322}, context, 30_000, _LIVE)
    assert brief_entry_point_options(alike) == ("[REDACTED]",)
    draft = dataclasses.replace(_CLEAN, entry_point="[REDACTED]")
    record = written_record(
        run | {"context": context.to_record()},
        path | {"entry_system": 322},
        threat,
        alike,
        WrittenScenario(draft, (), PlanCheck(PlanCheckStatus.CONSISTENT), Route.STANDALONE),
    )
    assert [system["entry_point"] for system in record["content"]["systems"]] == [False, True]
    assert brief_entry_point_options(_brief_of(threat)) == ("SCADA server", "Historian")


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
