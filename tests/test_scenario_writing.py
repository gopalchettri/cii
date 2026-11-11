"""Scenario writing: the brief, the owner's prompts, the exact safety checks, and what is stored and shown.
Fake AI models, no network."""

import copy
import dataclasses
import json
import re
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app import container
from app.core.config import get_settings
from app.core.constants import (
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    ActorRole,
    AiLimits,
    AiTask,
    AnswerProblem,
    Collection,
    Decision,
    ErrorCode,
    FindingCode,
    FindingSeverity,
    PathProblem,
    RunKind,
    ScenarioStatus,
    StrideCategory,
    ValidationStatus,
    WriterStyle,
    Writing,
)
from app.core.database import get_mongodb
from app.core.exceptions import PathNotWritable
from app.core.prompts import PROMPTS
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository, TitleTaken
from app.domain.scenario.session import build_scenario_view
from app.domain.scenario.write import (
    WRITER_SYSTEM_PROMPT,
    _apply_safety_checks,
    _find_actions_missing_from_story,
    _remove_system_names_from_actions,
    build_failure_card,
    build_scenario_card,
    build_scenario_id,
    build_writer_input,
    build_writer_prompt,
    build_writer_system_prompt,
    write_scenario_set,
)
from app.domain.shared.names import as_json, name_match_key
from app.models.scenario.plan import PlannedActor
from app.models.scenario.write import (
    Finding,
    LiveLibrary,
    PathFailure,
    ScenarioAnswer,
    ScenarioDraft,
    WrittenScenario,
)
from app.worker.scenario.path_writing import PathWriter, save_with_unique_title
from tests.fakes import FakeChatModel, brief_of, draft_answer, shared_facts, slot_blocks
from tests.planner_samples import CONTEXT, gap_fill_prompt, gate_prompt, planned, system_row

#: Everything the sample threats name is still active in the library.
_LIVE = LiveLibrary(frozenset({297}), frozenset({1}), frozenset({7, 8}))
_CLEAN = ScenarioDraft(
    "Loss of control integrity",
    "A cybercriminal could use a vendor session to push firmware to the SCADA server of Grid Control Centre.",
    "Loss of trusted control at Grid Control Centre could interrupt electricity transmission.",
    ("Assumes vendor sessions can update firmware - not recorded in the platform.",),
    "SCADA server",
)
#: A draft's reasons: the fake writer's (tests/fakes.py) for the "yes" system, code's for the "no" one.
_REASONS = (("SCADA server", "It could affect SCADA server."), ("Historian", Writing.NOT_REACHED_REASON))
_READ = dataclasses.replace(_CLEAN, system_reasons=_REASONS)


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
    record = threat.to_record({}) | fields
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
    return build_writer_input({threat["key"]: threat}, record | path, CONTEXT, budget, _LIVE)


def _chat_answering(writes: list[Any]) -> FakeChatModel:
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, *writes)
    return chat


def _calls(chat: FakeChatModel) -> list[AiTask]:
    return [task for task, _ in chat.calls]


def write_scenario(chat: FakeChatModel, brief: Any) -> WrittenScenario:
    """One brief written as a set of one: its scenario (a batch of one is a batch)."""
    ((_, written),) = write_scenario_set(chat, [("SC1", brief)])  # type: ignore[arg-type]
    assert isinstance(written, WrittenScenario), written
    return written


def _failure_of(chat: FakeChatModel, brief: Any) -> PathFailure:
    """One brief written as a set of one, its slot failing."""
    ((_, failed),) = write_scenario_set(chat, [("SC1", brief)])  # type: ignore[arg-type]
    assert isinstance(failed, PathFailure), failed
    return failed


def test_only_a_safety_fault_or_a_copy_blocks_and_only_a_copy_is_final() -> None:
    """A citation removed is a warning, never a blocker; a copy is the one final blocker."""
    blockers = {code for code, severity in FINDING_SEVERITIES.items() if severity == FindingSeverity.BLOCKER}
    assert {FindingCode.UNKNOWN_ID, FindingCode.UNCITED_ADVISORY_ID} | FINAL_FINDINGS <= blockers
    assert {FindingCode.NEAR_DUPLICATE} == FINAL_FINDINGS
    assert FINDING_SEVERITIES[FindingCode.CITATION_REMOVED] == FindingSeverity.WARNING
    written = WrittenScenario(_CLEAN, (Finding(FindingCode.CITATION_REMOVED, "m"),))
    assert written.list_blocking_codes() == [] and written.find_blocking_code() == ""
    copied = WrittenScenario(
        _CLEAN, (Finding(FindingCode.UNKNOWN_ID, "m"), Finding(FindingCode.NEAR_DUPLICATE, "m"))
    )
    assert copied.list_blocking_codes() == ["near_duplicate", "unknown_id"]
    assert copied.find_blocking_code() == FindingCode.NEAR_DUPLICATE
    assert Finding(FindingCode.UNKNOWN_ID, "m").build_record() == {
        "code": "unknown_id",
        "severity": "blocker",
        "message": "m",
    }


def test_the_answer_contract_needs_every_text() -> None:
    assert ScenarioAnswer.model_validate(draft_answer(_CLEAN)).entry_point == "SCADA server"
    for field in ("scenario_title", "scenario_statement", "risk_statement"):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScenarioAnswer.model_validate(draft_answer(_CLEAN) | {field: "  "})


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
    """Only this threat's systems, by name; the run's others marked "no"; no id, alias or secret."""
    brief = _brief_of(_plan_threat())
    assert [system["name"] for system in brief.systems] == ["SCADA server"]
    others = [system.name for system in brief.supporting_systems if not system.applicable]
    assert brief.entry_options == ("SCADA server",) and others == ["Historian"]
    assert (brief.facts["attacker"], brief.threat, brief.facts["threat"]["threat_type"]) == (
        "Cybercriminal",
        "Unauthorised firmware update",
        "Malware",
    )
    sent = json.dumps([brief.asset, *brief.systems, brief.facts["threat"]["why_it_applies"]])
    leaked = [
        token for token in ("321", "322", "103", "SYS1", '"id"', "alias", "ops@grid.example") if token in sent
    ]
    assert leaked == [] and _brief_of(_plan_threat(systems=())).entry_options == ()


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
        build_writer_input({threat["key"]: threat}, path, CONTEXT, 30_000, live)
    assert refused.value.code == ErrorCode.LIBRARY_RECORD_RETIRED and retired in refused.value.message


def test_long_facts_are_cut_to_the_budget_and_the_brief_stays_json() -> None:
    long_text = "Vendor maintenance window. " * 300
    context = dataclasses.replace(
        CONTEXT, asset_context=CONTEXT.asset_context | {"cii_asset_description": long_text}
    )
    threat = _plan_threat()
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_writer_input({threat["key"]: threat}, path, context, 4_000, _LIVE)
    facts = sum(len(json.dumps(part, ensure_ascii=False)) for part in (brief.asset, *brief.systems))
    assert facts <= 4_000 and brief.asset["description"].endswith("…")


def test_the_writer_reads_the_owners_prompt_and_the_brief_as_json() -> None:
    """The owner's text file, the configured word limits in their slots, the asset's and systems' facts
    once before the slot, each slot's own line saying no evidence is given while intelligence is off."""
    brief = _brief_of(_plan_threat())
    system, user = build_writer_prompt([("SC1", brief, "")])
    assert system == build_writer_system_prompt() and "No EVIDENCE is given" not in system
    ((label, slot),) = slot_blocks(user)
    assert "<scenario words>" not in system and (label, slot[: len("SLOT SC1\nBRIEF:\n")]) == (
        "SC1",
        "SLOT SC1\nBRIEF:\n",
    )
    assert shared_facts(user) == (brief.asset, list(brief.systems))
    no_evidence = (
        'No EVIDENCE is given for this slot: cite nothing, tell no real-world event and return "evid'
    )
    assert no_evidence in slot.splitlines()[-1]
    assert brief_of(slot)["supporting_systems"] == [
        {"name": "SCADA server", "applicable": "yes"},
        {"name": "Historian", "applicable": "no"},
    ]


def test_the_impact_comes_from_the_threats_own_action_and_no_prompt_names_the_platform_note() -> None:
    """Every prompt bans an added step and asks why, not how; none names the note code adds to assumptions."""
    gate = gate_prompt([{"slot": "R1"}])
    gap = gap_fill_prompt([StrideCategory.TAMPERING])
    for prompt in (gate, gap):
        assert "directly causes the loss the STRIDE category line describes" in prompt
        assert "only through an added step that is not part of the threat" in prompt
        assert "it never retells the attack steps" in prompt
        assert "An action that only obtains a credential, secret or session" in prompt
        assert "anything later done with it is an added step" in prompt
        assert '"theft" and "phishing" are not use' in prompt
    assert "LIBRARY-GAP BOUNDARY" not in gap and "TSG_SCENARIO_TARGET" not in gap
    assert '"attacker":' not in gap  # the gate picks the attacker from the matched type's list
    writer = WRITER_SYSTEM_PROMPT
    assert "never add a step that is not part of the threat" in writer
    assert "its primary impact is what the acquisition itself causes" in writer
    assert "never from a later use its name does not state (rule 1)" in writer
    split = "two names for the same act are one action"  # each prompt's own split, used without the list
    assert split in writer
    assert "naming the threat is not carrying it out" in writer
    assert "must be carried out in the story as the attacker's action, not only named" in writer
    assert "in your own words and concrete to this asset" in writer and "never copy the list's" in writer
    plain = writer.split("13. CLEAR, BALANCED LANGUAGE")[1].split("GENERATOR FINAL CHECK")[0]  # both readers
    assert "writes for security staff and for operators, managers and auditors who are not security" in writer
    assert "Short sentences, about 20 words at most" in plain and "Mix plain sentences with" in plain
    assert "Keep the precise security or technical term where it names the act" in plain  # not too simple
    assert '"exfiltrate (copy out) the records"' in plain and 'not "Someone could make the tank' in plain
    assert '"break into" or "take over", not "compromise"' not in plain  # no blanket swap of precise terms
    assert "each part its own short sentence" in writer and "one or two short sentences" in writer
    assert "Write in clear, balanced language (rule 13)" in writer
    assert "the category's loss (rule 11)" in plain and "locks" not in plain  # clear words keep the category
    stated = "the threat's name does not state"  # a use or objective the name states is the threat's own
    assert f"an objective {stated}" in writer and f"exposed information/access that {stated}" in writer
    assert f"later uses of access or information {stated}" in writer
    named = ("ransomware", "data theft extortion", "ddos", "wiper", "phishing and mfa")  # no library threat
    prompts = (gate, gap, writer)
    assert [n for n in named for prompt in prompts if n in prompt.casefold()] == []
    # D65: the writer gives only the step its evidence entry is about; code writes the sentence from it
    assert "In real-world attacks" not in writer and "No field includes a real-world precedent" in writer
    step = 'evidence_step: the one step of this story that the entry marked "cited": true is about'
    assert step in writer and "as a gerund phrase written as a normal clause with its articles" in writer
    assert "by its full name exactly as BRIEF gives it" in writer  # 30 Oct: steps said "the platform"
    assert "in this story's own words rather than the cited title's" in writer
    assert "6 to 20 words, with no title, no group, malware or campaign name and no quotes" in writer
    assert "the application writes the closing evidence sentence from evidence_step" in writer
    assert "the application adds who used" not in writer  # 31 Oct: no closing sentence names who used it
    assert '"evidence_statement"' not in writer and "words no other slot uses" not in writer
    # D66: the writer gives reasons only for "yes" systems; code writes a "no" system's
    assert "Never name it in scenario_statement and give it no system_reasons key." in writer
    assert 'system_reasons: one key for every BRIEF.supporting_systems name marked "yes"' in writer
    assert 'copied exactly; no key for a "no" system.' in writer
    assert "the application writes it" not in writer  # said once, in the schema and rule 4
    assert (
        "Applicability missing" not in writer and "explain its exclusion only in system_reasons" not in writer
    )
    assert "End scenario_statement on this consequence." in writer
    assert 'A "no" system must not be described as attacked or directly affected. Never name it' in writer
    assert "The story may describe the attacker's steps in the cited entry's terms" in writer
    assert "Do not reshape the specified threat" not in writer  # owner 2026-10-28: it may fit the evidence
    assert 'List an essential missing detail in assumptions as: "assumes <specific condition>".' in writer
    assert "every action its name states is its own" in gate
    assert [prompt for prompt in (gate, gap, writer) if "recorded in the platform" in prompt] == []
    assert "why_applies" not in writer


def test_the_brief_gives_the_chosen_attackers_reason_on_this_path_only_and_the_likelihood_word() -> None:
    """Owner, 31 Oct: the writer fits the story to why its attacker was chosen, never naming a system off the
    path or personal data; no reason, no key; the likelihood as a word."""
    reason = "Holds the SCADA server and Historian admin logins; mail ops@grid.example."
    brief = _brief_of(_plan_threat(attacker_check_reason=reason, likelihood=3))
    why = brief.facts["why_this_attacker"]
    assert brief.facts["likelihood"] == "HIGH" and "SCADA server" in why
    assert "Historian" not in why and "ops@grid.example" not in why
    asked = build_writer_prompt([("SC1", brief, "")])[1]
    assert why in asked and '"likelihood": "HIGH"' in asked
    unexplained = _brief_of(_plan_threat(attacker_check_reason=None, likelihood=1))
    assert "why_this_attacker" not in unexplained.facts and unexplained.facts["likelihood"] == "LOW"
    assert "why_this_attacker" not in build_writer_prompt([("SC1", unexplained, "")])[1].split("BRIEF:", 1)[1]


def test_the_writer_fits_the_attacker_to_its_reason_and_says_the_likelihood_in_the_cause() -> None:
    writer = build_writer_system_prompt()
    assert "When BRIEF gives why_this_attacker, the access, skill and motive the story gives" in writer
    assert "access it names that BRIEF does not record is an assumption (rule 2)" in writer
    assert 'HIGH "is likely", MEDIUM "is possible", LOW "is unlikely but possible"' in writer
    assert "Never write the level, a score or a reason for it." in writer


def test_the_writer_prompt_stays_within_its_size_limit() -> None:
    """The customer's 25,000 tokens a minute: the cap is the writer's size (the test settings' word ranges)
    plus about 110 characters."""
    assert len(build_writer_system_prompt()) <= 16_220


def test_the_story_and_the_active_voice_example_keep_could_or_may() -> None:
    """Replay, 30 Oct: with the slimmed prompt's only active-voice example in the present tense ("the attacker
    copies the records") and rule 6's could/may clause cut, 52 of 75 stories were told as certain (old 3)."""
    writer = build_writer_system_prompt()
    assert '(rule 13) with hypothetical language such as "could" or "may".' in writer
    assert '("the attacker could copy the records")' in writer and "attacker copies the records" not in writer


def test_the_set_note_gives_every_slot_the_configured_word_ranges() -> None:
    """Risk statements ran short in sets (11 of 13 under 80 words, 30 Oct): the set note, the prompt's last
    words, repeats each statement's range from the settings (the evidence sentence is code's: none asked)."""
    note = build_writer_system_prompt().rpartition("SET OF SCENARIOS")[2]
    settings = get_settings()
    for field, (least, most) in (
        ("scenario_statement", settings.scenario_words),
        ("risk_statement", settings.risk_words),
    ):
        assert f"{field} {least} to {most}" in note
    assert "evidence_statement" not in note and "evidence_step" not in note


def test_the_asset_and_its_affected_systems_form_one_whole() -> None:
    """Owner, D49: the asset and the systems the threat reaches are one whole, so they may work together;
    the "no joining" rule and the link check are gone, unreached systems stay out."""
    writer = WRITER_SYSTEM_PROMPT
    whole = 'The asset and its "yes" systems form one whole: they may work together where the event needs'
    assert whole in writer and 'or through another "yes" system' in writer
    assert "Name only supplied systems, exactly as given." in writer  # once, no longer also in rule 13
    assert "goes in assumptions (rule 2)" in writer
    assert 'A "no" system must not be described as attacked or directly affected.' in writer  # unreached
    for removed in (
        "Each system's access is its own",
        "Do not invent connections",
        "cross-system",
        "independent",
    ):
        assert removed not in writer
    assert "link_check" not in PROMPTS["scenario"]


def test_the_risk_opens_in_everyday_words_for_each_category() -> None:
    """Each category keeps one fixed opening, in words anyone can read; no formal opening is left."""
    shapes = WRITER_SYSTEM_PROMPT.split("11. CATEGORY SHAPES")[1].split("12. SYSTEM REASONS")[0]
    for opening in (
        '"People could no longer be sure that ..."',
        '"People could no longer trust ..."',
        '"No one could reliably tell who ..."',
        '"Sensitive information in ... could be exposed to ..."',
        '"could stop working or slow down"',
        '"Someone could gain privileges in ... that they were never given"',
    ):
        assert opening in shapes
    formal = (
        "Loss of assurance",
        "Loss of trust in",
        "Loss of accountability",
        "Exposure of",
        "Loss of control",
    )
    assert [phrase for phrase in formal if phrase in WRITER_SYSTEM_PROMPT] == []


def test_the_brief_never_carries_the_platform_note_of_an_older_record() -> None:
    """A stored relevance reason with the note reaches the writer without it."""
    threat = _plan_threat(reason="The SCADA server takes firmware, assumes X - not recorded in the platform.")
    assert (
        _brief_of(threat).facts["threat"]["why_it_applies"] == "The SCADA server takes firmware, assumes X."
    )


def test_the_writer_carries_the_threats_actions_and_no_split_prompt_is_left() -> None:
    """The writer carries out each listed action (the threat check's) in step 3; without the list (a plan
    made before the threat check gave them) it splits the name itself."""
    writer = WRITER_SYSTEM_PROMPT
    assert "threat_actions" not in PROMPTS["scenario"]  # no split prompt: no split call
    step3 = "3) Carry out every action in BRIEF.threat.threat_actions (without that list, every action"
    assert f"{step3} of your own split) once, in a realistic order" in writer
    assert "When the list is absent, split the specified threat's name into the actions it states" in writer
    assert "other_scenarios" not in writer and "described in rule 10" in writer and "12. SYSTEM" in writer


def _path_writer(chat: FakeChatModel, threat: dict[str, Any]) -> PathWriter:
    """One delivery's writer for a run planning `threat`, every library record still active."""
    run = {"_id": "r1", "context": CONTEXT.to_record(), "plan": {"threats": [threat]}}
    active = SimpleNamespace(catalogue_id=297, type_id=1)
    library = SimpleNamespace(threats=[active], actors=[SimpleNamespace(actor_id=7)])
    return PathWriter(run, chat, library, WriterStyle.ORIGINAL)  # type: ignore[arg-type]


def _sent_threats(chat: FakeChatModel) -> list[dict[str, Any]]:
    """The threat of every slot's BRIEF the writer was sent."""
    blocks = [block for prompt in chat.asked(AiTask.WRITE_SCENARIO) for _, block in slot_blocks(prompt)]
    return [dict(brief_of(block)["threat"]) for block in blocks]


def _path(threat: dict[str, Any], path_id: str = "p1") -> dict[str, Any]:
    return {
        "path_id": path_id,
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    }


def test_the_threat_checks_actions_reach_the_brief_with_no_split_call() -> None:
    """The plan's threat actions (the threat check's, systems by name) are the listed actions, without the
    names, of every BRIEF of that threat; the set makes one write, and no threat_actions call."""
    threat = _plan_threat(actions=["altering the SCADA server's setpoints", "hiding the change"])
    listed = ["altering setpoints", "hiding the change"]
    chat = FakeChatModel()
    chat.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    slots = [(f"SC{place}", _path(threat, f"p{place}")) for place in (1, 2)]
    outcomes = dict(_path_writer(chat, threat).write_scenario_set(slots, last_try=False))
    assert [outcome[0].threat_actions for outcome in outcomes.values() if isinstance(outcome, tuple)] == [
        tuple(listed)
    ] * 2
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]
    sent = _sent_threats(chat)
    assert len(sent) == 2 and all(threat["threat_actions"] == listed for threat in sent)


@pytest.mark.parametrize(
    ("name", "actions", "briefed"),
    [
        (  # the Historian is not on the path: no system named, the or-only name's alternatives one item
            "Secrets, API key or service credential theft",
            [
                "steal secrets from SCADA server",
                "steal API keys from the Historian",
                "steal service credentials",
            ],
            ["steal secrets or steal API keys or steal service credentials"],
        ),
        (  # "and" names several acts: each its own item
            "Credential phishing and MFA session theft",
            ["phish credentials from SCADA server", "steal MFA session from Historian"],
            ["phish credentials", "steal MFA session"],
        ),
        ("Log wiping", ["SCADA server", "wipe the logs on the Historian"], ["wipe the logs"]),  # nothing left
        ("Log wiping", ["wipe logs on SCADA server", "wipe logs in Historian", "Wipe  logs"], ["wipe logs"]),
        ("Data encryption", ["encrypt SCADA server"], ["encrypt the system"]),  # the act's object
        (
            "API abuse",
            ["access API of SCADA server without authorization"],
            ["access API without authorization"],
        ),
        ("Data theft", ["steal data from SCADA server and Historian"], ["steal data"]),  # a list of names
        ("Data theft", ["steal data from SCADA server, the Historian"], ["steal data"]),
        ("Data theft", ["steal SCADA server and Historian data"], ["steal data"]),
        ("Code injection", ["inject into the Historian"], ["inject into the system"]),  # a bare verb left
        (
            "Impersonation",
            ["impersonate executive to SCADA server staff"],
            ["impersonate executive to staff"],
        ),
        (
            "Extortion",
            ["extort with Historian data", "extort via the Historian's data"],
            ["extort with data", "extort via data"],
        ),
        (  # an "and" inside a part of the name: left split, so every act is still carried out
            "Command and Control channel or beacon abuse",
            ["open a command channel to SCADA server", "beacon from Historian"],
            ["open a command channel", "beacon from the system"],
        ),
    ],
)
def test_the_briefs_actions_name_no_system_and_an_or_only_names_alternatives_are_one_item(
    name: str, actions: list[str], briefed: list[str]
) -> None:
    """The writer carries out every listed action and names no system the path is not on; an or-only name
    is one of its alternatives."""
    assert list(_brief_of(_plan_threat(name=name, actions=actions)).threat_actions) == briefed


def test_a_system_name_inside_another_is_taken_out_with_it() -> None:
    """Review, 30 Oct: "Historian" inside "Plant Historian" was cut first, leaving "wipe logs on Plant"."""
    context = dataclasses.replace(CONTEXT, systems=[{"name": "Historian"}, {"name": "Plant Historian"}])
    threat = {"name": "Log wiping", "actions": ["wipe logs on Plant Historian"]}
    assert _remove_system_names_from_actions(threat, context) == ("wipe logs",)


def test_an_old_plan_sends_no_actions_and_makes_no_split_call() -> None:
    """A plan made before the threat check gave actions sends none: the writer splits the name itself (its
    prompt says how), with no AI call of its own, and the scenario is written."""
    threat = _plan_threat()
    threat.pop("actions", None)  # stored before the threat check gave actions
    chat = _chat_answering([draft_answer(_CLEAN)])
    ((_, outcome),) = _path_writer(chat, threat).write_scenario_set([("SC1", _path(threat))], last_try=False)
    assert isinstance(outcome, tuple) and outcome[0].threat_actions == ()
    assert outcome[1].draft == _READ and not outcome[1].list_blocking_codes()
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]
    assert [sorted(threat) for threat in _sent_threats(chat)] == [["threat", "threat_type", "why_it_applies"]]


def test_no_writer_prompt_carries_a_database_id() -> None:
    """Names only reach the AI: no catalogue, type, system, actor, asset or path id, no threat key, no id
    field, in the write or the rewrite of a set."""
    threat = _plan_threat(systems=(321, 322), actions=["pushing firmware"])
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, {"scenario_title": "x"})  # unreadable: the rewrite is sent too
    chat.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    slots = [(f"SC{place}", _path(threat, f"path-{place}")) for place in (1, 2)]
    list(_path_writer(chat, threat).write_scenario_set(slots, last_try=False))
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    for _, prompt in chat.calls:
        found = re.findall(r'\b(?:297|321|322|103|86)\b|"id"|lib:297|path-\d|\br1\b', prompt)
        assert found == [], found


def test_a_made_up_label_blocks_and_with_intelligence_off_any_advisory_id_does() -> None:
    """A label the brief gives is supplied; an advisory id from the asset's own facts blocks while off."""
    brief = _brief_of(_plan_threat())
    assert _apply_safety_checks(brief, _CLEAN).findings == ()
    made_up = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " SYS7 and CVE-2025-0001 help.")
    assert [finding.code for finding in _apply_safety_checks(brief, made_up).findings] == [
        FindingCode.UNKNOWN_ID,
        FindingCode.UNCITED_ADVISORY_ID,
    ]
    system = brief.systems[0] | {"name": "MicroSCADA Pro SYS600"}
    asset = brief.asset | {"description": "Patched against CVE-2024-1234 last spring."}
    given = as_json({"asset": asset, "systems": [system]} | brief.facts).casefold()
    supplied = dataclasses.replace(brief, systems=(system,), asset=asset, brief_text=given)
    told = dataclasses.replace(
        _CLEAN, statement="A cybercriminal could use CVE-2024-1234 on the MicroSCADA Pro SYS600."
    )
    (advisory,) = _apply_safety_checks(supplied, told).findings
    assert advisory.code == FindingCode.UNCITED_ADVISORY_ID and "CVE-2024-1234" in advisory.message
    story = dataclasses.replace(supplied, cited_index=0)  # an evidence story cites its entry 0
    assert _apply_safety_checks(story, told).findings == ()


def test_a_clean_draft_is_kept_after_one_call() -> None:
    chat = _chat_answering([draft_answer(_CLEAN)])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert written.draft == _READ and written.findings == ()
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]


def test_an_unreadable_answer_is_asked_once_more_and_twice_fails_the_scenario() -> None:
    no_risk = {key: value for key, value in draft_answer(_CLEAN).items() if key != "risk_statement"}
    elsewhere = draft_answer(_CLEAN) | {"entry_point": "scada  SERVER"}  # an offered option, any spelling
    chat = _chat_answering([no_risk, elsewhere])
    assert write_scenario(chat, _brief_of(_plan_threat())).draft == _READ
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert (
        "REJECTED: the earlier answer for this slot had these problems: the reply: risk_statement"
        in (chat.asked(AiTask.REPAIR_SCENARIO)[0])
    )
    chat = _chat_answering([{"title": "x"}, {"title": "y"}])
    failed = _failure_of(chat, _brief_of(_plan_threat()))
    assert failed.code == ErrorCode.GENERATION_FAILED and "repair_scenario" in failed.message
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]


def test_an_asset_level_threat_has_no_entry_point_whatever_was_written() -> None:
    chat = _chat_answering([draft_answer(_CLEAN) | {"entry_point": "Grid Control Centre"}])
    assert write_scenario(chat, _brief_of(_plan_threat(systems=()))).draft.entry_point == ""


def test_a_draft_the_exact_checks_block_is_kept_blocked_with_no_other_call() -> None:
    labelled = draft_answer(_CLEAN) | {"scenario_statement": _CLEAN.statement + " SYS7 helps."}
    chat = _chat_answering([labelled])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert [finding.code for finding in written.findings] == [FindingCode.UNKNOWN_ID]
    assert written.find_blocking_code() not in FINAL_FINDINGS
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]


@pytest.mark.parametrize(
    ("given", "scada_reason"),
    [
        (
            {"scada  SERVER": "It could stop the server.", "Historian": "Its records stay."},
            "It could stop the server.",
        ),
        ({}, _CLEAN.statement),
    ],
    ids=["no_system_reason_given_anyway", "yes_system_reason_missing"],
)
def test_every_supporting_system_gets_its_reason_without_a_rewrite(
    given: dict[str, str], scada_reason: str
) -> None:
    """D66: a "no" system's reason is code's, even over one the writer gave; a "yes" system given none takes
    the story's sentence naming it; a name matches case and spacing forgiven. Neither costs a rewrite, and
    the card serves one justification per system."""
    chat = _chat_answering([draft_answer(_CLEAN) | {"system_reasons": given}])
    brief = _brief_of(_plan_threat())
    written = write_scenario(chat, brief)
    reasons = (("SCADA server", scada_reason), ("Historian", Writing.NOT_REACHED_REASON))
    assert written.draft.system_reasons == reasons
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {"path_id": "p1", "category": "Tampering", "categories": ["Tampering"], "systems": [321]}
    view = build_scenario_view(build_scenario_card(run, path, _plan_threat(), brief, written))
    served = [(s.supporting_system, s.justification) for s in view.scenario.supporting_systems_involved]
    assert served == list(reasons)


_ACTIONS = ("pushing firmware", "hiding the change")


def _listed_brief() -> Any:
    return dataclasses.replace(_brief_of(_plan_threat()), threat_actions=_ACTIONS)


_PUSH = _CLEAN.statement  # sentence 1: the attacker pushes the firmware
_HIDE = "They could then hide the change."  # sentence 2
_COMPLETE = draft_answer(_CLEAN) | {
    "scenario_statement": f"{_PUSH} {_HIDE}",
    "action_sentences": {"pushing firmware": 1, "Hiding the  CHANGE": 2},  # case and spacing forgiven
}
_HIDE_MISSING = AnswerProblem.ACTION_SENTENCES_MISSING.format(actions='"hiding the change"')


@pytest.mark.parametrize(
    "numbers",
    [
        {"pushing firmware": 1, "hiding the change": 2},
        {"Pushing  Firmware": "1", "hiding the change": " 2 "},  # a numeric string
        {"pushing firmware": 2, "hiding the change": 2},  # one sentence may carry both
        {"pushing firmware": [1], "hiding the change": [2, 5]},  # review, 30 Oct: a merged act's sentences
        {"pushing firmware": "1-2", "hiding the change": 2.0},
    ],
)
def test_a_sentence_number_within_the_story_passes(numbers: dict[str, Any]) -> None:
    """D67: each listed act points at a sentence of its own scenario_statement by number."""
    answer = {"scenario_statement": f"{_PUSH} {_HIDE}", "action_sentences": numbers}
    assert _find_actions_missing_from_story(answer, _ACTIONS) == []


@pytest.mark.parametrize(
    "number", [None, 0, 3, -1, "3", "", "the second", 1.5, True, [[2]], float("nan"), float("inf")]
)
def test_a_missing_or_out_of_range_sentence_number_is_the_fault(number: Any) -> None:
    """D67: a missing key, or a number that is no sentence of the story (counted from 1), names the act."""
    numbers = {"pushing firmware": 1} | ({} if number is None else {"hiding the change": number})
    answer = {"scenario_statement": f"{_PUSH} {_HIDE}", "action_sentences": numbers}
    assert _find_actions_missing_from_story(answer, _ACTIONS) == [_HIDE_MISSING]
    assert _find_actions_missing_from_story(answer, ()) == []  # a brief with no listed action reads no number


@pytest.mark.parametrize(
    "sentences",
    [
        {"pushing firmware": 1},  # no number for one action
        {"pushing firmware": 1, "hiding the change": 2},  # past the end of a one-sentence story
        {"pushing firmware": 1, "hiding the change": 0},
        "every action is in the story",  # not a number per action
    ],
)
def test_a_draft_that_shows_no_story_sentence_for_a_listed_action_is_asked_again(sentences: Any) -> None:
    """Root cause of an act left only named: the writer must point at the story sentence where the attacker
    does each listed act, and code checks the number is a sentence of scenario_statement."""
    first = draft_answer(_CLEAN) | {"action_sentences": sentences}
    chat = _chat_answering([first, _COMPLETE])
    written = write_scenario(chat, _listed_brief())
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert written.draft.statement == _COMPLETE["scenario_statement"] and written.findings == ()


def test_the_rewrite_is_told_the_action_with_no_sentence_number() -> None:
    """D67: the round-2 note names the listed act whose number is past the story's end."""
    first = draft_answer(_CLEAN) | {"action_sentences": {"pushing firmware": 1, "hiding the change": 2}}
    chat = _chat_answering([first, _COMPLETE])
    write_scenario(chat, _listed_brief())
    (rewrite,) = chat.asked(AiTask.REPAIR_SCENARIO)
    assert _HIDE_MISSING in rewrite.split("REJECTED:")[1]


def test_a_long_problem_is_cut_at_a_word_in_the_rewrite_note() -> None:
    """Each problem the rewrite is told is cut at a word to the re-ask limit."""
    acts = tuple(f"action number {number} with a long name" for number in range(12))
    brief = dataclasses.replace(_brief_of(_plan_threat()), threat_actions=acts)
    chat = _chat_answering([draft_answer(_CLEAN) | {"action_sentences": {}}, draft_answer(_CLEAN)])
    write_scenario(chat, brief)
    (rewrite,) = chat.asked(AiTask.REPAIR_SCENARIO)
    problem = AnswerProblem.ACTION_SENTENCES_MISSING.format(actions=", ".join(json.dumps(a) for a in acts))
    assert len(problem) > AiLimits.REASK_PROBLEM_CHARS
    told = rewrite.split("REJECTED:")[1]
    assert problem[: AiLimits.REASK_PROBLEM_CHARS].rsplit(" ", 1)[0] in told and problem not in told


def test_a_draft_with_a_story_sentence_per_action_or_no_list_is_asked_once() -> None:
    """A second answer still missing a sentence is kept, never a failure."""
    chat = _chat_answering([_COMPLETE])
    write_scenario(chat, _listed_brief())
    no_list = _chat_answering([draft_answer(_CLEAN) | {"action_sentences": {}}])
    write_scenario(no_list, _brief_of(_plan_threat()))
    assert _calls(chat) == _calls(no_list) == [AiTask.WRITE_SCENARIO]
    still = draft_answer(_CLEAN) | {"action_sentences": {"pushing firmware": 1}}
    twice = _chat_answering([still, still])
    assert write_scenario(twice, _listed_brief()).draft.statement == _CLEAN.statement
    assert _calls(twice) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    rewrite_failed = _chat_answering([still, {"title": "x"}])  # its first draft is kept
    assert write_scenario(rewrite_failed, _listed_brief()).draft.statement == _CLEAN.statement


def test_the_writer_gives_each_action_s_story_sentence_number() -> None:
    """The writer's eighth field: a sentence number, never a copied quote; an act on the asset as a whole
    still gets a story sentence of its own (said once, in the schema, since the final check no longer
    repeats it)."""
    writer = WRITER_SYSTEM_PROMPT
    assert '{"<each item of BRIEF.threat.threat_actions, copied>": <sentence number>}' in writer
    assert "Include exactly these eight top-level fields" in writer
    assert "its value is the number (the first is 1) of the sentence of scenario_statement" in writer
    assert "of the sentence of scenario_statement that shows the attacker doing that action" in writer
    assert "still gets its own sentence in scenario_statement, never only in risk_statement" in writer
    assert "word for word" not in writer


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


def _saved_titles(title: str, qualifier: str, taken: int) -> list[str]:
    """The titles a save tries, the first `taken` of them already taken."""
    tried: list[str] = []

    def save(record: dict[str, Any]) -> bool:
        tried.append(record["content"]["title"])
        assert record["title_key"] == name_match_key(record["content"]["title"])
        if len(tried) <= taken:
            raise TitleTaken
        return True

    record = {"content": {"title": title}}
    assert save_with_unique_title(SimpleNamespace(save_scenario=save), record, qualifier)  # type: ignore[arg-type]
    return tried


def test_a_clashing_title_takes_the_threat_name_then_a_number() -> None:
    assert _saved_titles("Loss of control", "Firmware update", taken=2) == [
        "Loss of control",
        "Loss of control (Firmware update)",
        "Loss of control (2)",
    ]
    assert _saved_titles("Firmware update", "firmware UPDATE", taken=1) == [
        "Firmware update",
        "Firmware update (2)",
    ]


def test_a_saved_scenario_reads_back_through_the_api_view() -> None:
    """What the job stores is what the API shows: the texts, the attackers, every system with its reason,
    the route, and validation from the findings."""
    brief = _brief_of(_plan_threat())
    written = WrittenScenario(_READ, ())
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    path = {
        "path_id": "p1",
        "category": "Tampering",
        "categories": ["Tampering"],
        "rank": 3,
        "systems": [321],
    }
    record = build_scenario_card(run, path, _plan_threat(), brief, written)
    view = build_scenario_view(record)
    text = view.scenario
    assert record["_id"] == build_scenario_id("run-1", "p1", 1) and view.status == ScenarioStatus.DONE
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
    assert view.validation_status == ValidationStatus.OK and view.validation_notes == []
    assert view.threat.threat_name == "Unauthorised firmware update" and view.threat.scope_rank == 3
    assert (view.controls_status, record["rewritten"], view.evidence) == ("queued", False, [])
    assert record["plan_check"] == {
        "status": "unchecked", "problems": [], "unsupported": [], "same_threat": None, "same_impact": None,
    }  # fmt: skip


def test_the_card_keeps_each_systems_recorded_name_and_one_entry_point() -> None:
    """Two systems redacted alike in the prompt are told apart by their place in the brief."""
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    threat = _plan_threat(systems=(321, 322))
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": threat["systems"]}
    brief = build_writer_input({threat["key"]: threat}, path, context, 30_000, _LIVE)
    assert brief.entry_options == ("[REDACTED]", "[REDACTED]")
    draft = dataclasses.replace(_CLEAN, entry_point=brief.entry_options[0])
    written = WrittenScenario(draft, ())
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": context.to_record()}
    assert build_scenario_card(run, path, threat, brief, written)["content"]["systems"] == [
        {"id": 321, "name": "scada01.plant.local", "entry_point": True},
        {"id": 322, "name": "hist01.plant.local", "entry_point": False},
    ]


def test_the_writer_gets_in_through_its_turns_system_and_the_card_marks_that_one() -> None:
    """A path whose turn is the Historian's offers only the Historian as the way in: a reply naming the SCADA
    server is never asked again (D66: code assigns the way in), and the card marks the Historian, though it
    is the path's second system, even when the two names are redacted alike. A plan made before paths took
    turns offers any of its systems."""
    threat = _plan_threat(systems=(321, 322))
    brief = _brief_of(threat, entry_system=322)
    assert brief.entry_options == ("Historian",)
    chat = _chat_answering([draft_answer(_CLEAN)])
    written = write_scenario(chat, brief)
    assert written.draft.entry_point == "Historian"
    assert _calls(chat) == [AiTask.WRITE_SCENARIO]
    path = {"path_id": "p1", "steps": [threat["key"]], "category": "Tampering", "systems": [321, 322]}
    run = {"_id": "run-1", "entity_id": 86, "asset_id": 103, "context": CONTEXT.to_record()}
    assert build_scenario_card(run, path | {"entry_system": 322}, threat, brief, written)["content"][
        "systems"
    ] == [
        {"id": 321, "name": "SCADA server", "entry_point": False},
        {"id": 322, "name": "Historian", "entry_point": True},
    ]
    hosts = [system_row(321, "SYS1", "scada01.plant.local"), system_row(322, "SYS2", "hist01.plant.local")]
    context = dataclasses.replace(CONTEXT, systems=hosts)
    alike = build_writer_input({threat["key"]: threat}, path | {"entry_system": 322}, context, 30_000, _LIVE)
    assert alike.entry_options == ("[REDACTED]",)
    draft = dataclasses.replace(_CLEAN, entry_point="[REDACTED]")
    record = build_scenario_card(
        run | {"context": context.to_record()},
        path | {"entry_system": 322},
        threat,
        alike,
        WrittenScenario(draft, ()),
    )
    assert [system["entry_point"] for system in record["content"]["systems"]] == [False, True]
    assert _brief_of(threat).entry_options == ("SCADA server", "Historian")


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
    card = build_failure_card(
        {"_id": "r", "entity_id": 86, "asset_id": 103}, path, threat, PathFailure(ErrorCode.INVALID_PLAN, "m")
    )
    assert card["status"] == ScenarioStatus.FAILED and card["content"]["threat"]["name"] == ""
    assert card["content"]["actors"] == [] and card["failure"] == {
        "code": ErrorCode.INVALID_PLAN,
        "message": "m",
    }
