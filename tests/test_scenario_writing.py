"""Scenario writing (Step 12): the brief, the owner's prompts, the exact safety checks, the reviewer, and
what is stored and shown. Fake AI models, no network."""

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
from structlog.testing import capture_logs

from app import container
from app.core.config import get_settings
from app.core.constants import (
    CHAT_TEMPERATURES,
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    ActorRole,
    AiTask,
    AnswerProblem,
    Collection,
    Decision,
    ErrorCode,
    FindingCode,
    FindingSeverity,
    LogEvent,
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
    _PASSAGE,
    _PASSAGE_ABOUT,
    PLAN_CHECK_SET_PROMPT,
    PLAN_CHECK_SYSTEM_PROMPT,
    WRITER_SYSTEM_PROMPT,
    _acts_without_a_sentence,
    _without_system_names,
    brief_entry_point_options,
    build_brief,
    check_exact_rules,
    draft_answer,
    failure_record,
    finding_record,
    finding_severity,
    is_blocked,
    is_final,
    plan_check_record,
    plan_check_slot,
    scenario_id,
    slot_label,
    title_candidates,
    with_word_limits,
    write_set,
    writer_slot,
    writer_system_prompt,
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
from tests.fakes import FakeChatModel, brief_of, slot_blocks, truncated
from tests.planner_samples import CONTEXT, planned, system_row

#: Everything the sample threats name is still active in the library.
_LIVE = LiveLibrary(frozenset({297}), frozenset({1}), frozenset({7, 8}))
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


def write_scenario(chat: FakeChatModel, brief: Any) -> WrittenScenario:
    """One brief written as a set of one: its scenario (a batch of one is a batch)."""
    ((_, written),) = write_set(chat, [("SC1", brief)])  # type: ignore[arg-type]
    assert isinstance(written, WrittenScenario), written
    return written


def _failure_of(chat: FakeChatModel, brief: Any) -> PathFailure:
    """One brief written as a set of one, its slot failing."""
    ((_, failed),) = write_set(chat, [("SC1", brief)])  # type: ignore[arg-type]
    assert isinstance(failed, PathFailure), failed
    return failed


def check_against_plan(chat: FakeChatModel, brief: Any, draft: ScenarioDraft) -> tuple[PlanCheck, Any]:
    """The review of `draft` for `brief`, as a set of one writes it: its check and its findings."""
    chat.queued[AiTask.WRITE_SCENARIO].insert(0, draft_answer(draft))
    written = write_scenario(chat, brief)
    return written.plan_check, written.findings


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
    """The owner's text files, the configured word limits in their slots, each slot's own line saying no
    evidence is given while intelligence is off; the reviewer's PLAN is the brief plus the critical
    service."""
    brief = _brief_of(_plan_threat())
    system, slot = writer_system_prompt(), writer_slot("SC1", brief)
    assert system.startswith(with_word_limits(WRITER_SYSTEM_PROMPT)) and "No EVIDENCE is given" not in system
    assert "<scenario words>" not in system and slot.startswith("SLOT SC1\nBRIEF:\n")
    no_evidence = (
        'No EVIDENCE is given for this slot: cite nothing, tell no real-world event and return "evid'
    )
    assert no_evidence in slot.splitlines()[-1]
    assert brief_of(slot)["supporting_systems"] == [
        {"name": "SCADA server", "applicable": "yes"},
        {"name": "Historian", "applicable": "no"},
    ]
    review = plan_check_slot("SC1", brief, _CLEAN)
    plan_text, scenario_text = review.removeprefix("SLOT SC1\nPLAN:\n").split("\nSCENARIO:\n")
    plan, rest = json.JSONDecoder().raw_decode(plan_text)
    assert json.loads(scenario_text) == draft_answer(_CLEAN)
    assert plan["critical_service"] == "Electricity transmission"
    assert plan_text[rest:].strip().startswith("No EVIDENCE is given for this slot: any [n] marker")
    assert (
        PLAN_CHECK_SET_PROMPT.startswith(PLAN_CHECK_SYSTEM_PROMPT)
        and "No EVIDENCE" not in PLAN_CHECK_SET_PROMPT
    )
    assert CHAT_TEMPERATURES[AiTask.PLAN_CHECK] == 0.0


def test_the_impact_comes_from_the_threats_own_action_and_no_prompt_names_the_platform_note() -> None:
    """Every prompt bans an added step and asks why, not how; none names the note code adds to assumptions."""
    gate = relevance_gate_prompt("LANDSCAPE", [{"slot": "R1"}])[1]
    gap = gap_fill_prompt("LANDSCAPE", [(StrideCategory.TAMPERING, 3, ())])[1]
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
    plain = writer.split("13. CLEAR, BALANCED LANGUAGE")[1].split("GENERATOR FINAL CHECK")[0]  # both readers
    assert "writes for security staff and for operators, managers and auditors who are not security" in writer
    assert "Short sentences, about 20 words at most" in plain and "Mix plain sentences with" in plain
    assert "Keep the precise security or technical term where it names the act" in plain  # not too simple
    assert '"exfiltrate (copy out) the records"' in plain and 'not "Someone could make the tank' in plain
    assert '"break into" or "take over", not "compromise"' not in plain  # no blanket swap of precise terms
    assert "each part its own short sentence" in writer and "one or two short sentences" in writer
    assert "Write in clear, balanced language (rule 13)" in writer and "- Clear, balanced language:" in writer
    assert "the category's loss (rule 11)" in plain and "locks" not in plain  # clear words keep the category
    assert "in any words (judge the meaning, not the list's wording" in reviewer
    assert "or only named, not carried out as the attacker's action" in reviewer  # a rule 1 note
    stated = "the threat's name does not state"  # a use or objective the name states is the threat's own
    assert f"an objective {stated}" in writer and f"exposed information/access that {stated}" in writer
    assert f"later uses of access or information {stated}" in writer
    assert "an action, use or demand the threat's name states is part of the threat" in reviewer
    assert f"gained access/information that {stated}" in reviewer
    repair = PROMPTS["scenario"]["writer"]["repair"]  # code fills {actions} with the actions not carried out
    assert "these listed actions (BRIEF.threat.threat_actions) were not carried out: {actions}." in repair
    assert "each one is carried out as the attacker's action, in your own words" in repair
    assert "keep every other rule" in repair
    named = ("ransomware", "data theft extortion", "ddos", "wiper", "phishing and mfa")  # no library threat
    prompts = (gate, gap, writer, reviewer, repair)
    assert [n for n in named for prompt in prompts if n in prompt.casefold()] == []
    assert "Using access the threat only obtains (a stolen credential, secret or session)" in reviewer
    assert "including using access the threat only obtains" in reviewer
    # Owner 2026-10-28: the evidence passage closes the story with one link to its action, no stock opener.
    assert "In real-world attacks" not in writer and 'Never write "real-world"' in writer
    assert "End with at" not in writer and "ONE complete sentence" in writer
    # D60: it opens on the story's own step, on its named system, linked in words chosen for this sentence
    opening = "Open the sentence by referring back to the one step of this story that the cited entry is"
    assert opening in writer and "the system or asset where it happens, by name" in writer
    assert "Then link that step to the cited entry in linking words chosen for this sentence." in writer
    assert 'and say it is related when evidence_mode is "nearest"' in writer
    assert 'called "the related technique"' not in writer and "where it reads best in the sentence" in writer
    assert "Never name it in scenario_statement: explain its exclusion only in system_reasons" in writer
    assert "End scenario_statement on this consequence." in writer
    assert 'No "no" system named in scenario_statement' in writer
    assert "links that step to the entry in words no other slot uses" in writer
    # review, 30 Oct: "with the system ..." inside "true ONLY if" read as a requirement, so a step on the
    # asset or a system named a little differently would lose its sentence; the system may be named
    assert "(it may name the system or asset it acts on, as the story names them)" in reviewer
    assert 'never with "The attacker" or "This"' in writer  # owner 2026-10-28: 11 of 26 opened alike
    assert "The story may describe the attacker's steps in the cited entry's terms" in writer
    assert "Do not reshape the specified threat" not in writer  # owner 2026-10-28: it may fit the evidence
    assert (
        "plus exactly one link, at the passage's start, from an action `scenario_statement` tells" in reviewer
    )
    assert "false for a passage that does not open with such an action" in reviewer
    assert "a named user presented as this scenario's attacker" in reviewer
    assert 'List an essential missing detail in assumptions as: "assumes <specific condition>".' in writer
    assert "the primary impact comes from an added step that is not part of the threat" in reviewer
    assert "every action its name states is its own" in gate
    assert [prompt for prompt in (gate, gap, writer, reviewer) if "recorded in the platform" in prompt] == []
    assert "why_applies" not in writer and "why_applies" not in reviewer and '"9"' not in reviewer


def test_the_writer_and_reviewer_prompts_stay_within_their_size_limits() -> None:
    """The customer's 25,000 tokens a minute: D60's wording grew each system prompt by under 1% (writer
    21,434 and reviewer 8,675 characters before it). Each story slot's evidence line is sent once per slot in
    every write and rewrite, so it is bounded too (review, 30 Oct: it had grown from 194 to 310). The set
    note's word-range sentence added 160 (owner, 30 Oct: longer is fine without a material token cost)."""
    assert len(writer_system_prompt()) <= 21_850 and len(PLAN_CHECK_SYSTEM_PROMPT) <= 8_760
    assert len(_PASSAGE) <= 275 and len(_PASSAGE_ABOUT) <= 205


def test_the_set_note_gives_every_slot_the_configured_word_ranges() -> None:
    """Risk statements ran short in sets (11 of 13 under 80 words, 30 Oct): the set note, the prompt's last
    words, repeats each statement's range from the settings."""
    note = writer_system_prompt().rpartition("SET OF SCENARIOS")[2]
    settings = get_settings()
    for field, (least, most) in (
        ("scenario_statement", settings.scenario_words),
        ("risk_statement", settings.risk_words),
        ("evidence_statement", settings.evidence_words),
    ):
        assert f"{field} {least} to {most}" in note


def test_the_asset_and_its_affected_systems_form_one_whole() -> None:
    """Owner, D49: the asset and the systems the threat reaches are one whole, so they may work together;
    the "no joining" rule, its reviewer rule 4 and the link check are gone, unreached systems stay out."""
    writer, reviewer = WRITER_SYSTEM_PROMPT, PLAN_CHECK_SYSTEM_PROMPT
    whole = 'The asset and its "yes" systems form one whole: they may work together where the event needs'
    assert whole in writer and 'or through another "yes" system' in writer
    assert "goes in assumptions (rule 2)" in writer
    assert 'A "no" system must not be described as attacked or directly affected.' in writer  # unreached
    for removed in (
        "Each system's access is its own",
        "Do not invent connections",
        "cross-system",
        "independent",
    ):
        assert removed not in writer
    assert "RULE 4" not in reviewer and '"4": "holds"' not in reviewer and "Rule 4 violation" not in reviewer
    assert "Check all seven rules (1-3 and 5-8) independently." in reviewer and "eight" not in reviewer
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
    assert _brief_of(threat).why_it_applies == "The SCADA server takes firmware, assumes X."


def test_both_prompts_carry_the_threats_actions_and_no_split_prompt_is_left() -> None:
    """The writer carries out each listed action (the threat check's) in step 3 and the reviewer answers for
    each; without the list (a plan made before the threat check gave them) each splits the name itself."""
    writer, reviewer = WRITER_SYSTEM_PROMPT, PLAN_CHECK_SYSTEM_PROMPT
    assert "threat_actions" not in PROMPTS["scenario"]  # no split prompt: no split call
    step3 = "3) Carry out every action in BRIEF.threat.threat_actions (without that list, every action"
    assert f"{step3} of your own split) once, in a realistic order" in writer
    assert "When the list is absent, split the specified threat's name into the actions it states" in writer
    field = '"threat_actions": {"<each item of PLAN.threat.threat_actions, copied>": "carried out" | "only'
    assert field in reviewer and "For each item of PLAN.threat.threat_actions answer in `threat_" in reviewer
    assert 'wording; of alternatives an item joins with "or", one is enough)' in reviewer
    assert "Without that list, answer {} and split PLAN's threat name" in reviewer
    assert "`threat_actions` has one answer for each item of PLAN.threat.threat_actions" in reviewer
    assert "other_scenarios" not in writer and "described in rule 10" in writer and "12. SYSTEM" in writer


def _path_writer(chat: FakeChatModel, threat: dict[str, Any]) -> PathWriter:
    """One delivery's writer for a run planning `threat`, every library record still active."""
    run = {"_id": "r1", "context": CONTEXT.to_record(), "plan": {"threats": [threat]}}
    active = SimpleNamespace(catalogue_id=297, type_id=1)
    library = SimpleNamespace(threats=[active], actors=[SimpleNamespace(actor_id=7)])
    return PathWriter(run, chat, library, WriterStyle.ORIGINAL)  # type: ignore[arg-type]


def _sent_threats(chat: FakeChatModel) -> list[dict[str, Any]]:
    """The threat of every slot's BRIEF and PLAN the writer and the reviewer were sent."""
    prompts = [*chat.asked(AiTask.WRITE_SCENARIO), *chat.asked(AiTask.PLAN_CHECK)]
    blocks = [block for prompt in prompts for _, block in slot_blocks(prompt)]
    return [dict(json.JSONDecoder().raw_decode(block.split(":\n", 1)[1])[0]["threat"]) for block in blocks]


def _path(threat: dict[str, Any], path_id: str = "p1") -> dict[str, Any]:
    return {
        "path_id": path_id,
        "steps": [threat["key"]],
        "category": "Tampering",
        "systems": threat["systems"],
    }


def test_the_threat_checks_actions_reach_the_brief_and_the_review_with_no_split_call() -> None:
    """The plan's threat actions (the threat check's, systems by name) are the listed actions, without the
    names, of every BRIEF and PLAN of that threat; the set makes one write and one review, and no
    threat_actions call."""
    threat = _plan_threat(actions=["altering the SCADA server's setpoints", "hiding the change"])
    listed = ["altering setpoints", "hiding the change"]
    chat = FakeChatModel()
    done = {"threat_actions": dict.fromkeys(listed, "carried out")}
    chat.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN),
        AiTask.PLAN_CHECK: lambda _: _CONSISTENT | done,
    }
    slots = [(slot_label(place), _path(threat, f"p{place}")) for place in (1, 2)]
    outcomes = dict(_path_writer(chat, threat).write_set(slots, last_try=False))
    assert [outcome[0].threat_actions for outcome in outcomes.values() if isinstance(outcome, tuple)] == [
        tuple(listed)
    ] * 2
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    sent = _sent_threats(chat)
    assert len(sent) == 4 and all(threat["threat_actions"] == listed for threat in sent)


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
    """The writer carries out every listed action and names no system the path is not on, and the reviewer
    reads an or-only name as one of its alternatives: the brief's actions agree with both."""
    assert list(_brief_of(_plan_threat(name=name, actions=actions)).threat_actions) == briefed


def test_a_system_name_inside_another_is_taken_out_with_it() -> None:
    """Review, 30 Oct: "Historian" inside "Plant Historian" was cut first, leaving "wipe logs on Plant"."""
    assert (
        _without_system_names("wipe logs on Plant Historian", ["Historian", "Plant Historian"]) == "wipe logs"
    )


def test_a_merged_actions_quote_may_join_the_sentences_of_its_alternatives() -> None:
    """Live replay, 30 Oct: a merged "steal secrets or steal API keys" item was quoted with both of its
    sentences, which no single sentence of the story matches, and sent 4 slots to a rewrite."""
    first = "The attacker could steal secrets from the platform's vault."
    second = "The attacker could then steal API keys from its integration scripts."
    story = f"An insider could log in. {first} Alarms could stay quiet. {second} Operators could lose trust."
    action = "steal secrets or steal API keys"
    for quote in (f"{first} {second}", f"{first} ... {second}", f"{first}… {second}"):
        answer = {"scenario_statement": story, "action_sentences": {action: quote}}
        assert _acts_without_a_sentence(answer, (action,)) == []
    elsewhere = {"scenario_statement": story, "action_sentences": {action: f"{first} They sold them."}}
    assert _acts_without_a_sentence(elsewhere, (action,)) != []


def test_a_quote_found_whole_from_its_first_could_is_found_though_its_first_sentence_is_short() -> None:
    """Review, 30 Oct: looking up each sentence alone refused a quote whose short first sentence had a
    reworded opening, which the whole quote's check had found."""
    story = "A nation-state actor could then disrupt signals. Next it could flood the link with packets."
    quote = "The attacker could disrupt signals. Next it could flood the link with packets."
    answer = {"scenario_statement": story, "action_sentences": {"flood the link": quote}}
    assert _acts_without_a_sentence(answer, ("flood the link",)) == []


def test_an_old_plan_sends_no_actions_and_makes_no_split_call() -> None:
    """D3: a plan made before the threat check gave actions sends none: the writer and the reviewer split the
    name themselves (their prompts say how), with no AI call of their own, and the scenario is written."""
    threat = _plan_threat()
    threat.pop("actions", None)  # stored before the threat check gave actions
    chat = _chat_answering([draft_answer(_CLEAN)], [_CONSISTENT])
    ((_, outcome),) = _path_writer(chat, threat).write_set([("SC1", _path(threat))], last_try=False)
    assert isinstance(outcome, tuple) and outcome[0].threat_actions == ()
    assert outcome[1].draft == _READ and not is_blocked(outcome[1])
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    assert [sorted(threat) for threat in _sent_threats(chat)] == [
        ["threat", "threat_type", "why_it_applies"]
    ] * 2


def test_no_writer_or_reviewer_prompt_carries_a_database_id() -> None:
    """Names only reach the AI: no catalogue, type, system, actor, asset or path id, no threat key, no id
    field, in the write, the rewrite or the review of a set."""
    threat = _plan_threat(systems=(321, 322), actions=["pushing firmware"])
    chat = FakeChatModel()
    chat.queue(AiTask.WRITE_SCENARIO, {"scenario_title": "x"})  # unreadable: the rewrite is sent too
    chat.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN),
        AiTask.PLAN_CHECK: lambda _: _CONSISTENT | {"threat_actions": {"pushing firmware": "carried out"}},
    }
    slots = [(slot_label(place), _path(threat, f"path-{place}")) for place in (1, 2)]
    list(_path_writer(chat, threat).write_set(slots, last_try=False))
    assert _calls(chat) == [
        AiTask.WRITE_SCENARIO,
        AiTask.PLAN_CHECK,
        AiTask.REPAIR_SCENARIO,
        AiTask.PLAN_CHECK,
    ]
    for _, prompt in chat.calls:
        found = re.findall(r'\b(?:297|321|322|103|86)\b|"id"|lib:297|path-\d|\br1\b', prompt)
        assert found == [], found


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
    """_CLEAN reviewed by `answers`; a mismatch's round-2 repair is _CLEAN, judged by the last answer."""
    chat = FakeChatModel()
    chat.queue(AiTask.PLAN_CHECK, *answers, answers[-1])
    chat.queue(AiTask.REPAIR_SCENARIO, draft_answer(_CLEAN))
    return check_against_plan(chat, _brief_of(_plan_threat()), _CLEAN)


def test_every_broken_rule_is_a_note_and_a_changed_threat_is_a_mismatch() -> None:
    """Every "broken" verdict is a note for review; same_threat or same_impact false is the one blocker the
    reviewer gives."""
    assert _plan_checked(_CONSISTENT) == (PlanCheck(PlanCheckStatus.CONSISTENT), ())
    rules = {
        "1": "holds",
        "2": 'broken: "APT28 leads" - a named group attacks',
        "5": "broken - another impact",  # Rule 4's break is checked once more: its own test below
    }
    check, notes = _plan_checked({"rules": rules, "same_threat": True, "same_impact": True})
    assert check.status == PlanCheckStatus.INCONSISTENT
    assert [(note.code, note.message) for note in notes] == [
        (FindingCode.PLAN_CHECK, 'Rule 2: "APT28 leads" - a named group attacks'),
        (FindingCode.PLAN_CHECK, "Rule 5: another impact"),
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
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
    assert (
        "REJECTED: the earlier answer for this slot had these problems: the reply: risk_statement"
        in (chat.asked(AiTask.REPAIR_SCENARIO)[0])
    )
    chat = _chat_answering([{"title": "x"}, {"title": "y"}], [])
    failed = _failure_of(chat, _brief_of(_plan_threat()))
    assert failed.code == ErrorCode.GENERATION_FAILED and "repair_scenario" in failed.message
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]


def test_an_asset_level_threat_has_no_entry_point_whatever_was_written() -> None:
    chat = _chat_answering([draft_answer(_CLEAN) | {"entry_point": "Grid Control Centre"}], [_CONSISTENT])
    assert write_scenario(chat, _brief_of(_plan_threat(systems=()))).draft.entry_point == ""


def test_a_mismatch_is_repaired_once_and_a_repair_still_mismatched_keeps_the_blocked_first() -> None:
    """A mismatch is rewritten once in round 2; a repair still mismatched leaves the first draft blocked and
    not final, so its path is given up for a reserve (the writer's own retry is off)."""
    chat = _chat_answering([draft_answer(_CLEAN), draft_answer(_CLEAN)], [_MISMATCH, _MISMATCH])
    written = write_scenario(chat, _brief_of(_plan_threat()))
    assert is_blocked(written) and not is_final(written) and not written.rewritten
    assert _calls(chat) == _REVIEWED


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
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]


_ACTIONS = ("pushing firmware", "hiding the change")
_ALL_DONE = _CONSISTENT | {"threat_actions": dict.fromkeys(_ACTIONS, "carried out")}
_ONE_MISSING = _CONSISTENT | {"threat_actions": {_ACTIONS[0]: "carried out", _ACTIONS[1]: "missing"}}
_MISSING_ONE_UNJUDGED = _CONSISTENT | {"threat_actions": {_ACTIONS[0]: "carried out"}}
_NAMED_ONE_UNJUDGED = _CONSISTENT | {"threat_actions": {_ACTIONS[0]: "only named"}}  # inconsistent
_ALL_DONE_RULE_5_BROKEN = _ALL_DONE | {"rules": {"1": "holds", "5": 'broken: "x" - y'}}
_MISSING_NOTE = 'Rule 1: "hiding the change" is missing, not carried out'
_REPAIR_TEXT = PROMPTS["scenario"]["writer"]["repair"]
#: The calls of a draft written, reviewed and repaired, with the repair reviewed or not.
_REVIEWED = [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
_NOT_REVIEWED = _REVIEWED[:3]


def _repair_answering(repairs: list[Any], checks: list[Any]) -> FakeChatModel:
    """A writer whose first draft leaves "hiding the change" missing, then answers `repairs` and `checks`."""
    chat = _chat_answering([draft_answer(_CLEAN)], [_ONE_MISSING, *checks])
    chat.queue(AiTask.REPAIR_SCENARIO, *repairs)
    return chat


def _listed_brief() -> Any:
    return dataclasses.replace(_brief_of(_plan_threat()), threat_actions=_ACTIONS)


def test_a_draft_missing_a_listed_action_is_written_once_more_and_a_complete_repair_is_kept() -> None:
    """The repair is the writer's prompt plus the actions not carried out, reviewed like any draft."""
    repaired = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " They could then hide the change.")
    chat = _repair_answering([draft_answer(repaired)], [_ALL_DONE])
    with capture_logs() as logs:
        written = write_scenario(chat, _listed_brief())
    assert _calls(chat) == _REVIEWED
    assert written.draft.statement == repaired.statement and written.findings == () and written.rewritten
    assert written.plan_check == PlanCheck(PlanCheckStatus.CONSISTENT)
    (write,), (repair,) = chat.asked(AiTask.WRITE_SCENARIO), chat.asked(AiTask.REPAIR_SCENARIO)
    assert repair == write + _REPAIR_TEXT.replace("{actions}", '"hiding the change"')
    assert [log["outcome"] for log in logs if log["event"] == LogEvent.WRITER_SCENARIO_REPAIRED] == ["fixed"]


@pytest.mark.parametrize(
    ("repairs", "checks", "calls", "error_type"),
    [
        ([draft_answer(_CLEAN)], [_ONE_MISSING], _REVIEWED, None),  # still missing: no second repair
        ([draft_answer(_CLEAN)], [_NAMED_ONE_UNJUDGED], _REVIEWED, None),
        ([draft_answer(_CLEAN)], [_ALL_DONE_RULE_5_BROKEN], _REVIEWED, None),  # a rule the first held
        ([draft_answer(_CLEAN)], [_ALL_DONE | {"same_threat": False}], _REVIEWED, None),
        ([draft_answer(_CLEAN)], [_ALL_DONE | {"same_impact": False}], _REVIEWED, None),
        ([draft_answer(_CLEAN) | {"scenario_statement": "SYS7 helps."}], [], _NOT_REVIEWED, None),
        ([draft_answer(_CLEAN)], [{"verdict": "x"}], _REVIEWED, None),  # no third round: not reviewed
        ([Unavailable("AI down")], [], _NOT_REVIEWED, "Unavailable"),
        ([{"title": "x"}], [], _NOT_REVIEWED, None),  # unreadable: never asked again
        ([truncated()], [], _NOT_REVIEWED, None),
        ([draft_answer(_CLEAN)], [Unavailable("AI down")], _REVIEWED, "Unavailable"),
    ],
)
def test_a_repair_that_is_not_complete_or_fails_keeps_the_first_draft_with_its_note(
    repairs: list[Any], checks: list[Any], calls: list[AiTask], error_type: str | None
) -> None:
    """Still missing or left unjudged by an inconsistent review, a new broken rule, another threat, blocked,
    not reviewed, an outage or an unusable answer: the first."""
    chat = _repair_answering(repairs, checks)
    with capture_logs() as logs:
        written = write_scenario(chat, _listed_brief())
    assert _calls(chat) == calls and written.draft == _READ and not written.rewritten
    assert [finding.message for finding in written.findings] == [_MISSING_NOTE]
    assert written.plan_check.actions_not_carried_out == ("hiding the change",)
    (logged,) = [log for log in logs if log["event"] == LogEvent.WRITER_SCENARIO_REPAIRED]
    assert (logged["outcome"], logged.get("error_type")) == ("kept_first", error_type)


def test_a_repair_whose_consistent_review_leaves_a_listed_action_unjudged_is_kept() -> None:
    """Final review, 30 Oct: a consistent review's unjudged action is never repaired (_listed_actions), in a
    repair's review as in a first draft's, so it no longer keeps the repair from being taken."""
    chat = _repair_answering([draft_answer(_CLEAN)], [_MISSING_ONE_UNJUDGED])
    with capture_logs() as logs:
        written = write_scenario(chat, _listed_brief())
    assert _calls(chat) == _REVIEWED and written.rewritten and written.findings == ()
    assert written.plan_check.status is PlanCheckStatus.CONSISTENT
    assert written.plan_check.actions_not_carried_out == ("hiding the change",)
    assert [log["outcome"] for log in logs if log["event"] == LogEvent.WRITER_SCENARIO_REPAIRED] == ["fixed"]


_PUSH = _CLEAN.statement  # the sentence in which the attacker pushes the firmware
_HIDE = "They could then hide the change."
_COMPLETE = draft_answer(_CLEAN) | {
    "scenario_statement": f"{_PUSH} {_HIDE}",
    "action_sentences": {"pushing firmware": _PUSH, "Hiding the  CHANGE": _HIDE},  # case and spacing forgiven
}


@pytest.mark.parametrize(
    "sentences",
    [
        {"pushing firmware": _PUSH},  # no sentence for one action
        {
            "pushing firmware": _PUSH,
            "hiding the change": "They hide the change in the risk.",
        },  # not in the story
        {"pushing firmware": _PUSH, "hiding the change": ""},
        "every action is in the story",  # not a sentence per action
    ],
)
def test_a_draft_that_shows_no_story_sentence_for_a_listed_action_is_asked_again(sentences: Any) -> None:
    """Root cause of an act left only named: the writer must point at the story sentence where the attacker
    does each listed act, and code checks the sentence is really in scenario_statement."""
    first = draft_answer(_CLEAN) | {"action_sentences": sentences}
    chat = _chat_answering([first, _COMPLETE], [_ALL_DONE])
    written = write_scenario(chat, _listed_brief())
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
    assert written.draft.statement == _COMPLETE["scenario_statement"] and written.findings == ()


def test_a_draft_with_a_story_sentence_per_action_or_no_list_is_asked_once() -> None:
    """A second answer still missing a sentence is kept for the reviewer and the repair, never a failure."""
    chat = _chat_answering([_COMPLETE], [_ALL_DONE])
    write_scenario(chat, _listed_brief())
    no_list = _chat_answering([draft_answer(_CLEAN) | {"action_sentences": {}}], [_CONSISTENT])
    write_scenario(no_list, _brief_of(_plan_threat()))
    assert _calls(chat) == _calls(no_list) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    still = draft_answer(_CLEAN) | {"action_sentences": {"pushing firmware": _PUSH}}
    twice = _chat_answering([still, still], [_ALL_DONE])
    assert write_scenario(twice, _listed_brief()).draft.statement == _CLEAN.statement
    assert _calls(twice) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
    rewrite_failed = _chat_answering([still, {"title": "x"}], [_ALL_DONE])  # its first draft is kept
    assert write_scenario(rewrite_failed, _listed_brief()).draft.statement == _CLEAN.statement


_ECCC = "Enterprise Command & Control Centre Platform"
#: A real set (30 Oct, epoch 3): a listed action, its story's sentence, and the writer's quote of that
#: sentence with its opening reworded; each slot was written again for it alone.
_REWORDED_OPENINGS = [
    (
        f"tamper authoritative data on {_ECCC}",
        f"A nation-state actor could enter through the {_ECCC} and, assuming privileged access, tamper "
        f"authoritative data on the {_ECCC} to alter historical incident logs and current congestion "
        "indices.",
        f"The attacker could then tamper authoritative data on the {_ECCC} to alter historical incident logs "
        "and current congestion indices.",
    ),
    (
        f"evade monitoring on {_ECCC}",
        "A nation-state actor could enter through the Intelligent Traffic Systems Platform and, assuming "
        f"elevated OT access, evade monitoring on the {_ECCC} by disabling or filtering agent telemetry "
        "before it reaches the central dashboard.",
        f"The attacker could then evade monitoring on the {_ECCC} by disabling or filtering agent telemetry "
        "before it reaches the central dashboard.",
    ),
    (
        f"compromise backup on {_ECCC}",
        "A nation-state actor could enter through the Traffic Signal Control System and, assuming "
        f"administrative access to backup infrastructure, compromise backup on the {_ECCC} by deleting or "
        "encrypting database and configuration backups.",
        f"The attacker could then compromise backup on the {_ECCC} by deleting or encrypting database and "
        "configuration backups.",
    ),
    (
        f"install infostealer on {_ECCC}",
        "A cybercriminal could enter through the Incident Detection & Response Platform and, assuming an "
        f"initial foothold such as a malicious attachment, install infostealer on the {_ECCC} to harvest "
        "browser-saved passwords, tokens and traffic system configuration files.",
        f"The attacker could then install infostealer on the {_ECCC} to harvest browser-saved passwords, "
        "tokens and traffic system configuration files.",
    ),
]
_TAMPER, _, _BACKUP, _ = _REWORDED_OPENINGS


@pytest.mark.parametrize(("action", "story", "quote"), _REWORDED_OPENINGS)
def test_a_quote_with_its_opening_reworded_is_found_in_its_story(action: str, story: str, quote: str) -> None:
    """Root cause of a rewrite for an act the story has: the quote is found from its first "could" on."""
    answer = {"scenario_statement": story, "action_sentences": {action: quote}}
    assert _acts_without_a_sentence(answer, (action,)) == []


@pytest.mark.parametrize(
    ("action", "story", "sentences"),
    [
        (
            _BACKUP[0],
            f"The attacker could also compromise recovery on the {_ECCC} by corrupting failover "
            "orchestration scripts.",
            {_BACKUP[0]: _BACKUP[2]},
        ),  # another act on the same system
        (_TAMPER[0], _TAMPER[1], {_TAMPER[0]: f"The attacker could then wipe every backup of the {_ECCC}."}),
        (_TAMPER[0], _TAMPER[1], {"another action": _TAMPER[2]}),  # no quote for the listed action
        (_TAMPER[0], _TAMPER[1], {_TAMPER[0]: "They could then act."}),  # "act" is in "actor": too short
    ],
)
def test_a_quote_of_an_act_the_story_does_not_have_is_refused(
    action: str, story: str, sentences: dict[str, str]
) -> None:
    """A reworded opening is forgiven, never another act, a missing quote, or a tail too short to tell."""
    answer = {"scenario_statement": story, "action_sentences": sentences}
    assert _acts_without_a_sentence(answer, (action,)) == [
        AnswerProblem.ACTION_SENTENCES_MISSING.format(actions=json.dumps(action, ensure_ascii=False))
    ]


def test_the_writer_names_each_action_s_story_sentence() -> None:
    """The writer's eighth field and its final check."""
    writer = WRITER_SYSTEM_PROMPT
    assert '"action_sentences": {"<each item of BRIEF.threat.threat_actions, copied>"' in writer
    assert "Include exactly these eight top-level fields" in writer and "Exactly the eight required" in writer
    assert "its value is copied word for word from scenario_statement and shows the attacker doing" in writer
    assert "still gets its own sentence in scenario_statement, never only in risk_statement" in writer


def test_a_rule_4_verdict_is_never_a_note_and_no_extra_call_is_made() -> None:
    """Root cause removed (D49): joining the asset's affected systems is allowed, so no rule judges it. A
    reviewer answer that still carries rule 4, as an older one could, gives no note; one review, no other
    call."""
    rules = {"1": "holds", "4": 'broken: "the Historian then takes the firmware" - systems joined'}
    chat = _chat_answering([], [_CONSISTENT | {"rules": rules}])
    check, notes = check_against_plan(chat, _brief_of(_plan_threat()), _CLEAN)
    assert notes == () and check.status is PlanCheckStatus.CONSISTENT and check.problems == ()
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]


def test_every_action_not_carried_out_is_named_in_the_repair_prompt() -> None:
    both_missing = _CONSISTENT | {"threat_actions": dict.fromkeys(_ACTIONS, "missing")}
    chat = _chat_answering([draft_answer(_CLEAN)], [both_missing, _ALL_DONE])
    chat.queue(AiTask.REPAIR_SCENARIO, draft_answer(_CLEAN))
    write_scenario(chat, _listed_brief())
    (repair,) = chat.asked(AiTask.REPAIR_SCENARIO)
    assert repair.endswith(_REPAIR_TEXT.replace("{actions}", '"pushing firmware", "hiding the change"'))


def test_a_complete_draft_or_a_brief_without_listed_actions_is_never_repaired() -> None:
    """Only the brief's own listed actions count: a reviewer's unlisted one is a note, never a repair."""
    chat = _chat_answering([draft_answer(_CLEAN)], [_ALL_DONE])
    assert write_scenario(chat, _listed_brief()).findings == ()
    unlisted = _chat_answering([draft_answer(_CLEAN)], [_ONE_MISSING])  # reviewer verdicts, but no list
    notes = write_scenario(unlisted, _brief_of(_plan_threat())).findings
    assert [note.message for note in notes] == [_MISSING_NOTE]
    invented = _ALL_DONE | {"threat_actions": _ALL_DONE["threat_actions"] | {"an unlisted act": "missing"}}
    extra = _chat_answering([draft_answer(_CLEAN)], [invented])
    assert write_scenario(extra, _listed_brief()).plan_check.actions_not_carried_out == ()
    assert _calls(chat) == _calls(unlisted) == _calls(extra) == _REVIEWED[:2]


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
    assert written_record(run, path, _plan_threat(), brief, dataclasses.replace(written, rewritten=True))[
        "rewritten"
    ]


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
    assert written.draft.entry_point == "Historian"
    assert _calls(chat) == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
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
