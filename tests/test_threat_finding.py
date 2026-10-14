"""Threat finding (BLUEPRINT M10 T1-T10): T-THR-01..14, on an in-memory library with fake AI models."""

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from app.ai import TruncatedAiAnswer, UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import (
    ActorRole,
    AiTask,
    AttackerCheck,
    CandidateRejection,
    ErrorCode,
    FoldReason,
    GapFillOutcome,
    PlanMessage,
    Search,
    ThreatFinding,
)
from app.core.exceptions import PlanRefused, Unavailable
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.engine.scenarios.finding import threat_finder as threats_module
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai, library_search_queries
from app.engine.scenarios.finding.gate_verdicts import parse_verdict
from app.engine.scenarios.finding.relevance_gate import (
    RelevanceGate,
    accepted_library_threat,
    candidate_for_gate,
)
from app.engine.scenarios.finding.threat_finder import ThreatFinder
from app.engine.scenarios.threat_list.attacker_assignment import AttackerAssigner
from app.engine.scenarios.threat_list.attacker_choice import unranked_notes
from app.engine.scenarios.threat_list.duplicate_merge import merge_reworded_threats, merge_same_threats
from app.engine.scenarios.threat_list.same_attack_check import SameAttackCheck, pick_surviving_threat
from app.engine.shared.names import replace_codes_with_names
from app.engine.shared.parallel import run_in_parallel
from app.models.actor_choice import ActorPick
from app.models.asset_context import FrozenContext
from app.models.library import LibraryActor, RejectedLibraryThreat, ThreatLibrary
from app.models.threats import (
    FoldedThreat,
    PlannedActor,
    PlannedThreat,
    Verdict,
)
from app.search.service import LibrarySearch
from tests.fakes import FakeChatModel, FakeEmbeddings, FakeRerankModel, items_in, truncated
from tests.planner_samples import (
    ACTORS,
    ADMIN_ABUSE,
    AFFILIATE,
    CONTEXT,
    CREW,
    EXFILTRATION,
    FLOOD,
    GANG,
    INSIDER,
    LOG_WIPE,
    PHISHING,
    RANSOMWARE,
    THREATS,
    WORDS,
    S,
    audit_of,
    finder,
    gap_fill_for_elevation,
    judged,
    library_search,
    planned,
    planner_chat,
    system_row,
)


def test_the_landscape_keeps_to_its_budget_and_refuses_systems_judged_by_name_alone() -> None:
    """T-THR-01."""
    landscape = describe_asset_for_ai(CONTEXT, budget=30_000)
    assert landscape.text.startswith(
        'ASSET: {"asset": "Grid Control Centre", "asset_context": {"sector": "Energy"'
    )
    assert '\nSYS1 "SCADA server": {"name": "SCADA server", "asset_type": "OT"' in landscape.text
    assert "321" not in landscape.text and '"alias"' not in landscape.text  # never a database id
    assert "backup_tested" not in landscape.text  # an unrecorded fact is left out, never written as "no"
    assert landscape.facts_shortened_note is None and landscape.system_ids == {"SYS1": 321, "SYS2": 322}
    # SCADA's facts run 726 characters, the historian's 136: at 1,200 each system has 415 (SCADA's facts are
    # shortened, noted); at 600 only 113 (< 150): the plan is refused rather than judge SCADA by its name.
    wordy_scada = system_row(321, "SYS1", "SCADA server", past_incidents="Outage after a patch. " * 30)
    wordy = FrozenContext(**{**CONTEXT.to_record(), "systems": [wordy_scada, CONTEXT.systems[1]]})
    squeezed = describe_asset_for_ai(wordy, budget=1_200)
    assert squeezed.facts_shortened_note == PlanMessage.FACTS_SHORTENED.format(
        clipped=1, systems=2, share=415, longest=726
    )
    assert squeezed.text.split("\n")[1].endswith("…") and len(squeezed.text) <= 1_200
    with pytest.raises(PlanRefused) as refused:
        describe_asset_for_ai(wordy, budget=600)
    assert refused.value.code == ErrorCode.PLAN_REFUSED and "Assess fewer systems" in refused.value.message


def test_each_category_has_one_query_per_system_and_one_for_the_asset_from_text_facts_only() -> None:
    """T-THR-02."""
    queries = library_search_queries(CONTEXT, S.TAMPERING)
    head = "Tampering. unauthorised modification of data, configuration, commands or code Energy Electricity"
    assert len(queries) == 3 and all(query.startswith(head) for query in queries)
    assert "Siemens WinCC" in queries[0] and "OSIsoft PI" in queries[1] and "transmission grid" in queries[2]
    assert not any(fact in query for query in queries for fact in ("30.0", "2026-01-01", "4.0"))
    long_text = system_row(9, "SYS1", "PLC", past_incidents="x " * 2000)
    long_context = FrozenContext(**{**CONTEXT.to_record(), "systems": [long_text]})
    clipped_query = library_search_queries(long_context, S.TAMPERING)[0]
    assert len(clipped_query) <= Search.QUERY_MAX_CHARS and clipped_query.endswith("…")


def test_search_queries_carry_no_secret_personal_data_or_placeholder() -> None:
    """Review 2026-10-11: a query reaches the embedding model, yet it joined the raw recorded facts."""
    incident = "Leaked, password: Winter24! by a.b@corp.ae"
    leaky = system_row(9, "SYS1", "PLC", past_incidents=incident, vendor_name="N/A")
    query = library_search_queries(FrozenContext(**{**CONTEXT.to_record(), "systems": [leaky]}), S.TAMPERING)[
        0
    ]
    assert "Leaked" in query and not any(text in query for text in ("Winter24", "a.b@corp.ae", "N/A"))


def test_a_threat_shortlisted_under_one_category_is_judged_under_every_category_it_maps_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-THR-03: each query keeps only its category's threats before the top-k cut. With one hit per query,
    Denial of Service's own search finds the flood alone; the ransomware found under Tampering joins it."""
    monkeypatch.setattr(Search, "THREATS_PER_QUERY", 1)
    chat = planner_chat({FLOOD.name: ["SYS2"], RANSOMWARE.name: ["SYS1"]})
    finder(chat).find_threats(CONTEXT)
    gate_prompts = chat.asked(AiTask.RELEVANCE_GATE)
    (denial_of_service,) = [user for user in gate_prompts if "STRIDE category: Denial of Service" in user]
    assert [c["threat"] for c in items_in(denial_of_service, "CANDIDATES")] == [FLOOD.name, RANSOMWARE.name]


def test_a_bad_verdict_is_asked_again_and_a_rejection_needs_no_impact() -> None:
    """T-THR-04."""
    _, problems = parse_verdict(
        {
            "slot": "R1",
            "relevant": True,
            "systems": ["SYS9"],
            "reason": "",
            "impact": "BIG",
            "confidence": 101,
        },
        {"SYS1": 321},
    )
    assert problems == [
        "R1: systems must be listed aliases only (SYS1, SYS2 ...)",
        "R1: impact must be HIGH, MEDIUM or LOW",
        "R1: confidence must be a number from 0 to 100",
        "R1: every verdict needs its reason, a rejection's too",
    ]
    good = {
        "slot": "R1",
        "relevant": True,
        "systems": ["SYS1"],
        "reason": "On SYS1.",
        "impact": "HIGH",
        "confidence": 80,
    }
    rejection = {
        "slot": "R2",
        "relevant": False,
        "systems": [],
        "reason": "No mail.",
        "impact": "N/A",
        "confidence": 5,
    }
    chat = FakeChatModel()
    chat.queue(AiTask.RELEVANCE_GATE, {"verdicts": [good | {"systems": ["SYS9"]}, rejection]})
    chat.queue(AiTask.RELEVANCE_GATE, {"verdicts": [good, rejection]})
    items = [
        candidate_for_gate("R1", "Malware", RANSOMWARE.name, []),
        candidate_for_gate("R2", "Phish", PHISHING.name, []),
    ]
    verdicts = RelevanceGate(chat, describe_asset_for_ai(CONTEXT, 30_000)).judge_candidates(
        S.TAMPERING, items
    )  # type: ignore[arg-type]
    assert verdicts["R1"] == Verdict(True, (321,), "On SYS1.", 3, 80.0) and verdicts["R2"].relevant is False
    assert len(chat.calls) == 2  # one corrective re-ask


def test_a_cut_off_answer_is_asked_again_in_halves_and_a_single_threat_still_cut_off_raises() -> None:
    """T-THR-05."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    chat.queue(AiTask.RELEVANCE_GATE, truncated())
    gate = RelevanceGate(chat, describe_asset_for_ai(CONTEXT, 30_000))  # type: ignore[arg-type]
    items = [
        candidate_for_gate("R1", "Malware", RANSOMWARE.name, []),
        candidate_for_gate("R2", "Phish", PHISHING.name, []),
    ]
    assert set(gate.judge_candidates(S.TAMPERING, items)) == {"R1", "R2"}
    asked = [[c["slot"] for c in items_in(user, "CANDIDATES")] for user in chat.asked(AiTask.RELEVANCE_GATE)]
    assert asked == [["R1", "R2"], ["R1"], ["R2"]]
    chat.queue(AiTask.RELEVANCE_GATE, truncated())  # one threat cut off: asked afresh once, then answered
    assert set(gate.judge_candidates(S.TAMPERING, items[:1])) == {"R1"}
    chat.queue(AiTask.RELEVANCE_GATE, truncated(), truncated())
    with pytest.raises(TruncatedAiAnswer):
        gate.judge_candidates(S.TAMPERING, items[:1])


def test_a_category_still_unusable_on_its_second_try_is_not_assessed_and_the_run_goes_on() -> None:
    """T-THR-06."""
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda u: (
        {"verdicts": "?"} if "category: Spoofing" in u else gate(u)
    )
    findings = finder(chat).find_threats(CONTEXT)
    spoofing = audit_of(findings, S.SPOOFING)
    not_judged = PlanMessage.THREATS_NOT_JUDGED.format(not_judged=1, threats=1)
    not_asked = PlanMessage.GAP_FILL_NOT_ASKED.format(judged=0, records=1)
    assert spoofing.gap_fill == GapFillOutcome.NOT_ASSESSED and spoofing.note == f"{not_judged} {not_asked}"
    assert [r["code"] for r in spoofing.rejected] == [CandidateRejection.NOT_JUDGED] * spoofing.shortlisted
    spoofing_calls = [user for user in chat.asked(AiTask.RELEVANCE_GATE) if "category: Spoofing" in user]
    assert len(spoofing_calls) == 4  # its one batch asked twice, each re-asked once
    assert [threat.name for threat in findings.threats] == [LOG_WIPE.name]
    assert AttackPathSelector(target=0).build_plan(findings)["not_assessed"] == [S.SPOOFING]  # type: ignore[arg-type]


def test_an_unusable_batch_is_asked_again_alone_and_the_categorys_other_verdicts_are_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review 2026-10-11: one gate batch still unusable after its re-ask is asked afresh on its own; before,
    the whole category was judged again, every good batch paid twice and its verdicts thrown away."""
    monkeypatch.setattr(ThreatFinding, "GATE_BATCH_MAX_ITEMS", 1)  # one threat per batch
    chat = planner_chat({FLOOD.name: ["SYS2"], RANSOMWARE.name: ["SYS1"]})
    gate, flood_asks = chat.responders[AiTask.RELEVANCE_GATE], []

    def flood_unreadable_at_first(user: str) -> dict[str, Any]:
        if "category: Denial of Service" in user and FLOOD.name in user:
            flood_asks.append(user)
            if len(flood_asks) <= 2:  # the ask and its corrective re-ask
                return {"verdicts": "?"}
        return gate(user)

    chat.responders[AiTask.RELEVANCE_GATE] = flood_unreadable_at_first
    findings = finder(chat).find_threats(CONTEXT)
    assert audit_of(findings, S.DENIAL_OF_SERVICE).note is None  # its retry answered: nothing left unjudged
    assert len(flood_asks) == 3 and FLOOD.name in [threat.name for threat in findings.threats]
    denial = [user for user in chat.asked(AiTask.RELEVANCE_GATE) if "category: Denial of Service" in user]
    assert sum(RANSOMWARE.name in user for user in denial) == 1  # the good batch is never asked again


def test_a_batch_unusable_after_its_retries_costs_only_its_own_threats_and_is_never_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G210: one gate batch still unusable after all its retries made the WHOLE category not assessed, every
    other batch's good verdict thrown away. Now only its threats are not judged, the category keeps its other
    verdicts and its scenario, and the plan still lists it as not fully assessed, so the run ends partial."""
    monkeypatch.setattr(ThreatFinding, "GATE_BATCH_MAX_ITEMS", 1)  # one threat per batch
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], FLOOD.name: ["SYS2"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if "category: Denial of Service" in user and FLOOD.name in user else gate(user)
    )
    findings = finder(chat).find_threats(CONTEXT)
    denial = audit_of(findings, S.DENIAL_OF_SERVICE)
    assert [threat.name for threat in findings.threats] == [RANSOMWARE.name]  # its good verdict is kept
    flood = [r["code"] for r in denial.rejected if r["library_id"] == FLOOD.catalogue_id]
    assert flood == [CandidateRejection.NOT_JUDGED] and denial.relevant == 1
    assert denial.note == PlanMessage.THREATS_NOT_JUDGED.format(not_judged=1, threats=2)
    assert denial.judged_ids == {RANSOMWARE.catalogue_id} and denial.gap_fill is None
    plan = AttackPathSelector(target=0).build_plan(findings)  # type: ignore[arg-type]
    assert any(S.DENIAL_OF_SERVICE in path["categories"] for path in plan["paths"])  # it has a scenario
    assert plan["not_assessed"] == [S.DENIAL_OF_SERVICE]  # and the gap is still shown: the run is partial


def test_an_unusable_batch_cut_off_on_its_retry_is_still_asked_in_halves() -> None:
    """Review 2026-10-11: the batch's one retry went straight to the AI, so an answer cut off on it was never
    split; it now takes the same road as the first try."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    chat.queue(AiTask.RELEVANCE_GATE, {"verdicts": "?"}, {"verdicts": "?"}, truncated())
    gate = RelevanceGate(chat, describe_asset_for_ai(CONTEXT, 30_000))  # type: ignore[arg-type]
    items = [
        candidate_for_gate("R1", "Malware", RANSOMWARE.name, []),
        candidate_for_gate("R2", "Phish", PHISHING.name, []),
    ]
    assert set(gate.judge_candidates(S.TAMPERING, items)) == {"R1", "R2"}


def test_a_gap_fill_the_gate_cannot_judge_leaves_only_the_gap_not_assessed() -> None:
    """Review 2026-10-11: a gate that could not judge the AI's proposal made the whole category not assessed,
    re-marking every library threat of it "not judged" though each had its verdict."""
    proposal = {
        "applies": True,
        "threat_type": "Privilege misuse",
        "threat": "Engineering workstation takeover",
        "attacker": "Nation-state group",
        "systems": ["SYS1"],
        "reason": "SYS1 runs engineering tools.",
    }
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if proposal["threat"] in user else gate(user)
    )
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    elevation = audit_of(finder(chat).find_threats(CONTEXT), S.ELEVATION_OF_PRIVILEGE)
    assert (elevation.gap_fill, elevation.note) == (
        GapFillOutcome.NOT_ASSESSED,
        PlanMessage.GAP_FILL_NOT_ASSESSED,
    )
    assert [rejected["code"] for rejected in elevation.rejected] == [CandidateRejection.NOT_RELEVANT]
    asked = chat.asked(AiTask.RELEVANCE_GATE)
    assert sum(proposal["threat"] in user for user in asked) == 4  # the gate saw it: twice, each re-asked


def test_an_alias_that_is_not_a_string_is_re_asked_never_a_crash() -> None:
    """Review 2026-10-11: a list in place of an alias raised TypeError (unhashable), failing the run."""
    item = {"slot": "R1", "relevant": True, "systems": [["SYS1"]], "reason": "On SYS1.", "impact": "HIGH"}
    verdict, problems = parse_verdict(item | {"confidence": 80}, {"SYS1": 321})
    assert verdict is None and problems == ["R1: systems must be listed aliases only (SYS1, SYS2 ...)"]


def test_gap_fill_comes_only_after_the_whole_category_and_its_attacker_is_its_types_linked_actor() -> None:
    """T-THR-07."""
    proposal = {
        "applies": True,
        "threat_type": "Privilege misuse",
        "threat": "Engineering workstation takeover",
        "attacker": "Nation-state group",
        "systems": ["SYS1"],
        "reason": "SYS1 runs engineering tools.",
    }
    chat = planner_chat({"Engineering workstation takeover": ["SYS1"], LOG_WIPE.name: ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    rerank = FakeRerankModel({("Privilege misuse", "Privilege misuse"): 90.0})
    findings = finder(chat, rerank).find_threats(CONTEXT)
    (ai_threat,) = [threat for threat in findings.threats if not threat.from_library]
    assert ai_threat.key == "ai:engineering workstation takeover"
    assert (ai_threat.type_id, ai_threat.type_name) == (
        5,
        "Privilege misuse",
    )  # the library type, matched at 75
    # G108: the AI's "Nation-state group" is never used; the library type's linked actor acts.
    assert [actor.actor_id for actor in ai_threat.actors] == [INSIDER.actor_id]
    assert not ai_threat.closest_attacker
    assert audit_of(findings, S.ELEVATION_OF_PRIVILEGE).gap_fill == GapFillOutcome.ACCEPTED
    (elevation,) = [user for user in chat.asked(AiTask.GAP_FILL) if "category: Elevation" in user]
    assert (
        f'- "{ADMIN_ABUSE.name}"' in elevation
    )  # the rejected library threat is named: never proposed again
    assert not any(
        "category: Repudiation" in user for user in chat.asked(AiTask.GAP_FILL)
    )  # a library one applied


_PROPOSAL = {
    "applies": True,
    "threat_type": "Privilege misuse",
    "threat": "Engineering workstation takeover",
    "attacker": "Nation-state group",
    "systems": ["SYS1"],
    "reason": "SYS1 runs engineering tools.",
}


def test_an_untyped_gap_fill_proposal_becomes_a_note_not_a_threat() -> None:
    """G108 (spec v4.0 §7.2.2 step 6.2): a proposed type below the 75 bar is left for a curator, never
    planned."""
    proposal = _PROPOSAL | {"threat_type": "Quantum sabotage"}
    chat = planner_chat({"Engineering workstation takeover": ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    findings = finder(chat, FakeRerankModel()).find_threats(CONTEXT)  # no type scores at the bar
    assert [threat for threat in findings.threats if not threat.from_library] == []
    elevation = audit_of(findings, S.ELEVATION_OF_PRIVILEGE)
    assert elevation.gap_fill == GapFillOutcome.UNTYPED
    assert elevation.note == PlanMessage.GAP_FILL_UNTYPED.format(
        threat="Engineering workstation takeover", threat_type="Quantum sabotage"
    )
    assert elevation.rejected[-1]["code"] == CandidateRejection.AI_UNTYPED


def test_a_gap_fill_proposal_matching_rejected_wording_is_refused() -> None:
    """G108 (spec v4.0 §7.2.2 step 6.1): wording a curator rejected is never proposed again; refused before
    the gate is asked."""
    rejected = (RejectedLibraryThreat(99, "ENGINEERING  workstation takeover!", 5),)
    chat = planner_chat({"Engineering workstation takeover": ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL)
    search, embeddings = library_search(curator_rejected=rejected)
    threat_finder = ThreatFinder(chat, search, FakeRerankModel(), embeddings)  # type: ignore[arg-type]
    findings = threat_finder.find_threats(CONTEXT)
    elevation = audit_of(findings, S.ELEVATION_OF_PRIVILEGE)
    assert elevation.gap_fill == GapFillOutcome.PREVIOUSLY_REJECTED
    assert all(threat.from_library for threat in findings.threats)
    assert elevation.rejected[-1]["code"] == CandidateRejection.AI_PREVIOUSLY_REJECTED
    gate_prompts = [user for user in chat.asked(AiTask.RELEVANCE_GATE) if "Engineering workstation" in user]
    assert gate_prompts == []


def test_gap_fill_never_picks_an_attacker() -> None:
    """G108: the AI's attacker text is never shown to the gate, never searched and never used."""
    chat = planner_chat({"Engineering workstation takeover": ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL)
    rerank = FakeRerankModel({("Privilege misuse", "Privilege misuse"): 90.0})
    findings = finder(chat, rerank).find_threats(CONTEXT)
    (ai_threat,) = [threat for threat in findings.threats if not threat.from_library]
    assert "Nation-state group" not in str(chat.asked(AiTask.RELEVANCE_GATE))
    assert all(query != "Nation-state group" for query, _ in rerank.calls)
    assert ai_threat.actors[0].name == INSIDER.name  # the library type's linked actor


def test_a_gap_fill_that_repeats_a_library_threat_is_redundant() -> None:
    """T-THR-07."""
    proposal = {
        "applies": True,
        "threat_type": "Privilege misuse",
        "threat": "Insider misuses admin rights",
        "attacker": "Malicious insider",
        "systems": [],
        "reason": "Admins exist.",
    }
    chat = planner_chat({})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    rerank = FakeRerankModel({("Insider misuses admin rights", ADMIN_ABUSE.name): 80.0})
    findings = finder(chat, rerank).find_threats(CONTEXT)
    elevation = audit_of(findings, S.ELEVATION_OF_PRIVILEGE)
    assert elevation.gap_fill == GapFillOutcome.REDUNDANT and findings.threats == []
    assert elevation.rejected[-1]["code"] == CandidateRejection.AI_REDUNDANT
    assert audit_of(findings, S.REPUDIATION).gap_fill == GapFillOutcome.NONE_APPLIES


def test_the_threat_threshold_is_the_owners_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """G200: THREAT_SIMILARITY_THRESHOLD decides when an AI proposal IS a library threat: one the reranker
    scores 80 against the library threat repeats it at the default 75, and is no repeat of it at 85."""
    proposal = {
        "applies": True,
        "threat_type": "Privilege misuse",
        "threat": "Insider misuses admin rights",
        "attacker": "Malicious insider",
        "systems": [],
        "reason": "Admins exist.",
    }

    def gap_fill_outcome() -> GapFillOutcome:
        chat = planner_chat({})
        chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
        rerank = FakeRerankModel({("Insider misuses admin rights", ADMIN_ABUSE.name): 80.0})
        return audit_of(finder(chat, rerank).find_threats(CONTEXT), S.ELEVATION_OF_PRIVILEGE).gap_fill

    assert gap_fill_outcome() == GapFillOutcome.REDUNDANT
    monkeypatch.setattr(get_settings(), "threat_similarity_threshold", 85.0)
    assert gap_fill_outcome() != GapFillOutcome.REDUNDANT


def test_one_library_threat_found_under_two_categories_is_one_threat() -> None:
    """T-THR-08."""
    tampering = planned("lib:1", RANSOMWARE.name, (321,), impact=2)
    denial = planned("lib:1", RANSOMWARE.name, (322,), categories=(S.DENIAL_OF_SERVICE,), impact=3)
    (merged,), folded, _ = merge_same_threats([denial, tampering])
    assert merged.categories == (S.TAMPERING, S.DENIAL_OF_SERVICE) and merged.systems == (321, 322)
    assert merged.impact == 3 and folded == []


def test_an_ai_threat_named_like_a_library_threat_is_that_library_threat() -> None:
    """T-THR-09: the library name keeps its code, the AI's has none."""
    library = planned("lib:1", f"T1486 {RANSOMWARE.name}", (321,))
    ai_twin = planned("ai:x", RANSOMWARE.name, (322,), categories=(S.DENIAL_OF_SERVICE,))
    (kept,), (fold,), _ = merge_same_threats([library, ai_twin])
    assert kept.key == "lib:1" and kept.systems == (321, 322)
    assert kept.categories == (S.TAMPERING, S.DENIAL_OF_SERVICE)
    assert (fold.threat.key, fold.kept_key, fold.reason) == ("ai:x", "lib:1", FoldReason.SAME_NAME)


def test_an_ai_rewording_is_folded_by_meaning_and_a_different_ai_threat_is_kept() -> None:
    """T-THR-10: compared without the asset's name; library threats are never folded this way."""
    library = planned("lib:1", RANSOMWARE.name)
    reworded = planned("ai:a", "Ransomware locking the backup of Grid Control Centre", (322,))
    different = planned("ai:b", "Phishing of operators")
    embeddings = FakeEmbeddings(WORDS)
    kept, (fold,) = merge_reworded_threats([library, reworded, different], embeddings, "Grid Control Centre")  # type: ignore[arg-type]
    assert [threat.key for threat in kept] == ["lib:1", "ai:b"] and kept[0].systems == (321, 322)
    assert fold.reason == FoldReason.SAME_WORDING and fold.kept_key == "lib:1" and fold.score is not None
    assert merge_reworded_threats([library, library], embeddings, "x")[1] == []  # type: ignore[arg-type]


def test_same_name_with_a_different_type_is_kept_apart_with_a_note() -> None:
    """G109 (spec v4.0 §7.2.2 step 7.2): a canonical type is never overwritten by a merge."""
    library = planned("lib:1", RANSOMWARE.name, (321,), type_id=1, type_name="Malware")
    ai_twin = planned("ai:x", RANSOMWARE.name, (322,), type_id=5, type_name="Privilege misuse")
    kept, folded, notes = merge_same_threats([library, ai_twin])
    assert [threat.key for threat in kept] == ["ai:x", "lib:1"] and folded == []
    assert notes == [
        PlanMessage.TYPE_CONFLICT_KEPT_APART.format(
            threat=RANSOMWARE.name,
            threat_type="Privilege misuse",
            library_threat=RANSOMWARE.name,
            library_type="Malware",
        )
    ]


def test_rewordings_fold_only_within_one_type() -> None:
    """G109: a near-identical wording of another type is a different threat."""
    library = planned("lib:1", RANSOMWARE.name, type_id=1)
    reworded = planned("ai:a", "Ransomware locking the backup", (322,), type_id=5)
    embeddings = FakeEmbeddings(WORDS)
    kept, folded = merge_reworded_threats([library, reworded], embeddings, "x")  # type: ignore[arg-type]
    assert [threat.key for threat in kept] == ["lib:1", "ai:a"] and folded == []


def test_same_attack_never_groups_two_types() -> None:
    """G109: the AI's group of two types is refused; the threats stay apart."""
    library = planned("lib:1", RANSOMWARE.name, type_id=1)
    other_type = planned("ai:wipe", "Backup wipe", type_id=5)
    chat = FakeChatModel()
    group = {"same": [{"threats": ["THR1", "THR2"], "reason": "Same attack."}]}
    chat.queue(AiTask.SAME_ATTACK, group, group)
    check = SameAttackCheck(chat, describe_asset_for_ai(CONTEXT, 30_000))  # type: ignore[arg-type]
    kept, folded, notes = check.merge_same_attacks([library, other_type], [])
    assert [threat.key for threat in kept] == ["lib:1", "ai:wipe"] and folded == []
    assert notes == [PlanMessage.SAME_ATTACK_NOT_CHECKED.format(threats=2)]


def test_the_same_attack_in_other_words_folds_into_the_library_threat() -> None:
    """T-THR-11: only threats sharing a system are asked about; earlier folds follow the one kept."""
    library = planned("lib:1", RANSOMWARE.name, actors=(PlannedActor(1, GANG.name, ActorRole.ACTING),))
    ai_twin = planned("ai:wipe", "Backup wipe")
    elsewhere = planned("ai:far", "Historian outage", (322,))
    earlier = FoldedThreat(planned("ai:old", "Old"), "ai:wipe", FoldReason.SAME_WORDING)
    chat = FakeChatModel()
    chat.queue(
        AiTask.SAME_ATTACK, {"same": [{"threats": ["THR1", "THR2"], "reason": "THR1 is THR2 on SYS1."}]}
    )
    check = SameAttackCheck(chat, describe_asset_for_ai(CONTEXT, 30_000))  # type: ignore[arg-type]
    kept, folded, notes = check.merge_same_attacks([library, ai_twin, elsewhere], [earlier])
    assert [threat.key for threat in kept] == ["lib:1", "ai:far"] and notes == []
    assert [(fold.threat.key, fold.kept_key) for fold in folded] == [
        ("ai:old", "lib:1"),
        ("ai:wipe", "lib:1"),
    ]
    assert folded[1].why == f"Backup wipe is {RANSOMWARE.name} on SCADA server."
    shown = items_in(chat.calls[0][1], "THREATS")
    assert [slot["slot"] for slot in shown] == ["THR1", "THR2"]
    assert all("attacker" not in slot for slot in shown)  # none is chosen before this check (G110)
    chat.queue(AiTask.SAME_ATTACK, {"same": "?"}, {"same": "?"})
    kept, _, notes = check.merge_same_attacks([library, ai_twin], [])
    assert len(kept) == 2 and notes == [PlanMessage.SAME_ATTACK_NOT_CHECKED.format(threats=2)]


def test_attackers_are_ranked_only_for_threats_left_after_duplicates_are_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G110 (spec v4.0 §7.2.2 step 8): a threat folded into its twin never gets an actor search."""
    assigned: list[list[str]] = []

    class RecordingAssigner(AttackerAssigner):
        def assign_attackers(
            self, threats: list[PlannedThreat], sector: str, gate_judged: bool = False
        ) -> list[PlannedThreat]:
            assigned.append([threat.key for threat in threats])
            return super().assign_attackers(threats, sector, gate_judged)

    monkeypatch.setattr(threats_module, "AttackerAssigner", RecordingAssigner)
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], EXFILTRATION.name: ["SYS1"]})  # one type, one system
    one_attack = {"same": [{"threats": ["THR1", "THR2"], "reason": "One attack on SYS1."}]}
    chat.responders[AiTask.SAME_ATTACK] = lambda _: one_attack
    findings = finder(chat).find_threats(CONTEXT)
    assert [fold.threat.key for fold in findings.folded] == ["lib:4"]  # folded into lib:1
    assert assigned == [[threat.key for threat in findings.threats]]
    assert "lib:4" not in assigned[0] and "lib:1" in assigned[0]


def test_the_survivor_of_a_same_attack_group_ignores_its_attacker() -> None:
    """G110: the lowest library id stands for the group, whatever attacker either has."""
    closest = planned("lib:5", "Backup wipe", closest_attacker=True)
    linked = planned("lib:9", "Backup destruction")
    assert pick_surviving_threat([linked, closest]).key == "lib:5"


def test_linked_actors_are_ranked_and_the_next_ones_are_the_alternates() -> None:
    """T-THR-12 (owner, 2026-10-10): every linked actor can carry out the threat, so the next ones, best fit
    first, are its alternates; no name-similarity check (no linked pair of the dev library reached 0.80)."""
    search, _ = library_search()
    verdict = Verdict(True, (321,), "It encrypts the backup.", 3, 80.0)
    ransomware, phishing = AttackerAssigner(search.snapshot(), FakeRerankModel()).assign_attackers(
        [
            accepted_library_threat(S.TAMPERING, RANSOMWARE, verdict),
            accepted_library_threat(S.SPOOFING, PHISHING, verdict),
        ],
        "Energy",
    )
    assert ransomware.actors == (
        PlannedActor(GANG.actor_id, GANG.name, ActorRole.ACTING),
        PlannedActor(AFFILIATE.actor_id, AFFILIATE.name, ActorRole.ALTERNATE),
        PlannedActor(INSIDER.actor_id, INSIDER.name, ActorRole.ALTERNATE),  # fits the ransomware threat least
    )
    assert not ransomware.closest_attacker
    # G122: its type links no attacker, so the nearest comes from the attackers the library links to some
    # type; "Phishing crew" is linked to none (like a named group on the dev library) and is never offered.
    vetted = {GANG, AFFILIATE, INSIDER}
    assert phishing.closest_attacker and len(phishing.actors) == 1
    assert set(phishing.attacker_options) == vetted and CREW not in phishing.attacker_options
    assert phishing.actors[0].actor_id == phishing.attacker_options[0].actor_id


class _AttackerScores:
    """A reranker scoring each attacker by its name (0-100), recording what it was asked."""

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores, self.asked = scores, 0

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.asked += 1
        return [self.scores.get(document, 0.0) for document in documents]


def test_an_attacker_threshold_filters_only_the_closest_match_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G200 (owner 2026-10-11): with ACTOR_SIMILARITY_THRESHOLD set, a threat whose type links no attacker is
    offered only the nearest attackers at or above it, best score first; none reaches it: the closest still
    acts, flagged below_threshold. Linked attackers are never filtered, and 0 asks the reranker nothing."""
    search, _ = library_search()
    verdict = Verdict(True, (321,), "It encrypts the backup.", 3, 80.0)
    threats = [
        accepted_library_threat(S.TAMPERING, RANSOMWARE, verdict),
        accepted_library_threat(S.SPOOFING, PHISHING, verdict),
    ]
    rerank = _AttackerScores({GANG.name: 70.0, INSIDER.name: 55.0, AFFILIATE.name: 20.0})
    AttackerAssigner(search.snapshot(), rerank).assign_attackers(threats, "Energy")  # type: ignore[arg-type]
    assert rerank.asked == 0  # threshold 0: no filter, no reranker call
    monkeypatch.setattr(get_settings(), "actor_similarity_threshold", 50.0)
    ransomware, phishing = AttackerAssigner(search.snapshot(), rerank).assign_attackers(threats, "Energy")  # type: ignore[arg-type]
    assert rerank.asked == 1 and len(ransomware.actors) == 3  # linked: all kept, below 50 or not
    assert phishing.attacker_options == (GANG, INSIDER) and not phishing.actors[0].below_threshold
    monkeypatch.setattr(get_settings(), "actor_similarity_threshold", 80.0)
    _, phishing = AttackerAssigner(search.snapshot(), rerank).assign_attackers(threats, "Energy")  # type: ignore[arg-type]
    assert phishing.attacker_options == (GANG,) and phishing.actors[0].below_threshold
    assert phishing.to_record()["actors"][0]["below_threshold"] is True


def test_the_gates_pick_acts_none_fits_flags_and_no_pick_is_ranked_with_a_note() -> None:
    """T-THR-12, G229 (owner 2026-10-13: actor selection inside the existing planning call): the relevance
    gate's pick acts with its reason; "none fits" keeps the nearest, flagged; no usable pick leaves the search
    ranking, flagged, with one plan note; an outage falls back to library order. No attacker AI call."""
    search, embeddings = library_search()
    snapshot = search.snapshot()
    pick = ActorPick(INSIDER.name, "Holds the backup admin account.", ((INSIDER.name, "HIGH"),))
    picked = Verdict(True, (321,), "Phishing on SYS1.", 3, 80.0, actor_pick=pick)
    (phishing,) = AttackerAssigner(snapshot, FakeRerankModel()).assign_attackers(
        [accepted_library_threat(S.SPOOFING, PHISHING, picked)], "Energy", gate_judged=True
    )
    assert phishing.actors[0].actor_id == INSIDER.actor_id and phishing.attacker_check == AttackerCheck.CHOSEN
    assert phishing.attacker_check_reason == "Holds the backup admin account."
    assert phishing.to_record()["actor_selection"]["picked"] == INSIDER.name
    none = Verdict(True, (321,), "Phishing on SYS1.", 3, 80.0, actor_pick=ActorPick(None, "None could."))
    (nearest,) = AttackerAssigner(snapshot, FakeRerankModel()).assign_attackers(
        [accepted_library_threat(S.SPOOFING, PHISHING, none)], "Energy", gate_judged=True
    )
    assert nearest.attacker_check == AttackerCheck.NONE_FITS
    assert nearest.attacker_check_reason == "None could."
    assert nearest.closest_attacker and nearest.actors[0].actor_id == nearest.attacker_options[0].actor_id
    verdict = Verdict(True, (321,), "Phishing on SYS1.", 3, 80.0)
    (unchecked,) = AttackerAssigner(snapshot, FakeRerankModel()).assign_attackers(
        [accepted_library_threat(S.SPOOFING, PHISHING, verdict)], "Energy", gate_judged=True
    )
    assert unchecked.attacker_check == AttackerCheck.NOT_CHECKED
    assert unranked_notes([unchecked]) == [PlanMessage.ATTACKERS_RANKED_ONLY.format(threats=1)]
    assert "attacker_fit" not in {task.value for task in AiTask}
    embeddings.queries_down = True
    (unranked,) = AttackerAssigner(snapshot, FakeRerankModel()).assign_attackers(
        [accepted_library_threat(S.TAMPERING, RANSOMWARE, verdict)], "Energy"
    )
    assert (
        not unranked.actors_ranked
        and unranked.actors
        == (  # the library's order: insider, gang, affiliate
            PlannedActor(INSIDER.actor_id, INSIDER.name, ActorRole.ACTING),
            PlannedActor(GANG.actor_id, GANG.name, ActorRole.ALTERNATE),
            PlannedActor(AFFILIATE.actor_id, AFFILIATE.name, ActorRole.ALTERNATE),
        )
    )
    with pytest.raises(Unavailable):  # an unlinked type's nearest actor needs the vectors: the job retries
        AttackerAssigner(snapshot, FakeRerankModel()).assign_attackers(
            [accepted_library_threat(S.SPOOFING, PHISHING, verdict)], "Energy"
        )


def test_one_run_reads_one_library_version_even_when_the_library_changes_meanwhile() -> None:
    """G102: the run takes one snapshot; v1 loaded its library once per round. Every later read of the library
    returns a version whose actors are renamed: none of their names may reach the plan."""
    renamed = tuple(LibraryActor(actor.actor_id, f"Renamed {actor.name}") for actor in ACTORS)
    ids = ((6, "Denial of Service"), (5, " Tampering "))
    first = SimpleNamespace(
        threat_library=ThreatLibrary(THREATS, ACTORS, category_ids=ids), control_library=(), stamp=()
    )
    later = SimpleNamespace(threat_library=ThreatLibrary(THREATS, renamed), control_library=(), stamp=())
    versions = iter([first])
    library = SimpleNamespace(get_loaded_libraries=lambda: next(versions, later))
    search = LibrarySearch(library, FakeEmbeddings(WORDS))  # type: ignore[arg-type]
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], PHISHING.name: ["SYS1"]})
    findings = ThreatFinder(chat, search, FakeRerankModel(), FakeEmbeddings(WORDS)).find_threats(CONTEXT)  # type: ignore[arg-type]
    named = {actor.name for threat in findings.threats for actor in threat.actors}
    assert named and named <= {actor.name for actor in ACTORS}
    # The category ids each path keeps (G207) come from the same library version, by lower-case name.
    assert findings.category_ids == {"denial of service": 6, "tampering": 5}


def test_no_live_actor_refuses_the_plan_before_any_ai_call() -> None:
    """T-THR-13."""
    chat = planner_chat({})
    with pytest.raises(PlanRefused) as refused:
        finder(chat, actors=()).find_threats(CONTEXT)
    assert refused.value.code == ErrorCode.ACTOR_LIBRARY_EMPTY and chat.calls == []


def test_every_alias_the_ai_wrote_reads_as_the_system_name() -> None:
    """T-THR-14."""
    names = {"SYS1": "SCADA system", "SYS2": "Historian"}
    assert replace_codes_with_names('SYS1 "SCADA system" is exposed', names) == "SCADA system is exposed"
    assert (
        replace_codes_with_names("SCADA system and Historian (SYS1, SYS2) fail", names)
        == "SCADA system and Historian fail"
    )
    assert (
        replace_codes_with_names("Privilege Abuse on SYS1 'SCADA system'", names)
        == "Privilege Abuse on SCADA system"
    )
    assert (
        replace_codes_with_names("STEP7 project on SYS1", names) == "STEP7 project on SCADA system"
    )  # STEP7: a product
    findings = finder(planner_chat({LOG_WIPE.name: ["SYS1"]})).find_threats(CONTEXT)
    assert findings.threats[0].reason == f"{LOG_WIPE.name} hits SCADA server."
    assert all("SYS" not in rejected["reason"] for audit in findings.audits for rejected in audit.rejected)


def test_left_out_library_threats_are_named_on_the_plan() -> None:
    """G119: a threat the loader left out for bad library data is a note for a curator, never silent."""
    library = ThreatLibrary((), (), threats_without_category=(4, 9))
    note = PlanMessage.LIBRARY_DATA_INVALID.format(count=2, ids="4, 9")
    assert threats_module._library_data_notes(library) == [note]
    assert threats_module._library_data_notes(ThreatLibrary((), ())) == []


def test_every_category_judges_every_threat_even_when_its_shortlist_found_one() -> None:
    """G121 (owner, 2026-10-10): a relevant shortlisted threat no longer stops the category short."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    findings = finder(chat).find_threats(CONTEXT)
    for audit in findings.audits:
        in_category = {threat.catalogue_id for threat in THREATS if audit.category in threat.categories}
        assert audit.whole_category and audit.judged_ids == in_category, audit.category


def test_gate_batches_run_at_once_and_every_slot_keeps_its_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """G121: small batches sent together (paced by the AI slot limit), every verdict back under its slot."""
    monkeypatch.setattr(ThreatFinding, "GATE_BATCH_MAX_ITEMS", 1)
    running, peak, lock = [0], [0], threading.Lock()
    gate_answer = judged({"T1": ["SYS1"], "T3": ["SYS2"]})

    def slow_answer(user_prompt: str) -> dict[str, Any]:
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
        return gate_answer(user_prompt)

    chat = FakeChatModel()
    chat.responders[AiTask.RELEVANCE_GATE] = slow_answer
    gate = RelevanceGate(chat, describe_asset_for_ai(CONTEXT, 30_000))  # type: ignore[arg-type]
    items = [candidate_for_gate(f"R{n}", "Malware", f"T{n}", []) for n in range(1, 5)]
    verdicts = gate.judge_candidates(S.TAMPERING, items)
    assert peak[0] > 1 and len(chat.asked(AiTask.RELEVANCE_GATE)) == 4
    assert [slot for slot, verdict in sorted(verdicts.items()) if verdict.relevant] == ["R1", "R3"]


def test_an_outage_in_one_batch_wins_over_a_bad_answer_in_another() -> None:
    """G121: all batches finish, then the retryable error is raised so the job retries."""

    def work(item: int) -> int:
        if item == 1:
            raise UnreadableAiAnswer("bad answer")
        if item == 2:
            raise Unavailable("provider down")
        return item

    with pytest.raises(Unavailable):
        run_in_parallel(work, [0, 1, 2, 3], 4, "test")
    assert run_in_parallel(lambda item: item * 2, [1, 2, 3], 2, "test") == [2, 4, 6]
