"""Threat finding on an in-memory library with fake AI models: the landscape, the relevance gate, gap fill,
one threat per threat and who carries out each threat."""

import dataclasses
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from app.ai import UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import ActorRole, AiTask, AttackerCheck, CandidateRejection, ErrorCode
from app.core.exceptions import PlanRefused, Unavailable
from app.domain.scenario import plan as plan_module
from app.domain.scenario.plan import (
    ThreatFinder,
    assign_attackers,
    build_plan,
    describe_asset_for_ai,
    merge_reworded_threats,
    merge_same_threats,
    parse_verdict,
    relevance_gate_prompt,
    threat_from_library,
)
from app.domain.shared.names import replace_codes_with_names
from app.domain.shared.parallel import run_in_parallel
from app.models.library.library import LibraryActor, ThreatLibrary
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.plan import ActorPick, PlannedActor, PlannedThreat, Verdict
from app.search.service import LibrarySearch
from tests.fakes import FakeEmbeddings, FakeRerankModel, items_in, truncated
from tests.planner_samples import (
    ACTORS,
    ADMIN_ABUSE,
    CONTEXT,
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

_PROPOSAL = {
    "applies": True,
    "threat_type": "Privilege misuse",
    "threat": "Engineering workstation takeover",
    "attacker": "Nation-state group",
    "systems": ["SYS1"],
    "reason": "SYS1 runs engineering tools.",
}
#: The reranker matching the proposal's type to the library's "Privilege misuse".
_TYPE_MATCHES = {("Privilege misuse", "Privilege misuse"): 90.0}


def _library_threat(category: S, threat: Any, verdict: Verdict) -> PlannedThreat:
    return PlannedThreat(
        key=f"lib:{threat.catalogue_id}",
        catalogue_id=threat.catalogue_id,
        type_id=threat.type_id,
        type_name=threat.type_name,
        name=threat.name,
        categories=(category,),
        systems=verdict.systems,
        impact=verdict.impact,
        confidence=verdict.confidence,
        reason=verdict.reason,
        actor_pick=verdict.actor_pick,
    )


def test_the_landscape_names_systems_by_alias_and_keeps_to_its_budget() -> None:
    landscape = describe_asset_for_ai(CONTEXT, budget=30_000)
    assert landscape.text.startswith(
        'ASSET: {"asset": "Grid Control Centre", "asset_context": {"sector": "Energy"'
    )
    assert '\nSYS1 "SCADA server": {"name": "SCADA server", "asset_type": "OT"' in landscape.text
    assert "321" not in landscape.text and '"alias"' not in landscape.text  # never a database id
    assert "backup_tested" not in landscape.text  # an unrecorded fact is left out, never written as "no"
    assert landscape.system_ids == {"SYS1": 321, "SYS2": 322}
    listed = '"supporting_systems": [{"name": "SCADA server", "asset_type": "OT"}, {"name": "Historian"'
    assert listed in landscape.text and not landscape.cut  # the asset's systems by name and asset type
    wordy_scada = system_row(321, "SYS1", "SCADA server", past_incidents="Outage after a patch. " * 30)
    wordy = FrozenContext(**{**CONTEXT.to_record(), "systems": [wordy_scada, CONTEXT.systems[1]]})
    squeezed = describe_asset_for_ai(wordy, budget=1_200)
    # The longest fact is cut, never the last system: every system keeps its line, name and asset type.
    assert len(squeezed.text) <= 1_200 and squeezed.cut
    assert '\nSYS2 "Historian": {"name": "Historian"' in squeezed.text
    scada_line = next(line for line in squeezed.text.splitlines() if line.startswith("SYS1 "))
    assert "…" in scada_line and '"asset_type": "OT"' in scada_line


def test_a_verdict_is_checked_in_code_and_a_rejection_needs_no_impact() -> None:
    bad = {
        "slot": "R1",
        "relevant": True,
        "systems": ["SYS9"],
        "reason": "",
        "impact": "BIG",
        "confidence": 101,
    }
    assert parse_verdict(bad, {"SYS1": 321}, [])[1] == [
        "R1: systems must be listed aliases only (SYS1, SYS2 ...)",
        "R1: impact must be HIGH, MEDIUM or LOW",
        "R1: confidence must be a number from 0 to 100",
        "R1: every verdict needs its reason, a rejection's too",
    ]
    not_an_alias = {"slot": "R1", "relevant": True, "systems": [["SYS1"]], "reason": "On SYS1."}
    verdict, problems = parse_verdict(not_an_alias | {"impact": "HIGH", "confidence": 80}, {"SYS1": 321}, [])
    assert verdict is None and problems == ["R1: systems must be listed aliases only (SYS1, SYS2 ...)"]
    rejection = {"slot": "R2", "relevant": False, "systems": [], "reason": "No mail.", "impact": "N/A"}
    verdict, problems = parse_verdict(rejection | {"confidence": 5}, {"SYS1": 321}, [])
    assert problems == [] and verdict == Verdict(False, (), "No mail.", 0, 5.0)


def test_a_relevant_verdict_names_its_ways_in_among_its_own_systems() -> None:
    """The gate says through which of a threat's systems an attacker could get in: at least one when it
    names systems, never one it does not name; a rejection needs none, and the asset itself has none."""
    aliases = {"SYS1": 321, "SYS2": 322}
    relevant = {"slot": "R1", "relevant": True, "systems": ["SYS1", "SYS2"], "reason": "On both."}
    relevant |= {"impact": "HIGH", "confidence": 80}
    assert parse_verdict(relevant, aliases, [])[1] == [
        "R1: entry_points must name the systems among its own an attacker could get in through"
    ]
    outside = relevant | {"systems": ["SYS1"], "entry_points": ["SYS2"]}
    assert parse_verdict(outside, aliases, [])[1] == ["R1: entry_points must be aliases from its own systems"]
    verdict, problems = parse_verdict(relevant | {"entry_points": ["SYS2"]}, aliases, [])
    assert problems == [] and verdict is not None
    assert (verdict.systems, verdict.entry_points) == ((321, 322), (322,))
    rejected = relevant | {"relevant": False, "impact": None, "entry_points": ["SYS9"]}
    assert parse_verdict(rejected, aliases, [])[1] == []
    asset = relevant | {"systems": [], "entry_points": []}
    assert parse_verdict(asset, aliases, [])[0] == Verdict(True, (), "On both.", 3, 80.0)
    prompt = relevance_gate_prompt("LANDSCAPE", S.TAMPERING, [{"slot": "R1"}])[1]
    assert '"entry_points": ["SYS1"]' in prompt and "one, several or all of them" in prompt


def test_an_unreadable_gate_reply_retries_before_gap_fill_and_a_cut_off_one_is_skipped() -> None:
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda u: (
        {"verdicts": "?"} if "category: Spoofing" in u else gate(u)
    )
    with pytest.raises(Unavailable):
        finder(chat).find_threats(CONTEXT)
    assert chat.asked(AiTask.GAP_FILL) == []

    def cut_off_spoofing(user_prompt: str) -> dict[str, Any]:
        if "category: Spoofing" in user_prompt:
            raise truncated()
        return gate(user_prompt)

    chat.responders[AiTask.RELEVANCE_GATE] = cut_off_spoofing
    assert [threat.name for threat in finder(chat).find_threats(CONTEXT).threats] == [LOG_WIPE.name]


def test_on_the_last_attempt_a_broken_batch_is_skipped_and_its_category_gets_no_gap_fill() -> None:
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda u: (
        {"verdicts": "?"} if "category: Spoofing" in u else gate(u)
    )
    findings = finder(chat).find_threats(CONTEXT, last_attempt=True)
    spoofing = audit_of(findings, S.SPOOFING)
    assert spoofing.judged_ids == set() and spoofing.rejected == []
    assert len([user for user in chat.asked(AiTask.RELEVANCE_GATE) if "category: Spoofing" in user]) == 2
    assert not any("category: Spoofing" in user for user in chat.asked(AiTask.GAP_FILL))
    assert [threat.name for threat in findings.threats] == [LOG_WIPE.name]


def test_an_unusable_batch_on_the_last_attempt_costs_only_its_own_threats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plan_module, "GATE_BATCH_SIZE", 1)  # one threat per batch
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], FLOOD.name: ["SYS2"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if "category: Denial of Service" in user and FLOOD.name in user else gate(user)
    )
    findings = finder(chat).find_threats(CONTEXT, last_attempt=True)
    denial = audit_of(findings, S.DENIAL_OF_SERVICE)
    assert [threat.name for threat in findings.threats] == [RANSOMWARE.name]  # its good verdict is kept
    assert denial.judged_ids == {RANSOMWARE.catalogue_id}
    plan = build_plan(findings, 0)
    assert any(S.DENIAL_OF_SERVICE in path["categories"] for path in plan["paths"])  # it has a scenario


def test_an_asset_no_library_threat_fits_asks_no_gate_and_plans_nothing() -> None:
    chat = planner_chat({})
    it_only = dataclasses.replace(LOG_WIPE, asset_type="IT")  # linked to an actor; the asset is OT
    findings = finder(chat, threats=(it_only,)).find_threats(CONTEXT, last_attempt=True)
    assert findings.threats == [] and chat.asked(AiTask.RELEVANCE_GATE) == []


def test_gap_fill_comes_after_the_whole_category_takes_a_library_type_and_the_gates_attacker() -> None:
    """The AI's attacker text is never used: the gate picks among the matched type's linked actors."""
    chat = planner_chat({_PROPOSAL["threat"]: ["SYS1"], LOG_WIPE.name: ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL)
    answer, listed = chat.responders[AiTask.RELEVANCE_GATE], {}

    def picking(user_prompt: str) -> dict[str, Any]:
        verdicts = answer(user_prompt)["verdicts"]
        for item, verdict in zip(items_in(user_prompt, "CANDIDATES"), verdicts, strict=True):
            listed[item["threat"]] = item["attackers"]
            if item["threat"] == _PROPOSAL["threat"]:
                verdict |= {"attacker": INSIDER.name, "attacker_reason": "Holds the engineering login."}
        return {"verdicts": verdicts}

    chat.responders[AiTask.RELEVANCE_GATE] = picking
    rerank = FakeRerankModel(_TYPE_MATCHES)
    findings = finder(chat, rerank).find_threats(CONTEXT)
    (ai_threat,) = [threat for threat in findings.threats if not threat_from_library(threat)]
    assert ai_threat.key == "ai:engineering workstation takeover"
    assert (ai_threat.type_id, ai_threat.type_name) == (5, "Privilege misuse")  # the library type
    assert listed[_PROPOSAL["threat"]] == [INSIDER.name]  # its type's linked actor, never the AI's text
    assert ai_threat.actors == (PlannedActor(INSIDER.actor_id, INSIDER.name, ActorRole.ACTING),)
    assert ai_threat.attacker_check == AttackerCheck.CHOSEN
    assert ai_threat.attacker_check_reason == "Holds the engineering login."
    assert "Nation-state group" not in str(chat.asked(AiTask.RELEVANCE_GATE))
    assert all(query != "Nation-state group" for query, _ in rerank.calls)
    (elevation,) = [user for user in chat.asked(AiTask.GAP_FILL) if "category: Elevation" in user]
    assert f'- "{ADMIN_ABUSE.name}"' in elevation  # the rejected library threat is named: never proposed
    assert not any("category: Repudiation" in user for user in chat.asked(AiTask.GAP_FILL))  # one applied


def test_a_proposal_whose_type_matches_no_library_type_is_never_planned() -> None:
    chat = planner_chat({_PROPOSAL["threat"]: ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL | {"threat_type": "Quantum sabotage"})
    findings = finder(chat, FakeRerankModel()).find_threats(CONTEXT)  # no type scores at the bar
    assert all(threat_from_library(threat) for threat in findings.threats)
    assert not any(_PROPOSAL["threat"] in user for user in chat.asked(AiTask.RELEVANCE_GATE))


def test_a_proposal_whose_type_links_no_attacker_is_never_judged() -> None:
    chat = planner_chat({_PROPOSAL["threat"]: ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL)
    unlinked = dataclasses.replace(ADMIN_ABUSE, linked_actors=())
    threats = tuple(unlinked if threat is ADMIN_ABUSE else threat for threat in THREATS)
    findings = finder(chat, FakeRerankModel(_TYPE_MATCHES), threats=threats).find_threats(CONTEXT)
    assert any("category: Elevation" in user for user in chat.asked(AiTask.GAP_FILL))
    assert all(threat_from_library(threat) for threat in findings.threats)
    assert not any(_PROPOSAL["threat"] in user for user in chat.asked(AiTask.RELEVANCE_GATE))


def test_a_proposal_the_gate_cannot_judge_retries_the_job_and_on_the_last_attempt_is_dropped() -> None:
    chat = planner_chat({LOG_WIPE.name: ["SYS1"]})
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if _PROPOSAL["threat"] in user else gate(user)
    )
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(_PROPOSAL)
    with pytest.raises(Unavailable):
        finder(chat, FakeRerankModel(_TYPE_MATCHES)).find_threats(CONTEXT)
    findings = finder(chat, FakeRerankModel(_TYPE_MATCHES)).find_threats(CONTEXT, last_attempt=True)
    assert all(threat_from_library(threat) for threat in findings.threats)
    elevation = audit_of(findings, S.ELEVATION_OF_PRIVILEGE)
    assert [rejected["code"] for rejected in elevation.rejected] == [CandidateRejection.NOT_RELEVANT]


def test_a_proposal_repeating_a_library_threat_is_dropped_at_the_threat_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THREAT_SIMILARITY_THRESHOLD decides when a proposal IS a library threat: scored 80, it repeats one at
    the default 75 and is a new threat at 85."""
    proposal = _PROPOSAL | {"threat": "Insider misuses admin rights", "systems": []}

    def ai_threats() -> list[str]:
        chat = planner_chat({proposal["threat"]: []})
        chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
        scores = {(proposal["threat"], ADMIN_ABUSE.name): 80.0} | _TYPE_MATCHES
        found = finder(chat, FakeRerankModel(scores)).find_threats(CONTEXT)
        return [threat.name for threat in found.threats if not threat_from_library(threat)]

    assert ai_threats() == []
    monkeypatch.setattr(get_settings(), "threat_similarity_threshold", 85.0)
    assert ai_threats() == [proposal["threat"]]


def test_one_library_threat_found_under_two_categories_is_one_threat() -> None:
    tampering = planned("lib:1", RANSOMWARE.name, (321,), impact=2)
    denial = planned("lib:1", RANSOMWARE.name, (322,), categories=(S.DENIAL_OF_SERVICE,), impact=3)
    (merged,) = merge_same_threats([denial, tampering])
    assert merged.categories == (S.TAMPERING, S.DENIAL_OF_SERVICE) and merged.systems == (321, 322)
    assert merged.impact == 3


def test_an_ai_threat_named_like_a_library_threat_of_its_type_is_that_library_threat() -> None:
    """The library name keeps its code, the AI's has none; of another type, both are kept."""
    library = planned("lib:1", f"T1486 {RANSOMWARE.name}", (321,))
    ai_twin = planned("ai:x", RANSOMWARE.name, (322,), categories=(S.DENIAL_OF_SERVICE,))
    (kept,) = merge_same_threats([library, ai_twin])
    assert kept.key == "lib:1" and kept.systems == (321, 322)
    assert kept.categories == (S.TAMPERING, S.DENIAL_OF_SERVICE)
    other_type = planned("ai:x", RANSOMWARE.name, (322,), type_id=5, type_name="Privilege misuse")
    assert [threat.key for threat in merge_same_threats([library, other_type])] == ["ai:x", "lib:1"]


def test_an_ai_rewording_of_the_same_type_is_folded_by_meaning() -> None:
    """Compared without the asset's name; another type, or a different threat, is kept."""
    library = planned("lib:1", RANSOMWARE.name)
    reworded = planned("ai:a", "Ransomware locking the backup of Grid Control Centre", (322,))
    different = planned("ai:b", "Phishing of operators")
    other_type = planned("ai:c", "Ransomware locking the backup", (322,), type_id=5)
    embeddings = FakeEmbeddings(WORDS)
    kept = merge_reworded_threats(
        [library, reworded, different, other_type], embeddings, "Grid Control Centre"
    )  # type: ignore[arg-type]
    assert [threat.key for threat in kept] == ["lib:1", "ai:b", "ai:c"] and kept[0].systems == (321, 322)


def test_attackers_are_chosen_only_for_threats_left_after_the_merges(monkeypatch: pytest.MonkeyPatch) -> None:
    assigned: list[list[str]] = []

    def recording(snapshot: Any, threats: list[PlannedThreat], sector: str) -> Any:
        assigned.append([threat.key for threat in threats])
        return assign_attackers(snapshot, threats, sector)

    monkeypatch.setattr(plan_module, "assign_attackers", recording)
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    twin = _PROPOSAL | {
        "threat_type": "Malware",
        "threat": RANSOMWARE.name,
    }  # the gap fill names a library one
    chat.responders[AiTask.GAP_FILL] = lambda user: (
        twin if "category: Information Disclosure" in user else {"applies": False, "reason": "None."}
    )
    findings = finder(chat, FakeRerankModel({("Malware", "Malware"): 90.0})).find_threats(CONTEXT)
    assert assigned == [[threat.key for threat in findings.threats]] == [["lib:1"]]


def test_a_linked_type_ranks_its_own_actors_and_an_unlinked_one_gets_no_attacker() -> None:
    unlinked = dataclasses.replace(PHISHING, linked_actors=())
    search, _ = library_search(threats=(RANSOMWARE, unlinked))
    verdict = Verdict(True, (321,), "It encrypts the backup.", 3, 80.0)
    ransomware, phishing = assign_attackers(
        search.snapshot(),
        [_library_threat(S.TAMPERING, RANSOMWARE, verdict), _library_threat(S.SPOOFING, unlinked, verdict)],
        "Energy",
    )
    assert ransomware.actors[0].actor_id == GANG.actor_id
    assert phishing.actors == ()


def test_the_gates_pick_acts_none_fits_names_no_one_and_no_pick_takes_the_top_linked_actor() -> None:
    search, embeddings = library_search()
    snapshot = search.snapshot()

    def chosen(verdict: Verdict) -> PlannedThreat:
        (decided,) = assign_attackers(snapshot, [_library_threat(S.TAMPERING, RANSOMWARE, verdict)], "Energy")
        return decided

    pick = ActorPick(INSIDER.name, "Holds the backup admin account.")
    picked = chosen(Verdict(True, (321,), "Encrypts SYS1.", 3, 80.0, actor_pick=pick))
    assert picked.actors[0].actor_id == INSIDER.actor_id and picked.attacker_check == AttackerCheck.CHOSEN
    assert picked.attacker_check_reason == "Holds the backup admin account."
    nobody = chosen(Verdict(True, (321,), "Encrypts SYS1.", 3, 80.0, actor_pick=ActorPick(None, "None.")))
    assert nobody.attacker_check == AttackerCheck.NONE_FITS and nobody.actors == ()
    unchecked = chosen(Verdict(True, (321,), "Encrypts SYS1.", 3, 80.0))
    assert (
        unchecked.attacker_check == AttackerCheck.NOT_CHECKED
        and unchecked.actors[0].actor_id == GANG.actor_id
    )
    embeddings.queries_down = True
    with pytest.raises(Unavailable):  # no vectors, no ranking: the job retries
        chosen(Verdict(True, (321,), "Encrypts SYS1.", 3, 80.0))


def test_one_run_reads_one_library_version_even_when_the_library_changes_meanwhile() -> None:
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
    assert findings.category_ids == {"denial of service": 6, "tampering": 5}  # from the same version


def test_a_library_linking_no_actor_refuses_the_plan_before_any_ai_call() -> None:
    chat = planner_chat({})
    unlinked = tuple(dataclasses.replace(threat, linked_actors=()) for threat in THREATS)
    with pytest.raises(PlanRefused) as refused:
        finder(chat, threats=unlinked).find_threats(CONTEXT)
    assert refused.value.code == ErrorCode.ACTOR_LIBRARY_EMPTY and chat.calls == []


def test_every_alias_the_ai_wrote_reads_as_the_system_name() -> None:
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
    assert replace_codes_with_names("STEP7 project on SYS1", names) == "STEP7 project on SCADA system"
    findings = finder(planner_chat({LOG_WIPE.name: ["SYS1"]})).find_threats(CONTEXT)
    assert findings.threats[0].reason == f"{LOG_WIPE.name} hits SCADA server."


def test_every_category_judges_every_library_threat_of_it_in_library_order() -> None:
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    findings = finder(chat).find_threats(CONTEXT)
    for audit in findings.audits:
        in_category = {threat.catalogue_id for threat in THREATS if audit.category in threat.categories}
        assert audit.judged_ids == in_category, audit.category
    (denial,) = [user for user in chat.asked(AiTask.RELEVANCE_GATE) if "category: Denial of Service" in user]
    assert [c["threat"] for c in items_in(denial, "CANDIDATES")] == [RANSOMWARE.name, FLOOD.name]


def test_gate_batches_run_at_once_and_every_threat_keeps_its_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plan_module, "GATE_BATCH_SIZE", 1)
    running, peak, lock = [0], [0], threading.Lock()
    gate_answer = judged({RANSOMWARE.name: ["SYS1"], FLOOD.name: ["SYS2"]})

    def slow_answer(user_prompt: str) -> dict[str, Any]:
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
        return gate_answer(user_prompt)

    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = slow_answer
    findings = finder(chat).find_threats(CONTEXT)
    judged_pairs = sum(len(threat.categories) for threat in THREATS)
    assert peak[0] > 1 and len(chat.asked(AiTask.RELEVANCE_GATE)) == judged_pairs
    assert sorted(threat.name for threat in findings.threats) == sorted([FLOOD.name, RANSOMWARE.name])


def test_an_outage_in_one_call_wins_over_a_bad_answer_in_another() -> None:
    """All calls finish, then the retryable error is raised so the job retries."""

    def work(item: int) -> int:
        if item == 1:
            raise UnreadableAiAnswer("bad answer")
        if item == 2:
            raise Unavailable("provider down")
        return item

    with pytest.raises(Unavailable):
        run_in_parallel(work, [0, 1, 2, 3], 4, "test")
    assert run_in_parallel(lambda item: item * 2, [1, 2, 3], 2, "test") == [2, 4, 6]


def test_the_landscape_cut_is_even_and_never_blanks_a_fact() -> None:
    """Over budget, every long fact is cut to one common length, the first systems no less than the last; a
    fact cut to nothing is left out (unknown), never written as ""."""
    long_systems = [system_row(321 + n, f"SYS{n + 1}", f"S{n}", description="word " * 80) for n in range(6)]
    context = FrozenContext(**{**CONTEXT.to_record(), "systems": long_systems})
    squeezed = describe_asset_for_ai(context, budget=1_800)
    lines = [line for line in squeezed.text.splitlines() if line.startswith("SYS")]
    assert len(lines) == 6 and squeezed.cut and len(squeezed.text) <= 1_800
    lengths = {len(line) for line in lines}
    assert max(lengths) - min(lengths) <= 2  # one common length, give or take the alias digits
    assert '""' not in squeezed.text
    unrecorded = system_row(330, "SYS1", "Historian", category_name=None)
    listed = describe_asset_for_ai(FrozenContext(**{**CONTEXT.to_record(), "systems": [unrecorded]}), 30_000)
    assert '"supporting_systems": [{"name": "Historian"}]' in listed.text  # no asset type: left out, not null
