"""The lean relevance gate (plan Part C): one question judges every threat for all its own categories, the
answer is read slot by slot, category names strictly, and the plan makes one card per threat told as the
category the gate put first. Fake AI models; tests never read the developer's .env."""

import dataclasses
from typing import Any

import pytest
from structlog.testing import capture_logs

from app.core.ai_tuning_settings import AiTuningSettings
from app.core.constants import (
    CHAT_MAX_OUTPUT_TOKENS,
    AiLimits,
    AiTask,
    CandidateRejection,
    LogEvent,
)
from app.domain.scenario import plan as plan_module
from app.domain.scenario.plan import build_plan
from app.models.library.library import LibraryActor, LibraryThreat
from tests.fakes import FakeRerankModel, items_in, truncated
from tests.planner_samples import (
    ADMIN_ABUSE,
    CONTEXT,
    FLOOD,
    LOG_WIPE,
    PHISHING,
    RANSOMWARE,
    S,
    audit_of,
    finder,
    gap_fill,
    gap_filled,
    judged,
    planner_chat,
)

_DEFAULTS = AiTuningSettings.model_fields


@pytest.fixture(autouse=True)
def _shipped_gate_sizes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The code's own defaults, whatever the developer's .env says."""
    monkeypatch.setattr(plan_module, "GATE_BATCH_SIZE", _DEFAULTS["threats_per_question"].default)
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", _DEFAULTS["ai_call_tokens_limit"].default)
    gate_room = _DEFAULTS["answer_tokens_relevance_gate"].default
    monkeypatch.setitem(CHAT_MAX_OUTPUT_TOKENS, AiTask.RELEVANCE_GATE, gate_room)


def _library(count: int) -> tuple[LibraryThreat, ...]:
    """`count` library threats over the six categories, one or two each, every type linking an actor."""
    kinds, gang = list(S), (LibraryActor(1, "Ransomware gang"),)
    return tuple(
        LibraryThreat(n, f"Threat number {n}", n % 5, "Misuse", tuple(kinds[n % 6 : n % 6 + 2]), gang)
        for n in range(1, count + 1)
    )


def _answering(edit: dict[str, dict[str, Any]], relevant: dict[str, list[str]] | None = None) -> Any:
    """The sample gate, `relevant` threats applying on their systems, with each named threat's verdict
    changed by `edit` ({"drop": True}: its slot left out)."""
    gate = judged(relevant or {RANSOMWARE.name: ["SYS1"]})

    def answer(user_prompt: str) -> dict[str, Any]:
        threats = {item["slot"]: item["threat"] for item in items_in(user_prompt, "CANDIDATES")}
        verdicts = [
            verdict | edit.get(threats[verdict["slot"]], {}) for verdict in gate(user_prompt)["verdicts"]
        ]
        return {"verdicts": [verdict for verdict in verdicts if not verdict.get("drop")]}

    return answer


def test_a_plan_for_35_threats_makes_exactly_one_gate_call_and_41_make_two_split_evenly() -> None:
    for count, sizes in ((35, [35]), (41, [21, 20])):
        chat = planner_chat({"Threat number 3": ["SYS1"]})
        finder(chat, threats=_library(count)).find_threats(CONTEXT)
        asked = chat.asked(AiTask.RELEVANCE_GATE)
        assert [len(items_in(user, "CANDIDATES")) for user in asked] == sizes, count


def test_a_threat_applying_as_one_of_its_categories_is_rejected_under_the_other_sharing_its_place() -> None:
    """Ransomware is filed under Tampering and Denial of Service; the gate says it applies as Tampering only.
    With a need, it is refused under both."""
    as_tampering = {"categories": [{"name": "Tampering", "impact": "MEDIUM", "reason": "It encrypts SYS1."}]}
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _answering({RANSOMWARE.name: as_tampering})
    findings = finder(chat).find_threats(CONTEXT)
    (threat,) = [t for t in findings.threats if t.key == "lib:1"]
    assert threat.categories == (S.TAMPERING,) and (threat.systems, threat.impact, threat.confidence) == (
        (321,),
        2,
        80.0,
    )
    (denial,) = [r for r in audit_of(findings, S.DENIAL_OF_SERVICE).rejected if r["library_id"] == 1]
    assert (denial["code"], denial["detail"]) == (
        CandidateRejection.NOT_RELEVANT,
        "It applies as Tampering only.",
    )
    chat.responders[AiTask.RELEVANCE_GATE] = _answering({RANSOMWARE.name: as_tampering | {"needs": ["USB"]}})
    findings = finder(chat).find_threats(CONTEXT)
    assert findings.threats == []
    for kind in (S.TAMPERING, S.DENIAL_OF_SERVICE):
        (refused,) = [r for r in audit_of(findings, kind).rejected if r["library_id"] == 1]
        assert (refused["code"], refused["detail"]) == (CandidateRejection.NEEDS_UNRECORDED, "USB"), kind


def test_a_slot_missing_from_the_answer_is_asked_once_more_alone_and_the_others_are_kept() -> None:
    gate = judged({LOG_WIPE.name: ["SYS1"], FLOOD.name: ["SYS2"]})

    def without_the_log_wipe_at_first(user_prompt: str) -> dict[str, Any]:
        verdicts = gate(user_prompt)["verdicts"]
        whole = len(verdicts) > 1
        return {"verdicts": [v for v in verdicts if not (whole and v["threat"] == LOG_WIPE.name)]}

    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = without_the_log_wipe_at_first
    findings = finder(chat).find_threats(CONTEXT)
    whole, again = chat.asked(AiTask.RELEVANCE_GATE)
    assert len(items_in(whole, "CANDIDATES")) == 6
    assert [(item["slot"], item["threat"]) for item in items_in(again, "CANDIDATES")] == [
        ("R3", LOG_WIPE.name)
    ]
    assert sorted(threat.name for threat in findings.threats) == sorted([LOG_WIPE.name, FLOOD.name])


def test_a_cut_off_batch_is_asked_again_as_two_halves_both_judged() -> None:
    chat = planner_chat({})
    gate = judged({PHISHING.name: ["SYS1"], LOG_WIPE.name: ["SYS1"]})

    def cut_off_when_whole(user_prompt: str) -> dict[str, Any]:
        if len(items_in(user_prompt, "CANDIDATES")) > 1:
            raise truncated()
        return gate(user_prompt)

    chat.responders[AiTask.RELEVANCE_GATE] = cut_off_when_whole
    findings = finder(chat, threats=(PHISHING, LOG_WIPE)).find_threats(CONTEXT)
    asked = [
        [item["threat"] for item in items_in(user, "CANDIDATES")]
        for user in chat.asked(AiTask.RELEVANCE_GATE)
    ]
    assert asked == [[PHISHING.name, LOG_WIPE.name], [PHISHING.name], [LOG_WIPE.name]]
    assert sorted(threat.name for threat in findings.threats) == sorted([PHISHING.name, LOG_WIPE.name])


def test_a_batch_over_the_call_limit_is_sent_as_halves_each_under_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """CII_AI_CALL_TOKENS_LIMIT: the prompt's estimate plus the gate's answer room."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    finder(chat).find_threats(CONTEXT)
    (whole,) = chat.asked(AiTask.RELEVANCE_GATE)
    room, system = CHAT_MAX_OUTPUT_TOKENS[AiTask.RELEVANCE_GATE], len(plan_module._PLANNER_SYSTEM)

    def tokens(user: str) -> int:
        return (system + len(user)) // AiLimits.PROMPT_CHARS_PER_TOKEN + room

    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", tokens(whole) - 1)  # the whole batch: one token over
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    findings = finder(chat).find_threats(CONTEXT)
    asked = chat.asked(AiTask.RELEVANCE_GATE)
    assert [len(items_in(user, "CANDIDATES")) for user in asked] == [3, 3]
    assert all(tokens(user) <= AiLimits.CALL_TOKENS_LIMIT for user in asked)
    assert [threat.name for threat in findings.threats] == [RANSOMWARE.name]


def test_category_names_are_read_strictly_and_the_gates_first_category_leads_the_card() -> None:
    """ "Denial-of-Service" is Denial of Service; "DoS", no category, or another slot's threat is asked again;
    a STRIDE category the threat does not list is dropped with a warning naming it. Listed first, Denial of
    Service tells the one card, with Tampering as its other category, though STRIDE puts Tampering first."""
    both = {"name": "Denial-of-Service", "impact": "HIGH", "reason": "It stops SYS1."}
    both = {"categories": [both, {"name": "tampering", "impact": "HIGH", "reason": "It encrypts SYS1."}]}
    unlisted = {
        "categories": [{"name": "Spoofing", "impact": "LOW", "reason": "A fake login."}, *both["categories"]]
    }
    asked_again = {
        PHISHING.name: {"categories": [{"name": "Spoof", "impact": "HIGH", "reason": "Fake login."}]},
        LOG_WIPE.name: {"categories": []},
        FLOOD.name: {"threat": ADMIN_ABUSE.name},
    }
    relevant = {name: ["SYS1"] for name in (RANSOMWARE.name, PHISHING.name, LOG_WIPE.name, FLOOD.name)}
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _answering({RANSOMWARE.name: unlisted} | asked_again, relevant)
    with capture_logs() as logs:
        findings = finder(chat).find_threats(CONTEXT)
    _, *again = chat.asked(AiTask.RELEVANCE_GATE)  # the ask again, and its one corrective turn: still wrong
    bad = {PHISHING.name, LOG_WIPE.name, FLOOD.name}
    assert len(again) == 2 and all(
        {i["threat"] for i in items_in(user, "CANDIDATES")} == bad for user in again
    )
    assert audit_of(findings, S.REPUDIATION).not_judged == [LOG_WIPE]  # not judged; the job never retries
    dropped = [e for e in logs if e["event"] == LogEvent.PLANNER_THREATS_NOT_JUDGED and "threat_key" in e]
    assert [(e["threat_key"], e["categories"]) for e in dropped] == [("lib:1", [S.SPOOFING])]
    skipped = [e["asked"] for e in logs if e["event"] == LogEvent.PLANNER_THREATS_NOT_JUDGED and "asked" in e]
    assert skipped == [[PHISHING.name, LOG_WIPE.name, FLOOD.name]]  # the ask again: logged, then not judged
    (ransomware,) = [threat for threat in findings.threats if threat.key == "lib:1"]
    assert ransomware.categories == (S.DENIAL_OF_SERVICE, S.TAMPERING)
    assert ransomware.reason == "It stops SCADA server."  # its main category's, aliases named
    plan = build_plan(dataclasses.replace(findings, threats=[ransomware]), 0)
    (card,) = plan["paths"]  # one card per threat
    assert (card["category"], card["categories"]) == (S.DENIAL_OF_SERVICE, [S.DENIAL_OF_SERVICE, S.TAMPERING])
    assert plan["threats"][0]["category"] == S.DENIAL_OF_SERVICE == card["category"]


def test_the_gates_actions_reach_the_plan_by_system_name_with_no_split_call() -> None:
    acts = {"actions": ["alter SYS2 setpoints", " stop  SYS1 ", 7]}
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _answering({FLOOD.name: acts}, {FLOOD.name: ["SYS1", "SYS2"]})
    plan = build_plan(finder(chat).find_threats(CONTEXT), 0)
    (threat,) = plan["threats"]
    assert threat["actions"] == ["alter Historian setpoints", "stop SCADA server"]
    assert {task for task, _ in chat.calls} == {AiTask.RELEVANCE_GATE, AiTask.GAP_FILL}


def test_no_planner_prompt_carries_a_database_id() -> None:
    """Catalogue, type, actor and system ids never reach the AI: names, slots and aliases only."""
    actor = LibraryActor(50917, "Ransomware gang")
    odd = tuple(
        dataclasses.replace(threat, catalogue_id=90100 + n, type_id=70100 + n, linked_actors=(actor,))
        for n, threat in enumerate((RANSOMWARE, PHISHING, ADMIN_ABUSE))
    )
    proposal = {"applies": True, "threat_type": "Misuse", "threat": "Insider misuse", "attacker": "Anyone"}
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], proposal["threat"]: ["SYS2"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill({S.ELEVATION_OF_PRIVILEGE: proposal | {"reason": "It fits."}})
    rerank = FakeRerankModel({("Misuse", "Privilege misuse"): 90.0})
    finder(chat, rerank, threats=odd, actors=(actor,)).find_threats(CONTEXT)
    prompts = [user for _, user in chat.calls]
    assert len(prompts) == 3 and any(proposal["threat"] in user for user in chat.asked(AiTask.RELEVANCE_GATE))
    ids = [90100, 90101, 90102, 70100, 70101, 70102, 50917, 321, 322, 103, "lib:", "ai:"]
    assert [(i, user[:40]) for user in prompts for i in ids if str(i) in user] == []


def test_two_empty_categories_cost_one_gap_fill_and_one_gate_check() -> None:
    """Information Disclosure and Elevation of Privilege find no library threat: one ask proposes one threat
    for each, and one gate call judges both proposals; the first does not apply."""
    proposals = {
        kind: {"applies": True, "threat_type": kind_type, "threat": name, "attacker": "Anyone", "systems": []}
        | {"reason": "It fits."}
        for kind, kind_type, name in (
            (S.INFORMATION_DISCLOSURE, "Malware", "Data copied off SYS1"),
            (S.ELEVATION_OF_PRIVILEGE, "Privilege misuse", "Admin grab"),
        )
    }
    chat = planner_chat(
        {name: ["SYS1"] for name in (RANSOMWARE.name, PHISHING.name, LOG_WIPE.name, "Admin grab")}
    )
    chat.responders[AiTask.GAP_FILL] = gap_fill(proposals)
    rerank = FakeRerankModel({(name, name): 90.0 for name in ("Malware", "Privilege misuse")})
    findings = finder(chat, rerank).find_threats(CONTEXT)
    assert len(chat.asked(AiTask.GAP_FILL)) == 1  # one ask for both categories
    assert gap_filled(chat) == [S.INFORMATION_DISCLOSURE, S.ELEVATION_OF_PRIVILEGE]
    whole, check = chat.asked(AiTask.RELEVANCE_GATE)  # the library, then both proposals at once
    shown = [(item["threat"], item["categories"]) for item in items_in(check, "CANDIDATES")]
    assert shown == [
        ("Data copied off SYS1", [S.INFORMATION_DISCLOSURE]),
        ("Admin grab", [S.ELEVATION_OF_PRIVILEGE]),
    ]
    assert [t.name for t in findings.threats if t.catalogue_id is None] == ["Admin grab"]
    lost = audit_of(findings, S.INFORMATION_DISCLOSURE).gap_fill_lost
    assert lost is not None and lost["reason"] == CandidateRejection.NOT_RELEVANT
    assert len(items_in(whole, "CANDIDATES")) == 6
