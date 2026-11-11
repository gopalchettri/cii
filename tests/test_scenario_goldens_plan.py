"""Golden copies of planning: every prompt, embedding text and reranker call threat finding makes, and
the plan and trace it stores, for fixed fake answers. A difference is a behaviour change: only the plan's
listed ones may change a file (tests/goldens/scenario/plan_*.json)."""

import dataclasses
from types import SimpleNamespace
from typing import Any

import pytest

from app.ai import UnreadableAiAnswer
from app.core.constants import AiTask, ThreatFinding
from app.core.exceptions import PlanRefused, Unavailable
from app.domain.scenario.plan import ThreatFinder, build_plan, build_plan_trace
from app.models.library.library import LibraryActor, LibraryThreat, ThreatLibrary
from app.models.scenario.asset_context import FrozenContext
from app.search.service import LibrarySearch
from tests.fakes import FakeRerankModel, truncated
from tests.planner_samples import ACTORS, CONTEXT, THREATS, WORDS, system_row
from tests.scenario_goldens import (
    MANY_LIBRARY,
    RecordingChat,
    RecordingEmbeddings,
    S,
    check_golden,
    gap_fill_by_spec,
    gate_by_spec,
    rerank_calls,
)

CATEGORY_IDS = tuple((11 + number, str(kind)) for number, kind in enumerate(S))
LIBRARY = ThreatLibrary(THREATS, ACTORS, category_ids=CATEGORY_IDS)
#: The batching golden's context: the Historian is an IT system, so an IT-only threat fits it alone.
MIXED_TYPES = dataclasses.replace(
    CONTEXT,
    systems=[CONTEXT.systems[0], CONTEXT.systems[1] | {"category_code": "IT", "category_name": "IT"}],
)
THREE_SYSTEMS = dataclasses.replace(
    CONTEXT, systems=[*CONTEXT.systems, system_row(323, "SYS3", "Operator HMI", technology_used=["Windows"])]
)


@pytest.fixture(autouse=True)
def _fixed_planner(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate's batch size and call order as the goldens were made with."""
    assert ThreatFinding.THREATS_PER_QUESTION == 40, "goldens assume CII_THREATS_PER_QUESTION=40"
    assert ThreatFinding.AI_BATCHES_AT_ONCE == 1, "goldens assume CII_THREAT_QUESTIONS_AT_ONCE=1"


def _finder(chat: RecordingChat, rerank: FakeRerankModel, library: ThreatLibrary) -> tuple[ThreatFinder, Any]:
    loaded = SimpleNamespace(
        threat_library=library, control_library=(), stamp=(("Threat_Catalogue", b"\x01"),)
    )
    embeddings = RecordingEmbeddings(WORDS)
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: loaded), embeddings)  # type: ignore[arg-type]
    search.snapshot()
    return ThreatFinder(chat, search, rerank, embeddings), embeddings  # type: ignore[arg-type]


def _plan_golden(
    name: str,
    chat: RecordingChat,
    library: ThreatLibrary,
    context: FrozenContext = CONTEXT,
    rerank: FakeRerankModel | None = None,
    target: int = 0,
    last_attempt: bool = False,
) -> None:
    """Find the threats, build the plan and its trace, and compare everything asked and stored."""
    rerank = rerank or FakeRerankModel()
    finder, embeddings = _finder(chat, rerank, library)
    findings = finder.find_threats(context, "", is_last_attempt=last_attempt)
    plan = build_plan(findings, target)
    trace = build_plan_trace(findings, plan, 6)
    stored = {
        "plan": plan,
        "trace": trace,
        "library_stamp": findings.library_stamp,
        "category_ids": findings.category_ids,
        "library_threats": findings.library_threats,
        "ai_threats": findings.ai_threats,
    }
    asked = {"asks": chat.asks, "embeddings": embeddings.texts, "reranks": rerank_calls(rerank)}
    check_golden(f"plan_{name}", {"stored": stored, "asked": asked})


def test_golden_plan_mixed_verdicts_gap_fill_losses_and_an_ai_threat_named_by_alias() -> None:
    chat = RecordingChat()
    gate = {
        "Ransomware encrypts backup servers": {
            "impacts": {"Tampering": "HIGH", "Denial of Service": "MEDIUM"},
            "systems": ["SYS1", "SYS2"],
            "entry_points": ["SYS1"],
            "attacker": "Ransomware gang",
            "actions": ["encrypt the backups on SYS1", "demand a ransom"],
        },
        "Phishing steals operator credentials": {
            "systems": ["SYS1", "SYS2"],
            "entry_points": ["SYS2"],
            "attacker": "Phishing crew",
            "likelihood": "HIGH",
            "confidence": 65,
        },
        "Insider deletes audit logs": {"needs": ["a central log server"]},
        "Ransomware exfiltrates data": {"relevant": False, "reason": "No data leaves the control network."},
        "Flood of requests overwhelms the historian": {"systems": ["SYS2"], "attacker": "A botnet herder"},
        "Contractor escalates rights on SYS1 HMI": {"systems": ["SYS1"], "attacker": "Malicious insider"},
    }
    chat.responders[AiTask.RELEVANCE_GATE] = gate_by_spec(gate)
    proposals = {
        "Repudiation": {
            "applies": True,
            "threat_type": "Insider misuse",
            "threat": "Insider erases audit trail on SYS1",
            "reason": "An insider could hide changes.",
            "systems": ["SYS1"],
        },
        "Information Disclosure": {
            "applies": True,
            "threat_type": "Data theft",
            "threat": "Ransomware exfiltrates historian records",
            "reason": "Records could leave.",
            "systems": ["SYS2"],
        },
        "Elevation of Privilege": {
            "applies": True,
            "threat_type": "Privilege misuse",
            "threat": "Contractor escalates rights on SYS1 HMI",
            "reason": "A contractor could gain admin rights.",
            "systems": ["SYS1"],
        },
    }
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec(proposals)
    rerank = FakeRerankModel(
        {
            ("Insider erases audit trail on SYS1", "Insider deletes audit logs"): 90.0,
            ("Privilege misuse", "Privilege misuse"): 95.0,
        }
    )
    _plan_golden("mixed", chat, LIBRARY, rerank=rerank, target=2)


def test_golden_plan_twins_fold_by_name_and_by_rewording() -> None:
    chat = RecordingChat()
    library = ThreatLibrary(THREATS[:2] + THREATS[3:4], ACTORS, category_ids=CATEGORY_IDS)
    gate = {
        "Ransomware encrypts backup servers": {
            "impacts": {"Tampering": "HIGH"},
            "attacker": "Ransomware gang",
        },
        "Ransomware hits backup": {"systems": ["SYS2"], "attacker": "Ransomware gang", "likelihood": "HIGH"},
        "Phishing crew spoofs control room staff": {"systems": ["SYS1"], "attacker": "Phishing crew"},
    }
    chat.responders[AiTask.RELEVANCE_GATE] = gate_by_spec(gate)
    proposals = {
        "Denial of Service": {
            "applies": True,
            "threat_type": "Malware",
            "threat": "Ransomware encrypts backup servers",
            "reason": "It could stop the servers.",
            "systems": ["SYS1"],
        },
        "Information Disclosure": {
            "applies": True,
            "threat_type": "Malware",
            "threat": "Ransomware hits backup",
            "reason": "Backups could leak.",
            "systems": ["SYS2"],
        },
        "Spoofing": {
            "applies": True,
            "threat_type": "Social engineering",
            "threat": "Phishing crew spoofs control room staff",
            "reason": "Staff could be fooled.",
            "systems": ["SYS1"],
        },
        "Elevation of Privilege": {
            "applies": True,
            "threat_type": "Root access",
            "threat": "Attacker gains root on SYS1",
            "reason": "Root could be gained.",
            "systems": ["SYS1"],
        },
    }
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec(proposals)
    rerank = FakeRerankModel(
        {("Malware", "Malware"): 95.0, ("Social engineering", "Social engineering"): 95.0}
    )
    _plan_golden("twins", chat, library, rerank=rerank)


def _batches_gate() -> Any:
    """Every fifth threat applies; threat 30 first names an unknown system, then answers well."""
    spec: dict[str, dict[str, Any]] = {}
    for number in range(0, 45, 5):
        systems = [["SYS1"], ["SYS2"], ["SYS1", "SYS2"]][number % 3] if number != 10 else ["SYS1"]
        spec[f"Threat number {number} against control systems"] = {"systems": systems}
    answer, asked_30 = gate_by_spec(spec), []

    def respond(user_prompt: str) -> dict[str, Any]:
        verdicts = answer(user_prompt)
        for verdict in verdicts["verdicts"]:
            if verdict["threat"] == "Threat number 30 against control systems" and not asked_30:
                asked_30.append(True)
                verdict["systems"] = verdict["entry_points"] = ["SYS9"]
        return verdicts

    return respond


def test_golden_plan_two_batches_a_halved_cut_off_a_follow_up_and_a_type_mismatch() -> None:
    chat = RecordingChat()
    threats = list(MANY_LIBRARY.threats)
    threats[10] = dataclasses.replace(
        threats[10], asset_type="IT"
    )  # fits the IT Historian only, judged on SYS1
    library = dataclasses.replace(MANY_LIBRARY, threats=tuple(threats), category_ids=CATEGORY_IDS)
    chat.queue(AiTask.RELEVANCE_GATE, truncated())
    chat.responders[AiTask.RELEVANCE_GATE] = _batches_gate()
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec({})
    _plan_golden("batches", chat, library, context=MIXED_TYPES, target=5)


def test_golden_plan_turns_over_three_systems_and_the_asset() -> None:
    chat = RecordingChat()
    gate = {
        "Ransomware encrypts backup servers": {"systems": ["SYS1", "SYS2"], "entry_points": ["SYS1", "SYS2"]},
        "Phishing steals operator credentials": {"systems": ["SYS3"], "likelihood": "HIGH"},
        "Insider deletes audit logs": {"systems": [], "entry_points": [], "likelihood": "LOW"},
        "Ransomware exfiltrates data": {"systems": ["SYS2"], "impacts": {"Information Disclosure": "LOW"}},
        "Flood of requests overwhelms the historian": {"systems": ["SYS2"], "confidence": 95},
        "Insider abuses admin rights": {"systems": ["SYS1", "SYS3"], "entry_points": ["SYS3"]},
    }
    chat.responders[AiTask.RELEVANCE_GATE] = gate_by_spec(gate)
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec({})
    it_only = LibraryThreat(
        8, "Ransomware hits office laptops", 1, "Malware", (S.TAMPERING,), ACTORS[:2], "IT"
    )
    library = dataclasses.replace(LIBRARY, threats=(*THREATS, it_only))  # all three systems are OT
    _plan_golden("turns", chat, library, context=THREE_SYSTEMS, target=4)


def test_golden_plan_last_attempt_skips_an_unreadable_batch() -> None:
    chat = RecordingChat()
    library = dataclasses.replace(MANY_LIBRARY, category_ids=CATEGORY_IDS)
    chat.queue(AiTask.RELEVANCE_GATE, UnreadableAiAnswer("not json"))
    chat.responders[AiTask.RELEVANCE_GATE] = gate_by_spec({"Threat number 40 against control systems": {}})
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec({})
    _plan_golden("last_attempt", chat, library, last_attempt=True)


def test_golden_plan_refusals_before_and_after_the_gate() -> None:
    """No linked actor refuses before any AI call; an unreadable first ask, not the last try, raises."""
    outcomes = {}
    unlinked = ThreatLibrary(tuple(dataclasses.replace(t, linked_actors=()) for t in THREATS), ACTORS)
    chat = RecordingChat()
    finder, _ = _finder(chat, FakeRerankModel(), unlinked)
    with pytest.raises(PlanRefused) as refused:
        finder.find_threats(CONTEXT)
    outcomes["no_actor"] = {"code": refused.value.code, "message": str(refused.value), "asks": len(chat.asks)}
    chat = RecordingChat()
    chat.queue(AiTask.RELEVANCE_GATE, UnreadableAiAnswer("not json"), UnreadableAiAnswer("not json"))
    finder, _ = _finder(chat, FakeRerankModel(), LIBRARY)
    with pytest.raises(Unavailable) as unavailable:
        finder.find_threats(CONTEXT)
    outcomes["unreadable"] = {"message": str(unavailable.value), "asks": [ask["task"] for ask in chat.asks]}
    check_golden("plan_refusals", outcomes)


def test_golden_plan_attacker_lists_match_the_linked_actors() -> None:
    """An actor the library links to no threat is never offered."""
    lonely = (*ACTORS, LibraryActor(9, "Unlinked group"))
    chat = RecordingChat()
    chat.responders[AiTask.RELEVANCE_GATE] = gate_by_spec({THREATS[0].name: {}})
    chat.responders[AiTask.GAP_FILL] = gap_fill_by_spec({})
    library = ThreatLibrary((THREATS[0], LibraryThreat(7, "Spare", 9, "Other", (S.SPOOFING,), ())), lonely)
    _plan_golden("attackers", chat, library)
