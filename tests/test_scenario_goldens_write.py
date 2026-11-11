"""Golden copies of writing: every writer prompt a set sends and every card it stores (written, blocked,
failed, an evidence story, a regenerated version, duplicates), for fixed fake answers and the fixed input plan
tests/goldens/scenario/input_write_plan.json. Only the plan's listed behaviour changes may change a file."""

import copy
import json
from typing import Any

from app.core.constants import AiTask, FindingCode, FindingMessage, WriterStyle
from app.domain.scenario.write import (
    build_card_threat_fields,
    build_failure_card,
    build_scenario_card,
    find_duplicate_scenario_id,
)
from app.models.library.library import ThreatLibrary
from app.models.scenario.write import Finding, PathFailure
from app.worker.scenario.path_writing import PathWriter
from tests.fakes import brief_of
from tests.planner_samples import ACTORS, THREATS
from tests.scenario_goldens import GOLDENS, RecordingChat, check_golden
from tests.test_scenario_goldens_plan import THREE_SYSTEMS

INPUT = json.loads((GOLDENS / "input_write_plan.json").read_text(encoding="utf-8"))
RUN = {"_id": "run-golden-1", "entity_id": 86, "asset_id": 103, "context": THREE_SYSTEMS.to_record()}
#: The live library: threat 4 retired since the plan, so its path fails before any AI call.
LIVE = ThreatLibrary(tuple(threat for threat in THREATS if threat.catalogue_id != 4), ACTORS)
SAME_STORY = (
    "A cybercriminal could tamper with the SCADA server at Grid Control Centre. "
    "It could spread. It could stop."
)


def _good(brief: dict[str, Any], statement: str = "", **fields: Any) -> dict[str, Any]:
    options = brief["entry_point_options"]
    answer = {
        "scenario_title": f"{brief['threat']['threat']} at Grid Control Centre",
        "scenario_statement": statement
        or f"A {brief['attacker']} could act on {options[0] if options else 'the asset'}. It could spread. "
        f"It could stop transmission at Grid Control Centre.",
        "risk_statement": "Loss of control at Grid Control Centre could interrupt electricity transmission.",
        "assumptions": ["The office network reaches the control network."],
        "entry_point": options[0] if options else "",
        "evidence_step": "the attacker logs in with stolen operator credentials",
    }
    return answer | fields


def _writer() -> Any:
    """Answers by threat: one unusable then fixed, one missing its action sentences then an unusable
    rewrite, one with a made-up label, one telling another's very words."""
    seen: dict[str, int] = {}

    def answer(block: str) -> dict[str, Any]:
        brief = brief_of(block)
        threat = brief["threat"]["threat"]
        seen[threat] = seen.get(threat, 0) + 1
        if threat.startswith("Flood") and seen[threat] == 1:
            return {"scenario_title": "x"}
        if threat.startswith("Phishing"):
            return _good(brief, action_sentences={}) if seen[threat] == 1 else {"scenario_title": "y"}
        if threat.startswith("Insider deletes"):
            return _good(
                brief, "An insider on SYS1 could delete the audit logs. It could hide. It could stop."
            )
        if threat.startswith("Insider abuses"):
            return _good(brief, SAME_STORY)
        if threat.startswith("Ransomware encrypts"):
            return _good(brief, SAME_STORY, evidence_step="[1] the gang encrypts the backups")
        return _good(brief)

    return answer


def _write(chat: RecordingChat, threats: list[dict[str, Any]], style: WriterStyle) -> list[Any]:
    """Write every input path as one set; each path's card record, in the order they came."""
    run = RUN | {"plan": {"threats": threats}}
    writer = PathWriter(run, chat, LIVE, style)
    paths = {path["path_id"]: path for path in INPUT["paths"]}
    slots = [(f"SC{place}", path) for place, path in enumerate(INPUT["paths"], start=1)]
    cards = []
    for path_id, outcome in writer.write_scenario_set(slots, last_try=False, epoch=3):
        path = paths[path_id]
        threat = writer.threats[path["steps"][0]]
        if isinstance(outcome, PathFailure):
            cards.append(build_failure_card(run, path, threat, outcome))
        else:
            brief, written = outcome
            cards.append(build_scenario_card(run, path, threat, brief, written))
    return cards


def _duplicates(cards: list[dict[str, Any]]) -> list[Any]:
    """Each card's duplicate among the cards before it, and each path's held repeat among all cards."""
    found = []
    threats = {threat["key"]: threat for threat in INPUT["threats"]}
    for place, card in enumerate(cards):
        copy_id = find_duplicate_scenario_id(card["content"], card["path_id"], cards[:place])
        message = FindingMessage.NEAR_DUPLICATE.format(scenario_id=copy_id)
        copied = Finding(FindingCode.NEAR_DUPLICATE, message) if copy_id else None
        path = next(path for path in INPUT["paths"] if path["path_id"] == card["path_id"])
        held = find_duplicate_scenario_id(
            build_card_threat_fields(path, threats[path["steps"][0]]), path["path_id"], cards
        )
        found.append({"path_id": card["path_id"], "duplicate_of": copied, "held_repeat_of": held})
    return found


def test_golden_write_original_set_with_rewrites_blocks_a_failure_and_duplicates() -> None:
    chat = RecordingChat()
    chat.responders[AiTask.WRITE_SCENARIO] = _writer()
    cards = _write(chat, copy.deepcopy(INPUT["threats"]), WriterStyle.ORIGINAL)
    replaced = {"_id": cards[0]["_id"], "version": 1}
    path, threat = INPUT["paths"][0], INPUT["threats"][0]
    again = RecordingChat()
    again.responders[AiTask.WRITE_SCENARIO] = _writer()
    writer = PathWriter(
        RUN | {"plan": {"threats": copy.deepcopy(INPUT["threats"])}}, again, LIVE, WriterStyle.ORIGINAL
    )
    (_, (brief, written)), *_ = list(writer.write_scenario_set([("SC1", path)], last_try=False, epoch=4))
    version_2 = build_scenario_card(RUN, path, threat, brief, written, replaced)
    check_golden(
        "write_original",
        {"asks": chat.asks, "cards": cards, "duplicates": _duplicates(cards), "version_2": version_2},
    )


def _technique(title: str, users: bool = True, nearest: bool = False) -> dict[str, Any]:
    facts = ["It is used for these attacker goals: Initial Access, Persistence."]
    facts += ["Sandworm Team, a group, has used this technique."] if users else []
    facts += ["It can be reduced by: User Account Management."]
    entry = {
        "ref": "T0859",
        "kind": "technique",
        "source": "mitre_attack_ics",
        "title": title,
        "url": "https://attack.mitre.org/techniques/T0859/",
        "score": 41.5,
        "facts": facts,
        "applicability": None,
        "published": None,
        "fetched_at": None,
        "role": "context",
        "mitigations": ["User Account Management"],
        "modified": None,
        "joined": [],
        "searched_at": "<date>",
    }
    return entry | ({"nearest": True} if nearest else {})


def _vulnerability() -> dict[str, Any]:
    return {
        "ref": "CVE-2024-0001",
        "kind": "vulnerability",
        "source": "cisa_kev",
        "title": "Siemens WinCC flaw",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        "score": 30.0,
        "applicability": "unknown",
        "facts": ["CISA lists weaknesses in Siemens WinCC as exploited in real attacks (added 2025-01-01)."],
        "published": None,
        "fetched_at": None,
        "role": "context",
        "mitigations": [],
        "modified": None,
        "joined": [],
        "searched_at": "<date>",
    }


SEARCHED = {
    "query": "q",
    "asset_types": ["OT"],
    "snapshot_id": "snap-1",
    "threshold": 20.0,
    "considered": [],
    "failure": None,
    "rerank_model": "fake",
    "outage": None,
    "searched_at": "<date>",
}


def test_golden_write_evidence_stories_cited_nearest_vulnerability_and_uncitable() -> None:
    threats = copy.deepcopy(INPUT["threats"])
    evidence = {
        "lib:1": [_technique("Valid Accounts")],
        "lib:5": [_vulnerability()],
        "lib:2": [_technique("Spearphishing Attachment", nearest=True)],
        "lib:6": [_technique("Exploitation of Remote Services", users=False)],
    }
    for threat in threats:
        if threat["key"] in evidence:
            threat |= {"evidence": evidence[threat["key"]], "intel_search": SEARCHED}
    chat = RecordingChat()
    chat.responders[AiTask.WRITE_SCENARIO] = _writer()
    cards = _write(chat, threats, WriterStyle.EVIDENCE_STORY)
    check_golden("write_evidence", {"asks": chat.asks, "cards": cards})
