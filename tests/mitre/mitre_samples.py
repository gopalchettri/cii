"""Synthetic MITRE STIX data and engine inputs for the MITRE run's tests (ported from the POC's tests)."""

import copy
import json
from typing import Any

from app.core.config import Settings, get_settings
from app.core.constants import AiTask
from app.search.mitre.mitre_index import MitreIndex, build_mitre_index
from tests.fakes import FakeChatModel

PHISHING, CONTROL_LOGIC, VALID_ACCOUNTS, DENIAL_OF_CONTROL, LOSS_OF_AVAILABILITY = (
    "attack-pattern--phishing",
    "attack-pattern--control-logic",
    "attack-pattern--valid-accounts",
    "attack-pattern--denial-of-control",
    "attack-pattern--loss-of-availability",
)
ZETA, ALPHA, BETA, GAMMA = "intrusion-set--zeta", "intrusion-set--alpha", "intrusion-set--beta", "intrusion-set--gamma"
TOOL, CAMPAIGN, MITIGATION = "tool--example", "campaign--own", "course-of-action--training"
DELTA, PLC_ASSET = "intrusion-set--delta", "x-mitre-asset--plc"


def mitre_reference(mitre_id: str, source: str = "mitre-attack") -> list[dict[str, str]]:
    return [{"source_name": source, "external_id": mitre_id}]


def relationship(relationship_id: str, source_id: str, target_id: str, kind: str = "uses") -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{relationship_id}",
        "source_ref": source_id,
        "target_ref": target_id,
        "relationship_type": kind,
        "description": "Observed (Citation: Report 2020)",
        "modified": relationship_id,
    }


def technique(
    stix_id: str, mitre_id: str, name: str, tactic: str, description: str, source: str = "mitre-attack", **extra: Any
) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": description,
        "external_references": mitre_reference(mitre_id, source),
        "kill_chain_phases": [{"phase_name": tactic}],
        **extra,
    }


def group(stix_id: str, name: str, mitre_id: str, description: str, source: str = "mitre-attack") -> dict[str, Any]:
    reference = mitre_reference(mitre_id, source)
    return {
        "type": "intrusion-set",
        "id": stix_id,
        "name": name,
        "description": description,
        "external_references": reference,
    }


# Zeta uses Phishing and Modify Control Logic directly; Alpha uses Phishing only through Tool; Gamma is an ICS
# group using Phishing and Denial of Control; Beta uses nothing (its only software is deprecated).
DOCUMENTS: dict[str, list[dict[str, Any]]] = {
    "enterprise": [
        {"type": "x-mitre-ingestion", "id": "__ingestion__"},
        technique(
            PHISHING,
            "T1566",
            "Phishing",
            "initial-access",
            "Phishing for access (Citation: X)",
            x_mitre_platforms=["Windows"],
        ),
        technique(VALID_ACCOUNTS, "T1078", "Valid Accounts", "persistence", "Use valid accounts."),
        {**technique("attack-pattern--old", "T1001", "Old", "impact", "Retired"), "revoked": True},
        group(ZETA, "Zeta", "G0101", "Zeta targets wastewater utilities and water treatment plants."),
        group(ALPHA, "Alpha", "G0102", "Alpha steals payment card data from retail companies."),
        group(BETA, "Beta", "G0103", "Beta runs espionage campaigns against retail chains."),
        {
            "type": "tool",
            "id": TOOL,
            "name": "Tool",
            "description": "A tool",
            "external_references": mitre_reference("S0101"),
        },
        {
            "type": "tool",
            "id": "tool--retired",
            "name": "Retired tool",
            "description": "Old",
            "x_mitre_deprecated": True,
            "external_references": mitre_reference("S0199"),
        },
        {
            "type": "campaign",
            "id": CAMPAIGN,
            "name": "Own op",
            "description": "An operation against municipal water utilities in Europe.",
            "external_references": mitre_reference("C0101"),
        },
        {
            "type": "course-of-action",
            "id": MITIGATION,
            "name": "User Training",
            "external_references": mitre_reference("M1017"),
        },
        relationship("a1", ZETA, PHISHING),
        relationship("a2", ALPHA, TOOL),
        relationship("a3", TOOL, PHISHING),
        relationship("a4", CAMPAIGN, PHISHING),
        relationship("m1", MITIGATION, PHISHING, "mitigates"),
        relationship("r1", CAMPAIGN, ZETA, "attributed-to"),
        relationship("c1", BETA, "tool--retired"),
        relationship("c2", "tool--retired", VALID_ACCOUNTS),
    ],
    "ics": [
        technique(
            CONTROL_LOGIC,
            "T0831",
            "Modify Control Logic",
            "impair-process-control",
            "Change controller logic",
            "mitre-ics-attack",
        ),
        technique(
            DENIAL_OF_CONTROL,
            "T0813",
            "Denial of Control",
            "inhibit-response-function",
            "Temporarily prevent operators from controlling the process. More detail follows.",
            "mitre-ics-attack",
        ),
        technique(
            LOSS_OF_AVAILABILITY, "T0826", "Loss of Availability", "impact", "Disrupt the process.", "mitre-ics-attack"
        ),
        group(
            GAMMA, "Gamma", "G0104", "Gamma is an industrial group attacking power grid operators.", "mitre-ics-attack"
        ),
        relationship("a8", ZETA, CONTROL_LOGIC),
        relationship("b2", GAMMA, PHISHING),
        relationship("b3", GAMMA, DENIAL_OF_CONTROL),
    ],
}

ASSET: dict[str, Any] = {
    "asset_name": "Pump Controller",
    "asset_description": "Controls wastewater pumps",
    "asset_type": "OT",
    "supporting_systems": [{"name": "SCADA", "description": "Operations", "type": "OT", "technology_used": "PLC"}],
    "sector": "Utilities",
    "subsector": "Wastewater",
    "service_name": "Wastewater",
}
PORTAL = {"name": "Portal", "description": "Web", "type": "IT"}
IT_ASSET = {**ASSET, "asset_type": "IT", "supporting_systems": [PORTAL]}
MIXED_ASSET = {**ASSET, "supporting_systems": [*ASSET["supporting_systems"], PORTAL]}
# The POC test settings: sample answers are short, so the word ranges are wide open.
TEST_SETTINGS: dict[str, Any] = {
    "total_scenario_count": 0,
    "attack_path_techniques": "2-8",
    "mitre_parallel_writers": 3,
    "mitre_threat_scenario_word_limit": "1-500",
    "mitre_risk_statement_word_limit": "1-500",
    "mitre_risk_title_word_limit": "4-10",
    "mitre_scenario_title_word_limit": "3-8",
    "planner_relevant_actors": 15,
    "procedures_per_technique": 10,
    "candidate_groups_per_scenario": 15,
    "max_scenario_share_per_group": 0.5,
    "mitre_planner_single_call_limit": 40,
    "mitre_planner_max_further_rounds": 5,
}
# Quotes of at least five words from each actor's MITRE description, by MITRE ID.
QUOTES = {
    "G0101": "targets wastewater utilities and water treatment",
    "G0102": "steals payment card data from retail",
    "G0103": "runs espionage campaigns against retail chains",
    "G0104": "an industrial group attacking power grid",
    "C0101": "against municipal water utilities in Europe",
}
KNOWN_TECHNIQUES = {
    "T1566": ("Phishing", "enterprise", PHISHING),
    "T0831": ("Modify Control Logic", "ics", CONTROL_LOGIC),
    "T1078": ("Valid Accounts", "enterprise", VALID_ACCOUNTS),
}


def settings(**changes: Any) -> Settings:
    return get_settings().model_copy(update={**TEST_SETTINGS, **changes})


def asset_context(asset: dict[str, Any] | None = None) -> dict[str, Any]:
    return copy.deepcopy(asset or ASSET)


def documents() -> dict[str, list[dict[str, Any]]]:
    return json.loads(json.dumps(DOCUMENTS))  # a copy: the index must not share the caller's data


def sample_index(**setting_changes: Any) -> MitreIndex:
    return build_mitre_index(documents(), settings(**setting_changes))


def index_with_delta() -> MitreIndex:
    """The samples plus Delta, whose MITRE description has a markdown link, a curly apostrophe, an en dash and a
    citation label."""
    description = (
        "[Delta](https://attack.mitre.org/groups/G0105) compromised the local government’s wastewater "
        "control system using [Triton](https://attack.mitre.org/software/S1009) – a safety-system "
        "malware. (Citation: Report 2024)"
    )
    samples = documents()
    samples["ics"].append(group(DELTA, "Delta", "G0105", description, "mitre-ics-attack"))
    samples["ics"].append(relationship("d1", DELTA, CONTROL_LOGIC))
    return build_mitre_index(samples, settings())


def index_with_ics_assets() -> MitreIndex:
    """The samples plus a MITRE ICS asset type (PLC) targeted by Modify Control Logic, an alias and campaign dates."""
    samples = documents()
    samples["ics"].append(
        {
            "type": "x-mitre-asset",
            "id": PLC_ASSET,
            "name": "Programmable Logic Controller (PLC)",
            "description": "A PLC controls an industrial process. More text follows here.",
            "x_mitre_sectors": ["General"],
            "x_mitre_platforms": ["Embedded"],
            "x_mitre_related_assets": [{"name": "Field Controller"}],
            "external_references": mitre_reference("A0003", "mitre-ics-attack"),
        }
    )
    samples["ics"].append(relationship("t1", CONTROL_LOGIC, PLC_ASSET, "targets"))
    for stix_object in samples["enterprise"]:
        if stix_object.get("id") == ZETA:
            stix_object["aliases"] = ["Zeta", "Water Bear"]
        if stix_object.get("id") == CAMPAIGN:
            stix_object["first_seen"] = "2022-06-01T00:00:00.000Z"
            stix_object["last_seen"] = "2022-10-01T00:00:00.000Z"
    return build_mitre_index(samples, settings())


def actor_row(
    mitre_id: str, relevance: Any, reason: str = "Documented against similar organizations.", quote: str | None = None
) -> dict[str, Any]:
    """One relevant_actors row as the actor-selection model returns it."""
    return {
        "mitre_id": mitre_id,
        "relevance": relevance,
        "evidence_quote": QUOTES[mitre_id] if quote is None else quote,
        "reason": reason,
    }


def planner_answer(*paths: tuple[list[str], str], **extra: Any) -> dict[str, Any]:
    plans = []
    for position, (technique_ids, category) in enumerate(paths):
        plans.append(
            {
                "title": f"P{position}",
                "objective": "Disrupt pumping",
                "category": category,
                "technique_ids": technique_ids,
                "supporting_systems": ["SCADA"],
            }
        )
    return {"plans": plans, **extra}


def writer_answer(
    title: str = "Pump disruption",
    narrative: str = "An attacker could phish an operator, then alter pump control logic.",
    groups: tuple[tuple[str, str], ...] = (("Zeta", "G0101"),),
    techniques: tuple[str, ...] = ("T1566", "T0831"),
) -> dict[str, Any]:
    attack_techniques = []
    for mitre_id in techniques:
        name, domain, stix_id = KNOWN_TECHNIQUES[mitre_id]
        attack_techniques.append({"mitre_id": mitre_id, "name": name, "domain": domain, "stix_id": stix_id})
    relevant_groups = []
    for name, mitre_id in groups:
        relevant_groups.append(
            {"name": name, "mitre_id": mitre_id, "relevance": "MITRE documents it against water utilities."}
        )
    return {
        "scenario_title": title,
        "threat_scenario_description": "Unauthorized changes disrupt pumping",
        "threat_scenario": narrative,
        "risk_statement": "There is a risk that pumping is disrupted.",
        "relevant_groups": relevant_groups,
        "attack_techniques": attack_techniques,
        "supporting_systems": ["SCADA"],
        "assumptions": ["Operators can reach the controller."],
        "threat_type": "Unauthorised access",
    }


#: The library's threat types the writer copies one of: (type_id, name), as list_threat_choices gives them.
THREAT_TYPES: list[tuple[int, str]] = [(85, "Malware/Ransomware"), (2, "Unauthorised access")]


def selection_of(*actor_ids_and_relevance: tuple[str, int]) -> dict[str, Any]:
    """An actor selection in which the given actors were selected with the given relevance."""
    actors = {}
    for actor_id, relevance in actor_ids_and_relevance:
        actors[actor_id] = {"relevance": relevance, "evidence_quote": "a quote from MITRE", "reason": "Similar sector."}
    return {"actors": actors, "ranked_actor_ids": list(actors), "status": "complete", "rejected_rows": {}}


def fake_paths(count: int, crossing_positions: tuple[int, ...] = ()) -> list[dict[str, Any]]:
    paths = []
    for position in range(count):
        paths.append(
            {
                "title": f"P{position}",
                "objective": "o",
                "category": "Tampering",
                "technique_stix_ids": [PHISHING, CONTROL_LOGIC],
                "supporting_systems": ["SCADA"],
                "has_it_and_ot": position in crossing_positions,
            }
        )
    return paths


def planned_path_techniques(planned_path: dict[str, Any]) -> list[dict[str, str]]:
    """The attack_techniques of a fake written scenario: the planned path's own techniques."""
    techniques = []
    for technique_id in planned_path["technique_stix_ids"]:
        techniques.append({"stix_id": technique_id})
    return techniques


def no_repeat_found(_user_prompt: str) -> dict[str, Any]:
    """The duplicate judge's answer when a test does not give one: no path repeats another."""
    return {"new": []}


class MitreChat(FakeChatModel):
    """The fake AI of the MITRE tests: the duplicate judge finds no repeat unless a test answers it. A writer call
    is answered path by path: each entry of its "paths" is asked as its own block (the shared input with that
    path's own part, recorded as one asked prompt), so a test reads and answers one path at a time; the answer's
    first scenario gets the path's slot. writer_prompts keeps each real writer call's user prompt, writer_calls
    counts them."""

    def __init__(self) -> None:
        super().__init__()
        self.writer_prompts: list[str] = []
        self.responders[AiTask.MITRE_DUPLICATE_CHECK] = no_repeat_found

    @property
    def writer_calls(self) -> int:
        return len(self.writer_prompts)

    def _answer(self, task: AiTask, user_prompt: str) -> dict[str, Any]:
        if task is not AiTask.MITRE_WRITE:
            return super()._answer(task, user_prompt)
        self.writer_prompts.append(user_prompt)
        data = json.loads(user_prompt)
        shared = dict(data)
        del shared["paths"]
        scenarios = []
        for path in data["paths"]:
            answered = super()._answer(task, json.dumps({**shared, **path}))
            for item in (answered.get("scenarios") or [])[:1]:
                scenarios.append({**item, "slot": path["slot"]} if isinstance(item, dict) else item)
        return {"scenarios": scenarios}
