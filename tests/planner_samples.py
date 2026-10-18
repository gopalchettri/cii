"""The planner tests' shared samples: a six-threat library with four actors, an asset with two supporting
systems, and fake AI answers (tests/fakes.py)."""

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from app.core.constants import AiTask, StrideCategory
from app.domain.scenario.plan import ThreatFinder
from app.models.asset_context import FrozenContext
from app.models.library import LibraryActor, LibraryThreat, RejectedLibraryThreat, ThreatLibrary
from app.models.scenario.plan import CategoryAudit, PlannedThreat, ThreatFindings
from app.search.service import LibrarySearch
from tests.fakes import FakeChatModel, FakeEmbeddings, FakeRerankModel, items_in

S = StrideCategory
#: The fake vectors' dimensions: two texts mean the same when they share these words.
WORDS = ("ransomware", "phishing", "backup", "insider", "flood", "gang", "crew", "admin")
GANG, AFFILIATE, INSIDER, CREW = ACTORS = (
    LibraryActor(1, "Ransomware gang"),
    LibraryActor(2, "Ransomware gang affiliate"),
    LibraryActor(3, "Malicious insider"),
    LibraryActor(4, "Phishing crew"),
)
RANSOMWARE = LibraryThreat(
    1,
    "Ransomware encrypts backup servers",
    1,
    "Malware",
    (S.TAMPERING, S.DENIAL_OF_SERVICE),
    (INSIDER, GANG, AFFILIATE),
)
PHISHING = LibraryThreat(
    2, "Phishing steals operator credentials", 2, "Social engineering", (S.SPOOFING,), ()
)
LOG_WIPE = LibraryThreat(3, "Insider deletes audit logs", 3, "Insider misuse", (S.REPUDIATION,), (INSIDER,))
EXFILTRATION = LibraryThreat(
    4, "Ransomware exfiltrates data", 1, "Malware", (S.INFORMATION_DISCLOSURE,), (GANG,)
)
FLOOD = LibraryThreat(
    5, "Flood of requests overwhelms the historian", 4, "Overload", (S.DENIAL_OF_SERVICE,), ()
)
ADMIN_ABUSE = LibraryThreat(
    6, "Insider abuses admin rights", 5, "Privilege misuse", (S.ELEVATION_OF_PRIVILEGE,), (INSIDER,)
)
THREATS = (RANSOMWARE, PHISHING, LOG_WIPE, EXFILTRATION, FLOOD, ADMIN_ABUSE)
INCIDENT = "A flood of requests stopped it in 2024"
GAP_FILL_NONE = {"applies": False, "reason": "The library covers it."}


def system_row(system_id: int, alias: str, name: str, **facts: Any) -> dict[str, Any]:
    """A frozen supporting system (domain/scenario/plan.py), with only the facts a test sets."""
    return {
        "id": system_id,
        "alias": alias,
        "name": name,
        "category_code": "OT",
        "category_name": "OT",
        **facts,
    }


CONTEXT = FrozenContext(
    asset={"id": 103, "name": "Grid Control Centre"},
    asset_context={
        "cii_asset_description": f"Runs the transmission grid. {INCIDENT}.",
        "critical_service": "Electricity transmission",
        "sector": "Energy",
        "sub_sector": "Electricity",
        "target_rto_hours": 4.0,
        "asset_priority": "High",
    },
    systems=[
        system_row(
            321,
            "SYS1",
            "SCADA server",
            past_incidents=INCIDENT,
            technology_used=["Windows", "Siemens WinCC"],
            rto_target_mins=30.0,
            last_dr_test_date="2026-01-01",
            backup_tested=None,
        ),
        system_row(322, "SYS2", "Historian", past_incidents=INCIDENT, technology_used=["OSIsoft PI"]),
    ],
)


def judged(relevant: dict[str, list[str]]) -> Callable[[str], dict[str, Any]]:
    """A gate that finds a candidate relevant when its threat is a key of `relevant`, on those systems."""

    def answer(user_prompt: str) -> dict[str, Any]:
        verdicts = []
        for candidate in items_in(user_prompt, "CANDIDATES"):
            applies = candidate["threat"] in relevant
            verdicts.append(
                {
                    "slot": candidate["slot"],
                    "relevant": applies,
                    "systems": relevant.get(candidate["threat"], []),
                    "reason": f"{candidate['threat']} hits SYS1." if applies else "Nothing here allows it.",
                    "impact": "HIGH" if applies else None,
                    "confidence": 80,
                }
            )
        return {"verdicts": verdicts}

    return answer


def planner_chat(relevant: dict[str, list[str]]) -> FakeChatModel:
    """A chat model answering every planner task: the gate by `relevant`, no gap-fill threat."""
    chat = FakeChatModel()
    chat.responders = {AiTask.RELEVANCE_GATE: judged(relevant), AiTask.GAP_FILL: lambda _: GAP_FILL_NONE}
    return chat


def gap_fill_for_elevation(proposal: dict[str, Any]) -> Callable[[str], dict[str, Any]]:
    return lambda user_prompt: (
        proposal if "category: Elevation of Privilege" in user_prompt else GAP_FILL_NONE
    )


def library_search(
    actors: tuple[LibraryActor, ...] = ACTORS,
    curator_rejected: tuple[RejectedLibraryThreat, ...] = (),
    threats: tuple[LibraryThreat, ...] = THREATS,
    unknown_asset_type: tuple[int, ...] = (),
) -> tuple[LibrarySearch, FakeEmbeddings]:
    threat_library = ThreatLibrary(
        threats, actors, curator_rejected=curator_rejected, threats_unknown_asset_type=unknown_asset_type
    )
    library = SimpleNamespace(threat_library=threat_library, control_library=(), stamp=())
    embeddings = FakeEmbeddings(WORDS)
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), embeddings)  # type: ignore[arg-type]
    search.snapshot()  # built now: a test that takes the embeddings down later fails only query calls
    return search, embeddings


def finder(chat: FakeChatModel, rerank: FakeRerankModel | None = None, **library: Any) -> ThreatFinder:
    search, embeddings = library_search(**library)
    return ThreatFinder(chat, search, rerank or FakeRerankModel(), embeddings)  # type: ignore[arg-type]


def audit_of(findings: ThreatFindings, category: StrideCategory) -> CategoryAudit:
    return next(audit for audit in findings.audits if audit.category == category)


def planned(key: str, name: str, systems: tuple[int, ...] = (321,), **fields: Any) -> PlannedThreat:
    """A planned threat for the fold and path tests: "lib:<id>" keys are library threats."""
    catalogue_id = int(key.split(":")[1]) if key.startswith("lib:") else None
    defaults: dict[str, Any] = {
        "type_id": 1,
        "type_name": "Malware",
        "categories": (S.TAMPERING,),
        "impact": 2,
        "confidence": 70.0,
        "reason": "It applies.",
    }
    return PlannedThreat(key, catalogue_id, name=name, systems=systems, **(defaults | fields))
