r"""Threat_Catalogue.AssetType and Control_Library.AssetType are IT, OT or IT\OT (both). A library threat is
judged only when its type fits the asset or a chosen supporting system, and stays only where its type fits (an
OT threat never on an IT system); an empty value, or one that is not a type, fits everywhere."""

import dataclasses
from typing import Any

from structlog.testing import capture_logs

from app.core.asset_types import asset_type_fits, asset_type_label, canonical_asset_type
from app.core.constants import (
    AiTask,
    AssetType,
    CandidateRejection,
    LogEvent,
    StrideCategory,
)
from app.models.library.library import LibraryThreat
from tests.fakes import FakeRerankModel, items_in
from tests.planner_samples import (
    ADMIN_ABUSE,
    CONTEXT,
    FLOOD,
    LOG_WIPE,
    RANSOMWARE,
    THREATS,
    finder,
    gap_fill_for_elevation,
    planner_chat,
)
from tests.sql_fakes import load_library_from

S = StrideCategory
#: An IT asset whose SYS1 "SCADA server" is OT and SYS2 "Historian" is IT.
MIXED = dataclasses.replace(
    CONTEXT,
    asset=CONTEXT.asset | {"category_code": "IT"},
    systems=[CONTEXT.systems[0], CONTEXT.systems[1] | {"category_code": "IT"}],
)


def _library(*typed: LibraryThreat) -> tuple[LibraryThreat, ...]:
    """The sample library with some threats given an AssetType."""
    by_id = {threat.catalogue_id: threat for threat in typed}
    return tuple(by_id.get(threat.catalogue_id, threat) for threat in THREATS)


def _typed(threat: LibraryThreat, asset_type: str) -> LibraryThreat:
    return dataclasses.replace(threat, asset_type=asset_type)


def test_a_threat_whose_type_fits_neither_the_asset_nor_a_system_is_never_judged() -> None:
    """Every system of the sample run is OT: an IT threat is never shown to the AI, under any category."""
    hit = CONTEXT.systems[0] | {"past_incidents": "Ransomware encrypts backup servers"}
    context = dataclasses.replace(CONTEXT, systems=[hit, CONTEXT.systems[1]])
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], LOG_WIPE.name: ["SYS1"]})
    findings = finder(chat, threats=_library(_typed(RANSOMWARE, "IT"))).find_threats(context)
    assert [threat.name for threat in findings.threats] == [LOG_WIPE.name]
    asked = [
        item["threat"] for user in chat.asked(AiTask.RELEVANCE_GATE) for item in items_in(user, "CANDIDATES")
    ]
    assert RANSOMWARE.name not in asked and LOG_WIPE.name in asked


def test_a_threat_stays_only_where_its_type_fits_and_is_refused_where_it_cannot_be() -> None:
    """An OT threat judged to apply on the OT and the IT system keeps the OT one; judged to apply only on the
    IT system, or only on the IT asset itself, it is refused. Code decides, before any gap fill: a category
    it empties still gets its one AI threat."""
    relevant = {
        RANSOMWARE.name: ["SYS1", "SYS2"],
        FLOOD.name: ["SYS2"],
        ADMIN_ABUSE.name: [],  # the asset itself
        LOG_WIPE.name: ["SYS2"],  # untyped: fits everywhere
    }
    library = _library(_typed(RANSOMWARE, "OT"), _typed(FLOOD, "OT"), _typed(ADMIN_ABUSE, " ot "))
    chat = planner_chat(relevant)
    findings = finder(chat, threats=library).find_threats(MIXED)
    assert {threat.name: threat.systems for threat in findings.threats} == {
        RANSOMWARE.name: (321,),
        LOG_WIPE.name: (322,),
    }
    refused = {
        rejected["threat"]
        for audit in findings.audits
        for rejected in audit.rejected
        if rejected["code"] == CandidateRejection.ASSET_TYPE_MISMATCH
    }
    assert refused == {FLOOD.name, ADMIN_ABUSE.name}
    assert any("category: Elevation of Privilege" in user for user in chat.asked(AiTask.GAP_FILL))


def test_a_system_whose_type_is_not_recorded_takes_the_assets() -> None:
    """Unknown is not a type: an OT threat on an OT asset's system whose category code is not recorded stays
    there (the asset's type stands in); before, only untyped threats could stay on such a system."""
    unknown = CONTEXT.systems[1] | {"category_code": None}
    context = dataclasses.replace(
        CONTEXT, asset=CONTEXT.asset | {"category_code": "OT"}, systems=[CONTEXT.systems[0], unknown]
    )
    findings = finder(
        planner_chat({RANSOMWARE.name: ["SYS2"]}), threats=_library(_typed(RANSOMWARE, "OT"))
    ).find_threats(context)
    assert {threat.name: threat.systems for threat in findings.threats} == {RANSOMWARE.name: (322,)}


def test_an_asset_type_that_is_not_a_value_fits_everywhere() -> None:
    """ "IT-OT" is not a value: the threat is still judged, never silently lost."""
    library = _library(_typed(RANSOMWARE, "IT-OT"))
    findings = finder(
        planner_chat({RANSOMWARE.name: ["SYS1"]}), threats=library, unknown_asset_type=(1,)
    ).find_threats(CONTEXT)
    assert [threat.name for threat in findings.threats] == [RANSOMWARE.name]


def test_an_ai_proposal_is_never_a_repeat_of_a_library_threat_this_run_never_judged() -> None:
    """The gap fill's library match looks only at threats whose type fits the run, so a proposal is never
    dropped as "a repeat" of a library threat that was never shown to the AI."""
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
    scores = {
        ("Insider misuses admin rights", ADMIN_ABUSE.name): 80.0,
        ("Privilege misuse", "Privilege misuse"): 90.0,
    }
    library = _library(_typed(ADMIN_ABUSE, "IT"))  # every system of the sample run is OT
    finder(chat, FakeRerankModel(scores), threats=library).find_threats(CONTEXT)
    assert any(proposal["threat"] in user for user in chat.asked(AiTask.RELEVANCE_GATE))  # judged, no repeat


def test_a_threat_never_keeps_a_system_of_another_type_through_a_fold() -> None:
    """A merge unites the systems of the threats it joins: an OT threat on its OT system, merged with an AI
    twin of the same name and type on the IT system too, keeps only the OT one."""
    chat = planner_chat({RANSOMWARE.name: ["SYS1"]})
    on_both = planner_chat({RANSOMWARE.name: ["SYS1", "SYS2"]}).responders[AiTask.RELEVANCE_GATE]
    gate = chat.responders[AiTask.RELEVANCE_GATE]
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        on_both(user) if "category: Information Disclosure" in user else gate(user)
    )
    twin = {"applies": True, "threat_type": "Malware", "threat": RANSOMWARE.name, "attacker": "Gang"}
    twin |= {"systems": ["SYS1", "SYS2"], "reason": "It encrypts both."}
    chat.responders[AiTask.GAP_FILL] = lambda user: (
        twin if "category: Information Disclosure" in user else {"applies": False, "reason": "None."}
    )
    rerank = FakeRerankModel({("Malware", "Malware"): 90.0})
    findings = finder(chat, rerank, threats=_library(_typed(RANSOMWARE, "OT"))).find_threats(MIXED)
    assert {threat.name: threat.systems for threat in findings.threats} == {RANSOMWARE.name: (321,)}


def test_the_old_threat_procedure_and_an_unknown_control_type_are_never_silent() -> None:
    """The procedure from before G211 (no AssetType) still loads, every threat untyped, with a warning naming
    it; a control whose AssetType is not a value is used for every scenario, with a warning naming it."""

    class _OldProcedures(_Procedures):
        def execute_procedure(self, _procedure: object) -> list[list[dict[str, Any]]]:
            sets = super().execute_procedure(_procedure)
            sets[2] = [{key: value for key, value in row.items() if key != "AssetType"} for row in sets[2]]
            return sets

    with capture_logs() as logs:
        library = load_library_from(_OldProcedures().execute_procedure(None)).threat_library
    assert {threat.asset_type for threat in library.threats} == {None}
    assert [entry["event"] for entry in logs] == [LogEvent.LIBRARY_THREAT_ASSET_TYPE_MISSING]

    class _Controls:
        def execute_procedure(self, _procedure: object) -> list[list[dict[str, Any]]]:
            row = {"ControlLibraryID": 1, "ControlCode": "AC-01", "AssetType": "IT-OT", "Domain": "Access",
                   "ControlName": "Account management", "ControlDescription": "Reviews."}  # fmt: skip
            return [[row], []]

    with capture_logs() as logs:
        (control,) = load_library_from(control_sets=_Controls().execute_procedure(None)).control_library
    assert asset_type_fits(control.asset_type, set()) and [entry["event"] for entry in logs] == [
        LogEvent.LIBRARY_ASSET_TYPE_UNKNOWN
    ]


class _Procedures:
    """tsg_GetThreatLibrary's eight result sets: four threats, one of each kind of AssetType."""

    def execute_procedure(self, _procedure: object) -> list[list[dict[str, Any]]]:
        threats = [(1, "OT"), (2, r"IT\OT"), (3, "IT-OT"), (4, None)]
        return [
            [{"ThreatCategoryID": 2, "ThreatCategoryName": "Tampering"}],
            [{"ThreatTypeID": 7, "ThreatTypeName": "Malware", "ThreatCategoryID": 2}],
            [
                {
                    "ThreatCatalogueID": i,
                    "ThreatName": f"Threat {i}",
                    "ThreatTypeID": 7,
                    "AssetType": asset_type,
                }
                for i, asset_type in threats
            ],
            [{"ThreatActorID": 1, "ThreatActorName": "Crew"}],
            [{"ThreatTypeID": 7, "ThreatActorID": 1}],
            [{"ThreatCatalogueID": i, "ThreatCategoryID": 2} for i, _ in threats],
            [],
            [],
        ]


def test_the_loader_reads_each_threats_asset_type_and_lists_the_unknown_ones() -> None:
    library = load_library_from(_Procedures().execute_procedure(None)).threat_library
    assert [threat.asset_type for threat in library.threats] == ["OT", r"IT\OT", "IT-OT", None]
    assert library.threats_unknown_asset_type == (3,)


def test_it_slash_ot_is_both_and_is_kept_in_one_spelling() -> None:
    r"""G217 (owner 2026-10-13): DevTest5 writes "IT/OT" (291 controls were read as unknown, fitting
    everywhere with a warning); it means both, as IT\OT does. IT-OT stays not a value."""
    assert asset_type_label("IT/OT") == asset_type_label(r" it \ ot ") == AssetType.IT_OT
    assert asset_type_label("IT-OT") is None
    assert canonical_asset_type("IT/OT") == r"IT\OT" and canonical_asset_type("IT-OT") == "IT-OT"
    assert canonical_asset_type(None) is None
