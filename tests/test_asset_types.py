r"""G211 (owner 2026-10-12): Threat_Catalogue.AssetType and Control_Library.AssetType are IT, OT or IT\OT
(both). A library threat is judged only when its type fits the asset or a chosen supporting system, and stays
only where its type fits (an OT threat never on an IT system); an empty value, or one that is not a type, fits
everywhere and is never silently dropped."""

import dataclasses
from typing import Any

from structlog.testing import capture_logs

from app.core.constants import (
    AiTask,
    CandidateRejection,
    GapFillOutcome,
    LogEvent,
    PlanMessage,
    StrideCategory,
)
from app.data_access.library import LibraryRepository
from app.models.library import LibraryThreat
from tests.fakes import FakeRerankModel, items_in
from tests.planner_samples import (
    ADMIN_ABUSE,
    CONTEXT,
    EXFILTRATION,
    FLOOD,
    LOG_WIPE,
    RANSOMWARE,
    THREATS,
    audit_of,
    finder,
    gap_fill_for_elevation,
    planner_chat,
)

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
    """Every system of the sample run is OT: an IT threat is never even shown to the AI, and the plan says how
    many were left out and of which type. Its words are in the facts, so only a search scoped by type keeps it
    off the shortlist of another category it belongs to (Denial of Service)."""
    hit = CONTEXT.systems[0] | {"past_incidents": "Ransomware encrypts backup servers"}
    context = dataclasses.replace(CONTEXT, systems=[hit, CONTEXT.systems[1]])
    chat = planner_chat({RANSOMWARE.name: ["SYS1"], LOG_WIPE.name: ["SYS1"]})
    findings = finder(chat, threats=_library(_typed(RANSOMWARE, "IT"))).find_threats(context)
    assert [threat.name for threat in findings.threats] == [LOG_WIPE.name]
    asked = [
        item["threat"] for user in chat.asked(AiTask.RELEVANCE_GATE) for item in items_in(user, "CANDIDATES")
    ]
    assert RANSOMWARE.name not in asked and LOG_WIPE.name in asked
    takes = r"IT\OT, OT"  # every system of the sample run is OT
    assert PlanMessage.ASSET_TYPE_LEFT_OUT.format(count=1, types="IT", takes=takes) in findings.notes


def test_a_threat_stays_only_where_its_type_fits_and_is_refused_where_it_cannot_be() -> None:
    """An OT threat judged to apply on the OT and the IT system keeps the OT one; judged to apply only on the
    IT system, or only on the IT asset itself, it is refused with its reason. Code decides, before any
    gap-fill: a category it empties still gets its one AI threat."""
    relevant = {
        RANSOMWARE.name: ["SYS1", "SYS2"],
        FLOOD.name: ["SYS2"],
        ADMIN_ABUSE.name: [],  # the asset itself
        LOG_WIPE.name: ["SYS2"],  # untyped: fits everywhere
    }
    library = _library(_typed(RANSOMWARE, "OT"), _typed(FLOOD, "OT"), _typed(ADMIN_ABUSE, " ot "))
    findings = finder(planner_chat(relevant), threats=library).find_threats(MIXED)
    assert {threat.name: threat.systems for threat in findings.threats} == {
        RANSOMWARE.name: (321,),
        LOG_WIPE.name: (322,),
    }
    refused = {
        rejected["threat"]: rejected["reason"]
        for audit in findings.audits
        for rejected in audit.rejected
        if rejected["code"] == CandidateRejection.ASSET_TYPE_MISMATCH
    }
    mismatch = PlanMessage.ASSET_TYPE_MISMATCH
    assert refused == {
        FLOOD.name: mismatch.format(asset_type="OT", places="Historian (IT)"),
        ADMIN_ABUSE.name: mismatch.format(asset_type="OT", places="Grid Control Centre (IT)"),  # its label
    }
    assert audit_of(findings, S.ELEVATION_OF_PRIVILEGE).gap_fill == GapFillOutcome.NONE_APPLIES


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


def test_an_asset_type_that_is_not_a_value_fits_everywhere_and_is_noted_for_a_curator() -> None:
    """Owner: "IT-OT" is not a value. The threat is still judged, never silently lost; the plan names it."""
    library = _library(_typed(RANSOMWARE, "IT-OT"))
    findings = finder(
        planner_chat({RANSOMWARE.name: ["SYS1"]}), threats=library, unknown_asset_type=(1,)
    ).find_threats(CONTEXT)
    assert [threat.name for threat in findings.threats] == [RANSOMWARE.name]
    assert PlanMessage.ASSET_TYPE_UNKNOWN.format(count=1, ids="1") in findings.notes


def test_an_ai_proposal_is_never_a_repeat_of_a_library_threat_this_run_never_judged() -> None:
    """The gap-fill's library match looks only at threats whose type fits the run: before, an OT proposal
    could be dropped as "a repeat" of an IT library threat that was never shown to the AI."""
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
    library = _library(_typed(ADMIN_ABUSE, "IT"))  # every system of the sample run is OT
    elevation = audit_of(
        finder(chat, rerank, threats=library).find_threats(CONTEXT), S.ELEVATION_OF_PRIVILEGE
    )
    assert elevation.gap_fill == GapFillOutcome.REJECTED  # judged by the gate, not called a repeat
    assert CandidateRejection.AI_REDUNDANT not in [rejected["code"] for rejected in elevation.rejected]


def test_a_threat_never_keeps_a_system_of_another_type_through_a_fold() -> None:
    """G211 review: a fold unites the systems of the threats it joins. An OT threat placed on its OT system,
    folded with a twin (same attack, same type) also on the IT system, kept the IT one and was written
    on it."""
    relevant = {RANSOMWARE.name: ["SYS1"], EXFILTRATION.name: ["SYS1", "SYS2"]}  # EXFILTRATION: untyped
    chat = planner_chat(relevant)
    chat.responders[AiTask.SAME_ATTACK] = lambda _: {
        "same": [{"threats": ["THR1", "THR2"], "reason": "One."}]
    }
    library = _library(_typed(RANSOMWARE, "OT"))
    findings = finder(chat, threats=library).find_threats(MIXED)
    assert [fold.threat.key for fold in findings.folded] == [f"lib:{EXFILTRATION.catalogue_id}"]
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
        library = LibraryRepository(_OldProcedures()).load_threat_library()  # type: ignore[arg-type]
    assert {threat.asset_type for threat in library.threats} == {None}
    assert [entry["event"] for entry in logs] == [LogEvent.LIBRARY_THREAT_ASSET_TYPE_MISSING]

    class _Controls:
        def execute_procedure(self, _procedure: object) -> list[list[dict[str, Any]]]:
            row = {"ControlLibraryID": 1, "ControlCode": "AC-01", "AssetType": "IT-OT", "Domain": "Access",
                   "ControlName": "Account management", "ControlDescription": "Reviews."}  # fmt: skip
            return [[row], []]

    with capture_logs() as logs:
        (control,), _ = LibraryRepository(_Controls()).load_control_library()  # type: ignore[arg-type]
    assert control.fits(set()) and [entry["event"] for entry in logs] == [LogEvent.LIBRARY_ASSET_TYPE_UNKNOWN]


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
    library = LibraryRepository(_Procedures()).load_threat_library()  # type: ignore[arg-type]
    assert [threat.asset_type for threat in library.threats] == ["OT", r"IT\OT", "IT-OT", None]
    assert library.threats_unknown_asset_type == (3,)
