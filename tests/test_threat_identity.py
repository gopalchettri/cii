"""A hand-written scenario's threat identity (BLUEPRINT M05 Rule L2, BUILD_PLAN S55): live, pending, curator-
rejected and new wordings; ids and names that must agree; a threat the library files under another type; the
category rule. Pure, no store."""

from typing import Any

import pytest

from app.core.constants import ConflictReason, LibraryRowKind, LibraryStatus, StrideCategory
from app.core.exceptions import Invalid
from app.domain.remediation.threat_identity import resolve_threat
from app.models.library import (
    LibraryActor,
    LibraryThreat,
    LibraryThreatType,
    PendingLibraryRow,
    RejectedLibraryThreat,
    ThreatLibrary,
)
from app.models.remediation_requests import ManualScenario

CREW = LibraryActor(3, "Organised crime group")
TAMPERING, ELEVATION = StrideCategory.TAMPERING, StrideCategory.ELEVATION_OF_PRIVILEGE
LIBRARY = ThreatLibrary(
    threats=(LibraryThreat(10, "Firmware tampering", 1, "Malware", (TAMPERING, ELEVATION), (CREW,)),),
    actors=(CREW,),
    types=(
        LibraryThreatType(1, "Malware", TAMPERING, (CREW,)),
        LibraryThreatType(2, "Phishing", StrideCategory.SPOOFING),
    ),
    category_ids=((1, "Spoofing"), (2, "Tampering")),
    pending=(
        PendingLibraryRow(LibraryRowKind.TYPE, 5, "Supply chain", None),
        PendingLibraryRow(LibraryRowKind.THREAT, 20, "Vendor implant", 5),
    ),
    curator_rejected=(RejectedLibraryThreat(30, "Rogue USB", 1),),
)


def _flat(part: str, ref: dict[str, Any]) -> dict[str, Any]:
    """v1's flat fields of one reference: {"id": 1} → {"threat_type_id": 1, "threat_type_name": None}."""
    return {f"{part}_id": ref.get("id"), f"{part}_name": ref.get("name")}


def _resolved(threat_type: dict[str, Any], threat: dict[str, Any], **fields: Any) -> Any:
    category = fields.pop("threat_category", None)
    scenario = ManualScenario.model_validate(
        {
            "asset_id": 1179,
            "entity_id": 1,
            "supporting_system_ids": [1488],
            **_flat("threat_type", threat_type),
            **_flat("threat", threat),
            **(_flat("threat_category", category) if category else {}),
            "threat_scenario": "A cybercriminal could tamper with the RTU's firmware.",
            "risk_statement": "Loss of trusted control could interrupt transmission.",
        }
        | fields
    )
    return resolve_threat(LIBRARY, scenario)


def _refused(threat_type: dict[str, Any], threat: dict[str, Any], **fields: Any) -> Invalid:
    with pytest.raises(Invalid) as refused:
        _resolved(threat_type, threat, **fields)
    return refused.value


def test_a_live_threat_takes_its_first_category() -> None:
    identity = _resolved({"name": "malware"}, {"id": 10, "name": "Firmware Tampering"})
    found = (identity.category, identity.type_id, identity.catalogue_id, identity.status)
    assert found == (TAMPERING, 1, 10, LibraryStatus.ACTIVE)
    assert identity.threat_name == "Firmware tampering"


def test_pending_rejected_and_new_wordings() -> None:
    pending = _resolved({"name": "Supply chain"}, {"name": "vendor implant"})
    assert (pending.type_id, pending.catalogue_id, pending.status, pending.category) == (
        5,
        20,
        LibraryStatus.PENDING,
        None,
    )
    rejected = _resolved({"id": 1}, {"name": "Rogue USB"})
    found = (rejected.catalogue_id, rejected.status, rejected.type_id)
    assert found == (None, LibraryStatus.CURATOR_REJECTED, 1)
    new_threat = _resolved({"id": 1}, {"name": "Logic bomb"})
    assert (new_threat.status, new_threat.category, new_threat.type_name) == (None, TAMPERING, "Malware")
    new_type = _resolved({"name": "Insider sabotage"}, {"name": "Logic bomb"})
    assert (new_type.type_id, new_type.category) == (None, None)


def test_ids_and_names_must_agree_and_a_threat_keeps_its_type() -> None:
    """Every fault in one 422; a known threat under another type is type_mismatch, naming the library's
    type."""
    mismatch = _refused({"name": "Phishing"}, {"name": "Firmware tampering"})
    assert mismatch.reason == ConflictReason.TYPE_MISMATCH
    assert "'Malware'" in (mismatch.errors or [])[0]["message"]
    both = _refused({"id": 99}, {"id": 10, "name": "Wiper"})
    assert [error["field"] for error in both.errors or []] == [
        "body.manual_scenario.threat_type_id",
        "body.manual_scenario.threat_name",
        "body.manual_scenario.threat_type_id",  # and Firmware tampering is the library's Malware
    ]


def test_the_category_given_must_be_stride_and_one_the_threat_is_filed_under() -> None:
    by_id = _resolved({"name": "Malware"}, {"name": "Logic bomb"}, threat_category={"id": 2})
    assert by_id.category == TAMPERING
    filed = _resolved({"name": "Malware"}, {"id": 10}, threat_category={"name": "elevation of privilege"})
    assert filed.category == ELEVATION
    not_filed = _refused({"name": "Malware"}, {"id": 10}, threat_category={"name": "Spoofing"})
    assert "not 'Spoofing'" in (not_filed.errors or [])[0]["message"]
    both = _refused(
        {"name": "Malware"}, {"name": "Logic bomb"}, threat_category={"id": 2, "name": "Spoofing"}
    )
    assert (both.errors or [])[0]["field"] == "body.manual_scenario.threat_category_name"  # review S56
    unknown = _refused({"name": "Malware"}, {"name": "Logic bomb"}, threat_category={"name": "Fraud"})
    assert unknown.errors == [
        {"field": "body.manual_scenario.threat_category_name", "message": "'Fraud' is not a STRIDE category."}
    ]
