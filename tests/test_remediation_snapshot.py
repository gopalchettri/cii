"""A plan version's frozen input (BLUEPRINT M11 R4, BUILD_PLAN S48): the key order, register coverage
decided in code (twins included), the register's advisories, the one door's cut, a retired control. Pure,
no store."""

import json
from datetime import date
from typing import Any

from app.core.constants import Remediation, SnapshotWarning
from app.engine.remediation.register import register_half
from app.engine.remediation.snapshot import build_snapshot
from app.models.library import LibraryControl
from app.models.remediation_requests import RegisterData
from tests.planner_samples import CONTEXT

TODAY = date(2026, 10, 11)
LIBRARY = {
    1: LibraryControl(
        1, "CII-CID-1", "OT", "Integrity", "Firmware integrity verification", "Signed firmware."
    ),
    2: LibraryControl(2, "CII-CID-2", "IT", "Access", "Vendor remote-access approval", "Approves sessions."),
    5: LibraryControl(5, "CII-CID-5", "OT", "Access", "Vendor remote-access approval", "Approves sessions."),
}
SCENARIO: dict[str, Any] = {
    "content": {
        "title": "Loss of control integrity",
        "statement": "A cybercriminal could push unsigned firmware to the RTU at Grid Control Centre.",
        "risk_statement": "Loss of trusted control could interrupt transmission.",
        "category": "Tampering",
        "threat": {"type": "Malicious code", "name": "Firmware tampering"},
        "actors": [{"id": 7, "name": "Cybercriminal", "role": "acting"}],
        "systems": [{"id": 321, "name": "SCADA server", "entry_point": True}],
        "route": {"status": "standalone"},
    },
    "controls": {
        "items": [
            {"control_id": 1, "code": "CII-CID-1", "score": 87.4, "match": "exact"},
            {"control_id": 5, "code": "CII-CID-5", "score": 74.0, "match": "exact"},
            {"control_id": 9, "code": "CII-CID-9", "score": 66.0, "match": "exact"},
        ]
    },
}
RETIRED = SnapshotWarning.CONTROL_RETIRED.format(code="CII-CID-9")


def _snapshot(register: dict[str, Any]) -> dict[str, Any]:
    part = register_half(RegisterData.model_validate(register), list(LIBRARY.values()), TODAY)
    return build_snapshot(SCENARIO, CONTEXT, part, LIBRARY)


def test_the_keys_come_in_one_fixed_order() -> None:
    snapshot = _snapshot({})
    assert list(snapshot) == [
        "asset",
        "asset_context",
        "supporting_systems",
        "threat",
        "scenario",
        "existing_controls",
        "risk_assessment",
        "treatment_strategy",
        "register",
        "warnings",
    ]
    assert snapshot["treatment_strategy"] == "Mitigate"
    involved = snapshot["scenario"]["supporting_systems_involved"]
    assert involved == [{"supporting_system": "SCADA server", "is_entry_point": True}]
    assert [system["name"] for system in snapshot["supporting_systems"]] == ["SCADA server", "Historian"]


def test_coverage_is_decided_in_code_and_a_twin_counts_as_the_same_control() -> None:
    """The register names CII-CID-2 (IT); the scenario's CII-CID-5 is its OT twin (the same text): covered. A
    control retired since the mapping is left out, with a warning."""
    snapshot = _snapshot({"existing_controls": ["CII-CID-2", "Quarterly phishing simulation"]})
    controls = snapshot["existing_controls"]
    assert [(c["control_code"], c["covered_by_register"]) for c in controls["library_mapped"]] == [
        ("CII-CID-1", False),
        ("CII-CID-5", True),
    ]
    assert (controls["library_mapped_count"], controls["register_matched_count"]) == (2, 1)
    assert controls["register_controls"][1] == "Quarterly phishing simulation"
    assert controls["library_mapped"][0]["mapping_relevance"] == 87
    assert RETIRED in snapshot["warnings"]


def test_the_registers_numbers_and_its_three_advisories() -> None:
    """Ratings as JSON numbers (an int when whole: the AI cites them verbatim); a final rating compared with
    likelihood x impact at its own scale (20.00 is 4.47 x 4.47 rounded: no warning; 8 is not 3 x 2.46); no
    level and no final rating; a window already over; the window's inclusive length."""
    calm = _snapshot({"likelihood_rating": "4.47", "impact_rating": "4.47", "final_risk_rating": "20.00"})
    assert calm["warnings"] == [RETIRED]
    assert calm["risk_assessment"]["final_risk_rating"] == 20
    flagged = _snapshot(
        {
            "likelihood_rating": 3,
            "impact_rating": 2.46,
            "final_risk_rating": 8,
            "mitigation_start_date": "2026-01-01",
            "mitigation_end_date": "2026-03-31",
        }
    )
    assert flagged["warnings"][0].startswith("final_risk_rating 8 does not equal likelihood x impact")
    assert SnapshotWarning.WINDOW_OVER.format(end="2026-03-31") in flagged["warnings"]
    assert flagged["risk_assessment"]["assessment_window"]["total_days"] == 90
    assert SnapshotWarning.NOT_CALIBRATED in _snapshot({})["warnings"]


def test_the_risk_owner_is_echoed_never_shown_and_long_text_is_cut_visibly() -> None:
    """The risk owner (a person) stays in the echo-only block; the AI-written statement, which no request
    bounds, is cut at Remediation.TEXT_MAX_CHARS with a visible mark; a justification of a Yes/No nobody
    gave is left out."""
    register = {
        "risk_owner": "Head of Grid Operations",
        "existing_controls_all_subsystems_justification": "SCADA",
    }
    part = register_half(RegisterData.model_validate(register), list(LIBRARY.values()), TODAY)
    past_the_limit = "x" * 4500  # G227: a statement is whole up to 4,000, then cut visibly
    long_scenario = SCENARIO | {"content": SCENARIO["content"] | {"statement": past_the_limit}}
    snapshot = build_snapshot(long_scenario, CONTEXT, part, LIBRARY)
    assert snapshot["register"]["risk_owner"] == "Head of Grid Operations"
    shown_to_ai = {key: value for key, value in snapshot.items() if key not in ("register", "warnings")}
    assert "Head of Grid Operations" not in json.dumps(shown_to_ai)
    statement = snapshot["scenario"]["statement"]
    assert len(statement) == Remediation.STATEMENT_MAX_CHARS + len(Remediation.TRUNCATED_MARK)
    assert statement.endswith(" [truncated]")
    assert snapshot["existing_controls"]["applied_to_all_subsystems_justification"] is None
