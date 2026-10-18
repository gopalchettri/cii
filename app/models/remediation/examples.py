"""The two published bodies of `POST /v1/remediation` (Swagger's example picker): v1's approved payloads, one
per kind of scenario. A test validates each against PlanRequest, so an example can never drift from the
model."""

from typing import Any

from pydantic import JsonValue

#: The register's data, as the platform sends it with either kind.
_REGISTER: dict[str, Any] = {
    "existing_controls": [{"control_code": "CII-CID-202"}, "User Awareness"],
    "likelihood_rating": 4,
    "impact_rating": 5,
    "final_risk_rating": 20,
    "risk_level": "Critical",
    "risk_identification_date": "2026-09-15T09:30:00Z",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Power Generation Operations",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification": "Controls are deployed on corporate IT systems only.",
    "mitigation_start_date": "2026-10-01",
    "mitigation_end_date": "2026-12-31",
}

PLAN_REQUEST_EXAMPLES: list[JsonValue] = [
    # A generated scenario: the run's id and the accepted scenario's id (from GET /v1/sessions/{id}/results).
    {
        "is_manual": False,
        "session_id": "<session_id>",
        "scenario_id": "<accepted scenario_id>",
        **_REGISTER,
    },
    # A hand-written scenario (send an Idempotency-Key header with it): TSG saves it, accepts it and plans it.
    {
        "is_manual": True,
        "manual_scenario": {
            "asset_id": 1166,
            "entity_id": 1,
            "supporting_system_id": [2301, 2302],
            "threat_category_name": "Tampering",
            "threat_type_name": "Malware/Ransomware",
            "threat_name": "Ransomware encrypts the historian server",
            "threat_scenario": "An attacker phishes an engineer, moves to the historian and encrypts it.",
            "risk_statement": "Operators lose process history and plant reporting stops for days.",
            "mapped_controls": [{"control_code": "CII-CID-213"}],
        },
        **_REGISTER,
    },
]
