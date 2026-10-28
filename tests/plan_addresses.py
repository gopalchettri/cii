"""v1's plan addresses and request body for a stored plan or scenario (owner, 2026-10-15): every call on a
plan names its run and scenario, /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan...; a
generated scenario's plan request names both, with is_manual=false."""

from typing import Any

from app.core.constants import Collection
from app.core.database import get_mongodb


def plan_url(remediation_id: str, action: str = "") -> str:
    """v1's address of a stored plan (its run and scenario read from its record); `action` e.g. "status"."""
    record = get_mongodb()[Collection.REMEDIATIONS].find_one(
        {"_id": remediation_id}, {"session_id": 1, "scenario_id": 1}
    )
    assert record is not None, f"no plan {remediation_id}"
    base = f"/v1/sessions/{record['session_id']}/scenarios/{record['scenario_id']}/treatment-plan"
    return f"{base}/{action}" if action else base


#: The risk on both supporting systems of the tests' runs (tests/planner_samples.CONTEXT: 321, 322); a test
#: about the systems sends its own lists.
ON_EVERY_SYSTEM = {"supporting_systems_applicable_to_risk": [321, 322]}


def generated(scenario_id: str, **fields: Any) -> dict[str, Any]:
    """The is_manual=false request for a stored scenario (its run read from it; unknown: no run)."""
    found = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id}, {"session_id": 1})
    run = found["session_id"] if found else "no-run"
    return {"is_manual": False, "session_id": run, "scenario_id": scenario_id, **ON_EVERY_SYSTEM, **fields}
