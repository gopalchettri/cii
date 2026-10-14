"""Replacing a failed path within the hard limit (G229, owner 2026-10-13: "Maintain a bounded pool of eligible
reserve candidates ... Rank replacement candidates using critical-risk priority, incremental threat and
supporting-system coverage, evidence eligibility, and redundancy reduction ... Prevent duplicate promotion,
replacement cycles, and unbounded retries ... final_scenario_count <= TOTAL_SCENARIO_COUNT").

The reserves are the paths TOTAL_SCENARIO_COUNT left out (target_reached), already found and ranked: a run is
never padded. With TOTAL_SCENARIO_COUNT 0 every valid path is already selected, so there is no reserve. A
reserve is promoted at most once (then it is selected) and a replaced path never comes back (its reason is
replaced_after_failure), so there is no cycle; the selected count never grows. The best reserve adds the most
to what the kept paths cover, in the ranking's own order (a HIGH-impact threat not yet covered, new systems, a
new kind, a new threat); with intelligence on, never one whose threat's search already found nothing, one with
evidence in hand first; then plan rank. A set may spend its own paths x MAX_PATH_ATTEMPTS write calls, today's
worst case: a replacement is written only while that budget is not spent. Pure."""

from collections.abc import Iterable
from typing import Any

from app.core.constants import Generation, ThreatFinding, UnselectedReason

_HIGH = ThreatFinding.IMPACT_RANK["HIGH"]
#: A reserve's evidence: in hand (first), not searched yet, or searched and none found (never promoted).
_IN_HAND, _UNSEARCHED, _NONE = 0, 1, 2


def best_reserve(
    paths: Iterable[dict[str, Any]], threats: dict[str, dict[str, Any]], needs_evidence: bool
) -> dict[str, Any] | None:
    """The reserve to write in a failed path's place, or None (no reserve: TOTAL_SCENARIO_COUNT 0, all
    used, or, intelligence on, none with a chance of evidence)."""
    every = list(paths)
    kept = [path for path in every if path["selected"] and not path["abandoned"]]
    reserves = [
        path
        for path in every
        if not path["selected"] and path.get("unselected_reason") == UnselectedReason.TARGET_REACHED
    ]
    evidence = {
        path["path_id"]: _evidence_of(path, threats) if needs_evidence else _IN_HAND for path in reserves
    }
    reserves = [path for path in reserves if evidence[path["path_id"]] != _NONE]
    if not reserves:
        return None
    systems = {system for path in kept for system in path["systems"]}
    kinds = {path["categories"][0] for path in kept}
    covered = {key for path in kept for key in path["steps"]}

    def order(path: dict[str, Any]) -> tuple[Any, ...]:
        new_threat = any(key not in covered for key in path["steps"])
        critical = (path.get("impact") or 0) >= _HIGH and new_threat
        new_systems = len(set(path["systems"]) - systems)
        new_kind = path["categories"][0] not in kinds
        return (
            not critical,
            -new_systems,
            not new_kind,
            not new_threat,
            evidence[path["path_id"]],
            path["rank"],
        )

    return min(reserves, key=order)


def budget_left(set_paths: Iterable[dict[str, Any]]) -> bool:
    """Whether the set may still write a replacement: the write calls spent (each try that failed, each path
    written) stay under its own paths x MAX_PATH_ATTEMPTS (replacements bring no budget of their own)."""
    paths = list(set_paths)
    own = sum(not path.get("replaces") for path in paths)
    spent = sum(path["attempts"] + (1 if path["served"] else 0) for path in paths)
    return spent < own * Generation.MAX_PATH_ATTEMPTS


def _evidence_of(path: dict[str, Any], threats: dict[str, dict[str, Any]]) -> int:
    threat = (threats.get(path["steps"][0]) or {}) if path["steps"] else {}
    search = threat.get("intel_search")
    if search is None or search.get("failure") is not None or search.get("snapshot_id") is None:
        return _UNSEARCHED
    return _IN_HAND if threat.get("evidence") else _NONE
