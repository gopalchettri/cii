"""A run's coverage (G223, owner 2026-10-13: "Maintain a coverage record", "coverage claims are traceable to
the selected scenarios"): for every supporting system of the asset and every kind of attack, the finished
scenarios' paths that cover it (count and ids), and whatever none covers with why.

G227: worked out from the plan each time the results are read, never stored. G228: only the results read the
fields it needs. G229 (owner 2026-10-13: "Coverage is calculated only from successfully finalized
scenarios"): a path counts once its scenario is finished (served), never merely because it was selected; a
gap says why: no relevant threat, the scenario limit, its scenarios failed, or not written yet (a next set
writes it). Every path given up is listed with its reason, and with the reserve that replaced it if one did.
A path's kind is its first category (G216). A path stored without systems or categories counts in the totals
and in no system or kind, so it never fails the read."""

from typing import Any

from app.core.constants import STRIDE_DEFINITIONS, CoverageGap

#: What the results read of a run to work its coverage out: a few small fields per path.
_PATH_FIELDS = (
    "path_id", "systems", "categories", "selected", "abandoned", "served", "abandoned_reason", "replaced_by",
)  # fmt: skip
COVERAGE_FIELDS: dict[str, int] = {
    "plan.target": 1,
    **{f"plan.paths.{field}": 1 for field in _PATH_FIELDS},
    "context.systems.id": 1,
    "context.systems.name": 1,
}


def run_coverage(record: dict[str, Any]) -> dict[str, Any] | None:
    """The run's coverage from its plan (`record` read with COVERAGE_FIELDS); None before a plan exists."""
    plan = record.get("plan") or {}
    if not plan.get("paths"):
        return None
    systems = {system["id"]: system["name"] for system in (record.get("context") or {}).get("systems") or []}
    return coverage_record(plan["paths"], systems, plan.get("target") or 0)


def coverage_record(paths: list[dict[str, Any]], systems: dict[int, str], limit: int) -> dict[str, Any]:
    """`paths`: the plan's paths; `systems`: every supporting system's name by id; `limit`:
    TOTAL_SCENARIO_COUNT the plan was made with (0 = none)."""
    finished = sorted((path for path in paths if path.get("served")), key=lambda path: path["path_id"])
    by_system = [
        {"id": system_id, "name": name, **_covering(finished, lambda path, s=system_id: s in _systems(path))}
        for system_id, name in sorted(systems.items())
    ]
    kinds = {
        str(kind): _covering(finished, lambda path, k=kind: _kind(path) == k) for kind in STRIDE_DEFINITIONS
    }
    gaps = [
        {"system": system["name"], "reason": _why(paths, lambda path, s=system["id"]: s in _systems(path))}
        for system in by_system
        if not system["finished"]
    ] + [
        {"kind": kind, "reason": _why(paths, lambda path, k=kind: _kind(path) == k)}
        for kind, covered in kinds.items()
        if not covered["finished"]
    ]
    return {
        "limit": limit,
        "candidates": len(paths),
        "selected": sum(bool(path.get("selected")) and not path.get("abandoned") for path in paths),
        "finished": len(finished),
        "asset_itself": sum(path.get("systems") == [] for path in finished),
        "systems": by_system,
        "kinds": kinds,
        "not_covered": gaps,
        "given_up": _given_up(paths),
    }


def _given_up(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every path given up for good, its reason, and the reserve that took its place (None: none could)."""
    return [
        {
            "path_id": path["path_id"],
            "reason": path.get("abandoned_reason"),
            "replaced_by": path.get("replaced_by"),
        }
        for path in sorted(paths, key=lambda path: path["path_id"])
        if path.get("abandoned")
    ]


def _systems(path: dict[str, Any]) -> list[Any]:
    return path.get("systems") or []


def _kind(path: dict[str, Any]) -> str | None:
    return (path.get("categories") or [None])[0]


def _covering(finished: list[dict[str, Any]], fits: Any) -> dict[str, Any]:
    """The finished paths that fit: how many and their ids, one each, in id order."""
    ids = list(dict.fromkeys(path["path_id"] for path in finished if fits(path)))
    return {"finished": len(ids), "path_ids": ids}


def _why(paths: list[dict[str, Any]], fits: Any) -> CoverageGap:
    """No path at all: no relevant threat; a selected one still to write: a next set writes it; one given up:
    its scenarios failed; else only paths the limit left out."""
    fitting = [path for path in paths if fits(path)]
    if not fitting:
        return CoverageGap.NO_RELEVANT_THREAT
    if any(path.get("selected") and not path.get("abandoned") for path in fitting):
        return CoverageGap.AWAITING_NEXT_SET
    if any(path.get("abandoned") for path in fitting):
        return CoverageGap.SCENARIOS_FAILED
    return CoverageGap.LIMIT_REACHED
