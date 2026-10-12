"""Which scenario ids a review call may act on: every id at
fault is named with its reason, so the caller fixes the whole request at once. Pure functions on the targets a
call read (app/data_access/scenario_review.py); no database call here."""

from collections import Counter
from collections.abc import Collection
from typing import Any

from app.core.constants import Decision, RunKind, ScenarioStatus, TargetProblem

Targets = dict[str, dict[str, Any]]


def why_ids_cannot_be_decided(
    scenario_ids: list[str], targets: Targets, decision: Decision, known_threat_ids: Collection[int]
) -> list[dict[str, str]]:
    """Why each id cannot take `decision`: not a served scenario of the run, a failure card, already given the
    other decision (decisions are final), and for an accept two versions of one path or a library threat
    retired since it was written. Already given `decision` is no fault, whatever changed since (a threat
    retired after the accept, G146): a repeat lists it again."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        if target is None:
            reason: TargetProblem | None = TargetProblem.UNKNOWN
        elif target["status"] != ScenarioStatus.DONE:
            reason = TargetProblem.FAILURE_SCENARIO
        elif target["decision"] == decision:
            reason = None
        elif target["decision"] != Decision.PENDING:
            reason = (
                TargetProblem.ALREADY_REJECTED
                if decision == Decision.ACCEPTED
                else TargetProblem.ALREADY_ACCEPTED
            )
        elif decision == Decision.ACCEPTED:
            reason = _accept_problem(target, versions_per_path, known_threat_ids)
        else:
            reason = None
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    return errors


def why_ids_cannot_be_regenerated(scenario_ids: list[str], targets: Targets) -> list[dict[str, str]]:
    """Why each id cannot be regenerated: only the current written version of a path, one per path. A failure
    card is retried by the write job itself (R-8), never regenerated, so two jobs never write one path."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        if target is None:
            reason: TargetProblem | None = TargetProblem.UNKNOWN
        elif target["status"] != ScenarioStatus.DONE:
            reason = TargetProblem.FAILURE_SCENARIO
        elif target.get("source") == RunKind.MANUAL:
            reason = TargetProblem.HAND_WRITTEN
        elif target.get("superseded_by"):
            reason = TargetProblem.VERSION_NOT_CURRENT
        elif versions_per_path[target["path_id"]] > 1:
            reason = TargetProblem.DUPLICATE_VERSION
        else:
            reason = None
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    return errors


def threat_still_in_library(target: dict[str, Any], known_threat_ids: Collection[int]) -> bool:
    """A scenario's library threat is still live or pending (G126's rule, at decision time); an AI-proposed
    threat has no library row until a person promotes it, so it always passes."""
    threat = (target.get("content") or {}).get("threat") or {}
    library_id = threat.get("library_id")
    return bool(threat.get("ai_generated")) or library_id is None or library_id in known_threat_ids


def _accept_problem(
    target: dict[str, Any], versions_per_path: Counter[str], known_threat_ids: Collection[int]
) -> TargetProblem | None:
    if versions_per_path[target["path_id"]] > 1:
        return TargetProblem.DUPLICATE_VERSION
    if not threat_still_in_library(target, known_threat_ids):
        return TargetProblem.LIBRARY_INACTIVE
    return None
