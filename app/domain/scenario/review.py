"""Which scenarios a reviewer may accept, reject or regenerate: checks on the run and the scenarios it read,
each naming every id at fault, so a call refuses before it writes."""

from collections import Counter
from collections.abc import Collection
from datetime import datetime
from typing import Any

from app.core.constants import (
    AiOutage,
    ConflictReason,
    Decision,
    ReviewMessage,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    TargetProblem,
)
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.models.admin.api_clients import Principal
from app.models.scenario.views import SessionStatus, TargetSkipped

Targets = list[dict[str, Any]]


def check_session_of_caller(record: dict[str, Any] | None, session_id: str, entity_id: int) -> dict[str, Any]:
    """The scenario session record the caller's entity owns: 404 when there is none, 403 when another's."""
    if record is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    if record["entity_id"] != entity_id:
        raise Forbidden(SessionMessage.OTHER_ENTITY.format(session_id=session_id))
    return record


def check_review_open(run: SessionStatus) -> None:
    """409 while the run generates, or when it failed or was cancelled finding threats (no scenario)."""
    if run.status in (Status.QUEUED, Status.RUNNING):
        message = ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
        raise Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)
    if run.status == Status.FAILED and run.step == Step.THREATS:
        message = ReviewMessage.RUN_FAILED.format(session_id=run.session_id)
        raise Conflict(message, reason=ConflictReason.RUN_FAILED)
    if run.status == Status.CANCELLED and run.step == Step.THREATS:
        message = ReviewMessage.RUN_CANCELLED.format(session_id=run.session_id)
        raise Conflict(message, reason=ConflictReason.RUN_CANCELLED)


def decided_stamp(principal: Principal, now: datetime, decision_id: str) -> dict[str, Any]:
    """Who decided and when; `decision_id` names the call, so a race's re-read knows which ids it decided."""
    return {
        "decided_by": principal.user_id,
        "decided_by_client": principal.client_id,
        "decided_at": now,
        "decision_id": decision_id,
        "updated_at": now,
    }


def why_ids_cannot_be_decided(
    scenario_ids: list[str],
    targets: dict[str, dict[str, Any]],
    decision: Decision,
    known_threat_ids: Collection[int],
) -> list[dict[str, str]]:
    """Why each id cannot take `decision`: unknown, a failure card, already given the other decision, and for
    an accept two versions of one path or a retired library threat. Already holding `decision` is no fault."""
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
            accepting = decision == Decision.ACCEPTED
            reason = TargetProblem.ALREADY_REJECTED if accepting else TargetProblem.ALREADY_ACCEPTED
        elif decision == Decision.ACCEPTED:
            reason = _accept_problem(target, versions_per_path, known_threat_ids)
        else:
            reason = None
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    return errors


def decidable_targets(
    scenario_ids: list[str],
    targets: dict[str, dict[str, Any]],
    decision: Decision,
    known_threat_ids: Collection[int],
) -> Targets:
    """The targets in the order sent; 409 scenarios_not_decidable naming every id at fault."""
    errors = why_ids_cannot_be_decided(scenario_ids, targets, decision, known_threat_ids)
    if errors:
        message = ReviewMessage.NOT_DECIDABLE.format(decision=decision)
        raise Conflict(message, reason=ConflictReason.SCENARIOS_NOT_DECIDABLE, errors=errors)
    return [targets[scenario_id] for scenario_id in scenario_ids]


def threat_still_in_library(target: dict[str, Any], known_threat_ids: Collection[int]) -> bool:
    """The scenario's library threat is still live or pending; an AI-proposed threat always passes."""
    threat = (target.get("content") or {}).get("threat") or {}
    library_id = threat.get("library_id")
    return bool(threat.get("ai_generated")) or library_id is None or library_id in known_threat_ids


def _accept_problem(
    target: dict[str, Any], versions_per_path: Counter[str], known_threat_ids: Collection[int]
) -> TargetProblem | None:
    """Why a pending scenario cannot be accepted: another version of its path, or a retired library threat."""
    if versions_per_path[target["path_id"]] > 1:
        return TargetProblem.DUPLICATE_VERSION
    if not threat_still_in_library(target, known_threat_ids):
        return TargetProblem.LIBRARY_INACTIVE
    return None


def check_something_to_accept(session_id: str, rows: Targets) -> None:
    """409 nothing_to_accept when the run has no current written version that is not rejected."""
    if not rows:
        message = ReviewMessage.NOTHING_TO_ACCEPT.format(session_id=session_id)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_ACCEPT)


def split_accept_all(
    rows: Targets, accepted: dict[str, str], known_threat_ids: Collection[int]
) -> tuple[Targets, list[TargetSkipped]]:
    """Accept-all's targets among the current written versions not rejected (`accepted`: each path's accepted
    version). Skipped: a path with another accepted version (accept-all never replaces), a second current
    version of a path, a retired library threat."""
    taken = dict(accepted)
    targets, skipped = [], []
    for row in rows:
        if row["decision"] == Decision.ACCEPTED:  # listed again, whatever has changed since
            targets.append(row)
        elif taken.setdefault(row["path_id"], row["_id"]) != row["_id"]:
            skipped.append(TargetSkipped(scenario_id=row["_id"], reason=TargetProblem.DUPLICATE_VERSION))
        elif not threat_still_in_library(row, known_threat_ids):
            skipped.append(TargetSkipped(scenario_id=row["_id"], reason=TargetProblem.LIBRARY_INACTIVE))
        else:
            targets.append(row)
    return targets, skipped


def versions_to_replace(targets: Targets, accepted: dict[str, str], replace: bool) -> list[str]:
    """One accepted version per path: the other accepted versions of the targets' paths, to go back to
    pending first; 409 duplicate_version naming each target when `replace` (replace_accepted) is off."""
    wanted = {target["path_id"]: target["_id"] for target in targets}
    others = {path_id: sid for path_id, sid in accepted.items() if sid != wanted[path_id]}
    if others and not replace:
        errors = [
            {"scenario_id": wanted[path_id], "reason": TargetProblem.DUPLICATE_VERSION} for path_id in others
        ]
        message = ReviewMessage.ANOTHER_VERSION_ACCEPTED
        raise Conflict(message, reason=ConflictReason.DUPLICATE_VERSION, errors=errors)
    return list(others.values())


def decision_outcome(
    ids: list[str], pending: list[str], now: dict[str, dict[str, Any]], decision: Decision, decision_id: str
) -> tuple[list[str], list[str], list[TargetSkipped]]:
    """(ids holding `decision` now, newly given it by the call `decision_id`, skipped by a race) from the
    targets re-read after an update that could not change every pending one."""
    holding = [scenario_id for scenario_id in ids if now.get(scenario_id, {}).get("decision") == decision]
    mine = {scenario_id for scenario_id, row in now.items() if row.get("decision_id") == decision_id}
    newly = [scenario_id for scenario_id in pending if scenario_id in mine]
    raced = [
        TargetSkipped(scenario_id=scenario_id, reason=TargetProblem.CHANGED_CONCURRENTLY)
        for scenario_id in ids
        if scenario_id not in holding
    ]
    return holding, newly, raced


def controls_pending(targets: Targets, accepted: list[str]) -> list[str]:
    """The accepted ids whose controls are not mapped yet."""
    mapping = {t["_id"] for t in targets if (t.get("controls") or {}).get("status") != Status.DONE}
    return [scenario_id for scenario_id in accepted if scenario_id in mapping]


def why_ids_cannot_be_regenerated(
    scenario_ids: list[str], targets: dict[str, dict[str, Any]]
) -> list[dict[str, str]]:
    """Why each id cannot be regenerated: only the current written version of a path, or an AI outage's
    failure card (its path written again, even one given up), one per path."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        if target is None:
            reason: TargetProblem | None = TargetProblem.UNKNOWN
        elif target["status"] != ScenarioStatus.DONE and not _is_outage_card(target):
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


def regenerate_batch(scenario_ids: list[str], targets: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """The write batch replacing each chosen scenario with a new version of its path, or writing an outage
    card's path again in place (replaces None); 409 scenarios_not_regenerable naming each bad id."""
    errors = why_ids_cannot_be_regenerated(scenario_ids, targets)
    if errors:
        message = ReviewMessage.NOT_REGENERABLE
        raise Conflict(message, reason=ConflictReason.SCENARIOS_NOT_REGENERABLE, errors=errors)
    return [
        {"path_id": targets[sid]["path_id"], "replaces": None if _is_outage_card(targets[sid]) else sid}
        for sid in scenario_ids
    ]


def _is_outage_card(target: dict[str, Any]) -> bool:
    """A failure card an AI outage left."""
    reason = (target.get("failure") or {}).get("reason")
    return target["status"] == ScenarioStatus.FAILED and reason in AiOutage


def controls_were_cancelled(run: SessionStatus) -> bool:
    """True when the run shows a cancel: cancelled, stamped by one, or holding cancelled controls."""
    return (
        run.status == Status.CANCELLED
        or run.cancelled is not None
        or run.counts.get("controls_cancelled", 0) > 0
    )


def cancel_stamp_seen(run: SessionStatus) -> datetime | None:
    """When the cancel the caller saw on the run was made; None when it saw none."""
    return (run.cancelled or {}).get("at")
