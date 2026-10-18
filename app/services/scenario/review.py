"""Accepting and rejecting a run's scenarios: a call names every id at fault before it writes, then decides in
one update filtered on the decision it expects, so of two racing calls exactly one changes a scenario."""

import uuid
from collections import Counter
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    Decision,
    ReviewMessage,
    ScenarioStatus,
    Status,
    Step,
    TargetProblem,
)
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.scenario.repository import scenarios
from app.models.api_clients import Principal
from app.models.library import ThreatLibrary
from app.models.scenario.views import (
    AcceptRequest,
    AcceptResult,
    RejectResult,
    ScenarioIdsRequest,
    SessionStatus,
    TargetSkipped,
)
from app.realtime.publisher import publish_session_status
from app.search.library_cache import get_library_service
from app.services.audit import audit_target, caller_actor

Targets = list[dict[str, Any]]


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


def decided_stamp(principal: Principal) -> dict[str, Any]:
    """Who decided and when; `decision_id` names this call, so a race's re-read knows which ids it decided."""
    now = datetime.now(UTC)
    return {
        "decided_by": principal.user_id,
        "decided_by_client": principal.client_id,
        "decided_at": now,
        "decision_id": uuid.uuid4().hex,
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


def list_review_targets(session_id: str, scenario_ids: list[str]) -> dict[str, dict[str, Any]]:
    """The scenario session's served tsg_scenarios among `scenario_ids`, by id; another's is not found."""
    found = scenarios.list(fields="target", scenario_id_in=scenario_ids, session_id=session_id, served=True)
    return {row["_id"]: row for row in found}


def _accepted_version_of_attack_paths(session_id: str, path_ids: list[str]) -> dict[str, str]:
    """{path_id: scenario_id} of each attack path's accepted tsg_scenarios version (one at most)."""
    found = scenarios.list(
        fields="path_id", session_id=session_id, path_id_in=path_ids, decision=Decision.ACCEPTED
    )
    return {row["path_id"]: row["_id"] for row in found}


class ReviewService:
    def __init__(self, threat_library: Callable[[], ThreatLibrary]) -> None:
        self._threat_library = threat_library

    def accept(self, principal: Principal, run: SessionStatus, request: AcceptRequest) -> AcceptResult:
        """Accepts the chosen scenarios, or every acceptable one ("all")."""
        check_review_open(run)
        replaced: list[str] = []
        if request.scenario_ids == "all":
            targets, skipped = self._everything_acceptable(run.session_id)
        else:
            targets, skipped = self._chosen(run.session_id, request.scenario_ids, Decision.ACCEPTED), []
            replaced = self._make_room(run.session_id, targets, request.replace_accepted, principal)
        accepted, newly, raced = self._decide(run.session_id, targets, Decision.ACCEPTED, principal)
        skipped += raced
        changes = {"accepted": newly, "replaced": replaced}
        self._announce(principal, run.session_id, AuditAction.SCENARIOS_ACCEPTED, changes, skipped)
        mapping = {t["_id"] for t in targets if (t.get("controls") or {}).get("status") != Status.DONE}
        controls_pending = [scenario_id for scenario_id in accepted if scenario_id in mapping]
        return AcceptResult(
            accepted=accepted, replaced=replaced, skipped=skipped, controls_pending=controls_pending
        )

    def reject(self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest) -> RejectResult:
        """Rejects the chosen scenarios."""
        check_review_open(run)
        targets = self._chosen(run.session_id, request.scenario_ids, Decision.REJECTED)
        rejected, newly, skipped = self._decide(run.session_id, targets, Decision.REJECTED, principal)
        self._announce(
            principal, run.session_id, AuditAction.SCENARIOS_REJECTED, {"rejected": newly}, skipped
        )
        return RejectResult(rejected=rejected, skipped=skipped)

    def _chosen(self, session_id: str, scenario_ids: list[str], decision: Decision) -> Targets:
        """The targets in the order sent; 409 scenarios_not_decidable naming every id at fault."""
        found = list_review_targets(session_id, scenario_ids)
        known = self._threat_library().known_threat_ids() if decision == Decision.ACCEPTED else frozenset()
        errors = why_ids_cannot_be_decided(scenario_ids, found, decision, known)
        if errors:
            message = ReviewMessage.NOT_DECIDABLE.format(decision=decision)
            raise Conflict(message, reason=ConflictReason.SCENARIOS_NOT_DECIDABLE, errors=errors)
        return [found[scenario_id] for scenario_id in scenario_ids]

    def _everything_acceptable(self, session_id: str) -> tuple[Targets, list[TargetSkipped]]:
        """Accept-all's targets: current written versions not rejected. Skipped: a path with another accepted
        version (accept-all never replaces), a second current version of a path, a retired library threat."""
        rows = scenarios.list(
            fields="target",
            sort="created_at",
            session_id=session_id,
            status=ScenarioStatus.DONE,
            newest=True,
            not_rejected=True,
        )
        if not rows:
            message = ReviewMessage.NOTHING_TO_ACCEPT.format(session_id=session_id)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_ACCEPT)
        accepted = _accepted_version_of_attack_paths(session_id, sorted({row["path_id"] for row in rows}))
        known = self._threat_library().known_threat_ids()
        targets, skipped = [], []
        for row in rows:
            if row["decision"] == Decision.ACCEPTED:  # listed again, whatever has changed since
                targets.append(row)
            elif accepted.setdefault(row["path_id"], row["_id"]) != row["_id"]:
                skipped.append(TargetSkipped(scenario_id=row["_id"], reason=TargetProblem.DUPLICATE_VERSION))
            elif not threat_still_in_library(row, known):
                skipped.append(TargetSkipped(scenario_id=row["_id"], reason=TargetProblem.LIBRARY_INACTIVE))
            else:
                targets.append(row)
        return targets, skipped

    def _make_room(self, session_id: str, targets: Targets, replace: bool, principal: Principal) -> list[str]:
        """One accepted version per path: another accepted version of a target's path is 409
        duplicate_version, or with replace_accepted goes back to pending first (its ids returned)."""
        wanted = {target["path_id"]: target["_id"] for target in targets}
        accepted = _accepted_version_of_attack_paths(session_id, list(wanted))
        others = {path_id: sid for path_id, sid in accepted.items() if sid != wanted[path_id]}
        if others and not replace:
            errors = [
                {"scenario_id": wanted[path_id], "reason": TargetProblem.DUPLICATE_VERSION}
                for path_id in others
            ]
            message = ReviewMessage.ANOTHER_VERSION_ACCEPTED
            raise Conflict(message, reason=ConflictReason.DUPLICATE_VERSION, errors=errors)
        if others:
            # A crash before the accept leaves the path with none accepted: the same call repeated heals it.
            stamp = decided_stamp(principal)
            scenarios.update_scenario_decisions(
                list(others.values()), Decision.ACCEPTED, Decision.PENDING, stamp
            )
        return list(others.values())

    def _decide(
        self, session_id: str, targets: Targets, decision: Decision, principal: Principal
    ) -> tuple[list[str], list[str], list[TargetSkipped]]:
        """(ids holding `decision` now, newly given it, skipped by a race): one update for the pending ones,
        and one re-read only when it could not change them all."""
        ids = [target["_id"] for target in targets]
        pending = [target["_id"] for target in targets if target["decision"] == Decision.PENDING]
        stamp = decided_stamp(principal)
        changed = (
            scenarios.update_scenario_decisions(pending, Decision.PENDING, decision, stamp) if pending else 0
        )
        if changed == len(pending):
            return ids, pending, []
        now = list_review_targets(session_id, ids)
        holding = [scenario_id for scenario_id in ids if now.get(scenario_id, {}).get("decision") == decision]
        mine = {
            scenario_id for scenario_id, row in now.items() if row.get("decision_id") == stamp["decision_id"]
        }
        newly = [scenario_id for scenario_id in pending if scenario_id in mine]
        raced = [
            TargetSkipped(scenario_id=scenario_id, reason=TargetProblem.CHANGED_CONCURRENTLY)
            for scenario_id in ids
            if scenario_id not in holding
        ]
        return holding, newly, raced

    def _announce(
        self,
        principal: Principal,
        session_id: str,
        action: AuditAction,
        changes: dict[str, list[str]],
        skipped: list[TargetSkipped],
    ) -> None:
        """One audit row and the decision metric for what changed, then the run's counts and a live update
        (on a repeat too, which heals counts an earlier call could not refresh)."""
        decided = changes.get("accepted", changes.get("rejected", []))
        if decided or changes.get("replaced"):
            decision = Decision.ACCEPTED if action == AuditAction.SCENARIOS_ACCEPTED else Decision.REJECTED
            metrics.DECISIONS.labels(decision).inc(len(decided))
            audit_records.create_audit_record(
                action,
                caller_actor(principal),
                audit_target(AuditTarget.SESSION, session_id),
                after=changes,
                details={"skipped": [skip.model_dump(mode="json") for skip in skipped]},
            )
        scenarios.update_scenario_session_counts(session_id)
        publish_session_status(session_id)


@singleton
def get_review_service() -> ReviewService:
    """The process's review service."""
    return ReviewService(get_library_service().get_threat_library)
