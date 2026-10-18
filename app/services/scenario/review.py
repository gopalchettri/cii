"""Accepting and rejecting a run's scenarios: a call names every id at fault before it writes, then decides in
one update filtered on the decision it expects, so of two racing calls exactly one changes a scenario."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.core.constants import AuditAction, AuditTarget, Decision, ScenarioStatus
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.scenario.repository import scenarios
from app.domain.scenario.library_rules import known_threat_ids
from app.domain.scenario.review import (
    Targets,
    check_review_open,
    check_something_to_accept,
    controls_pending,
    decidable_targets,
    decided_stamp,
    decision_outcome,
    split_accept_all,
    versions_to_replace,
)
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


def _new_decided_stamp(principal: Principal) -> dict[str, Any]:
    """This call's decided stamp: now, and a new decision id."""
    return decided_stamp(principal, datetime.now(UTC), uuid.uuid4().hex)


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
        return AcceptResult(
            accepted=accepted,
            replaced=replaced,
            skipped=skipped,
            controls_pending=controls_pending(targets, accepted),
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
        known = known_threat_ids(self._threat_library()) if decision == Decision.ACCEPTED else frozenset()
        return decidable_targets(scenario_ids, found, decision, known)

    def _everything_acceptable(self, session_id: str) -> tuple[Targets, list[TargetSkipped]]:
        """Accept-all's targets and skips among the run's current written versions not rejected."""
        rows = scenarios.list(
            fields="target",
            sort="created_at",
            session_id=session_id,
            status=ScenarioStatus.DONE,
            newest=True,
            not_rejected=True,
        )
        check_something_to_accept(session_id, rows)
        accepted = _accepted_version_of_attack_paths(session_id, sorted({row["path_id"] for row in rows}))
        return split_accept_all(rows, accepted, known_threat_ids(self._threat_library()))

    def _make_room(self, session_id: str, targets: Targets, replace: bool, principal: Principal) -> list[str]:
        """One accepted version per path: the other accepted versions of the targets' paths go back to
        pending first, with replace_accepted (their ids returned), else 409 duplicate_version."""
        path_ids = list(dict.fromkeys(target["path_id"] for target in targets))
        accepted = _accepted_version_of_attack_paths(session_id, path_ids)
        others = versions_to_replace(targets, accepted, replace)
        if others:
            # A crash before the accept leaves the path with none accepted: the same call repeated heals it.
            stamp = _new_decided_stamp(principal)
            scenarios.update_scenario_decisions(others, Decision.ACCEPTED, Decision.PENDING, stamp)
        return others

    def _decide(
        self, session_id: str, targets: Targets, decision: Decision, principal: Principal
    ) -> tuple[list[str], list[str], list[TargetSkipped]]:
        """(ids holding `decision` now, newly given it, skipped by a race): one update for the pending ones,
        and one re-read only when it could not change them all."""
        ids = [target["_id"] for target in targets]
        pending = [target["_id"] for target in targets if target["decision"] == Decision.PENDING]
        stamp = _new_decided_stamp(principal)
        changed = (
            scenarios.update_scenario_decisions(pending, Decision.PENDING, decision, stamp) if pending else 0
        )
        if changed == len(pending):
            return ids, pending, []
        now = list_review_targets(session_id, ids)
        return decision_outcome(ids, pending, now, decision, stamp["decision_id"])

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
