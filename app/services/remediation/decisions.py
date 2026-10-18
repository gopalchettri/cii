"""Accepting or rejecting a remediation plan version: any done
version (by default the newest done one), at most one accepted, while the plan's scenario is still accepted.
One update fenced on `decision_seq`; when another decision landed in between, read again once and retry, then
409 changed_concurrently. A repeat changes nothing and audits nothing."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import AuditAction, AuditTarget, ConflictReason, Decision, RemediationMessage, Status
from app.core.exceptions import Conflict, NotFound
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.admin.repository import audit_records
from app.data_access.remediation.repository import remediation_plans
from app.data_access.scenario.repository import scenarios
from app.domain.remediation.decisions import newest_done_version, version_status, work_out_decision_change
from app.models.api_clients import Principal
from app.models.remediation import RemediationStatus
from app.models.remediation_reviews import DecisionRequest
from app.realtime.publisher import publish_remediation_status
from app.services.audit import audit_target, caller_actor
from app.services.remediation.queries import get_remediation_status
from app.services.remediation.regenerate import read_owned, refuse_read_only

_AUDITED = {Decision.ACCEPTED: AuditAction.PLAN_ACCEPTED, Decision.REJECTED: AuditAction.PLAN_REJECTED}


class PlanDecisions:
    def accept(self, principal: Principal, remediation_id: str, body: DecisionRequest) -> RemediationStatus:
        return self._decide(principal, remediation_id, body, Decision.ACCEPTED)

    def reject(self, principal: Principal, remediation_id: str, body: DecisionRequest) -> RemediationStatus:
        return self._decide(principal, remediation_id, body, Decision.REJECTED)

    @traced("remediation.decide")
    def _decide(
        self, principal: Principal, remediation_id: str, body: DecisionRequest, decision: Decision
    ) -> RemediationStatus:
        decided_by = {"decided_by": principal.user_id, "decided_by_client": principal.client_id}
        for _read_again in range(2):
            read = read_owned(principal, remediation_id)
            refuse_read_only(scenarios.get(fields=("status", "decision"), _id=read["scenario_id"]), read)
            version = _decidable(read, body.version, remediation_id)
            now = datetime.now(UTC)
            change = work_out_decision_change(read, version, decision, decided_by, body.comment, now)
            if change is None:  # a repeat
                return _status(remediation_id)
            if remediation_plans.update_remediation_plan_decision(
                remediation_id, read["decision_seq"], change
            ):
                before = {"accepted_version": read.get("accepted_version")}
                after = {"version": version, "decision": decision}
                target = audit_target(AuditTarget.REMEDIATION, remediation_id)
                audit_records.create_audit_record(
                    _AUDITED[decision], caller_actor(principal), target, before=before, after=after
                )
                publish_remediation_status(remediation_id)
                return _status(remediation_id)
        message = RemediationMessage.CHANGED_CONCURRENTLY.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.CHANGED_CONCURRENTLY)


def _status(remediation_id: str) -> RemediationStatus:
    status = get_remediation_status(remediation_id)
    if status is None:  # deleted with its run just now
        raise NotFound(RemediationMessage.PLAN_NOT_FOUND.format(remediation_id=remediation_id))
    return status


def _decidable(read: dict[str, Any], asked: int | None, remediation_id: str) -> int:
    """The version to decide: the one asked for, else the newest done one; 404 when it does not exist, 409
    when it is not done (still being written, or failed)."""
    version = asked if asked is not None else newest_done_version(read)
    if version is None:
        message = RemediationMessage.NO_DONE_VERSION.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    item = next((item for item in read["versions"] if item["version"] == version), None)
    if item is None:
        message = RemediationMessage.VERSION_NOT_FOUND.format(remediation_id=remediation_id, version=version)
        raise NotFound(message, reason=ConflictReason.VERSION_NOT_FOUND)
    if (status := version_status(read, item)) != Status.DONE:
        message = RemediationMessage.NOT_COMPLETE.format(
            version=version, remediation_id=remediation_id, status=status
        )
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    return version


@singleton
def get_plan_decisions() -> PlanDecisions:
    return PlanDecisions()
