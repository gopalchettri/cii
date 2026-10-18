"""The library's curation: a curator lists, approves or rejects the threats proposed to the library."""

from typing import Any

from app.core.constants import AuditAction, AuditTarget
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.domain.library.curation import decision_operation_key
from app.domain.shared.audit import admin_actor, audit_target
from app.models.library.curation import LibraryDecisions


class ThreatLibraryService:
    def __init__(self, threats: ThreatRepository, audit: AuditRepository) -> None:
        self._threats, self._audit = threats, audit

    def list_pending_library_threats(self, offset: int, limit: int) -> dict[str, Any]:
        """A page of the rows waiting for a curator, with the total."""
        items, total = self._threats.list_pending_threats(offset, limit)
        return {"items": items, "total": total}

    def decide_pending_library_threats(self, decisions: LibraryDecisions, decided_by: str) -> dict[str, Any]:
        """One outcome per id in one transaction, and one audit row findable by any of its ids. The same
        decisions sent again (a retry) answer the first answer; another call on decided ids answers
        already_approved or already_rejected."""
        operation_key = decision_operation_key(decisions.approve, decisions.reject, decided_by)
        results, applied_now = self._threats.decide_pending_threats(
            operation_key, decisions.approve, decisions.reject, decided_by
        )
        if not applied_now:  # answered from its operation record: audited when it was applied
            return {"results": results}
        self._audit.create_audit_record(
            AuditAction.LIBRARY_DECIDED,
            admin_actor(decided_by),
            audit_target(AuditTarget.LIBRARY_THREAT, [str(row["catalogue_id"]) for row in results]),
            details={"approve": decisions.approve, "reject": decisions.reject, "results": results},
        )
        return {"results": results}
