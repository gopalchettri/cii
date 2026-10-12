"""The curator's use cases (#23, #24; BLUEPRINT WF-10): list the threats waiting for a decision, and approve
or reject them. Approved threats go live in SQL at once; every pod reloads the library within a minute (the
stamp check) and the next embeddings build gives them their vectors."""

from typing import Any

from app.core.constants import AuditAction, AuditTarget
from app.core.database import get_stored_procedure_client
from app.core.singletons import singleton
from app.data_access.pending_threats import PendingThreats
from app.models.library_curation import LibraryDecisions
from app.services.audit import admin_actor, audit_targets, record_audit


class LibraryCuration:
    def __init__(self, pending: PendingThreats) -> None:
        self._pending = pending

    def list_pending(self, offset: int, limit: int) -> dict[str, Any]:
        items, total = self._pending.list_page(offset, limit)
        return {"items": items, "total": total}

    def decide(self, decisions: LibraryDecisions, decided_by: str) -> dict[str, Any]:
        """One outcome per id, in one transaction; one audit record for the call, findable by any of its ids.
        Safe to retry: a repeated decision answers already_approved or already_rejected."""
        results = self._pending.decide(decisions.approve, decisions.reject, decided_by)
        record_audit(
            AuditAction.LIBRARY_DECIDED,
            admin_actor(decided_by),
            audit_targets(AuditTarget.LIBRARY_THREAT, [str(row["catalogue_id"]) for row in results]),
            details={"approve": decisions.approve, "reject": decisions.reject, "results": results},
        )
        return {"results": results}


@singleton
def get_library_curation() -> LibraryCuration:
    return LibraryCuration(PendingThreats(get_stored_procedure_client()))
