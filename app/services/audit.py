"""The audit trail: who did what to which record, kept Audit.KEEP_DAYS in tsg_audit
(app/data_access/audit.py).

A failed write never fails the action it describes: it is logged, counted (tsg_audit_failures_total) and
alerted on (AuditWriteFailing). Each record costs one insert; its indexes are made at start-up."""

from typing import Any

from app.core.constants import AuditTarget
from app.data_access.audit import record_audit
from app.models.api_clients import Principal


def caller_actor(principal: Principal) -> dict[str, Any]:
    """The actor of a business call: the calling system, its user and their entity."""
    return {"client_id": principal.client_id, "user_id": principal.user_id, "entity_id": principal.entity_id}


def admin_actor(user_id: str) -> dict[str, Any]:
    """The actor of an admin-key call (no API client, no entity)."""
    return {"admin": True, "user_id": user_id}


def audit_target(kind: AuditTarget, target_id: str) -> dict[str, str]:
    """The record an action changed: {type, id} — `target.id` is indexed."""
    return {"type": kind, "id": target_id}


def audit_targets(kind: AuditTarget, target_ids: list[str]) -> dict[str, Any]:
    """Several records changed by one call (#24): `target.id` holds them all, and the index on it finds the
    record by any one of them."""
    return {"type": kind, "id": target_ids}


# record_audit lives in app/data_access/audit.py (a worker audits too); the services import it from here.
__all__ = ["admin_actor", "audit_target", "audit_targets", "caller_actor", "record_audit"]
