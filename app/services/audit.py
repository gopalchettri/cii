"""The audit trail: who did what to which record. A failed write never fails the action it describes (it is
logged, counted and alerted on): audit_records.create_audit_record in app/data_access/admin/repository.py."""

from typing import Any

from app.core.constants import AuditTarget
from app.models.api_clients import Principal


def caller_actor(principal: Principal) -> dict[str, Any]:
    """The actor of a business call: the calling system, its user and their entity."""
    return {"client_id": principal.client_id, "user_id": principal.user_id, "entity_id": principal.entity_id}


def admin_actor(user_id: str) -> dict[str, Any]:
    """The actor of an admin-key call (no API client, no entity)."""
    return {"admin": True, "user_id": user_id}


def audit_target(kind: AuditTarget, target_id: str | list[str]) -> dict[str, Any]:
    """The record (or records) an action changed: {type, id}; the index on `target.id` finds any one."""
    return {"type": kind, "id": target_id}
