"""The audit trail: who did what to which record. A failed write never fails the action it describes (it is
logged, counted and alerted on): AuditRepository.create_audit_record in
app/data_access/admin/audit_repository.py."""

import functools
from collections.abc import Callable
from typing import Any, cast

from app.core.constants import AiApi, AuditTarget
from app.core.logging import job_origin_scope
from app.models.admin.api_clients import Principal


def caller_actor(principal: Principal) -> dict[str, Any]:
    """The actor of a business call: the calling system, its user and their entity."""
    return {"client_id": principal.client_id, "user_id": principal.user_id, "entity_id": principal.entity_id}


def origin_of_its_jobs[**Params, Result](
    api: AiApi,
) -> Callable[[Callable[Params, Result]], Callable[Params, Result]]:
    """A service method (self, principal, ...) whose jobs work for API call `api` and its caller while it runs
    (job.origin, carried by their AI usage rows); one it calls keeps the outer name."""

    def decorate(method: Callable[Params, Result]) -> Callable[Params, Result]:
        @functools.wraps(method)
        def named(*args: Params.args, **kwargs: Params.kwargs) -> Result:
            principal = cast(Principal, kwargs.get("principal") or args[1])
            with job_origin_scope(api, principal.client_id, principal.entity_id):
                return method(*args, **kwargs)

        return named

    return decorate


def admin_actor(user_id: str) -> dict[str, Any]:
    """The actor of an admin-key call (no API client, no entity)."""
    return {"admin": True, "user_id": user_id}


def audit_target(kind: AuditTarget, target_id: str | list[str]) -> dict[str, Any]:
    """The record (or records) an action changed: {type, id}; the index on `target.id` finds any one."""
    return {"type": kind, "id": target_id}
