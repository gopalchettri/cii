"""Shared request dependencies: who is calling (API key + identity headers), the request's idempotency key,
the caller's run, and the admin-key check."""

import hashlib
import hmac
import json
from typing import Annotated

from fastapi import Depends, Path, Query, Request
from fastapi import Header as HeaderParam

from app.container import get_admin_service, get_remediation_plan_service, get_threat_scenario_service
from app.core.clock import epoch_seconds
from app.core.config import Settings, get_settings
from app.core.constants import Audit, ErrorMessage, Header, Idempotency, Limits, Review
from app.core.exceptions import Forbidden, Unauthorized
from app.models.admin.api_clients import Principal
from app.models.remediation.plan import RemediationStatus
from app.models.scenario.views import SessionStatus
from app.services.admin.admin_service import AdminService
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.services.scenario.threat_scenario_service import ThreatScenarioService


def get_authenticated_principal(
    request: Request,
    clients: Annotated[AdminService, Depends(get_admin_service)],
    api_key: Annotated[str | None, HeaderParam(alias=Header.API_KEY)] = None,
    user_id: Annotated[
        str | None, HeaderParam(alias=Header.USER_ID, max_length=Limits.MAX_IDENTITY_CHARS)
    ] = None,
    # Typed: "abc" or "-1" is refused with 422 here, never passed on to a query.
    # Up to SQL Server's INT: a larger number would fail inside the stored procedure (500), not here (422).
    entity_id: Annotated[int | None, HeaderParam(alias=Header.ENTITY_ID, gt=0, le=Limits.MAX_SQL_INT)] = None,
    tenant_id: Annotated[
        str | None, HeaderParam(alias=Header.TENANT_ID, max_length=Limits.MAX_IDENTITY_CHARS)
    ] = None,
) -> Principal:
    """The caller: a known API key and all four identity headers, else 401."""
    # Stripped BEFORE the check, so a header of spaces counts as missing.
    user_id, tenant_id = (user_id or "").strip(), (tenant_id or "").strip()
    if not (api_key and user_id and entity_id and tenant_id):
        raise Unauthorized(ErrorMessage.IDENTITY_REQUIRED)
    client_id = clients.get_api_client_id(api_key)
    if client_id is None:
        raise Unauthorized(ErrorMessage.API_KEY_INVALID)
    # Which system called, for the request's access line.
    # request.state is the scope dict the middleware reads; a log contextvar bound here would not
    # reach it, because a sync dependency runs in a worker thread.
    request.state.client_id = client_id
    return Principal(client_id, user_id, entity_id, tenant_id)


async def raw_body(request: Request) -> bytes:
    """The request body exactly as sent (FastAPI has read it already)."""
    return await request.body()


def idempotency_key(
    request: Request,
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
    body: Annotated[bytes, Depends(raw_body)],
    supplied: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> str:
    """The caller's Idempotency-Key, else one derived from the request; kept for the answer and the log."""
    key = supplied or derived_idempotency_key(principal, request.method, request.url.path, body)
    request.state.idempotency_key = key  # the middleware echoes it in the header and logs it
    return key


def derived_idempotency_key(principal: Principal, method: str, path: str, body: bytes) -> str:
    """'derived-' and a hash of the caller, method, path, exact body and the current window."""
    # ponytail: fixed windows, so a repeat that straddles a window edge (gap/60 s of double clicks) starts
    # new work; an anchored claim (first request's time + window, TTL index) if that ever matters.
    window = int(epoch_seconds() // Idempotency.DERIVED_WINDOW_SECONDS)
    caller = (principal.tenant_id, principal.entity_id, principal.user_id, principal.client_id)
    request = json.dumps([*caller, method, path, window]).encode() + body  # the list's "]" ends the prefix
    return Idempotency.DERIVED_PREFIX + hashlib.sha256(request).hexdigest()


def admin_user_id(
    user_id: Annotated[
        str | None, HeaderParam(alias=Header.USER_ID, max_length=Limits.MAX_IDENTITY_CHARS)
    ] = None,
) -> str:
    """Who an admin call is recorded as: the X-User-Id the admin sent, else Audit.ADMIN_USER."""
    return (user_id or "").strip() or Audit.ADMIN_USER


def require_admin_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    admin_key: Annotated[str | None, HeaderParam(alias=Header.ADMIN_KEY)] = None,
) -> None:
    """403 while no admin key is set, 401 for a wrong one."""
    expected = settings.admin_api_key.get_secret_value()
    if not expected:
        raise Forbidden(ErrorMessage.ADMIN_DISABLED)
    if not admin_key or not hmac.compare_digest(admin_key.encode(), expected.encode()):
        raise Unauthorized(ErrorMessage.ADMIN_KEY_INVALID)


#: A run's and a scenario's id in a path: /v1/sessions/{session_id}/scenarios/{scenario_id}.
SessionId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
ScenarioId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]


def valid_session(
    session_id: SessionId,
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
    scenarios: Annotated[ThreatScenarioService, Depends(get_threat_scenario_service)],
) -> SessionStatus:
    """The caller's run: an unknown id → 404, another entity's run → 403."""
    return scenarios.get_threat_scenario_session_status(session_id, principal.entity_id)


def valid_plan(
    session_id: SessionId,
    scenario_id: ScenarioId,
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
    plans: Annotated[RemediationPlanService, Depends(get_remediation_plan_service)],
) -> RemediationStatus:
    """The plan of the caller's scenario: none (or the scenario is in another run) → 404; another's → 403."""
    return plans.get_remediation_plan_status(session_id, scenario_id, principal.entity_id)


#: The Idempotency-Key the caller sent, else one the server derived, as a route parameter.
IdempotencyKey = Annotated[str, Depends(idempotency_key)]
#: Who an admin call is recorded as (X-User-Id, else Audit.ADMIN_USER), as a route parameter.
AdminUser = Annotated[str, Depends(admin_user_id)]
#: The authenticated caller, and the caller's run (404 unknown, 403 another entity's), as route parameters.
Caller = Annotated[Principal, Depends(get_authenticated_principal)]
CallersRun = Annotated[SessionStatus, Depends(valid_session)]
#: The caller's scenario's remediation plan (404 none, 403 another entity's), as a route parameter.
CallersPlan = Annotated[RemediationStatus, Depends(valid_plan)]
#: A paged list's position and page size, as query parameters.
# Up to SQL Server's INT: a procedure's @Offset INT would overflow (500), not refuse (422).
Offset = Annotated[int, Query(ge=0, le=Limits.MAX_SQL_INT)]
Limit = Annotated[int, Query(ge=1, le=Limits.PAGE_SIZE_MAX)]
