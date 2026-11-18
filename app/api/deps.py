"""The shared FastAPI dependencies: settings, the stores, the caller, its idempotency key, run and plan."""

import hashlib
import hmac
import json
from typing import Annotated, NamedTuple

from fastapi import Depends, Path, Query, Request
from fastapi import Header as HeaderParam
from pymongo.database import Database

from app.core.clock import epoch_seconds
from app.core.config import Settings, get_settings
from app.core.constants import Audit, ErrorMessage, Header, Idempotency, Limits, Review
from app.core.database import get_mongodb
from app.core.exceptions import Forbidden, Unauthorized
from app.core.security import Principal
from app.crud import admin as admin_crud
from app.domain.remediation import plans
from app.domain.scenario import runs
from app.schemas.remediation import RemediationStatus
from app.schemas.scenarios import SessionStatus


def get_authenticated_principal(
    request: Request,
    db: Annotated[Database, Depends(get_mongodb)],
    api_key: Annotated[str | None, HeaderParam(alias=Header.API_KEY)] = None,
    user_id: Annotated[str | None, HeaderParam(alias=Header.USER_ID, max_length=Limits.MAX_IDENTITY_CHARS)] = None,
    # Typed: "abc" or "-1" is refused with 422 here, never passed on to a query.
    # Up to SQL Server's INT: a larger number would fail inside the stored procedure (500), not here (422).
    entity_id: Annotated[int | None, HeaderParam(alias=Header.ENTITY_ID, gt=0, le=Limits.MAX_SQL_INT)] = None,
    tenant_id: Annotated[str | None, HeaderParam(alias=Header.TENANT_ID, max_length=Limits.MAX_IDENTITY_CHARS)] = None,
) -> Principal:
    """The caller: a known API key and all four identity headers, else 401."""
    # Stripped BEFORE the check, so a header of spaces counts as missing.
    user_id, tenant_id = (user_id or "").strip(), (tenant_id or "").strip()
    if not (api_key and user_id and entity_id and tenant_id):
        raise Unauthorized(ErrorMessage.IDENTITY_REQUIRED)
    client_id = admin_crud.get_active_client_id(db, api_key)
    if client_id is None:
        raise Unauthorized(ErrorMessage.API_KEY_INVALID)
    # Which system called, for the request's access line.
    # request.state is the scope dict the middleware reads; a log contextvar bound here would not
    # reach it, because a sync dependency runs in a worker thread.
    request.state.client_id = client_id
    return Principal(client_id, user_id, entity_id, tenant_id)


class RequestIdempotencyKey(NamedTuple):
    """The key a request is idempotent under, and whether the server derived it (the caller sent none)."""

    value: str
    derived: bool


async def idempotency_key(
    request: Request,
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
    supplied: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> RequestIdempotencyKey:
    """The caller's Idempotency-Key, else 'derived-' and a hash of the caller, method, path, body and window."""
    # ponytail: fixed windows, so a repeat that straddles a window edge (gap/60 s of double clicks) starts
    # new work; an anchored claim (first request's time + window, TTL index) if that ever matters.
    window = int(epoch_seconds() // Idempotency.DERIVED_WINDOW_SECONDS)
    caller = (principal.tenant_id, principal.entity_id, principal.user_id, principal.client_id)
    hashed = json.dumps([*caller, request.method, request.url.path, window]).encode()  # its "]" ends the prefix
    derived = Idempotency.DERIVED_PREFIX + hashlib.sha256(hashed + await request.body()).hexdigest()
    key = RequestIdempotencyKey(supplied or derived, derived=not supplied)  # a caller's key replays
    request.state.idempotency_key = key.value  # the middleware echoes it in the header and logs it
    return key


def admin_user_id(
    user_id: Annotated[str | None, HeaderParam(alias=Header.USER_ID, max_length=Limits.MAX_IDENTITY_CHARS)] = None,
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
    session_id: SessionId, principal: Annotated[Principal, Depends(get_authenticated_principal)]
) -> SessionStatus:
    """The caller's run: an unknown id → 404, another entity's run → 403."""
    return runs.get_threat_scenario_session_status(session_id, principal.entity_id)


def valid_plan(
    session_id: SessionId,
    scenario_id: ScenarioId,
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
) -> RemediationStatus:
    """The plan of the caller's scenario: none (or the scenario is in another run) → 404; another's → 403."""
    return plans.read_plan_status(session_id, scenario_id, principal.entity_id)


#: The Idempotency-Key the caller sent, else one the server derived (and which it is), as a route parameter.
IdempotencyKey = Annotated[RequestIdempotencyKey, Depends(idempotency_key)]
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

#: The shared, pooled MongoDB database (tests swap it with app.dependency_overrides).
DbDep = Annotated[Database, Depends(get_mongodb)]
