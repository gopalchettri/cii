"""Shared request dependencies: who is calling (API key + identity headers), the caller's run, and the
admin-key check."""

import hmac
from typing import Annotated

from fastapi import Depends, Path, Query, Request
from fastapi import Header as HeaderParam

from app.core.config import Settings, get_settings
from app.core.constants import Audit, ErrorMessage, Header, Limits, Review
from app.core.exceptions import Forbidden, Unauthorized
from app.models.api_clients import Principal
from app.models.scenarios import SessionStatus
from app.services.api_clients import ApiClientService, get_api_client_service
from app.services.session_status import find_status_for_caller


def get_authenticated_principal(
    request: Request,
    clients: Annotated[ApiClientService, Depends(get_api_client_service)],
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
    # Stripped BEFORE the check, so a header of spaces counts as missing.
    user_id, tenant_id = (user_id or "").strip(), (tenant_id or "").strip()
    if not (api_key and user_id and entity_id and tenant_id):
        raise Unauthorized(ErrorMessage.IDENTITY_REQUIRED)
    client_id = clients.find_client_id_for_api_key(api_key)
    if client_id is None:
        raise Unauthorized(ErrorMessage.API_KEY_INVALID)
    # Which system called, for the request's access line.
    # request.state is the scope dict the middleware reads; a log contextvar bound here would not
    # reach it, because a sync dependency runs in a worker thread.
    request.state.client_id = client_id
    return Principal(client_id, user_id, entity_id, tenant_id)


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
    expected = settings.admin_api_key.get_secret_value()
    if not expected:
        raise Forbidden(ErrorMessage.ADMIN_DISABLED)
    if not admin_key or not hmac.compare_digest(admin_key.encode(), expected.encode()):
        raise Unauthorized(ErrorMessage.ADMIN_KEY_INVALID)


def valid_session(
    session_id: str, principal: Annotated[Principal, Depends(get_authenticated_principal)]
) -> SessionStatus:
    """The caller's run: an unknown id → 404, another entity's run → 403 (as the live-update stream)."""
    return find_status_for_caller(session_id, principal.entity_id)


#: Who an admin call is recorded as (X-User-Id, else Audit.ADMIN_USER), as a route parameter.
AdminUser = Annotated[str, Depends(admin_user_id)]
#: The authenticated caller, and the caller's run (404 unknown, 403 another entity's), as route parameters.
Caller = Annotated[Principal, Depends(get_authenticated_principal)]
CallersRun = Annotated[SessionStatus, Depends(valid_session)]
#: A remediation plan's id in the path (its ownership is checked by the service: 404 unknown, 403 another's).
RemediationId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
#: A paged list's position and page size, as query parameters.
# Up to SQL Server's INT: a procedure's @Offset INT would overflow (500), not refuse (422).
Offset = Annotated[int, Query(ge=0, le=Limits.MAX_SQL_INT)]
Limit = Annotated[int, Query(ge=1, le=Limits.PAGE_SIZE_MAX)]
