"""A run's status for the caller who asks: only their entity's runs (404 unknown, 403 another entity's)."""

from typing import Any

import structlog

from app.core.constants import Dependency, LogEvent, SessionMessage
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Forbidden, NotFound
from app.data_access.sessions import find_session_status
from app.models.run_board import build_board
from app.models.scenarios import SessionStatus

log = structlog.get_logger(__name__)


def find_status_for_caller(session_id: str, entity_id: int) -> SessionStatus:
    """The status body of a session the caller's entity owns; an AppError says why not (a MongoDB outage
    is answered 503 by the API's store handler)."""
    status = find_session_status(session_id)
    if status is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    if status.entity_id != entity_id:
        raise Forbidden(SessionMessage.OTHER_ENTITY.format(session_id=session_id))
    return status


def read_current_status(session_id: str) -> dict[str, Any] | None:
    """The run's status body read now (the same body as GET /v1/sessions/{id}); None when MongoDB cannot say
    (the next published change follows anyway); NotFound once the run is gone (its owner deleted it, G214)."""
    try:
        status = find_session_status(session_id)
    except MONGO_UNAVAILABLE_ERRORS:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        return None
    if status is None:
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=session_id))
    return build_board(status).model_dump(mode="json")
