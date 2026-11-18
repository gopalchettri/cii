"""The global error handlers: every error leaves the API as one RFC 9457 problem body."""

from http import HTTPStatus
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.constants import Dependency, ErrorCode, ErrorMessage, Header, LogEvent, Problem
from app.core.exceptions import (
    MONGO_UNAVAILABLE_ERRORS,
    REDIS_UNAVAILABLE_ERRORS,
    AppError,
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    Unauthorized,
    Unavailable,
)

log = structlog.get_logger(__name__)


#: A framework error's code: ours for the same status, else validation_error.
_ERROR_CODE_BY_HTTP_STATUS = {error.status: error.code for error in (Unauthorized, Forbidden, NotFound, Conflict)}

_LOGGED_PROBLEM_FIELDS = ("code", "detail", "reason", "errors", "details")


def build_problem_body(
    status: int,
    code: ErrorCode,
    detail: str,
    *,
    request_id: str | None = None,
    reason: str | None = None,
    errors: list[dict[str, Any]] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The one error body (RFC 9457) for every HTTP error response."""
    body: dict[str, Any] = {
        "type": Problem.TYPE,
        "title": HTTPStatus(status).phrase,
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": request_id,
    }
    if reason:
        body["reason"] = reason
    if errors:
        body["errors"] = errors
    if details:
        body["details"] = details
    return body


def build_problem_response(
    request: Request,
    status: int,
    code: ErrorCode,
    detail: str,
    *,
    reason: str | None = None,
    errors: list[dict[str, Any]] | None = None,
    details: dict[str, Any] | None = None,
    retry_after: int | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    body = build_problem_body(
        status, code, detail, request_id=request_id, reason=reason, errors=errors, details=details
    )
    request.state.problem = {key: body[key] for key in _LOGGED_PROBLEM_FIELDS if key in body}
    # A 500 is answered outside every middleware, so only this puts the id on it.
    headers: dict[str, str] = {Header.REQUEST_ID.value: request_id} if request_id else {}
    if retry_after:
        headers["Retry-After"] = str(retry_after)
    if status == 401:  # RFC 9110 §15.5.2: a 401 names how to authenticate
        headers["WWW-Authenticate"] = Problem.AUTH_CHALLENGE
    return JSONResponse(body, status_code=status, media_type=Problem.MEDIA_TYPE, headers=headers)


async def answer_app_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)  # registered for AppError only
    if exc.status >= 500:
        # The cause tells a rotated password from a short outage.
        cause = exc.__cause__
        log.warning(
            LogEvent.HTTP_APP_ERROR,
            code=exc.code,
            detail=exc.detail,
            error_type=type(cause).__name__ if cause is not None else None,
            message=str(cause) if cause is not None else None,
        )
    return build_problem_response(
        request,
        exc.status,
        exc.code,
        exc.detail,
        reason=exc.reason,
        errors=exc.errors,
        details=exc.details,
        retry_after=exc.retry_after,
    )


async def answer_invalid_request(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # registered for RequestValidationError only
    errors = [
        {"field": ".".join(str(part) for part in error["loc"]), "message": error["msg"]} for error in exc.errors()
    ]
    return build_problem_response(request, Invalid.status, Invalid.code, ErrorMessage.FIELDS_INVALID, errors=errors)


async def answer_http_error(request: Request, exc: Exception) -> JSONResponse:
    """Errors the framework raises itself (404, 405, 413 …), with their own headers kept."""
    assert isinstance(exc, StarletteHTTPException)  # registered for StarletteHTTPException only
    code = _ERROR_CODE_BY_HTTP_STATUS.get(exc.status_code, ErrorCode.VALIDATION_ERROR)
    response = build_problem_response(request, exc.status_code, code, str(exc.detail))
    response.headers.update(exc.headers or {})
    return response


async def answer_store_unavailable(request: Request, exc: Exception) -> JSONResponse:
    """A driver error meaning the store is unreachable: 503 + Retry-After, never a 500."""
    is_mongo = isinstance(exc, MONGO_UNAVAILABLE_ERRORS)
    dependency = Dependency.MONGO if is_mongo else Dependency.REDIS
    log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=dependency, message=str(exc))
    outage = Unavailable(ErrorMessage.MONGO_UNREACHABLE if is_mongo else ErrorMessage.REDIS_UNREACHABLE)
    return build_problem_response(request, outage.status, outage.code, outage.detail, retry_after=outage.retry_after)


async def answer_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception(LogEvent.HTTP_UNHANDLED_ERROR, path=request.url.path)
    return build_problem_response(request, AppError.status, AppError.code, ErrorMessage.UNEXPECTED)


def register_exception_handlers(app: FastAPI) -> None:
    """Every error leaves the API as one problem body (RFC 9457)."""
    app.add_exception_handler(AppError, answer_app_error)
    app.add_exception_handler(RequestValidationError, answer_invalid_request)
    app.add_exception_handler(StarletteHTTPException, answer_http_error)
    for error_type in (*MONGO_UNAVAILABLE_ERRORS, *REDIS_UNAVAILABLE_ERRORS):
        app.add_exception_handler(error_type, answer_store_unavailable)
    app.add_exception_handler(Exception, answer_unexpected_error)
