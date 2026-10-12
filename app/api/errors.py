"""The global error handlers: every error leaves the API as one RFC 9457 problem body. Messages come from
app/core/constants/ (ErrorMessage and the domain message enums); a title is its HTTP status phrase."""

from collections.abc import Awaitable, Callable
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


#: A framework error's code: the code of our error with the same status. Any other 4xx it raises (405,
#: 413 …) is the caller's input: validation_error.
_ERROR_CODE_BY_HTTP_STATUS = {
    error.status: error.code for error in (Unauthorized, Forbidden, NotFound, Conflict)
}


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
    """The one error body (RFC 9457) for every HTTP error response. With type "about:blank" the title is
    the status phrase ("Not Found"), the same whoever raised the error (RFC 9457 §4.2.1)."""
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
    # Set here too: a 500 is answered outside every middleware, so only this puts the id on it.
    headers: dict[str, str] = {Header.REQUEST_ID.value: request_id} if request_id else {}
    if retry_after:
        headers["Retry-After"] = str(retry_after)
    if status == 401:  # RFC 9110 §15.5.2: a 401 names how to authenticate
        headers["WWW-Authenticate"] = Problem.AUTH_CHALLENGE
    return JSONResponse(body, status_code=status, media_type=Problem.MEDIA_TYPE, headers=headers)


async def answer_app_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)  # registered for AppError only
    if exc.status >= 500:
        # With the driver's own error: a rotated password and a short outage both answer 503, and only the
        # cause tells them apart.
        cause = repr(exc.__cause__) if exc.__cause__ is not None else None
        log.warning(LogEvent.HTTP_APP_ERROR, code=exc.code, detail=exc.detail, cause=cause)
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
        {"field": ".".join(str(part) for part in error["loc"]), "message": error["msg"]}
        for error in exc.errors()
    ]
    return build_problem_response(
        request, Invalid.status, Invalid.code, ErrorMessage.FIELDS_INVALID, errors=errors
    )


async def answer_http_error(request: Request, exc: Exception) -> JSONResponse:
    """Errors the framework raises itself (404 unknown route, 405, 413 …), with their own headers kept
    (e.g. `Allow` on a 405)."""
    assert isinstance(exc, StarletteHTTPException)  # registered for StarletteHTTPException only
    code = _ERROR_CODE_BY_HTTP_STATUS.get(exc.status_code, ErrorCode.VALIDATION_ERROR)
    response = build_problem_response(request, exc.status_code, code, str(exc.detail))
    response.headers.update(exc.headers or {})
    return response


def store_unavailable_answer(
    dependency: Dependency, message: ErrorMessage
) -> Callable[[Request, Exception], Awaitable[JSONResponse]]:
    """A driver error meaning the store is unreachable: 503 + Retry-After, never a 500."""

    async def answer_store_unavailable(request: Request, exc: Exception) -> JSONResponse:
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=dependency, error=str(exc))
        outage = Unavailable(message)
        return build_problem_response(
            request, outage.status, outage.code, outage.detail, retry_after=outage.retry_after
        )

    return answer_store_unavailable


async def answer_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception(LogEvent.HTTP_UNHANDLED_ERROR, path=request.url.path)
    return build_problem_response(request, AppError.status, AppError.code, ErrorMessage.UNEXPECTED)


_STORE_OUTAGES: tuple[tuple[tuple[type[Exception], ...], Dependency, ErrorMessage], ...] = (
    (MONGO_UNAVAILABLE_ERRORS, Dependency.MONGO, ErrorMessage.MONGO_UNREACHABLE),
    (REDIS_UNAVAILABLE_ERRORS, Dependency.REDIS, ErrorMessage.REDIS_UNREACHABLE),
)


def register_exception_handlers(app: FastAPI) -> None:
    """Every error leaves the API as one problem body (RFC 9457)."""
    app.add_exception_handler(AppError, answer_app_error)
    app.add_exception_handler(RequestValidationError, answer_invalid_request)
    app.add_exception_handler(StarletteHTTPException, answer_http_error)
    for errors, dependency, message in _STORE_OUTAGES:
        answer = store_unavailable_answer(dependency, message)
        for error_type in errors:
            app.add_exception_handler(error_type, answer)
    app.add_exception_handler(Exception, answer_unexpected_error)
