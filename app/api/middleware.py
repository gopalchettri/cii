"""The API's middleware: the request context (id, body-size cap, access line, metrics) and unexpected errors."""

import re
import time
import uuid

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import answer_unexpected_error
from app.core import metrics
from app.core.config import get_settings
from app.core.constants import ErrorMessage, Header, LogEvent

_ENTITY_ID = re.compile(r"\d{1,18}")  # the X-Entity-Id the identity check accepts: a positive whole number
#: Health probes: /ready answers 503 on purpose while a part is missing: never an error.
_PROBE_ROUTES = frozenset({"/health", "/ready", "/metrics"})
log = structlog.get_logger("http")
_BYTES_PER_MB = 1024 * 1024


class RequestContextMiddleware:
    """Request id, echoed idempotency key, body-size cap, one access line and metrics (a crash: status 500)."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request_id = _bind_request_context(scope)
        status = 500  # stays 500 when the app raises before it starts a response
        body_bytes = 0
        response_started: float | None = None
        limit = get_settings().max_request_mb * _BYTES_PER_MB

        async def receive_within_size_limit() -> Message:
            nonlocal body_bytes
            message = await receive()
            body_bytes += len(message.get("body", b""))
            if body_bytes > limit:  # counted, so a chunked body without a length is capped too
                raise HTTPException(413, ErrorMessage.REQUEST_TOO_LARGE.format(limit=limit))
            return message

        async def send_with_request_id(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status = message["status"]
                response_started = time.perf_counter()
                headers = MutableHeaders(scope=message)
                headers[Header.REQUEST_ID] = request_id
                if idempotency_key := scope["state"].get("idempotency_key"):  # a replay and a refusal too
                    headers[Header.IDEMPOTENCY_KEY] = idempotency_key
            await send(message)

        started = time.perf_counter()
        try:
            await self._app(scope, receive_within_size_limit, send_with_request_id)
        finally:
            _record_request(scope, status, started, response_started)


def _bind_request_context(scope: Scope) -> str:
    headers = Headers(scope=scope)
    supplied_id = headers.get(Header.REQUEST_ID, "")
    # A caller's own id only when short and plain, so it cannot forge or flood log lines.
    request_id = supplied_id if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", supplied_id) else uuid.uuid4().hex
    scope.setdefault("state", {})["request_id"] = request_id
    structlog.contextvars.clear_contextvars()
    entity_id = headers.get(Header.ENTITY_ID, "")
    structlog.contextvars.bind_contextvars(
        request_id=request_id, entity_id=entity_id if _ENTITY_ID.fullmatch(entity_id) else None
    )
    return request_id


def _record_request(scope: Scope, status: int, started: float, response_started: float | None) -> None:
    seconds = time.perf_counter() - started
    route = getattr(scope.get("route"), "path", "unmatched")
    # Latency = time until the response starts: a live-update stream stays open for minutes.
    latency = (response_started or time.perf_counter()) - started
    metrics.HTTP_REQUESTS.labels(scope["method"], route, str(status)).inc()
    metrics.HTTP_SECONDS.labels(route).observe(latency)
    state = scope.get("state", {})
    failed = status >= 400 and route not in _PROBE_ROUTES
    write = (log.error if status >= 500 else log.warning) if failed else log.info
    write(
        LogEvent.HTTP_REQUEST,
        method=scope["method"],
        route=route,
        path=scope["path"],
        status=status,
        duration_ms=round(seconds * 1000, 1),
        client_id=state.get("client_id"),  # the calling system; None without a valid key
        # Not "..._key": logs mask such fields.
        idempotency=state.get("idempotency_key"),
        **state.get("problem", {}),
    )


class AnswerUnexpectedErrors:
    """Innermost: an unexpected error becomes the 500 problem here, inside CORS and the request context."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = False

        async def send_and_note(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self._app(scope, receive, send_and_note)
        except Exception as exc:
            if started:  # part of a response is already sent (a stream): nothing else can be answered
                raise
            response = await answer_unexpected_error(Request(scope), exc)
            await response(scope, receive, send)
