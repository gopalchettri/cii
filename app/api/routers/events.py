"""Live updates over Server-Sent Events (SSE).

A client opens GET /v1/sessions/{session_id}/events (#8) or GET /v1/remediation/{remediation_id}/events (#28)
with the usual identity headers. It receives the current status at once, then every change as a
`session.updated` or `remediation.updated` event, until it closes the connection; or until the run or plan is
deleted (G214): one `session.deleted` or `remediation.deleted` event, then the stream ends."""

import asyncio
from collections.abc import AsyncIterator, Callable
from functools import partial
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.dependencies import get_authenticated_principal
from app.core.constants import Event, Realtime, SessionState, StageState, Status
from app.core.exceptions import NotFound
from app.models.api_clients import Principal
from app.realtime.event_hub import EventHub
from app.realtime.publisher import remediation_channel, session_channel
from app.services.remediation.queries import (
    find_remediation_status_for_caller,
    read_current_remediation_status,
)
from app.services.session_status import find_status_for_caller, read_current_status

router = APIRouter(tags=["live updates"])

#: A plan's queued or running version; a run's job still at work.
_UNFINISHED = {Status.QUEUED, Status.RUNNING, SessionState.ACTIVE}


async def check_session_for_caller(
    session_id: str, principal: Annotated[Principal, Depends(get_authenticated_principal)]
) -> None:
    """Runs before the stream starts, so an unknown run (404), another entity's run (403) or an outage (503)
    is an ordinary problem response, not a broken stream."""
    await asyncio.to_thread(find_status_for_caller, session_id, principal.entity_id)


@router.get(
    "/v1/sessions/{session_id}/events",
    response_class=EventSourceResponse,
    dependencies=[Depends(check_session_for_caller)],
    summary="Live status of a run (Server-Sent Events)",
)
async def stream_session_events(session_id: str, request: Request) -> AsyncIterator[ServerSentEvent]:
    reads = partial(read_current_status, session_id)
    gone = ServerSentEvent(event=Event.SESSION_DELETED, data={"session_id": session_id})
    channel = session_channel(session_id)
    async for event in _status_stream(request, channel, reads, (Event.SESSION_UPDATED, gone)):
        yield event


async def check_remediation_for_caller(
    remediation_id: str, principal: Annotated[Principal, Depends(get_authenticated_principal)]
) -> None:
    await asyncio.to_thread(find_remediation_status_for_caller, remediation_id, principal.entity_id)


@router.get(
    "/v1/remediation/{remediation_id}/events",
    response_class=EventSourceResponse,
    dependencies=[Depends(check_remediation_for_caller)],
    summary="Live status of a remediation plan (Server-Sent Events)",
)
async def stream_remediation_events(remediation_id: str, request: Request) -> AsyncIterator[ServerSentEvent]:
    reads = partial(read_current_remediation_status, remediation_id)
    channel = remediation_channel(remediation_id)
    gone = ServerSentEvent(event=Event.REMEDIATION_DELETED, data={"remediation_id": remediation_id})
    async for event in _status_stream(request, channel, reads, (Event.REMEDIATION_UPDATED, gone)):
        yield event


async def _status_stream(
    request: Request,
    channel: str,
    read_status: Callable[[], dict[str, Any] | None],
    events: tuple[Event, ServerSentEvent],
) -> AsyncIterator[ServerSentEvent]:
    """Subscribed first, read second: a change saved between the two is never missed. A message only says
    "this record changed" (or RESYNC: "read again"): the status is always read from MongoDB, so a status
    that a worker published late can never replace a newer one, and a burst of changes costs one read."""
    hub: EventHub = request.app.state.event_hub
    (event, gone), last_sent = events, None
    async with hub.listen(channel) as updates:
        while True:
            try:  # None: MongoDB cannot say; the next change announced brings it
                status = await asyncio.to_thread(read_status)
            except NotFound:  # deleted (G214): the watcher is told once, and nothing more can come
                yield gone
                return
            if status is not None and status != last_sent:
                yield ServerSentEvent(event=event, data=status, retry=Realtime.RETRY_MS)
                last_sent = status
            # An unfinished record is read again every Realtime.RECHECK_SECONDS even with no message: its last
            # change may never be announced (a failed publish, a failed read), and nothing comes after it.
            unfinished = last_sent is None or _unfinished(last_sent)
            try:
                await asyncio.wait_for(updates.get(), Realtime.RECHECK_SECONDS if unfinished else None)
            except TimeoutError:
                continue
            while not updates.empty():
                updates.get_nowait()  # one read covers every change announced meanwhile


def _unfinished(body: dict[str, Any]) -> bool:
    """A run whose job is at work or whose controls are still being matched (`session_status`, `progress`); a
    plan whose latest version is queued or running (`latest_status`)."""
    if (body.get("progress") or {}).get("controls") == StageState.RUNNING:
        return True
    return str(body.get("session_status") or body.get("latest_status")) in _UNFINISHED
