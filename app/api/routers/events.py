"""Live updates over Server-Sent Events: a run's or a plan's status now, then at every change, until the
client closes or the record is deleted (one `.deleted` event, then the stream ends)."""

import asyncio
from collections.abc import AsyncIterator, Callable
from functools import partial
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.dependencies import CallersPlan, SessionId, valid_session
from app.core.constants import ApiTag, Event, Realtime, SessionState, StageState, Status
from app.core.exceptions import NotFound
from app.realtime.event_hub import EventHub
from app.realtime.publisher import remediation_channel, session_channel
from app.services.remediation.queries import read_current_remediation_status
from app.services.scenario.runs import read_current_status

router = APIRouter(tags=[ApiTag.LIVE_UPDATES])

#: A plan's queued or running version; a run's job still at work.
_UNFINISHED = {Status.QUEUED, Status.RUNNING, SessionState.ACTIVE}


@router.get(
    "/v1/sessions/{session_id}/events",
    response_class=EventSourceResponse,
    dependencies=[Depends(valid_session)],  # before the stream: a 404, 403 or 503 is an ordinary response
    summary="1. A run's live status",
)
async def stream_session_events(session_id: SessionId, request: Request) -> AsyncIterator[ServerSentEvent]:
    """Server-Sent Events: `session.updated` (the body of `GET /v1/sessions/{session_id}`) now and at
    every change; `session.deleted` once when it is deleted. Swagger cannot show a stream: use
    `curl -N` or a browser EventSource."""
    reads = partial(read_current_status, session_id)
    gone = ServerSentEvent(event=Event.SESSION_DELETED, data={"session_id": session_id})
    channel = session_channel(session_id)
    async for event in _status_stream(request, channel, reads, (Event.SESSION_UPDATED, gone)):
        yield event


@router.get(
    "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/events",
    response_class=EventSourceResponse,
    summary="2. A plan's live status",
)
async def stream_remediation_events(plan: CallersPlan, request: Request) -> AsyncIterator[ServerSentEvent]:
    """The plan's status now (`remediation.updated`: the body of `.../treatment-plan/status`), then every
    change, until the client closes; `remediation.deleted` once, when its run is deleted."""
    remediation_id = plan.remediation_id
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
            await asyncio.sleep(Realtime.COALESCE_SECONDS)  # a burst (a batch of saves) ends first: one read
            while not updates.empty():
                updates.get_nowait()  # one read covers every change announced meanwhile


def _unfinished(body: dict[str, Any]) -> bool:
    """A run whose job is at work or whose controls are still being matched (`session_status`, `progress`); a
    plan whose latest version is queued or running (`latest_status`)."""
    if (body.get("progress") or {}).get("controls") == StageState.RUNNING:
        return True
    return str(body.get("session_status") or body.get("latest_status")) in _UNFINISHED
