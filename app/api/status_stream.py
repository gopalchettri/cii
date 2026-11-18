"""Shared SSE loop for records whose current status lives in MongoDB."""

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any

import structlog
from fastapi import Request
from fastapi.sse import ServerSentEvent

from app.core.constants import Dependency, Event, LogEvent, Realtime
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, NotFound
from app.realtime.event_hub import EventHub

log = structlog.get_logger(__name__)


async def status_stream(
    request: Request,
    channel: str,
    read_status: Callable[[], dict[str, Any] | None],
    event: Event,
    still_allowed: Callable[[], bool],
    gone: ServerSentEvent | None = None,
) -> AsyncIterator[ServerSentEvent]:
    """Subscribe before reading, coalesce changes, and recheck after missed publications."""
    hub: EventHub = request.app.state.event_hub
    last_sent = None
    async with hub.listen(channel) as updates:
        while True:
            try:
                allowed = await asyncio.to_thread(still_allowed)
            except MONGO_UNAVAILABLE_ERRORS:
                allowed = True  # a MongoDB blip skips this re-check, the stream goes on
            if not allowed:
                return
            try:
                status = await asyncio.to_thread(read_status)
            except NotFound:
                if gone is not None:
                    yield gone
                return
            except MONGO_UNAVAILABLE_ERRORS:
                log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
                status = None  # a MongoDB blip skips this read, the stream goes on
            if status is not None and status != last_sent:
                yield ServerSentEvent(event=event, data=status, retry=Realtime.RETRY_MS)
                last_sent = status
            try:
                await asyncio.wait_for(updates.get(), Realtime.RECHECK_SECONDS)
            except TimeoutError:
                continue
            await asyncio.sleep(Realtime.COALESCE_SECONDS)
            while not updates.empty():
                updates.get_nowait()
