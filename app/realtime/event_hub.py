"""The event hub: how a saved change reaches every client streaming that run.

A worker saves the change in MongoDB, then publishes the run's id on its Redis channel
(app/realtime/publisher.py). Every API process holds ONE Redis subscription covering all channels (EventHub)
and hands each message to the streams open on that run (each stream is in app/api/routers/scenario.py). So
any API pod can serve any client, and Redis carries one connection per API process, not one per open
stream."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress

import structlog
from redis.asyncio import Redis as AsyncRedis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import get_settings
from app.core.constants import ErrorMessage, LogEvent, Realtime, Timeouts
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS

log = structlog.get_logger(__name__)


# Redis dropping the hub's connection; the hub waits and subscribes again.
_HUB_CONNECTION_ERRORS: tuple[type[Exception], ...] = (*REDIS_UNAVAILABLE_ERRORS, OSError)


RESYNC = object()  # put in every stream's queue after (re)subscribing: messages may have been missed


class EventHub:
    """One Redis pattern subscription per API process, shared by every open stream. It starts with the first
    stream, re-subscribes by itself after a Redis outage, and then tells every stream to re-read its status
    (messages published while it was cut off are gone)."""

    def __init__(self) -> None:
        self._streams: dict[str, set[asyncio.Queue[object]]] = {}
        self._reader: asyncio.Task[None] | None = None

    @asynccontextmanager
    async def listen(self, channel: str) -> AsyncGenerator[asyncio.Queue[object], None]:
        updates: asyncio.Queue[object] = asyncio.Queue(maxsize=Realtime.STREAM_BUFFER)
        self._streams.setdefault(channel, set()).add(updates)
        if self._reader is None or self._reader.done():
            self._reader = asyncio.create_task(self._read_forever())
        try:
            yield updates
        finally:
            listeners = self._streams.get(channel, set())
            listeners.discard(updates)
            if not listeners:
                self._streams.pop(channel, None)

    async def close(self) -> None:
        """Process shutdown: stop reading. Open streams are not ended here: uvicorn runs this only after its
        graceful-shutdown wait (--timeout-graceful-shutdown) has closed them; their clients reconnect to
        another pod and get the current status first."""
        if self._reader is not None:
            self._reader.cancel()
            with suppress(asyncio.CancelledError):
                await self._reader

    async def _read_forever(self) -> None:
        # This task was started inside the first stream's request and copied its log fields (request_id,
        # entity_id): cleared, so the hub's own lines never name that one caller. The task has its own copy.
        structlog.contextvars.clear_contextvars()
        while True:
            try:
                await self._read_until_disconnected()
            except _HUB_CONNECTION_ERRORS:
                log.warning(LogEvent.EVENT_HUB_RECONNECTING, exc_info=True)
            except Exception:  # noqa: BLE001 — any other failure (a refused PSUBSCRIBE, a bad reply) must not
                # end live updates for good: logged as an error, then the hub subscribes again.
                log.exception(LogEvent.EVENT_HUB_FAILED)
            await asyncio.sleep(Realtime.RECONNECT_SECONDS)

    async def _read_until_disconnected(self) -> None:
        redis = AsyncRedis.from_url(
            get_settings().redis_url, socket_connect_timeout=Timeouts.REDIS_SECONDS, decode_responses=True
        )
        async with redis, redis.pubsub() as subscription:
            await subscription.psubscribe(Realtime.CHANNEL_PATTERN)
            await _wait_for_subscription(subscription)
            self._send_to_every_stream(RESYNC)
            await self._relay(subscription)

    async def _relay(self, subscription: PubSub) -> None:
        """Hand each message to the streams open on its channel. A quiet connection is pinged every poll; one
        that answers nothing, not even PONG, for Realtime.SILENT_LIMIT_SECONDS counts as lost. A black-holed
        Redis keeps a dead socket open for minutes, and redis-py's own health check never waits for the reply,
        so without this every stream would silently stop updating."""
        loop = asyncio.get_running_loop()
        last_heard = loop.time()
        while True:
            message = await subscription.get_message(timeout=Realtime.POLL_SECONDS)
            if message is not None:
                last_heard = loop.time()
                if message["type"] == "pmessage":  # not a PONG or a subscription notice
                    for updates in tuple(self._streams.get(message["channel"], ())):
                        _offer(updates, message["data"])
            elif loop.time() - last_heard > Realtime.SILENT_LIMIT_SECONDS:
                raise RedisConnectionError(
                    ErrorMessage.EVENT_HUB_SILENT.format(seconds=Realtime.SILENT_LIMIT_SECONDS)
                )
            else:
                await subscription.ping()

    def _send_to_every_stream(self, item: object) -> None:
        for listeners in tuple(self._streams.values()):
            for updates in tuple(listeners):
                _offer(updates, item)


async def _wait_for_subscription(subscription: PubSub) -> None:
    """Redis's confirmation of the PSUBSCRIBE. Only then is every stream told to re-read its status: a refused
    subscription (NOPERM) raises here, so a persistent refusal never makes each open stream query MongoDB on
    every reconnect (2 s)."""
    confirmation = await subscription.get_message(timeout=Timeouts.REDIS_SECONDS)
    if confirmation is None or confirmation["type"] != "psubscribe":
        raise RedisConnectionError(ErrorMessage.EVENT_HUB_SILENT.format(seconds=Timeouts.REDIS_SECONDS))


def _offer(updates: asyncio.Queue[object], item: object) -> None:
    """Never blocks the shared reader: a client too slow to keep up loses its oldest update (each update is a
    full status, so only the latest matters)."""
    if updates.full():
        updates.get_nowait()
    updates.put_nowait(item)
