"""The event hub: how a saved change reaches every client streaming that run."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress

import structlog
from redis.asyncio import Redis as AsyncRedis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import get_settings
from app.core.constants import ErrorMessage, LogEvent, Realtime, Timeouts
from app.core.database import redis_tls_options
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS

log = structlog.get_logger(__name__)
_HUB_CONNECTION_ERRORS: tuple[type[Exception], ...] = (*REDIS_UNAVAILABLE_ERRORS, OSError)  # Redis dropped us
RESYNC = object()  # put in every stream's queue after (re)subscribing: messages may have been missed


class EventHub:
    """One Redis pattern subscription per API process, shared by every stream; re-subscribes after an outage."""

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
        """Process shutdown: stop reading."""
        if self._reader is not None:
            self._reader.cancel()
            with suppress(asyncio.CancelledError):
                await self._reader

    async def _read_forever(self) -> None:
        # Started inside the first stream's request: its log fields are cleared, so hub lines never name it.
        structlog.contextvars.clear_contextvars()
        while True:
            try:
                await self._read_until_disconnected()
            except _HUB_CONNECTION_ERRORS:
                log.warning(LogEvent.EVENT_HUB_RECONNECTING, exc_info=True)
            except Exception:  # noqa: BLE001 — any other failure must not end live updates for good
                log.exception(LogEvent.EVENT_HUB_FAILED)
            await asyncio.sleep(Realtime.RECONNECT_SECONDS)

    async def _read_until_disconnected(self) -> None:
        url = get_settings().redis_url
        redis = AsyncRedis.from_url(
            url, socket_connect_timeout=Timeouts.REDIS_SECONDS, decode_responses=True, **redis_tls_options(url)
        )
        async with redis, redis.pubsub() as subscription:
            await subscription.psubscribe(Realtime.CHANNEL_PATTERN)
            await _wait_for_subscription(subscription)
            for listeners in tuple(self._streams.values()):  # messages may have been missed
                for updates in tuple(listeners):
                    _offer(updates, RESYNC)
            await self._relay(subscription)

    async def _relay(self, subscription: PubSub) -> None:
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
                raise RedisConnectionError(ErrorMessage.EVENT_HUB_SILENT.format(seconds=Realtime.SILENT_LIMIT_SECONDS))
            else:
                await subscription.ping()


async def _wait_for_subscription(subscription: PubSub) -> None:
    confirmation = await subscription.get_message(timeout=Timeouts.REDIS_SECONDS)
    if confirmation is None or confirmation["type"] != "psubscribe":
        raise RedisConnectionError(ErrorMessage.EVENT_HUB_SILENT.format(seconds=Timeouts.REDIS_SECONDS))


def _offer(updates: asyncio.Queue[object], item: object) -> None:
    if updates.full():
        updates.get_nowait()
    updates.put_nowait(item)
