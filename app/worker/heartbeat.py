"""Worker heartbeat: how /ready knows every queue has a live worker.

Each worker pod stamps its hostname, with the time, under every queue it consumes (one Redis sorted set per
queue), every Worker.HEARTBEAT_SECONDS. /ready counts only stamps newer than Worker.ONLINE_WITHIN_SECONDS, so
a pod that dies without a word drops out within a minute."""

import contextlib
import threading
from collections.abc import Iterable
from pathlib import Path

import structlog

from app.core.clock import epoch_seconds
from app.core.constants import LogEvent, Worker
from app.core.database import get_redis_client
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS

log = structlog.get_logger(__name__)


class WorkerHeartbeat:
    """One worker process's heartbeat: a background thread that beats until the worker shuts down."""

    def __init__(self, queues: Iterable[str], hostname: str) -> None:
        self._keys = [Worker.HEARTBEAT_KEY.format(queue=queue) for queue in queues]
        self._hostname = hostname
        self._stopped = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._beat_until_stopped, name="worker-heartbeat", daemon=True).start()

    def beat(self) -> None:
        """One Redis round trip: stamp this worker and drop stamps too old to count."""
        now = epoch_seconds()
        with get_redis_client().pipeline(transaction=False) as pipe:
            for key in self._keys:
                pipe.zadd(key, {self._hostname: now})
                pipe.zremrangebyscore(key, "-inf", now - Worker.ONLINE_WITHIN_SECONDS)
            pipe.execute()

    def stop(self) -> None:
        """Leave at once on a clean shutdown, instead of looking alive for another minute."""
        self._stopped.set()
        pipe = get_redis_client().pipeline(transaction=False)
        for key in self._keys:
            pipe.zrem(key, self._hostname)
        with contextlib.suppress(*REDIS_UNAVAILABLE_ERRORS):  # Redis down: the stamp ages out within a minute
            pipe.execute()

    def _beat_until_stopped(self) -> None:
        while True:
            _touch_liveness_file()  # first and whatever Redis does: the pod's liveness probe reads its age
            try:
                self.beat()
            except Exception:  # noqa: BLE001 — ANY Redis error (failover read-only, OOM, auth…) must not end
                # the thread: a dead heartbeat makes /ready drop every API pod until this worker restarts.
                log.warning(LogEvent.WORKER_HEARTBEAT_FAILED, exc_info=True)
            if self._stopped.wait(Worker.HEARTBEAT_SECONDS):
                return


def _touch_liveness_file() -> None:
    """Mark this worker alive for its pod's liveness probe (the file's age), with no Redis involved."""
    with contextlib.suppress(OSError):  # ponytail: no /tmp (a Windows laptop) means no probe to feed
        Path(Worker.LIVENESS_FILE).touch()
