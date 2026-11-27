"""A worker process's Celery signal receivers: start-up checks, each task's logs and metrics, shutdown."""

import contextlib
import re
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import structlog
from celery import Task, signals
from celery.concurrency import get_implementation
from prometheus_client import start_http_server

from app.core import metrics
from app.core.clock import epoch_seconds
from app.core.constants import AiLimits, Dependency, ErrorMessage, LogEvent, TaskName, Worker, module_of
from app.core.database import get_mongodb, get_redis_client, get_stored_procedure_client
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS
from app.core.lease_signal import start_thread_without_lease
from app.core.logging import configure_logging
from app.core.readiness import check_stores, log_mongodb_topology, log_redis_eviction_policy
from app.crud import indexes, work_control
from app.worker.celery_app import REQUEST_ID_HEADER, queue_of, settings
from app.worker.intel import start_following_active_snapshot, warm_up_intelligence
from app.worker.jobs import JOB_COLLECTIONS, JobWaiting
from app.worker.lease_renewal import hand_back_running_jobs

log = structlog.get_logger(__name__)

_SUPPORTED_POOLS = ("celery.concurrency.thread", "celery.concurrency.solo")
_job_started: dict[str, float] = {}


@signals.setup_logging.connect
def keep_our_logging(**_: object) -> None:
    """Connected, so Celery never resets logging to its own --loglevel (CII_LOG_LEVEL decides)."""
    configure_logging(settings)


@signals.worker_init.connect
def prepare_worker(sender: Any, **_: object) -> None:
    """Runs once before any task; SystemExit on any failure (Celery only logs an exception raised here)."""
    try:
        pool = get_implementation(sender.pool_cls).__module__
        if pool not in _SUPPORTED_POOLS:
            raise ValueError(ErrorMessage.WORKER_POOL_UNSUPPORTED.format(pool=pool))
        configure_logging(settings, log_file_role(sender.hostname))
        metrics.start_job_counters(TaskName)
        start_http_server(settings.worker_metrics_port)
        log.info(LogEvent.WORKER_METRICS_SERVING, port=settings.worker_metrics_port, pool=pool)
    except Exception as exc:  # noqa: BLE001 — any start-up failure stops the worker
        raise _start_failed(exc) from exc
    _prepare_stores_and_models()
    log_mongodb_topology()
    warm_up_external_intelligence(sender)  # before Celery starts the consumer and sends worker_ready


def _prepare_stores_and_models() -> None:
    from app import ai
    from app.ai import slots as ai_slots

    try:
        ai_slots._ai_slot_wait_seconds = AiLimits.WORKER_SLOT_WAIT_SECONDS  # a worker waits longer
        ai_slots._waits_out_rate_limits = True  # and waits out a 429: its job would only be retried later
        indexes.create_all_indexes(JOB_COLLECTIONS)
        log_redis_eviction_policy()
        ai.build_ai_gateways()
    except Exception as exc:  # noqa: BLE001 — any start-up failure stops the worker
        raise _start_failed(exc) from exc
    work_control.clear_mitre_controls_once()  # owner 2026-11-27: once, never stops start-up
    pools = [(str(AiLimits.SEARCH_POOL), ai_slots.get_ai_slots()), *ai_slots.get_module_ai_slots().items()]
    for pool, slots in pools:  # AiSlotsSaturated reads both gauges, pool by pool
        metrics.AI_SLOTS_IN_USE.labels(pool).set_function(slots.count_calls_in_progress)
        metrics.AI_SLOTS_CAP.labels(pool).set_function(slots.current_limit)


@signals.beat_init.connect
def prepare_beat(**_: object) -> None:
    """Beat writes <CII_LOG_DIR>/beat.log too, so its errors reach the logs Grafana reads."""
    try:
        configure_logging(settings, "beat")
    except OSError as exc:
        raise _start_failed(exc) from exc


def _start_failed(exc: Exception) -> SystemExit:
    log.error(LogEvent.WORKER_START_FAILED, message=str(exc), exc_info=True)
    return SystemExit(ErrorMessage.WORKER_START_FAILED.format(reason=exc))


def log_file_role(hostname: str) -> str:
    """worker-<node name>: two workers on one laptop (-n dev@%h, -n dev2@%h) never append to the same file."""
    return "worker-" + re.sub(r"[^\w.-]", "_", hostname.split("@", 1)[0])


class WorkerHeartbeat:
    """One worker process's heartbeat: a background thread that beats until the worker shuts down."""

    def __init__(self, queues: Iterable[str], hostname: str) -> None:
        self._keys = [Worker.HEARTBEAT_KEY.format(queue=queue) for queue in queues]
        self._hostname = hostname
        self._stopped = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._beat_until_stopped, name="worker-heartbeat", daemon=True).start()

    def beat(self) -> None:
        """Stamp this worker and drop stamps too old to count, in one round trip."""
        now = epoch_seconds()
        with get_redis_client().pipeline(transaction=False) as pipe:
            for key in self._keys:
                pipe.zadd(key, {self._hostname: now})
                pipe.zremrangebyscore(key, "-inf", now - Worker.ONLINE_WITHIN_SECONDS)
            pipe.execute()

    def stop(self) -> None:
        """Leave at once on a clean shutdown."""
        self._stopped.set()
        pipe = get_redis_client().pipeline(transaction=False)
        for key in self._keys:
            pipe.zrem(key, self._hostname)
        with contextlib.suppress(*REDIS_UNAVAILABLE_ERRORS):  # Redis down: the stamp ages out within a minute
            pipe.execute()

    def _beat_until_stopped(self) -> None:
        while True:
            with contextlib.suppress(OSError):  # first, whatever Redis does: the liveness probe reads its age
                Path(Worker.LIVENESS_FILE).touch()  # ponytail: no /tmp (a Windows laptop) means no probe
            try:
                self.beat()
            except Exception:  # noqa: BLE001 — ANY Redis error (failover read-only, OOM, auth…) must not end
                # the thread: a dead heartbeat makes /ready drop every API pod until this worker restarts.
                log.warning(LogEvent.WORKER_HEARTBEAT_FAILED, exc_info=True)
            check_stores((Dependency.MONGO, Dependency.REDIS))  # never SQL Server; never raises, waits <= 5 s
            if self._stopped.wait(Worker.HEARTBEAT_SECONDS):
                return


_heartbeat: WorkerHeartbeat | None = None  # this process's heartbeat, once the worker is ready


@signals.worker_ready.connect
def start_heartbeat(sender: Any, **_: object) -> None:
    """Starts once the worker consumes, so a worker that cannot reach its queues never looks alive."""
    global _heartbeat  # noqa: PLW0603 — one heartbeat per worker process, stopped by worker_shutdown
    _heartbeat = WorkerHeartbeat(sorted(sender.app.amqp.queues.consume_from), sender.hostname)
    _heartbeat.start()


def warm_up_external_intelligence(sender: Any) -> None:
    """On a scenario writer: build the intelligence index, then follow the active snapshot (never raises)."""
    if queue_of(TaskName.WRITE_SCENARIOS) not in sender.app.amqp.queues.consume_from:
        return  # maintenance still builds and publishes the index at each refresh
    warm_up_intelligence()
    start_following_active_snapshot()


@signals.task_prerun.connect
def start_job_clock(task_id: str, task: Task, args: tuple | None = None, **_: object) -> None:
    """Every task's start, logged with its record or job id, worker and the API request that sent it."""
    structlog.contextvars.clear_contextvars()  # pool threads are reused: no field leaks into the next task
    request = getattr(task, "request", None)
    request_id = getattr(request, REQUEST_ID_HEADER, None) or (getattr(request, "headers", None) or {}).get(
        REQUEST_ID_HEADER
    )
    structlog.contextvars.bind_contextvars(
        task_id=task_id,
        task=task.name,
        module=module_of(task.name),
        worker=getattr(request, "hostname", None),
        **({"record_id": str(args[0])} if args else {}),
        **({"epoch": args[1]} if args and len(args) > 1 else {}),
        **({"request_id": request_id} if request_id else {}),
    )
    _job_started[task_id] = time.perf_counter()
    log.info(LogEvent.JOB_STARTED)


@signals.task_postrun.connect
def record_job_outcome(task_id: str, task: Task, state: str | None = None, retval: object = None, **_: object) -> None:
    """Counts each delivery by its Celery state, or as `waiting` when its job waits for another job."""
    started = _job_started.pop(task_id, None)
    outcome = "waiting" if isinstance(retval, JobWaiting) else (state or "unknown").lower()
    if outcome == "ignored":
        log.info(LogEvent.JOB_FINISHED, outcome=outcome)  # another delivery owns the job: no job done
        return  # a delivery that found its job owned by another did no job: no outcome, no duration
    metrics.count_job(task.name, outcome)
    seconds = None if started is None else time.perf_counter() - started
    if seconds is not None and outcome != "waiting":  # a look for another job's work, not a job's run
        metrics.record_job_seconds(task.name, seconds)
    log.info(LogEvent.JOB_FINISHED, outcome=outcome, seconds=None if seconds is None else round(seconds, 1))


@signals.task_revoked.connect
def record_expired_delivery(sender: Task, request: Any = None, expired: bool = False, **_: object) -> None:
    """Counts a beat message dropped unrun after its expiry (on the consumer thread: nothing is bound)."""
    if expired:
        metrics.count_job(sender.name, "expired")
        job = {"task": sender.name, "module": module_of(sender.name), "task_id": getattr(request, "id", None)}
        log.warning(LogEvent.JOB_FINISHED, outcome="expired", **job)


@signals.worker_shutting_down.connect
def hand_back_jobs_when_stopping(**_: object) -> None:
    """After Worker.HAND_BACK_AFTER_SECONDS, queue the still-running jobs again (Celery calls this from its
    OS signal handler, hence the thread)."""
    start_thread_without_lease("hand-back", hand_back_running_jobs, Worker.HAND_BACK_AFTER_SECONDS)


@signals.worker_shutdown.connect
def stop_heartbeat(**_: object) -> None:
    if _heartbeat is not None:
        _heartbeat.stop()


@signals.worker_shutdown.connect
def close_connections(**_: object) -> None:
    """Close the pools this process opened."""
    if get_mongodb.is_built():
        get_mongodb().client.close()
    if get_stored_procedure_client.is_built():
        get_stored_procedure_client().close()
