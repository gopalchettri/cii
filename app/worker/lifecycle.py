"""The life of a worker process: what it checks before its first task, what it does around each task, and
how it shuts down. Each function decorated with a signal is a Celery signal receiver."""

import re
import time
from typing import Any

import structlog
from celery import Task, signals, states
from celery.concurrency import get_implementation
from prometheus_client import start_http_server

from app.ai import get_chat_model, get_embedding_model, get_rerank_model
from app.ai.slots import get_ai_slots, set_ai_slot_wait_seconds
from app.core import metrics
from app.core.constants import AiLimits, ErrorMessage, LogEvent, TaskName
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.logging import configure_logging
from app.data_access.indexes import ensure_indexes
from app.worker.celery_app import settings
from app.worker.heartbeat import WorkerHeartbeat
from app.worker.jobs import JOB_COLLECTIONS

log = structlog.get_logger(__name__)

_SUPPORTED_POOLS = ("celery.concurrency.thread", "celery.concurrency.solo")
_heartbeat: WorkerHeartbeat | None = None  # this process's heartbeat, once the worker is ready
_job_started: dict[str, float] = {}


@signals.setup_logging.connect
def keep_our_logging(**_: object) -> None:
    """Connected, so Celery does not set up logging itself (worker and beat): it would reset the root level to
    its own --loglevel after worker_init, and CII_LOG_LEVEL would no longer decide what is logged."""
    configure_logging(settings)


@signals.worker_init.connect
def prepare_worker(sender: Any, **_: object) -> None:
    """Runs once in the worker process before any task. SystemExit, not an exception: Celery only logs an
    exception raised here and starts anyway, and a worker without metrics, indexes or the right pool must
    not run."""
    pool = get_implementation(sender.pool_cls).__module__
    if pool not in _SUPPORTED_POOLS:
        raise SystemExit(ErrorMessage.WORKER_POOL_UNSUPPORTED.format(pool=pool))
    try:
        configure_logging(settings, log_file_role(sender.hostname))  # a bad CII_LOG_DIR stops the worker
    except OSError as exc:
        raise SystemExit(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc
    metrics.start_job_counters(TaskName)
    _serve_metrics(pool)
    _prepare_stores_and_models()


def _serve_metrics(pool: str) -> None:
    try:
        start_http_server(settings.worker_metrics_port)
    except OSError as exc:
        raise SystemExit(
            ErrorMessage.WORKER_METRICS_PORT_BUSY.format(port=settings.worker_metrics_port)
        ) from exc
    log.info(LogEvent.WORKER_METRICS_SERVING, port=settings.worker_metrics_port, pool=pool)


def _prepare_stores_and_models() -> None:
    """As the API does at start-up: every MongoDB index (the reaper's scans included), and the AI gateways.
    A model name with no profile, or an unreachable store, stops the worker now instead of failing every
    job later with "Unexpected error"."""
    set_ai_slot_wait_seconds(AiLimits.WORKER_SLOT_WAIT_SECONDS)  # before the gateways take their limiter
    try:
        ensure_indexes(JOB_COLLECTIONS)
        get_chat_model()
        get_embedding_model()
        get_rerank_model()
    except Exception as exc:  # noqa: BLE001 — any start-up failure must stop the worker (SystemExit below)
        raise SystemExit(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc
    metrics.AI_SLOTS_IN_USE.set_function(
        get_ai_slots().count_calls_in_progress
    )  # AiSlotsSaturated reads both
    metrics.AI_SLOTS_CAP.set(settings.max_concurrent_ai_calls)


@signals.beat_init.connect
def prepare_beat(**_: object) -> None:
    """Beat writes <CII_LOG_DIR>/beat.log too, as the API and workers write theirs, so its errors (a
    schedule it could not send) reach the logs Grafana reads, not only its own window."""
    try:
        configure_logging(settings, "beat")
    except OSError as exc:
        raise SystemExit(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc


def log_file_role(hostname: str) -> str:
    """worker-<node name>: two workers on one laptop (-n dev@%h, -n dev2@%h) never append to the same file."""
    return "worker-" + re.sub(r"[^\w.-]", "_", hostname.split("@", 1)[0])


@signals.worker_ready.connect
def start_heartbeat(sender: Any, **_: object) -> None:
    """Starts once the worker is connected to its broker and consuming (not at worker_init): a worker that
    cannot reach its queues never looks alive to /ready."""
    global _heartbeat  # noqa: PLW0603 — one heartbeat per worker process, stopped by worker_shutdown
    _heartbeat = WorkerHeartbeat(sorted(sender.app.amqp.queues.consume_from), sender.hostname)
    _heartbeat.start()


@signals.task_prerun.connect
def start_job_clock(task_id: str, task: Task, **_: object) -> None:
    structlog.contextvars.clear_contextvars()  # pool threads are reused: no field leaks into the next task
    structlog.contextvars.bind_contextvars(task_id=task_id, task=task.name)
    _job_started[task_id] = time.perf_counter()


@signals.task_postrun.connect
def record_job_outcome(task_id: str, task: Task, state: str | None = None, **_: object) -> None:
    started = _job_started.pop(task_id, None)
    if state == states.IGNORED:
        return  # a delivery that found its job owned by another did no job: no outcome, no duration
    metrics.JOBS.labels(task.name, (state or "unknown").lower()).inc()
    if started is not None:
        metrics.JOB_SECONDS.labels(task.name).observe(time.perf_counter() - started)


@signals.worker_shutdown.connect
def stop_heartbeat(**_: object) -> None:
    if _heartbeat is not None:
        _heartbeat.stop()


@signals.worker_shutdown.connect
def close_connections(**_: object) -> None:
    """Close the pools this process opened (only those: a client never used is never created here)."""
    if get_mongodb.is_built():
        get_mongodb().client.close()
    if get_stored_procedure_client.is_built():
        get_stored_procedure_client().close()
