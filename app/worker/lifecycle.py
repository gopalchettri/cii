"""The life of a worker process: what it checks before its first task, what it does around each task, and
how it shuts down. Each function decorated with a signal is a Celery signal receiver."""

import re
import time
from typing import Any

import structlog
from celery import Task, signals
from celery.concurrency import get_implementation
from prometheus_client import start_http_server

from app.core import metrics
from app.core.constants import ErrorMessage, LogEvent, TaskName, module_of
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.logging import configure_logging
from app.core.readiness import log_mongodb_topology
from app.worker.celery_app import REQUEST_ID_HEADER, queue_of, settings
from app.worker.external_intelligence.warm_up import start_following_active_snapshot, warm_up_intelligence
from app.worker.heartbeat import WorkerHeartbeat
from app.worker.jobs import JOB_COLLECTIONS, JobWaiting

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
    if queue_of(TaskName.REAP) in sender.app.amqp.queues.consume_from:  # -Q is read before worker_init
        metrics.start_reaper_clock()
    _serve_metrics(pool)
    _prepare_stores_and_models()
    log_mongodb_topology()
    warm_up_external_intelligence(sender)  # before Celery starts the consumer and sends worker_ready


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
    from app import container

    try:
        container.set_up_worker(JOB_COLLECTIONS)
    except Exception as exc:  # noqa: BLE001 — any start-up failure must stop the worker (SystemExit below)
        raise SystemExit(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc
    metrics.AI_SLOTS_IN_USE.set_function(
        container.get_ai_slots().count_calls_in_progress
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


def warm_up_external_intelligence(sender: Any) -> None:
    """On a worker that writes scenarios (the index's only reader), before it consumes or beats: build the
    intelligence search index while the switch is on, then follow the active snapshot every minute (G242).
    Never stops the worker (both swallow their faults)."""
    if queue_of(TaskName.WRITE_SCENARIOS) not in sender.app.amqp.queues.consume_from:
        return  # maintenance still builds and publishes the index at each refresh
    from app import container

    switch = container.get_intelligence_switch()
    warm_up_intelligence(switch, container.get_evidence_index_keeper)
    start_following_active_snapshot(settings, switch, container.get_evidence_index_keeper)


@signals.task_prerun.connect
def start_job_clock(task_id: str, task: Task, args: tuple | None = None, **_: object) -> None:
    """Every task's start, logged with what identifies it: its record or job id (its first argument), its
    worker, and the API request that sent it (that request's id, so one id finds both sides)."""
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
        **({"request_id": request_id} if request_id else {}),
    )
    _job_started[task_id] = time.perf_counter()
    log.info(LogEvent.JOB_STARTED)


@signals.task_postrun.connect
def record_job_outcome(
    task_id: str, task: Task, state: str | None = None, retval: object = None, **_: object
) -> None:
    """Counts each delivery by its Celery state, or as `waiting` when its job waits for another job."""
    started = _job_started.pop(task_id, None)
    outcome = "waiting" if isinstance(retval, JobWaiting) else (state or "unknown").lower()
    if outcome == "ignored":
        log.info(LogEvent.JOB_FINISHED, outcome=outcome)  # another delivery owns the job: no job done
        return  # a delivery that found its job owned by another did no job: no outcome, no duration
    metrics.JOBS.labels(task.name, outcome).inc()
    seconds = None if started is None else time.perf_counter() - started
    if seconds is not None and outcome != "waiting":  # a look for another job's work, not a job's run
        metrics.JOB_SECONDS.labels(task.name).observe(seconds)
    log.info(LogEvent.JOB_FINISHED, outcome=outcome, seconds=None if seconds is None else round(seconds, 1))


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
