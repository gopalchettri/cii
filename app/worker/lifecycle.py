"""The life of a worker process: what it checks before its first task, what it does around each task, and
how it shuts down. Each function decorated with a signal is a Celery signal receiver."""

import re
import sys
import threading
import time
from typing import Any

import structlog
from celery import Task, signals
from celery.concurrency import get_implementation
from prometheus_client import start_http_server

from app.ai import RerankModel
from app.core import metrics
from app.core.constants import AiLimits, ErrorMessage, LogEvent, TaskName, Worker, module_of
from app.core.database import get_mongodb, get_stored_procedure_client
from app.core.lease_signal import start_thread_without_lease
from app.core.logging import configure_logging
from app.core.readiness import log_mongodb_topology
from app.worker.celery_app import REQUEST_ID_HEADER, queue_of, settings
from app.worker.external_intelligence.warm_up import start_following_active_snapshot, warm_up_intelligence
from app.worker.heartbeat import WorkerHeartbeat
from app.worker.jobs import JOB_COLLECTIONS, JobWaiting
from app.worker.lease_renewal import hand_back_running_jobs

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
        raise _start_failed(ErrorMessage.WORKER_POOL_UNSUPPORTED.format(pool=pool))
    try:
        configure_logging(settings, log_file_role(sender.hostname))  # a bad CII_LOG_DIR stops the worker
    except OSError as exc:
        raise _start_failed(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc
    metrics.start_job_counters(TaskName)
    _serve_metrics(pool)
    _prepare_stores_and_models()
    log_mongodb_topology()
    warm_up_external_intelligence(sender)  # before Celery starts the consumer and sends worker_ready
    preload_local_reranker(sender)


def _start_failed(message: str) -> SystemExit:
    """Log why this process cannot start (with the exception in hand, if any); the SystemExit to raise."""
    log.error(LogEvent.WORKER_START_FAILED, message=message, exc_info=sys.exc_info()[1] is not None)
    return SystemExit(message)


def _serve_metrics(pool: str) -> None:
    try:
        start_http_server(settings.worker_metrics_port)
    except OSError as exc:
        raise _start_failed(
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
        raise _start_failed(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc
    pools = {
        AiLimits.SEARCH_POOL: container.get_ai_slots()
    }  # AiSlotsSaturated reads both gauges, pool by pool
    pools |= {module: main for module, (main, _) in container.get_module_ai_slots().items()}
    for pool, slots in pools.items():
        metrics.AI_SLOTS_IN_USE.labels(pool).set_function(slots.count_calls_in_progress)
        metrics.AI_SLOTS_CAP.labels(pool).set_function(slots.current_limit)


@signals.beat_init.connect
def prepare_beat(**_: object) -> None:
    """Beat writes <CII_LOG_DIR>/beat.log too, as the API and workers write theirs, so its errors (a
    schedule it could not send) reach the logs Grafana reads, not only its own window."""
    try:
        configure_logging(settings, "beat")
    except OSError as exc:
        raise _start_failed(ErrorMessage.WORKER_START_FAILED.format(reason=exc)) from exc


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


def preload_local_reranker(sender: Any) -> threading.Thread | None:
    """On a worker that writes scenarios or maps controls, load the reranker from a daemon thread, so the
    first set after a start does not wait for the laptop's cold load; the worker consumes meanwhile."""
    reranking = (queue_of(TaskName.WRITE_SCENARIOS), queue_of(TaskName.MAP_CONTROLS))
    if not any(queue in sender.app.amqp.queues.consume_from for queue in reranking):
        return None
    from app import container

    rerank = container.get_rerank_model()
    thread = threading.Thread(target=_preload, args=(rerank,), name="rerank-preload", daemon=True)
    thread.start()
    return thread


def _preload(rerank: RerankModel) -> None:
    try:
        rerank.preload()
    except Exception:  # noqa: BLE001 — never stops the worker: the first rerank loads it instead
        log.warning(LogEvent.WORKER_RERANKER_PRELOAD_FAILED, exc_info=True)


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
        **({"epoch": args[1]} if args and len(args) > 1 else {}),
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
    metrics.count_job(task.name, outcome)
    seconds = None if started is None else time.perf_counter() - started
    if seconds is not None and outcome != "waiting":  # a look for another job's work, not a job's run
        metrics.record_job_seconds(task.name, seconds)
    log.info(LogEvent.JOB_FINISHED, outcome=outcome, seconds=None if seconds is None else round(seconds, 1))


@signals.task_revoked.connect
def record_expired_delivery(sender: Task, request: Any = None, expired: bool = False, **_: object) -> None:
    """Counts a timer message the worker dropped unrun because it arrived after its expiry (beat's clock
    behind the worker's, or its worker stuck). Runs on the consumer thread: nothing of the task is bound."""
    if expired:
        metrics.count_job(sender.name, "expired")
        job = {"task": sender.name, "module": module_of(sender.name), "task_id": getattr(request, "id", None)}
        log.warning(LogEvent.JOB_FINISHED, outcome="expired", **job)


@signals.worker_shutting_down.connect
def hand_back_jobs_when_stopping(**_: object) -> None:
    """A stopping worker queues the jobs still running Worker.HAND_BACK_AFTER_SECONDS later again, no attempt
    used, before its pod is killed. In a thread: Celery sends this signal from its OS signal handler."""
    start_thread_without_lease("hand-back", hand_back_running_jobs, Worker.HAND_BACK_AFTER_SECONDS)


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
