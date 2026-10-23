"""The Celery app: its queues, routes and beat schedule, and how a job is sent.

Pool = threads, one process per worker pod. The tasks mostly wait on AI answers, so threads fit; and one
process means one library copy, one set of connection pools shared by every thread (the MongoDB, SQL Server
and Redis clients are thread-safe), and one metrics registry, served on settings.worker_metrics_port for
Prometheus. A prefork pool would copy open connections into forked children and keep each child's AI metrics
where Prometheus never looks, so start-up refuses every pool but threads (app/worker/lifecycle.py).

Start (one deployment per queue; dev gives the mapper and maintenance separate workers):
    celery -A app.worker worker --pool=threads -c 4 -Q tsg_threats
    celery -A app.worker beat"""

import structlog
from celery import Celery, current_task
from kombu.exceptions import OperationalError as BrokerUnavailable

from app.core.config import get_settings
from app.core.constants import (
    TASK_ROUTES,
    Cache,
    Controls,
    IntelLimits,
    Lease,
    LogEvent,
    Queue,
    TaskName,
    Timeouts,
    Worker,
)
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, JobFailed

log = structlog.get_logger(__name__)
settings = get_settings()

#: Every module that defines tasks: a task missing here is never registered and its messages are refused.
TASK_MODULES = [
    "app.worker.service_mapper.tasks",
    "app.worker.jobs",
    "app.worker.reaper",
    "app.worker.admin.library_indexes",
    "app.worker.scenario.tasks",
    "app.worker.remediation.tasks",
    "app.worker.external_intelligence.refresh_task",
]

celery_app = Celery("tsg", broker=settings.redis_celery_broker_url, include=TASK_MODULES)
celery_app.conf.update(
    task_routes=TASK_ROUTES,
    task_default_queue=Queue.MAINTENANCE,
    task_serializer="json",
    accept_content=["json"],
    task_acks_late=True,  # acknowledged when the task ends: a worker that dies mid-task loses nothing
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # a busy worker never holds messages another worker could run
    task_ignore_result=True,  # no result backend: every status lives in MongoDB
    # No Celery retry limit for any task (retry(max_retries=None) alone means "the task's default", 3): the
    # limit is Lease.MAX_ATTEMPTS, counted on the record (app/worker/jobs.py).
    # JobFailed is a run's own end (e.g. plan_refused): Celery logs it in one line, with no traceback, and
    # it still counts as a failure.
    task_annotations={"*": {"max_retries": None, "throws": (JobFailed,)}},
    task_publish_retry_policy={
        "max_retries": 2,
        "interval_start": 0,
        "interval_step": 0.5,
        "interval_max": 1,
    },
    worker_pool="threads",
    worker_concurrency=Worker.THREADS,
    worker_send_task_events=True,  # Flower shows every task
    task_send_sent_event=True,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "visibility_timeout": Worker.BROKER_VISIBILITY_SECONDS,
        "global_keyprefix": Worker.BROKER_KEY_PREFIX,
        "socket_timeout": Timeouts.REDIS_SECONDS,
        "socket_connect_timeout": Timeouts.REDIS_SECONDS,
    },
    beat_schedule={
        TaskName.REAP: {
            "task": TaskName.REAP,
            "schedule": Lease.REAPER_EVERY_SECONDS,
            "options": {"expires": Lease.REAPER_EVERY_SECONDS},
        },
        TaskName.RETRY_CONTROLS: {
            "task": TaskName.RETRY_CONTROLS,
            "schedule": Controls.SWEEP_EVERY_SECONDS,
            "options": {"expires": Controls.SWEEP_EVERY_SECONDS},
        },
        TaskName.BUILD_LIBRARY_INDEXES: {
            "task": TaskName.BUILD_LIBRARY_INDEXES,
            "schedule": Cache.LIBRARY_INDEXES_EVERY_SECONDS,
            "options": {"expires": Cache.LIBRARY_INDEXES_EVERY_SECONDS},
        },
        # Only while the master switch is on: with it off no check is ever queued (as before the feature).
        **(
            {
                TaskName.REFRESH_EXTERNAL_INTELLIGENCE: {
                    "task": TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
                    "schedule": IntelLimits.CHECK_EVERY_SECONDS,
                    "options": {"expires": IntelLimits.CHECK_EVERY_SECONDS},
                }
            }
            if settings.external_intelligence_enabled
            else {}
        ),
    },
    timezone="UTC",
)


def queue_of(task: str) -> str:
    """The queue a task's messages go to (its route, else the default queue)."""
    return str(celery_app.conf.task_routes.get(task, {}).get("queue", celery_app.conf.task_default_queue))


def count_waiting_messages(queue: str) -> int:
    """Messages waiting in a queue, not yet taken by a worker. kombu counts the queue's Redis lists through
    the broker connection (key prefix included); declaring a Redis queue creates nothing."""
    with celery_app.connection_for_read() as connection:
        return int(connection.default_channel.queue_declare(queue=queue).message_count)


#: The message header that carries the API request's id to the worker (lifecycle.start_job_clock binds it).
REQUEST_ID_HEADER = "tsg_request_id"


def _request_id_header() -> dict[str, str]:
    """The id of the API request sending a job (bound by the API middleware), so one id finds the request and
    every log line of the work it started; {} outside a request (the reaper, beat)."""
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    return {REQUEST_ID_HEADER: request_id} if request_id else {}


def current_worker() -> dict[str, str | None]:
    """The running task's id and its worker's name, saved on the job it claims; None outside a task."""
    request = current_task.request if current_task else None
    return {"task_id": getattr(request, "id", None), "worker": getattr(request, "hostname", None)}


def send_admin_job(task: TaskName, job_id: str) -> bool:
    """Queue an admin job (#18). False when the broker is unreachable: no reaper re-sends admin jobs, so the
    caller fails the job at once instead of leaving it queued."""
    try:
        celery_app.send_task(task, args=[job_id], headers=_request_id_header())
    except (BrokerUnavailable, *REDIS_UNAVAILABLE_ERRORS):
        log.warning(LogEvent.JOB_SEND_FAILED, task=task, record_id=job_id, exc_info=True)
        return False
    return True


def send_job(task: TaskName, record_id: str, epoch: int) -> None:
    """Queue a job whose record already says queued: ids only, the record holds the data. A failed send is
    only logged, because the reaper re-sends every record left queued (Lease.REQUEUE_QUEUED_AFTER_SECONDS)."""
    try:
        celery_app.send_task(task, args=[record_id, epoch], headers=_request_id_header())
    except (BrokerUnavailable, *REDIS_UNAVAILABLE_ERRORS):
        log.warning(LogEvent.JOB_SEND_FAILED, task=task, record_id=record_id, exc_info=True)
