"""The Celery app (threads pool, one process per worker pod): its queues, routes, beat schedule and sends.

celery -A app.worker worker --pool=threads -c 4 -Q tsg_threats
celery -A app.worker beat"""

import contextlib
from datetime import timedelta
from typing import Any

import structlog
from celery import Celery, current_task
from kombu.exceptions import OperationalError as BrokerUnavailable

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    JOB_RECORD_COLLECTIONS,
    TASK_ROUTES,
    AiUsageLimits,
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
from app.core.database import get_mongodb, redis_tls_options
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, REDIS_UNAVAILABLE_ERRORS, JobFailed
from app.core.logging import current_request_id
from app.crud.jobs import JobRepository

log = structlog.get_logger(__name__)
settings = get_settings()

#: Every module that defines tasks: a task missing here is never registered and its messages are refused.
TASK_MODULES = [
    "app.worker.service_mapper",
    "app.worker.jobs",
    "app.worker.admin.library_indexes",
    "app.worker.admin.ai_usage_tools",
    "app.worker.scenario.tasks",
    "app.worker.scenario.mitre.mitre_tasks",
    "app.worker.remediation",
    "app.worker.intel",
    "app.worker.control_links",
]


def shared_celery_conf() -> dict[str, Any]:
    """Message encoding and broker options (TLS, key prefix, priority steps), shared with every sender."""
    return {
        "task_serializer": "json",
        "accept_content": ["json"],
        # Set, never left to kombu: a bare rediss:// broker URL gets TLS that trusts any server certificate.
        "broker_use_ssl": redis_tls_options(get_settings().redis_celery_broker_url),
        "broker_transport_options": {
            "visibility_timeout": Worker.BROKER_VISIBILITY_SECONDS,
            "global_keyprefix": Worker.BROKER_KEY_PREFIX,  # every key and pub/sub channel, the mailbox's too
            # Next stages and retries (0), new work (3), a busy entity's plans (6): one step each.
            "priority_steps": [Worker.NEXT_STAGE_PRIORITY, Worker.NEW_WORK_PRIORITY, Worker.BUSY_ENTITY_PRIORITY],
            "socket_timeout": Timeouts.REDIS_SECONDS,
            "socket_connect_timeout": Timeouts.REDIS_SECONDS,
        },
    }


#: (task, every, expires): three intervals for the reaper, the sweep and the intelligence check (only one check
#: wins its claim), so a clock a little ahead never drops every pass; that check (the MITRE ATT&CK import) runs
#: whatever the external-intelligence switch says (ADR-010).
_BEAT = [
    (TaskName.REAP, Lease.REAPER_EVERY_SECONDS, 3 * Lease.REAPER_EVERY_SECONDS),
    (TaskName.RETRY_CONTROLS, Controls.SWEEP_EVERY_SECONDS, 3 * Controls.SWEEP_EVERY_SECONDS),
    (TaskName.BUILD_LIBRARY_INDEXES, Cache.LIBRARY_INDEXES_EVERY_SECONDS, Cache.LIBRARY_INDEXES_EVERY_SECONDS),
    (TaskName.ROLL_UP_AI_USAGE, AiUsageLimits.ROLLUP_EVERY_SECONDS, AiUsageLimits.ROLLUP_EVERY_SECONDS),
    (TaskName.REFRESH_EXTERNAL_INTELLIGENCE, IntelLimits.CHECK_EVERY_SECONDS, 3 * IntelLimits.CHECK_EVERY_SECONDS),
]

celery_app = Celery("tsg", broker=settings.redis_celery_broker_url, include=TASK_MODULES)
celery_app.conf.update(
    shared_celery_conf(),
    task_routes=TASK_ROUTES,
    task_default_queue=Queue.MAINTENANCE,
    task_acks_late=False,  # acknowledged at start: a killed pod's job comes back through the reaper only
    worker_prefetch_multiplier=1,
    task_ignore_result=True,  # every status lives in MongoDB
    # No Celery retry limit (Lease.MAX_ATTEMPTS on the record is); JobFailed logs without a traceback.
    task_annotations={"*": {"max_retries": None, "throws": (JobFailed,)}},
    task_publish_retry_policy={"max_retries": 2, "interval_start": 0, "interval_step": 0.5, "interval_max": 1},
    worker_pool="threads",
    worker_concurrency=Worker.THREADS,
    worker_send_task_events=True,
    task_send_sent_event=True,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        task: {"task": task, "schedule": every, "options": {"expires": expires}} for task, every, expires in _BEAT
    },
    timezone="UTC",
)


def queue_of(task: str) -> str:
    """The queue a task's messages go to (its route, else the default queue)."""
    return str(celery_app.conf.task_routes.get(task, {}).get("queue", celery_app.conf.task_default_queue))


def count_waiting_messages(queue: str) -> int:
    """Messages waiting in a queue (kombu counts every priority list; declaring creates nothing)."""
    with celery_app.connection_for_read() as connection:
        return int(connection.default_channel.queue_declare(queue=queue).message_count)


#: The message header that carries the API request's id to the worker (lifecycle.start_job_clock binds it).
REQUEST_ID_HEADER = "tsg_request_id"


def _request_id_header() -> dict[str, str]:
    request_id = current_request_id()
    return {REQUEST_ID_HEADER: request_id} if request_id else {}


def current_worker() -> dict[str, str | None]:
    """The running task's id and its worker's name, saved on the job it claims; None outside a task."""
    request = current_task.request if current_task else None
    return {"task_id": getattr(request, "id", None), "worker": getattr(request, "hostname", None)}


def send_admin_job(task: TaskName, job_id: str) -> bool:
    """Queue an admin job; False when the broker is unreachable (the caller fails the job at once)."""
    return _send(task, [job_id], job_id, None)


def send_job(task: TaskName, record_id: str, epoch: int, priority: int = Worker.NEW_WORK_PRIORITY) -> bool:
    """Queue a job whose record says queued; False when the broker refused it (shown on the job's status)."""
    if _send(task, [record_id, epoch], record_id, priority):
        return True
    if collection := JOB_RECORD_COLLECTIONS.get(task):  # MongoDB down too: nothing shown, nothing raised
        retry_at = utc_now() + timedelta(seconds=Lease.REQUEUE_QUEUED_AFTER_SECONDS)
        with contextlib.suppress(*MONGO_UNAVAILABLE_ERRORS):
            JobRepository(get_mongodb()[collection]).note_unsent_job(record_id, task, epoch, retry_at)
    return False


def _send(task: TaskName, args: list[Any], record_id: str, priority: int | None) -> bool:
    try:
        celery_app.send_task(task, args=args, headers=_request_id_header(), priority=priority)
    except (BrokerUnavailable, *REDIS_UNAVAILABLE_ERRORS):
        log.warning(LogEvent.JOB_SEND_FAILED, task=task, record_id=record_id, exc_info=True)
        return False
    return True
