"""The Celery settings of the workers and of every process that sends them a job or reads a queue."""

from typing import Any

from app.core.constants import Timeouts, Worker


def shared_celery_conf() -> dict[str, Any]:
    """How messages are encoded, and the broker options that name the Redis keys, lists and channels."""
    return {
        "task_serializer": "json",
        "accept_content": ["json"],
        "broker_transport_options": {
            # Also the probe's: its poll gives back unacked messages older than this, never a running job's.
            "visibility_timeout": Worker.BROKER_VISIBILITY_SECONDS,
            "global_keyprefix": Worker.BROKER_KEY_PREFIX,  # every key and pub/sub channel, the mailbox's too
            # Next stages and retries (0) before new work (3). kombu's own separator stays: it also joins the
            # queue bindings Redis keeps, so pods with another one could not read each other's and every send
            # would fail.
            "priority_steps": [Worker.NEXT_STAGE_PRIORITY, Worker.NEW_WORK_PRIORITY],
            "socket_timeout": Timeouts.REDIS_SECONDS,
            "socket_connect_timeout": Timeouts.REDIS_SECONDS,
        },
    }
