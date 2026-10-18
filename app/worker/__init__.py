"""Background work (Celery, threads pool): the app and how jobs are sent (celery_app), the worker process's
start and stop (lifecycle), leased jobs and their retries (jobs), the reaper that repairs abandoned jobs
(reaper), the heartbeat /ready reads (heartbeat), and one folder of jobs per module (scenario, remediation,
external_intelligence, admin).

`celery -A app.worker …` finds `celery_app` here. Importing `lifecycle` registers its signal receivers."""

from app.core.constants import ROUTED_QUEUES
from app.worker import lifecycle
from app.worker.celery_app import celery_app, send_job

__all__ = ["ROUTED_QUEUES", "celery_app", "lifecycle", "send_job"]
