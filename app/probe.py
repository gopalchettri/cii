"""The Celery app of every worker's startup and liveness probe:
    celery -A app.probe inspect ping -d "celery@$HOSTNAME" --timeout 10

Only the broker and the settings a ping needs, so a probe loads no worker code: anything under app.worker
loads the AI clients first (about 233 MB and 5 CPU-s per probe)."""

from celery import Celery

from app.core.broker import shared_celery_conf
from app.core.config import get_settings

probe_app = Celery("tsg", broker=get_settings().redis_celery_broker_url, set_as_current=False)
probe_app.conf.update(shared_celery_conf())
