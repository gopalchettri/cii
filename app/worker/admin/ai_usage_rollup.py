"""Background job of the AI usage reports: add the usage rows up per hour (maintenance queue, every
AiUsageLimits.ROLLUP_EVERY_SECONDS), so a dashboard reads a few totals, never every row."""

from app.core.constants import TaskName
from app.worker.celery_app import celery_app


@celery_app.task(name=TaskName.ROLL_UP_AI_USAGE)
def roll_up_ai_usage() -> None:
    """Beat task: add up every hour since the last add-up (catching up after any downtime)."""
    from app import container

    container.get_ai_usage_service().roll_up_ai_usage()
