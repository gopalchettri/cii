"""G244 (owner 2026-10-14): a retried job reuses the answers it already got. A job is retried only after a
temporary outage (worker/jobs.py run_leased_job: an unusable answer fails it, never retries it), so every
answer its earlier attempt received was usable; asking for them again only cost time and calls (run 45b8c63b:
one timed-out batch in 20 made planning ask all 20 three times, 38 extra calls and ~4 minutes). A first
attempt reads nothing; a retry reads one indexed document per call, by its Celery task id and exact prompt."""

import structlog

from app.ai.chat_messages import prompt_hash
from app.core.constants import AiTask, LogEvent
from app.data_access.ai_calls import AiCallRecords

log = structlog.get_logger(__name__)


def earlier_reply(records: AiCallRecords, task: AiTask, messages: list[dict]) -> str | None:
    """The reply this job got for these exact `messages` in an earlier attempt, when it was usable; None on a
    first attempt, outside a job, or when the record store cannot be read (the model is asked, as before)."""
    context = structlog.contextvars.get_contextvars()
    task_id, attempt = context.get("task_id"), context.get("attempt")
    if not task_id or not isinstance(attempt, int) or attempt < 2:
        return None
    try:
        reply = records.find_usable_reply(task_id, prompt_hash(messages))
    except Exception:  # noqa: BLE001 - a store fault never stops the call: the model answers instead
        log.warning(LogEvent.AI_CALL_REUSE_FAILED, task=task, exc_info=True)
        return None
    if reply is not None:
        log.info(LogEvent.AI_CALL_REUSED, task=task, attempt=attempt)
    return reply
