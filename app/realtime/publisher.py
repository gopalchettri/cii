"""Publishing live updates: "this run (or plan) changed", sent on its Redis channel after every saved change.

Used by workers and services. It holds no web code, so a worker never loads the API to publish; the hub that
relays these messages to clients is app/realtime/event_hub.py, and each stream reads the status itself."""

import structlog

from app.core.constants import LogEvent, Realtime
from app.core.database import get_redis_client

log = structlog.get_logger(__name__)


def session_channel(session_id: str) -> str:
    return Realtime.SESSION_CHANNEL.format(session_id=session_id)


def publish_session_status(session_id: str) -> None:
    """Tell everyone streaming a session that it changed; each stream then reads the current status from
    MongoDB (app/api/routers/scenario.py). The status itself is not sent: two workers changing one run moments
    apart could publish in the opposite order, and a client would keep the older status."""
    _publish(session_channel(session_id), session_id)


def remediation_channel(remediation_id: str) -> str:
    return Realtime.REMEDIATION_CHANNEL.format(remediation_id=remediation_id)


def publish_remediation_status(remediation_id: str) -> None:
    """Tell everyone streaming a remediation plan that it changed (#28), as for a session."""
    _publish(remediation_channel(remediation_id), remediation_id)


def _publish(channel: str, record_id: str) -> None:
    """Best effort, on purpose: the change is already saved, so a failure here costs only this live update
    (the client sees it on its next change or reconnect), never the job; any failure is logged, never
    raised."""
    try:
        get_redis_client().publish(channel, record_id)
    except Exception:  # noqa: BLE001 — best effort by contract: a live update must never fail a saved change
        log.warning(LogEvent.EVENT_PUBLISH_FAILED, channel=channel, exc_info=True)
