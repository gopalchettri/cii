"""Publishing live updates: "this run (or plan) changed", sent on its Redis channel after every saved change."""

import structlog

from app.core.constants import LogEvent, Realtime
from app.core.database import get_redis_client

log = structlog.get_logger(__name__)


def session_channel(session_id: str) -> str:
    return Realtime.SESSION_CHANNEL.format(session_id=session_id)


def publish_session_status(session_id: str) -> None:
    """Tell everyone streaming a session that it changed; each stream re-reads the status (order-safe)."""
    _publish(session_channel(session_id), session_id)


def remediation_channel(remediation_id: str) -> str:
    return Realtime.REMEDIATION_CHANNEL.format(remediation_id=remediation_id)


def publish_remediation_status(remediation_id: str) -> None:
    """Tell everyone streaming a remediation plan that it changed, as for a session."""
    _publish(remediation_channel(remediation_id), remediation_id)


def mapping_channel(mapping_id: str) -> str:
    return Realtime.MAPPING_CHANNEL.format(mapping_id=mapping_id)


def publish_mapping_status(mapping_id: str) -> None:
    """Tell mapping streams to re-read the saved status, without putting results on Redis."""
    _publish(mapping_channel(mapping_id), mapping_id)


def _publish(channel: str, record_id: str) -> None:
    try:
        get_redis_client().publish(channel, record_id)
    except Exception:  # noqa: BLE001 — best effort by contract: a live update must never fail a saved change
        log.warning(LogEvent.EVENT_PUBLISH_FAILED, channel=channel, exc_info=True)
