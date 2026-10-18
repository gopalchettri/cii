"""tsg_audit: append-only; only inserts here, and the TTL index deletes a record after Audit.KEEP_DAYS.
Below the services, so a worker can audit what a job does as a service audits a call."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pymongo
import structlog
from pymongo.collection import Collection as MongoCollection

from app.core import metrics
from app.core.constants import Audit, AuditAction, Collection, LogEvent, Timeouts
from app.core.database import expire_documents_after, get_mongodb

log = structlog.get_logger(__name__)


def record_audit(
    action: AuditAction,
    actor: dict[str, Any],
    target: dict[str, Any],
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Append one audit record. Called after the action's own write succeeded."""
    # Also a log line, so Grafana shows the trail next to the logs (Loki keeps 7 days; tsg_audit keeps 365).
    # before/after stay out of the log: the full record lives only in tsg_audit.
    log.info(LogEvent.AUDIT_RECORDED, action=action, actor=actor, target=target)
    record = {
        "at": datetime.now(UTC),
        "action": action,
        "actor": actor,
        "target": target,
        "before": before,
        "after": after,
        "details": details,
        "request_id": structlog.contextvars.get_contextvars().get("request_id"),
    }
    try:
        # The action has already happened and its answer is waiting: bounded, unlike the 30 s socket timeout.
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            _audit_records().insert_one(record)
    except Exception:  # noqa: BLE001 — the action already happened: an audit outage must not undo or fail it
        metrics.AUDIT_FAILURES.inc()
        log.warning(LogEvent.AUDIT_WRITE_FAILED, action=action, target=target, exc_info=True)


def ensure_audit_indexes() -> None:
    """At start-up (API lifespan), never on the write path: a failure here stops start-up with its reason
    instead of silently dropping every audit record later."""
    records = _audit_records()
    records.create_index([("actor.entity_id", 1), ("at", -1)])
    records.create_index([("target.id", 1), ("at", -1)])
    expire_documents_after(records, "at", int(timedelta(days=Audit.KEEP_DAYS).total_seconds()))


def _audit_records() -> MongoCollection:
    """The tsg_audit collection."""
    return get_mongodb()[Collection.AUDIT]
