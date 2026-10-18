"""tsg_audit: the audit trail, append-only."""

from datetime import UTC, datetime, timedelta

import pymongo
import structlog
from pymongo.collection import Collection as MongoCollection

from app.core import metrics
from app.core.constants import Audit, AuditAction, Collection, LogEvent, Timeouts
from app.data_access.base import MongoRepository, Record

log = structlog.get_logger(__name__)

_DAY_SECONDS = int(timedelta(days=1).total_seconds())


class AuditRepository(MongoRepository):
    """tsg_audit: append-only; the TTL index deletes a record after Audit.KEEP_DAYS."""

    def __init__(self, collection: str | MongoCollection = Collection.AUDIT) -> None:
        """tsg_audit with its actor and target indexes and its expiry."""
        super().__init__(
            collection,
            indexes=[
                {"keys": [("actor.entity_id", 1), ("at", -1)]},
                {"keys": [("target.id", 1), ("at", -1)]},
            ],
            ttl=[("at", Audit.KEEP_DAYS * _DAY_SECONDS)],
            schema_version=1,
        )

    def create_audit_record(  # noqa: PLR0913 — the audit record's own fields
        self,
        action: AuditAction,
        actor: Record,
        target: Record,
        before: Record | None = None,
        after: Record | None = None,
        details: Record | None = None,
    ) -> None:
        """Appends one tsg_audit record after the action's own write succeeded, within
        Timeouts.RECORD_WRITE_SECONDS; a failure is logged and counted, never raised."""
        # Also a log line (Grafana shows the trail next to the logs); before/after stay in tsg_audit only.
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
            with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):  # the answer is waiting: not the 30 s socket
                self.collection.insert_one(record)
        except Exception:  # noqa: BLE001 — the action already happened: an audit outage must not fail it
            metrics.AUDIT_FAILURES.inc()
            log.warning(LogEvent.AUDIT_WRITE_FAILED, action=action, target=target, exc_info=True)
