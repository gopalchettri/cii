"""The admin's view and control of external intelligence: the run-time switch (turning it ON also queues a
refresh), and the health report with the evidence settings (which reranker, which threshold, and whether an
operator calibrated that threshold on that reranker). The env master switch decides first: with it off nothing
is read from the intelligence stores here."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import Settings, get_settings
from app.core.constants import (
    EVIDENCE_THRESHOLD_CALIBRATED_ON,
    AuditAction,
    AuditTarget,
    IntelRefreshMessage,
    IntelSource,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.models.external_intelligence.switch_state import SwitchState
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.services.audit import admin_actor, audit_target, record_audit
from app.services.external_intelligence.health import HealthReporter
from app.services.external_intelligence.intel_refreshes import IntelRefreshes, get_intel_refreshes
from app.services.external_intelligence.purge_revoked_source import RevokedSourcePurger
from app.services.external_intelligence.switch import (
    ExternalIntelligenceSwitch,
    get_external_intelligence_switch,
)

log = structlog.get_logger(__name__)


class IntelAdmin:
    def __init__(
        self,
        switch: ExternalIntelligenceSwitch,
        reporter: HealthReporter,
        refreshes: IntelRefreshes,
        settings: Settings,
        purger: RevokedSourcePurger,
        feeds: FeedStatusStore,
    ) -> None:
        self._switch, self._reporter, self._refreshes, self._settings = switch, reporter, refreshes, settings
        self._purger, self._feeds = purger, feeds

    def read_switch(self) -> dict[str, Any]:
        """With the env master OFF the switch answers from the environment alone (no store is read)."""
        return self._switch.state().as_doc()

    def change_switch(self, enabled: bool, changed_by: str) -> dict[str, Any]:
        """The run-time switch set and audited (409 while the env master switch is off); turned ON it also
        queues a refresh, so the first data does not wait for the next hourly check. A refresh already running
        is fine."""
        if not self._settings.external_intelligence_enabled:  # nothing of the feature is written while off
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        after = self._switch.change_runtime_flag(enabled, changed_by)  # audits and logs the change, once
        if enabled and after.effective:
            self._queue_refresh(changed_by)
        return after.as_doc()

    def describe_health(self) -> dict[str, Any]:
        """The health report with the evidence settings. With the master switch off, only the switch state."""
        evidence = self._evidence_settings()
        if not self._settings.external_intelligence_enabled:
            state = SwitchState(env_enabled=False).as_doc()  # no store is read while off
            return {
                "switch": state,
                "snapshot_id": None,
                "sources": [],
                "stale": False,
                "pending_sources": [],
                "no_data": False,
                "evidence": evidence,
            }
        return self._reporter.describe_health(datetime.now(UTC)).as_doc() | {"evidence": evidence}

    def revoke_source(self, source: IntelSource, requested_by: str) -> dict[str, Any]:
        """Legal withdrew a source: it is audited FIRST (a purge that fails half-way still leaves the decision
        on record), then marked unapproved, its records and vectors are purged and the next snapshot no longer
        holds it. Works whatever the switch says (a purge is never refused); with the env master OFF it only
        deletes what exists and creates nothing. Evidence already copied onto written scenarios and plans is
        NOT removed (docs/EXTERNAL_INTELLIGENCE.md says how an operator handles that)."""
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        record_audit(
            AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_REVOKED,
            admin_actor(requested_by),
            target,
            after={"approved": False},
        )
        if self._settings.external_intelligence_enabled:
            purged = self._purger.revoke_and_purge(source)
        else:
            purged = self._purger.purge_existing_only(source)
        return {"source": source, "records_purged": purged}

    def approve_source(self, source: IntelSource, requested_by: str) -> dict[str, Any]:
        """A revoked source approved again (409 while the env master is OFF): its health starts blank, the
        approval is audited and a refresh of that source is queued, so its data comes back from the start.
        `refresh_job_id` is None when a refresh was already queued or running (it, or the next hourly check,
        picks the source up)."""
        if not self._settings.external_intelligence_enabled:
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        self._feeds.approve_source(source)
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        record_audit(
            AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_APPROVED,
            admin_actor(requested_by),
            target,
            after={"approved": True},
        )
        return {"source": source, "refresh_job_id": self._queue_refresh(requested_by, source)}

    def _queue_refresh(self, requested_by: str, source: IntelSource | None = None) -> str | None:
        try:
            return self._refreshes.start(requested_by, source)["job_id"]
        except Conflict:
            return None  # one is already queued or running: it does the work

    def _evidence_settings(self) -> dict[str, Any]:
        model = self._settings.rerank_model.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        calibrated_on = EVIDENCE_THRESHOLD_CALIBRATED_ON.get(model)
        return {
            "rerank_model": model,
            "threshold": self._settings.evidence_similarity_threshold,
            "threshold_calibrated": calibrated_on is not None,
            "threshold_calibrated_on": calibrated_on,
        }


@singleton
def get_intel_admin() -> IntelAdmin:
    db = get_mongodb()
    switch = get_external_intelligence_switch()
    feeds, keeper = FeedStatusStore(db), get_evidence_index_keeper()
    reporter = HealthReporter(feeds, SnapshotPointerStore(db), switch, keeper)
    purger = RevokedSourcePurger(IntelRecordStore(db), feeds, keeper)
    return IntelAdmin(switch, reporter, get_intel_refreshes(), get_settings(), purger, feeds)
