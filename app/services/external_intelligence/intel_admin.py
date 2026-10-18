"""The admin's view and control of external intelligence: the run-time switch, the sources' approval and the
health report with the evidence settings. With the env master switch off no intelligence store is read."""

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
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.data_access.admin.repository import audit_records
from app.data_access.external_intelligence.repository import (
    IntelFeedRepository,
    intel_feeds,
    intel_records,
    intel_snapshots,
)
from app.models.external_intelligence.switch_state import SwitchState
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.services.audit import admin_actor, audit_target
from app.services.external_intelligence.health import HealthReporter
from app.services.external_intelligence.intel_refreshes import IntelRefreshes, get_intel_refreshes
from app.services.external_intelligence.purge_revoked_source import RevokedSourcePurger
from app.services.external_intelligence.switch import (
    ExternalIntelligenceSwitch,
    get_external_intelligence_switch,
)

log = structlog.get_logger(__name__)


class IntelAdmin:
    """The admin API's external intelligence actions."""

    def __init__(
        self,
        switch: ExternalIntelligenceSwitch,
        reporter: HealthReporter,
        refreshes: IntelRefreshes,
        settings: Settings,
        purger: RevokedSourcePurger,
        feeds: IntelFeedRepository,
    ) -> None:
        self._switch, self._reporter, self._refreshes, self._settings = switch, reporter, refreshes, settings
        self._purger, self._feeds = purger, feeds

    def read_switch(self) -> dict[str, Any]:
        """The switch state; with the env master off it answers from the environment alone."""
        return self._switch.state().as_doc()

    def change_switch(self, enabled: bool, changed_by: str) -> dict[str, Any]:
        """Set and audit the run-time switch (409 while the env master switch is off); turning it on also
        queues a refresh, so the first data does not wait for the hourly check."""
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
        """Revoke a source Legal withdrew: audited first (a purge that fails half-way still leaves the
        decision on record), then unapproved and its records and vectors purged, whatever the switch says.
        Evidence already copied onto scenarios and plans stays (docs/EXTERNAL_INTELLIGENCE.md)."""
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        audit_records.create_audit_record(
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
        """Approve a revoked source again (409 while the env master is off): its health starts blank, the
        approval is audited and its refresh queued; `refresh_job_id` is None when a refresh was already queued
        or the run-time switch is off (either picks the source up later)."""
        if not self._settings.external_intelligence_enabled:
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        self._feeds.update_intel_feed_approval(source, True)
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        audit_records.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_APPROVED,
            admin_actor(requested_by),
            target,
            after={"approved": True},
        )
        return {"source": source, "refresh_job_id": self._queue_refresh(requested_by, source)}

    def _queue_refresh(self, requested_by: str, source: IntelSource | None = None) -> str | None:
        """Queue a refresh and return its job id; None when one is already queued or the switch is off."""
        try:
            return self._refreshes.start(requested_by, source)["job_id"]
        except Conflict:
            return None  # one is already queued or running and does the work, or the switch is off

    def _evidence_settings(self) -> dict[str, Any]:
        """The reranker's name (never its path), the threshold and whether an operator calibrated it there."""
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
    """The process's IntelAdmin over the process's stores, switch and index keeper."""
    switch, keeper = get_external_intelligence_switch(), get_evidence_index_keeper()
    reporter = HealthReporter(intel_feeds, intel_snapshots, switch, keeper)
    purger = RevokedSourcePurger(intel_records, intel_feeds, keeper)
    return IntelAdmin(switch, reporter, get_intel_refreshes(), get_settings(), purger, intel_feeds)
