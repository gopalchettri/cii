"""Refreshes the approved sources: each due one claimed (a fence renewed before every batch), downloaded
and stored, then the evidence index rebuilt. A failing source never stops the others; its last data stays."""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import structlog

from app.core.constants import (
    REFRESH_AFTER_HOURS,
    AuditAction,
    AuditTarget,
    Dependency,
    IntelLimits,
    IntelSource,
    LogEvent,
    TaskName,
)
from app.core.exceptions import IntelFetchFailed
from app.data_access.admin.repository import audit_records
from app.data_access.external_intelligence.repository import IntelFeedRepository, IntelRecordRepository
from app.models.external_intelligence.refresh_summary import RefreshResult, RefreshSummary, SourceRefresh
from app.models.external_intelligence.source_health import (
    SourceHealth,
    refresh_failure_fields,
    refresh_success_fields,
    sources_in_registry_order,
)
from app.search.external_intelligence import intelligence_metrics as metrics
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.audit import audit_target
from app.services.external_intelligence.record_batch_writer import (
    ClaimLost,
    RefreshMessage,
    WriteRefused,
    write_fetch_result,
)
from app.services.external_intelligence.sources.source_catalogue import IntelSourceFetcher, SourceCatalogue

log = structlog.get_logger(__name__)
_ACTOR = {"system": TaskName.REFRESH_EXTERNAL_INTELLIGENCE}


class SourceRefresher:
    """Refreshes sources one by one; a failure is recorded against its source and its claim given back."""

    def __init__(
        self,
        catalogue: SourceCatalogue,
        record_store: IntelRecordRepository,
        feed_store: IntelFeedRepository,
        index_keeper: EvidenceIndexKeeper,
    ) -> None:
        self._catalogue = catalogue
        self._records = record_store
        self._feeds = feed_store
        self._keeper = index_keeper

    def refresh_due_sources(self, now: datetime) -> RefreshSummary:
        """Refresh every approved source that is due, in the catalogue's order (KEV before EPSS and NVD)."""
        self._feeds.create_missing_intel_feeds()
        approved = set(sources_in_registry_order(self._feeds.list(["_id"], sources=True, approved=True)))
        outcomes = tuple(
            self._refresh(source, fetcher, now, forced=False)
            for source, fetcher in self._catalogue.fetchers().items()
            if source in approved
        )
        return self._finish(outcomes)

    def refresh_one_source(self, source: IntelSource, now: datetime) -> RefreshSummary:
        """Refresh one named source now, due or not (the admin job); revoked or being refreshed is skipped."""
        self._feeds.create_missing_intel_feeds()
        fetcher = self._catalogue.fetchers().get(source)
        outcome = (
            self._refresh(source, fetcher, now, forced=True)
            if fetcher is not None
            else SourceRefresh(source, RefreshResult.SKIPPED)
        )
        return self._finish((outcome,))

    def _finish(self, outcomes: tuple[SourceRefresh, ...]) -> RefreshSummary:
        """Rebuild the index whatever happened (an unchanged corpus costs one read) and sum the refresh up."""
        try:
            self._keeper.rebuild_index().result()
            rebuilt = True
        except Exception:  # the keeper logged it and keeps the old index; the refresh stands
            rebuilt = False
        return RefreshSummary(outcomes, rebuilt)

    def _refresh(
        self, source: IntelSource, fetcher: IntelSourceFetcher, now: datetime, *, forced: bool
    ) -> SourceRefresh:
        """Claim one due (or `forced`) source, download and store it; a failure is recorded against it."""
        doc = self._feeds.get(_id=source)
        health = None if doc is None else SourceHealth.from_doc(doc)
        if health is None or not (forced or self._is_due(health, now)):
            return SourceRefresh(source, RefreshResult.SKIPPED)
        stale_before = now - timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)
        claim = self._feeds.claim_intel_feed_refresh(source, now, stale_before)
        if claim is None:
            return SourceRefresh(source, RefreshResult.SKIPPED)
        try:
            outcome = self._download_and_store(source, claim, fetcher, health, now)
        except Exception as exc:  # recorded against the source; the others still run
            outcome = self._fail(source, claim, _reason(exc), now)
        except BaseException as exc:  # a stop signal: give the claim back before it propagates
            self._fail(source, claim, _reason(exc), now)
            raise
        metrics.REFRESHES.labels(source, _metric_outcome(outcome)).inc()
        return outcome

    def _is_due(self, health: SourceHealth, now: datetime) -> bool:
        """True when the source never succeeded, its last run was cut short, or its period has passed."""
        if health.last_success_at is None or self._feeds.count(_id=health.source, more_pending=True):
            return True
        return now - health.last_success_at >= timedelta(hours=REFRESH_AFTER_HOURS[health.source])

    def _download_and_store(
        self,
        source: IntelSource,
        claim: str,
        fetcher: IntelSourceFetcher,
        health: SourceHealth,
        now: datetime,
    ) -> SourceRefresh:
        """Download the source's changes and store them under the claim; a revoke meanwhile purges again."""
        result = fetcher.download_changes(_trusted_checkpoint(health))
        if result is None:  # the source's version marker is the one already stored, or it has nothing to ask
            return self._nothing_new(source, claim, health, now)
        if not self._feeds.count(_id=source, approved=True):  # revoked while it downloaded
            return self._fail(source, claim, RefreshMessage.REVOKED.format(source=source), now)
        try:
            counts, retired = write_fetch_result(
                self._records, source, result, now, lambda: self._holds(source, claim)
            )
        except ClaimLost:
            log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)
            return SourceRefresh(source, RefreshResult.CLAIM_LOST)
        finally:
            revoked = self._purge_if_revoked(source)
        if revoked:
            return self._fail(source, claim, RefreshMessage.REVOKED.format(source=source), now)
        stored = self._records.count(source=source, current=True)
        self._succeed(source, claim, (result.checkpoint, result.source_version), now, result.more, stored)
        metrics.QUARANTINED.labels(source).inc(counts.quarantined)
        done = SourceRefresh(source, RefreshResult.REFRESHED, counts, retired)
        _announce(done)
        return done

    def _nothing_new(
        self, source: IntelSource, claim: str, health: SourceHealth, now: datetime
    ) -> SourceRefresh:
        """Record an unchanged source as a success; one that never delivered just gives its claim back."""
        checkpoint, version = health.checkpoint, health.source_version
        if checkpoint is None or version is None:
            _log_if_claim_lost(self._feeds.release_intel_feed_refresh(source, claim), source)
            return SourceRefresh(source, RefreshResult.SKIPPED)
        self._succeed(source, claim, (checkpoint, version), now, False, health.records)
        return SourceRefresh(source, RefreshResult.UNCHANGED)

    def _holds(self, source: IntelSource, claim: str) -> bool:
        """The heartbeat before a write: the claim is ours and fresh again, and the source still approved."""
        return self._feeds.renew_intel_feed_refresh(source, claim, datetime.now(UTC))

    def _purge_if_revoked(self, source: IntelSource) -> bool:
        """Delete the records of a source revoked meanwhile (perhaps mid-write); True when revoked."""
        if self._feeds.count(_id=source, approved=True):
            return False
        self._records.delete(source=source)
        return True

    def _succeed(
        self, source: IntelSource, claim: str, marks: tuple[str, str], now: datetime, more: bool, records: int
    ) -> None:
        """Record a success with its checkpoint and version, giving the claim back."""
        checkpoint, version = marks
        success = refresh_success_fields(checkpoint, version, now, more=more, records=records)
        _log_if_claim_lost(self._feeds.release_intel_feed_refresh(source, claim, success), source)

    def _fail(self, source: IntelSource, claim: str, reason: str, now: datetime) -> SourceRefresh:
        """Record the failure against the source and give its claim back, then audit and log it."""
        try:
            failure = refresh_failure_fields(reason, now)
            _log_if_claim_lost(self._feeds.release_intel_feed_refresh(source, claim, failure), source)
        except Exception:  # the store is down: the claim goes stale by itself, the others go on
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        audit_records.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_REFRESH_FAILED, _ACTOR, _target(source), after={"error": reason}
        )
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SOURCE_FAILED, source=source, error=reason)
        return SourceRefresh(source, RefreshResult.FAILED, error=reason)


def _log_if_claim_lost(released: bool, source: IntelSource) -> None:
    """Log a claim taken over meanwhile (the run outlived CLAIM_STALE_SECONDS): its write changed nothing."""
    if not released:
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)


def _announce(done: SourceRefresh) -> None:
    """Audit and log a source refreshed."""
    after = done.as_doc()
    audit_records.create_audit_record(
        AuditAction.EXTERNAL_INTELLIGENCE_REFRESHED, _ACTOR, _target(done.source), after=after
    )
    log.info(
        LogEvent.EXTERNAL_INTELLIGENCE_REFRESHED,
        source=done.source,
        **asdict(done.counts),
        retired=done.retired,
    )


def _trusted_checkpoint(health: SourceHealth) -> str | None:
    """The stored checkpoint, trusted only with its version (they are saved together): a row missing either
    is downloaded in full."""
    return health.checkpoint if health.source_version is not None else None


def _reason(exc: BaseException) -> str:
    """A source's own message is written for people; any other exception shows only its type (it may carry
    a provider's or a driver's details)."""
    if isinstance(exc, IntelFetchFailed | WriteRefused):
        return exc.message
    return RefreshMessage.UNEXPECTED.format(error=type(exc).__name__)


def _metric_outcome(outcome: SourceRefresh) -> metrics.MetricOutcome:
    """The refresh metric's outcome: failed for a failure or a lost claim, else ok."""
    lost = outcome.result in (RefreshResult.FAILED, RefreshResult.CLAIM_LOST)
    return metrics.MetricOutcome.FAILED if lost else metrics.MetricOutcome.OK


def _target(source: IntelSource) -> dict[str, str]:
    """The audit target of one source."""
    return audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, source)
