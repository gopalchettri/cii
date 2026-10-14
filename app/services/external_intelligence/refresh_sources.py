"""Refreshes the approved sources: fetch each one that is due, store what it says, then rebuild the evidence
index.

Per source: approved, due (REFRESH_AFTER_HOURS, or the last run stopped at its budget), claimed atomically
(two workers never refresh one source), downloaded, stored in batches, and only then its checkpoint moves. A
failure is recorded against the source with a people-readable reason (a message text or an exception type,
never a driver's details), audited and logged, and the claim is always given back. One source failing never
stops the others, and the last good data stays in use.

The claim is a fence: it is renewed before every batch is written (a heartbeat), a run that finds it lost or
the source revoked stops writing (CLAIM_LOST), and when the writes are done the approval is read once more: a
source revoked meanwhile has its records purged again, so a revoke never leaves its data behind. A first run
with nothing to ask for yet (EPSS, NVD and ICS wait for KEV's CVEs) changes nothing and is not a failure."""

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
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.models.external_intelligence.refresh_summary import RefreshResult, RefreshSummary, SourceRefresh
from app.models.external_intelligence.source_health import SourceHealth
from app.search.external_intelligence import intelligence_metrics as metrics
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.audit import audit_target, record_audit
from app.services.external_intelligence.record_batch_writer import ClaimLost, RecordBatchWriter, WriteRefused
from app.services.external_intelligence.refresh_messages import RefreshMessage
from app.services.external_intelligence.sources.source_catalogue import SourceCatalogue
from app.services.external_intelligence.sources.source_fetcher import IntelSourceFetcher

log = structlog.get_logger(__name__)
_ACTOR = {"system": TaskName.REFRESH_EXTERNAL_INTELLIGENCE}


class SourceRefresher:
    def __init__(
        self,
        catalogue: SourceCatalogue,
        record_store: IntelRecordStore,
        feed_store: FeedStatusStore,
        index_keeper: EvidenceIndexKeeper,
    ) -> None:
        self._catalogue = catalogue
        self._records = record_store
        self._feeds = feed_store
        self._keeper = index_keeper
        self._writer = RecordBatchWriter(record_store)

    def refresh_due_sources(self, now: datetime) -> RefreshSummary:
        """Every approved source that is due, in the catalogue's order (KEV before EPSS and NVD)."""
        self._feeds.seed_sources()
        approved = set(self._feeds.list_approved_sources())
        outcomes = tuple(
            self._refresh(source, fetcher, now, forced=False)
            for source, fetcher in self._catalogue.fetchers().items()
            if source in approved
        )
        return self._finish(outcomes)

    def refresh_one_source(self, source: IntelSource, now: datetime) -> RefreshSummary:
        """One named source now, due or not (the admin job); revoked or being refreshed is skipped."""
        self._feeds.seed_sources()
        fetcher = self._catalogue.fetchers().get(source)
        outcome = (
            self._refresh(source, fetcher, now, forced=True)
            if fetcher is not None
            else SourceRefresh(source, RefreshResult.SKIPPED)
        )
        return self._finish((outcome,))

    def _finish(self, outcomes: tuple[SourceRefresh, ...]) -> RefreshSummary:
        """Always asks for a rebuild: a revoked source or a first run changes the corpus with no new record,
        and an unchanged corpus costs one read of the records and no embedding."""
        try:
            self._keeper.rebuild_index().result()
            rebuilt = True
        except Exception:  # noqa: BLE001 - the keeper logged it and keeps the old index; the refresh stands
            rebuilt = False
        return RefreshSummary(outcomes, rebuilt)

    def _refresh(
        self, source: IntelSource, fetcher: IntelSourceFetcher, now: datetime, *, forced: bool
    ) -> SourceRefresh:
        health = self._feeds.read_source_health(source)
        if health is None or not (forced or self._is_due(health, now)):
            return SourceRefresh(source, RefreshResult.SKIPPED)
        stale_before = now - timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)
        claim = self._feeds.claim_source_for_refresh(source, now, stale_before)
        if claim is None:
            return SourceRefresh(source, RefreshResult.SKIPPED)
        try:
            outcome = self._download_and_store(source, claim, fetcher, health, now)
        except Exception as exc:  # noqa: BLE001 - recorded against the source; the others still run
            outcome = self._fail(source, claim, _reason(exc), now)
        except BaseException as exc:  # a stop signal: give the claim back before it propagates
            self._fail(source, claim, _reason(exc), now)
            raise
        metrics.REFRESHES.labels(source, _metric_outcome(outcome)).inc()
        return outcome

    def _is_due(self, health: SourceHealth, now: datetime) -> bool:
        if health.last_success_at is None or self._feeds.is_more_pending(health.source):
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
        result = fetcher.download_changes(_trusted_checkpoint(health))
        if result is None:  # the source's version marker is the one already stored, or it has nothing to ask
            return self._nothing_new(source, claim, health, now)
        if not self._feeds.is_source_approved(source):  # revoked while it downloaded
            return self._fail(source, claim, RefreshMessage.REVOKED.format(source=source), now)
        try:
            counts, retired = self._writer.write_result(
                source, result, now, lambda: self._holds(source, claim)
            )
        except ClaimLost:
            log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)
            return SourceRefresh(source, RefreshResult.CLAIM_LOST)
        finally:
            revoked = self._purge_if_revoked(source)
        if revoked:
            return self._fail(source, claim, RefreshMessage.REVOKED.format(source=source), now)
        stored = self._records.count_current_records([source])
        self._succeed(source, claim, (result.checkpoint, result.source_version), now, result.more, stored)
        metrics.QUARANTINED.labels(source).inc(counts.quarantined)
        done = SourceRefresh(source, RefreshResult.REFRESHED, counts, retired)
        _announce(done)
        return done

    def _nothing_new(
        self, source: IntelSource, claim: str, health: SourceHealth, now: datetime
    ) -> SourceRefresh:
        """Unchanged since the last success; or, on a source that never delivered, nothing to ask for yet:
        the claim goes back and nothing else changes (no failure, no audit), the next check looks again."""
        checkpoint, version = health.checkpoint, health.source_version
        if checkpoint is None or version is None:
            self._release(self._feeds.release_claim(source, claim), source)
            return SourceRefresh(source, RefreshResult.SKIPPED)
        self._succeed(source, claim, (checkpoint, version), now, False, health.records)
        return SourceRefresh(source, RefreshResult.UNCHANGED)

    def _holds(self, source: IntelSource, claim: str) -> bool:
        """The heartbeat before a write: the claim is ours and fresh again, and the source still approved."""
        return self._feeds.renew_claim(source, claim, datetime.now(UTC))

    def _purge_if_revoked(self, source: IntelSource) -> bool:
        """A revoke can land while batches are written (its purge may run before the last one): once the
        writes are over, a source no longer approved has its records deleted again. True when revoked."""
        if self._feeds.is_source_approved(source):
            return False
        self._records.purge_source(source)
        return True

    def _succeed(
        self, source: IntelSource, claim: str, marks: tuple[str, str], now: datetime, more: bool, records: int
    ) -> None:
        checkpoint, version = marks
        released = self._feeds.record_refresh_success(
            source, claim, checkpoint, version, now, more=more, records=records
        )
        self._release(released, source)

    def _release(self, released: bool, source: IntelSource) -> None:
        """A claim taken over meanwhile (this run outlived CLAIM_STALE_SECONDS) changed nothing: say so."""
        if not released:
            log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)

    def _fail(self, source: IntelSource, claim: str, reason: str, now: datetime) -> SourceRefresh:
        try:
            self._release(self._feeds.record_refresh_failure(source, claim, reason, now), source)
        except Exception:  # noqa: BLE001 - the store is down: the claim goes stale by itself, others go on
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
        record_audit(
            AuditAction.EXTERNAL_INTELLIGENCE_REFRESH_FAILED, _ACTOR, _target(source), after={"error": reason}
        )
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SOURCE_FAILED, source=source, error=reason)
        return SourceRefresh(source, RefreshResult.FAILED, error=reason)


def _announce(done: SourceRefresh) -> None:
    after = done.as_doc()
    record_audit(AuditAction.EXTERNAL_INTELLIGENCE_REFRESHED, _ACTOR, _target(done.source), after=after)
    log.info(
        LogEvent.EXTERNAL_INTELLIGENCE_REFRESHED,
        source=done.source,
        **asdict(done.counts),
        retired=done.retired,
    )


def _trusted_checkpoint(health: SourceHealth) -> str | None:
    """A checkpoint is trusted only with its version (they are always saved together, G217): a row missing
    either is downloaded in full, and its success saves both again."""
    return health.checkpoint if health.source_version is not None else None


def _reason(exc: BaseException) -> str:
    """A source's own message is written for people; any other exception shows only its type (it may carry
    a provider's or a driver's details)."""
    if isinstance(exc, IntelFetchFailed | WriteRefused):
        return exc.message
    return RefreshMessage.UNEXPECTED.format(error=type(exc).__name__)


def _metric_outcome(outcome: SourceRefresh) -> metrics.MetricOutcome:
    lost = outcome.result in (RefreshResult.FAILED, RefreshResult.CLAIM_LOST)
    return metrics.MetricOutcome.FAILED if lost else metrics.MetricOutcome.OK


def _target(source: IntelSource) -> dict[str, str]:
    return audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, source)
