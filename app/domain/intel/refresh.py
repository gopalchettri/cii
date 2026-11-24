"""Importing the sources: which stored checkpoint is trusted, when a claim is stale."""

from collections.abc import Callable
from datetime import datetime, timedelta

import structlog

from app.ai.common import apply_proxy_once
from app.core.clock import utc_now
from app.core.constants import AttackRecord, Dependency, ErrorCode, IntelLimits, IntelMessage, IntelSource, LogEvent
from app.core.exceptions import IntelFetchFailed, job_error_of
from app.crud.attack import get_attack_repository
from app.crud.intel import (
    IntelRecordRepository,
    delete_removed_sources,
    get_intel_feed_repository,
    get_intel_record_repository,
)
from app.crud.mitre.mitre_stix import (
    MitreStixRepository,
    get_mitre_enterprise_stix_repository,
    get_mitre_ics_stix_repository,
)
from app.domain.intel.index import EvidenceIndexRefused, get_evidence_index_keeper
from app.domain.intel.sources.attack import MitreAttackSource
from app.domain.intel.switch import get_intelligence_switch
from app.schemas.intel_records import (
    FetchResult,
    RefreshResult,
    RefreshSummary,
    SourceHealth,
    SourceRefresh,
    content_hash_of,
    refresh_failure_fields,
    refresh_success_fields,
)

log = structlog.get_logger(__name__)


def is_cut_short_feed(current_count: int, kept: int) -> bool:
    """True when a result keeps under MIN_RETIRE_RATIO of the source's current records."""
    return bool(current_count) and kept < IntelLimits.MIN_RETIRE_RATIO * current_count


class ClaimLost(Exception):
    """The claim on the source was taken over."""


def write_fetch_result(
    records: IntelRecordRepository,
    source: IntelSource,
    result: FetchResult,
    now: datetime,
    still_ours: Callable[[], bool],
) -> tuple[int, int]:
    """Store `result` in batches of IntelLimits.BATCH_SIZE and retire what it left out: (new versions, retired)."""
    if not result.records:  # the source failed: nothing is retired
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=source)
    seen = {record.external_id for record in result.records}
    current = {doc["external_id"] for doc in records.list(["external_id"], source=source, current=True)}
    kept = len(current & seen)
    if is_cut_short_feed(len(current), kept):
        raise IntelFetchFailed(IntelMessage.CUT_SHORT, source=source, kept=kept, current=len(current))
    size = IntelLimits.BATCH_SIZE
    new_versions = 0
    for start in range(0, len(result.records), size):
        if not still_ours():
            raise ClaimLost
        new_versions += records.save_intel_records(result.records[start : start + size], now)
    if not still_ours():
        raise ClaimLost
    return new_versions, records.retire_intel_records_missing_from(source, seen, now)


def refresh_all_sources(now: datetime, keep_going: Callable[[], bool] = lambda: True) -> RefreshSummary:
    """Every source, in registry order; once `keep_going()` is false the rest is skipped."""
    _prepare_sources()
    return _finish(tuple(_refresh(source, now) for source in IntelSource if keep_going()))


def refresh_one_source(source: IntelSource, now: datetime) -> RefreshSummary:
    """Refresh one named source now (the admin job)."""
    _prepare_sources()
    return _finish((_refresh(source, now),))


def _prepare_sources() -> None:
    """Deletes what sources no longer imported left, then adds each missing source document."""
    deleted = delete_removed_sources()
    if any(deleted.values()):
        log.info(LogEvent.EXTERNAL_INTELLIGENCE_REMOVED_SOURCES_DELETED, **deleted)
    get_intel_feed_repository().create_missing_intel_feeds()


def _finish(outcomes: tuple[SourceRefresh, ...]) -> RefreshSummary:
    graph_changed = any(outcome.graph_changed for outcome in outcomes)
    if not get_intelligence_switch().is_on():  # the import always runs (ADR-010); evidence only while on
        return RefreshSummary(outcomes, False, graph_changed=graph_changed)
    try:
        get_evidence_index_keeper().rebuild_index().result()
    except EvidenceIndexRefused as exc:  # nothing current to index yet: its message says so
        return RefreshSummary(outcomes, False, {"code": ErrorCode.CONFLICT, "message": str(exc)}, graph_changed)
    except Exception as exc:  # the keeper logged it and keeps the old index; the refresh stands
        return RefreshSummary(outcomes, False, job_error_of(exc), graph_changed)
    return RefreshSummary(outcomes, True, graph_changed=graph_changed)


def _refresh(source: IntelSource, now: datetime) -> SourceRefresh:
    apply_proxy_once()
    feeds = get_intel_feed_repository()
    doc = feeds.get(_id=source)
    if doc is None:
        return SourceRefresh(source, RefreshResult.SKIPPED)
    health = SourceHealth.from_doc(doc)
    stale_before = now - timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)  # an older claim: a dead worker's
    claim = feeds.claim_intel_feed_refresh(source, now, stale_before)
    if claim is None:
        return SourceRefresh(source, RefreshResult.SKIPPED)
    try:
        outcome = _download_and_store(source, claim, health, now)
    except Exception as exc:  # recorded against the source; the others still run
        outcome = _fail(source, claim, _reason(exc), now)
    except BaseException as exc:  # a stop signal: give the claim back before it propagates
        _fail(source, claim, _reason(exc), now)
        raise
    return outcome


def _download_and_store(source: IntelSource, claim: str, health: SourceHealth, now: datetime) -> SourceRefresh:
    feeds, records, attack = get_intel_feed_repository(), get_intel_record_repository(), get_attack_repository()
    version = health.source_version  # the checkpoint is trusted only with its version, that release's graph
    trusted = version is not None and attack.is_release_stored(source, version)  # and that release's STIX objects
    trusted = trusted and _scenario_stix_repository(source).stored_versions() == [version]
    checkpoint = health.checkpoint if trusted else None
    result = MitreAttackSource(source).download_changes(checkpoint)
    if result is None:  # the source's version marker is the one already stored
        return _nothing_new(source, claim, health, now)
    for kind in AttackRecord if result.graph else ():  # the records' rule, for the graph's objects and its links
        current, kept = attack.count(source=source, record=kind), sum(doc["record"] == kind for doc in result.graph)
        if is_cut_short_feed(current, kept):  # before anything is written: the stored graph and records stay
            raise IntelFetchFailed(IntelMessage.CUT_SHORT, source=source, kept=kept, current=current)
    try:
        new_versions, retired = write_fetch_result(
            records, source, result, now, lambda: feeds.renew_intel_feed_refresh(source, claim, utc_now())
        )
        graph_changed = _store_graph(source, claim, result)
        _store_scenario_stix(source, claim, result)
    except ClaimLost:
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)
        return SourceRefresh(source, RefreshResult.CLAIM_LOST)
    _succeed(source, claim, (result.checkpoint, result.source_version), now, records.count(source=source, current=True))
    unchanged, quarantined = len(result.records) - new_versions, len(result.rejected)
    counts = {"new_versions": new_versions, "unchanged": unchanged, "quarantined": quarantined, "retired": retired}
    log.info(LogEvent.EXTERNAL_INTELLIGENCE_REFRESHED, source=source, **counts)
    return SourceRefresh(source, RefreshResult.REFRESHED, new_versions, retired, graph_changed=graph_changed)


def _store_graph(source: IntelSource, claim: str, result: FetchResult) -> bool:
    """Replaces the source's ATT&CK graph when the fetched one differs from the stored one; True when it did."""
    if not result.graph:
        return False
    attack = get_attack_repository()
    version = f"{result.source_version}|{content_hash_of(result.graph)}"  # the same content: the same version
    if attack.count(source=source) == len(result.graph) == attack.count(source=source, version=version):
        return False
    if not get_intel_feed_repository().renew_intel_feed_refresh(source, claim, utc_now()):
        raise ClaimLost
    stored = attack.replace_source(source, result.graph, version)
    log.info(LogEvent.ATTACK_GRAPH_STORED, source=source, source_version=result.source_version, records=stored)
    return True


def _scenario_stix_repository(source: IntelSource) -> MitreStixRepository:
    if source == IntelSource.ATTACK_ICS:
        return get_mitre_ics_stix_repository()
    return get_mitre_enterprise_stix_repository()


def _store_scenario_stix(source: IntelSource, claim: str, result: FetchResult) -> None:
    """Replaces the source's STIX objects the MITRE run reads, unless that release is stored whole already.
    An empty result writes nothing, so the stored objects stay."""
    if not result.raw_stix:
        return
    stix = _scenario_stix_repository(source)
    stored_whole = stix.stored_versions() == [result.source_version] and stix.count() == len(result.raw_stix)
    if stored_whole:
        return
    if not get_intel_feed_repository().renew_intel_feed_refresh(source, claim, utc_now()):
        raise ClaimLost
    stored = stix.replace_stix_objects(result.raw_stix, result.source_version)
    log.info(LogEvent.MITRE_STIX_STORED, source=source, source_version=result.source_version, records=stored)


def _nothing_new(source: IntelSource, claim: str, health: SourceHealth, now: datetime) -> SourceRefresh:
    checkpoint, version = health.checkpoint, health.source_version
    assert checkpoint is not None and version is not None  # only a stored checkpoint is answered "nothing new"
    _succeed(source, claim, (checkpoint, version), now, health.records)
    return SourceRefresh(source, RefreshResult.UNCHANGED)


def _succeed(source: IntelSource, claim: str, marks: tuple[str, str], now: datetime, records: int) -> None:
    checkpoint, version = marks
    success = refresh_success_fields(checkpoint, version, now, records=records)
    _log_if_claim_lost(get_intel_feed_repository().release_intel_feed_refresh(source, claim, success), source)


def _fail(source: IntelSource, claim: str, reason: str, now: datetime) -> SourceRefresh:
    try:
        failure = refresh_failure_fields(reason, now)
        _log_if_claim_lost(get_intel_feed_repository().release_intel_feed_refresh(source, claim, failure), source)
    except Exception:  # the store is down: the claim goes stale by itself, the others go on
        log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.MONGO, exc_info=True)
    log.warning(LogEvent.EXTERNAL_INTELLIGENCE_SOURCE_FAILED, source=source, message=reason)
    return SourceRefresh(source, RefreshResult.FAILED, error=reason)


def _log_if_claim_lost(released: bool, source: IntelSource) -> None:
    if not released:
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_CLAIM_LOST, source=source)


def _reason(exc: BaseException) -> str:
    if isinstance(exc, IntelFetchFailed):
        return exc.message
    return IntelMessage.UNEXPECTED.format(error=type(exc).__name__)
