"""What the worker's intelligence code reads, each only when asked. The master switch (env) is checked
FIRST and alone: with it off, or with no run-time switch installed, nothing here reads or writes any
store, builds any index or calls any service, so the app behaves exactly as it did before external
intelligence."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.core.constants import IntelWorkEvent, WriterStyle
from app.core.database import get_mongodb
from app.core.singletons import singleton
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.engine.external_intelligence.evidence_finder import EvidenceFinder
from app.engine.external_intelligence.threat_relevance import threat_relevance
from app.models.asset_context import FrozenContext
from app.models.external_intelligence.evidence import EvidenceBatchSummary
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.models.external_intelligence.feed_freshness import FeedFreshness
from app.models.threats import PlannedThreat
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.worker.external_intelligence.evidence_request_builder import nearness_of
from app.worker.external_intelligence.intel_runtime import IntelRuntime, RefresherPort
from app.worker.external_intelligence.relevance_corpus import RelevanceCorpus, get_relevance_corpus

log = structlog.get_logger(__name__)


@singleton
def get_evidence_finder() -> EvidenceFinder:
    """One per process: it holds no run's state and follows the active snapshot's index."""
    keeper = get_evidence_index_keeper()
    return EvidenceFinder(lambda: keeper.current_index(), get_settings().evidence_similarity_threshold)


class IntelAccess:
    def __init__(
        self,
        finder: Callable[[], EvidenceFinder] = get_evidence_finder,
        is_stale: Callable[[], bool] | None = None,
        relevance: Callable[[], RelevanceCorpus] = get_relevance_corpus,
    ) -> None:
        self._runtime: IntelRuntime | None = None
        self._finder = finder
        self._relevance = relevance
        self._is_stale = is_stale or self._feeds_are_stale

    def install(self, runtime: IntelRuntime) -> None:
        self._runtime = runtime

    def is_on(self) -> bool:
        """True only when the env master switch AND the run-time switch are on. An outage of the switch's
        store keeps its last value (the switch's own rule); no installed switch counts as off."""
        if not get_settings().external_intelligence_enabled:
            return False
        if self._runtime is None:
            log.warning(IntelWorkEvent.RUNTIME_MISSING)
            return False
        try:
            return self._runtime.switch().is_enabled()
        except Exception:  # noqa: BLE001 - a switch that cannot be read is off: the original writer runs
            log.warning(IntelWorkEvent.SWITCH_UNREADABLE, exc_info=True)
            return False

    def writer_style(self) -> WriterStyle:
        return WriterStyle.EVIDENCE_STORY if self.is_on() else WriterStyle.ORIGINAL

    def refresher(self) -> RefresherPort:
        if self._runtime is None:
            raise RuntimeError(IntelWorkEvent.RUNTIME_MISSING)
        return self._runtime.refresher()

    def find_evidence(
        self, requests: Sequence[EvidenceRequest]
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        """One batch's evidence (ONE embedding call): the engine, told whether the intelligence is stale."""
        return self._finder().find_evidence(requests, stale=self._is_stale())

    def plan_intel(
        self, threats: list[PlannedThreat], context: FrozenContext
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        """G232: each planned threat's nearness to the deployment's country, by keywords (no AI or embedding
        call), and the stamp of the snapshot it was read from (its id and each source's release): one read,
        so a plan records exactly the data it ranked with. G238: never waits, never the old data (its own
        small copy, RelevanceCorpus). ({}, {}) when off; a store fault plans without it, logged. No ATT&CK
        technique stored: no tie-break, but the stamp still names the snapshot the writer will search."""
        if not self.is_on():
            return {}, {}
        try:
            corpus, active = self._relevance().current()
        except Exception:  # noqa: BLE001 - the plan is made without the tie-break, never lost to it
            log.warning(IntelWorkEvent.RELEVANCE_SKIPPED, exc_info=True)
            return {}, {}
        stamp = {
            "intel_snapshot_id": active.get("snapshot_id"),
            "intel_sources": dict(active.get("source_versions") or {}),
        }
        near = threat_relevance(corpus, threats, nearness_of(context)) if corpus is not None else {}
        return near, stamp

    def _feeds_are_stale(self) -> bool:
        """True when an approved source that has data is older than IntelLimits.STALE_AFTER_HOURS (the health
        report's rule; a source that never succeeded is pending, not stale)."""
        feeds = FeedStatusStore(get_mongodb())
        health, approved = feeds.read_all_source_health(), feeds.list_approved_sources()
        return FeedFreshness.of(health, approved, datetime.now(UTC)).stale


@singleton
def get_intel_access() -> IntelAccess:
    return IntelAccess()
