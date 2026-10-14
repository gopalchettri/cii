"""How external intelligence is doing: the switch, the active snapshot and every source's freshness."""

from datetime import datetime

from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.models.external_intelligence.feed_freshness import FeedFreshness
from app.models.external_intelligence.source_health import HealthReport
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.external_intelligence.switch import ExternalIntelligenceSwitch


class HealthReporter:
    def __init__(
        self,
        feed_store: FeedStatusStore,
        snapshot_store: SnapshotPointerStore,
        switch: ExternalIntelligenceSwitch,
        index_keeper: EvidenceIndexKeeper,
    ) -> None:
        self._feeds = feed_store
        self._snapshots = snapshot_store
        self._switch = switch
        self._keeper = index_keeper

    def describe_health(self, now: datetime) -> HealthReport:
        """`stale`: an approved source that HAS succeeded is older than IntelLimits.STALE_AFTER_HOURS. An
        approved source that never succeeded is `pending_sources` (and `no_data` when all are): waiting for
        first data, not stale. The snapshot is the active one of the fleet; before any, the one this process
        serves. Reading starts no build."""
        sources = tuple(self._feeds.read_all_source_health())
        freshness = FeedFreshness.of(sources, self._feeds.list_approved_sources(), now)
        active = self._snapshots.read_active_snapshot()
        snapshot_id = active.get("snapshot_id") if active else self._keeper.peek_index().snapshot_id
        return HealthReport(
            self._switch.state(), snapshot_id, sources, freshness.stale, freshness.pending, freshness.no_data
        )
