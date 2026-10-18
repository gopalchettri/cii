"""How external intelligence is doing: the switch, the active snapshot and every source's freshness."""

from datetime import datetime

from app.core.constants import IntelDocId
from app.data_access.external_intelligence.repository import IntelFeedRepository, IntelSnapshotRepository
from app.models.external_intelligence.source_health import (
    FeedFreshness,
    HealthReport,
    source_health_in_registry_order,
    sources_in_registry_order,
)
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.external_intelligence.switch import ExternalIntelligenceSwitch


class HealthReporter:
    """Builds the health report from the stores, the switch and the index in use."""

    def __init__(
        self,
        feed_store: IntelFeedRepository,
        snapshot_store: IntelSnapshotRepository,
        switch: ExternalIntelligenceSwitch,
        index_keeper: EvidenceIndexKeeper,
    ) -> None:
        self._feeds = feed_store
        self._snapshots = snapshot_store
        self._switch = switch
        self._keeper = index_keeper

    def describe_health(self, now: datetime) -> HealthReport:
        """The report at `now`: an approved source that never succeeded is pending, not stale; the snapshot is
        the fleet's active one, else the one this process serves. Reading starts no build."""
        sources = tuple(source_health_in_registry_order(self._feeds.list(sources=True)))
        approved = sources_in_registry_order(self._feeds.list(["_id"], sources=True, approved=True))
        freshness = FeedFreshness.of(sources, approved, now)
        active = self._snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
        snapshot_id = active.get("snapshot_id") if active else self._keeper.peek_index().snapshot_id
        return HealthReport(
            self._switch.state(), snapshot_id, sources, freshness.stale, freshness.pending, freshness.no_data
        )
