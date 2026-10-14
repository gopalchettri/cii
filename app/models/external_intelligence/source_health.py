"""How each source and the whole feature are doing: a source's stored status, and the report built on it."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.constants import FeedStatus, IntelLimits, IntelSource
from app.models.external_intelligence.switch_state import SwitchState


@dataclass(frozen=True)
class SourceHealth:
    """One source's row of `tsg_external_feed_status`."""

    source: IntelSource
    status: FeedStatus = FeedStatus.NEVER_RUN
    checkpoint: str | None = None  # the source's own version marker of the last committed refresh
    source_version: str | None = None
    records: int = 0  # current records of this source
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None  # an IntelMessage, filled in
    # set while a worker refreshes it; older than IntelLimits.CLAIM_STALE_SECONDS: the worker is dead
    claimed_at: datetime | None = None

    @property
    def is_pending(self) -> bool:
        """Never succeeded yet (not run, or only failed so far): waits for first data, is not out of date."""
        return self.last_success_at is None

    def is_stale(self, now: datetime) -> bool:
        """Has data, but its last success is older than IntelLimits.STALE_AFTER_HOURS. A source that never
        succeeded is pending, not stale: nothing it holds is old."""
        return self.last_success_at is not None and now - self.last_success_at > timedelta(
            hours=IntelLimits.STALE_AFTER_HOURS
        )

    def as_doc(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "checkpoint": self.checkpoint,
            "source_version": self.source_version,
            "records": self.records,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "claimed_at": self.claimed_at,
        }


@dataclass(frozen=True)
class HealthReport:
    """What the health endpoint shows: the switch, the active snapshot and every source."""

    switch: SwitchState
    snapshot_id: str | None  # None: no snapshot is active
    sources: tuple[SourceHealth, ...]
    stale: bool  # an approved source that HAS succeeded is older than the age limit
    #: approved sources that never succeeded: first data awaited
    pending_sources: tuple[IntelSource, ...] = ()
    no_data: bool = False  # no approved source has ever succeeded: nothing to be stale yet

    def as_doc(self) -> dict[str, Any]:
        return {
            "switch": self.switch.as_doc(),
            "snapshot_id": self.snapshot_id,
            "stale": self.stale,
            "pending_sources": list(self.pending_sources),
            "no_data": self.no_data,
            "sources": [source.as_doc() for source in self.sources],
        }
