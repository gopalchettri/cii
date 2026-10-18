"""How each source and the whole feature are doing: a source's stored status, the report built on it, and
how fresh the approved sources are."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.constants import FeedStatus, IntelLimits, IntelSource, StoreLimits
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

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> "SourceHealth":
        """A tsg_external_feed_status source document as its SourceHealth, missing fields at defaults."""
        source = IntelSource(doc["_id"])
        values = {name: doc.get(name, default) for name, default in cls(source).as_doc().items()}
        return cls(**{**values, "source": source, "status": FeedStatus(values["status"])})

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
        """The row as the health report shows it."""
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
        """The report as the health endpoint serves it."""
        return {
            "switch": self.switch.as_doc(),
            "snapshot_id": self.snapshot_id,
            "stale": self.stale,
            "pending_sources": list(self.pending_sources),
            "no_data": self.no_data,
            "sources": [source.as_doc() for source in self.sources],
        }


@dataclass(frozen=True)
class FeedFreshness:
    """`stale`: an approved source that HAS succeeded is older than IntelLimits.STALE_AFTER_HOURS. `pending`:
    approved sources that never succeeded (NVD's first pass takes hours; a fresh install has none yet): they
    wait for first data and are never "stale". `no_data`: no approved source has succeeded yet."""

    stale: bool
    pending: tuple[IntelSource, ...]
    no_data: bool

    @classmethod
    def of(
        cls, sources: Iterable[SourceHealth], approved: Collection[IntelSource], now: datetime
    ) -> "FeedFreshness":
        """The freshness of the approved sources among `sources` at `now`."""
        counted = [health for health in sources if health.source in approved]
        pending = tuple(health.source for health in counted if health.is_pending)
        return cls(
            stale=any(health.is_stale(now) for health in counted),
            pending=pending,
            no_data=len(pending) == len(counted),
        )


def refresh_success_fields(
    checkpoint: str, source_version: str, now: datetime, *, more: bool, records: int
) -> dict[str, Any]:
    """What a successful refresh records on its source: the new checkpoint, version and count."""
    return {
        "status": FeedStatus.OK,
        "checkpoint": checkpoint,
        "source_version": source_version,
        "records": records,
        "last_success_at": now,
        "last_error": None,
        "more_pending": more,
    }


def refresh_failure_fields(error: str, now: datetime) -> dict[str, Any]:
    """What a failed refresh records on its source; the checkpoint and last success stay, so the last good
    data stays usable until stale."""
    return {
        "status": FeedStatus.FAILED,
        "last_attempt_at": now,
        "last_error": error[: StoreLimits.MAX_ERROR_CHARS],
    }


def source_health_in_registry_order(docs: Iterable[dict[str, Any]]) -> list[SourceHealth]:
    """tsg_external_feed_status source documents as their SourceHealth, in registry order."""
    by_source = {doc["_id"]: SourceHealth.from_doc(doc) for doc in docs}
    return [by_source[source] for source in IntelSource if source in by_source]


def sources_in_registry_order(docs: Iterable[dict[str, Any]]) -> list[IntelSource]:
    """The sources of tsg_external_feed_status documents, in registry order."""
    found = {doc["_id"] for doc in docs}
    return [source for source in IntelSource if source in found]
