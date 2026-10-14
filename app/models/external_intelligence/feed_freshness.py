"""How fresh the approved sources are: one answer for the health report and the evidence search flag."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import datetime

from app.core.constants import IntelSource
from app.models.external_intelligence.source_health import SourceHealth


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
        counted = [health for health in sources if health.source in approved]
        pending = tuple(health.source for health in counted if health.is_pending)
        return cls(
            stale=any(health.is_stale(now) for health in counted),
            pending=pending,
            no_data=len(pending) == len(counted),
        )
