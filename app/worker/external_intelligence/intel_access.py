"""The worker's door to external intelligence. The env master switch is checked first and alone: with it off,
or no run-time switch installed, nothing here reads a store, builds an index or calls a service."""

from collections.abc import Callable, Collection, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

from app.core.config import get_settings
from app.core.constants import ErrorMessage, IntelSource, IntelWorkEvent
from app.core.exceptions import Unavailable
from app.core.singletons import singleton
from app.data_access.external_intelligence.repository import intel_feeds
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.models.external_intelligence.evidence import EvidenceBatchSummary
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.models.external_intelligence.source_health import (
    FeedFreshness,
    source_health_in_registry_order,
    sources_in_registry_order,
)
from app.models.external_intelligence.switch_state import SwitchState
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper

log = structlog.get_logger(__name__)


class SwitchPort(Protocol):
    """The run-time switch as the worker sees it (the services layer installs it)."""

    def state(self) -> SwitchState:
        """The switch state now."""


class RefresherPort(Protocol):
    """The source refresher as the worker sees it (the services layer installs it)."""

    def refresh_due_sources(self, now: datetime) -> Any:
        """Refresh every approved source that is due."""

    def refresh_one_source(self, source: IntelSource, now: datetime) -> Any:
        """Refresh one source now."""


@singleton
def get_evidence_finder() -> EvidenceFinder:
    """The process's evidence finder: it holds no run's state and follows the active snapshot's index."""
    keeper = get_evidence_index_keeper()
    return EvidenceFinder(lambda: keeper.current_index(), get_settings().evidence_similarity_threshold)


class IntelAccess:
    """The switch, the refresher, the evidence search and the approved sources, each read only when asked."""

    def __init__(
        self,
        finder: Callable[[], EvidenceFinder] = get_evidence_finder,
        is_stale: Callable[[Collection[IntelSource]], bool] | None = None,
    ) -> None:
        self._switch: Callable[[], SwitchPort] | None = None
        self._refresher: Callable[[], RefresherPort] | None = None
        self._finder = finder
        self._is_stale = is_stale or self._feeds_are_stale

    def install(self, switch: Callable[[], SwitchPort], refresher: Callable[[], RefresherPort]) -> None:
        """Install the services layer's providers of the run-time switch and the source refresher."""
        self._switch, self._refresher = switch, refresher

    def is_on(self, sure: bool = False) -> bool:
        """True only when the env master switch and the run-time switch are on; no installed switch, or one
        that cannot be read, is off. `sure`: a switch in doubt raises Unavailable instead of reading off."""
        if not get_settings().external_intelligence_enabled:
            return False
        if self._switch is None:
            log.warning(IntelWorkEvent.RUNTIME_MISSING)
            return False
        try:
            state: SwitchState | None = self._switch().state()
        except Exception:  # a switch that cannot be read is off: the original writer runs
            log.warning(IntelWorkEvent.SWITCH_UNREADABLE, exc_info=True)
            state = None
        if sure and (state is None or not state.known):
            raise Unavailable(ErrorMessage.MONGO_UNREACHABLE)
        return state is not None and state.effective

    def refresher(self) -> RefresherPort:
        """The installed source refresher; RuntimeError when none is installed."""
        if self._refresher is None:
            raise RuntimeError(IntelWorkEvent.RUNTIME_MISSING)
        return self._refresher()

    def find_evidence(
        self, requests: Sequence[EvidenceRequest], stale: bool
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        """One batch's evidence (one embedding call), the finder told whether the intelligence is stale."""
        return self._finder().find_evidence(requests, stale=stale)

    def approved_sources(self) -> list[IntelSource]:
        """The sources Legal still allows."""
        return sources_in_registry_order(intel_feeds.list(["_id"], sources=True, approved=True))

    def is_stale(self, approved: Collection[IntelSource]) -> bool:
        """True when an approved source that has data is older than IntelLimits.STALE_AFTER_HOURS."""
        return self._is_stale(approved)

    def _feeds_are_stale(self, approved: Collection[IntelSource]) -> bool:
        """The staleness of these approved sources, from one read of the source health."""
        health = source_health_in_registry_order(intel_feeds.list(sources=True))
        return FeedFreshness.of(health, approved, datetime.now(UTC)).stale


@singleton
def get_intel_access() -> IntelAccess:
    """The process's IntelAccess, which the services layer's worker_runtime installs into."""
    return IntelAccess()
