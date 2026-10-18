"""A worker's intelligence steps at start, only with external intelligence on: build the evidence index in the
background, and follow the active snapshot from a daemon thread. Neither blocks nor fails the start."""

import threading
from collections.abc import Callable

import structlog

from app.core.config import Settings
from app.core.constants import IntelLimits, IntelWorkEvent
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper

log = structlog.get_logger(__name__)

#: The keeper's provider: called only while the switch is on, so with intelligence off nothing is built.
KeeperProvider = Callable[[], EvidenceIndexKeeper]


def warm_up_intelligence(switch: IntelligenceSwitch, keeper: KeeperProvider) -> None:
    """Start building the evidence index in the background while the switch is on, so the first batch need
    not wait for it; never raises."""
    try:
        if not switch.is_on():
            log.info(IntelWorkEvent.WARM_UP_SKIPPED)
            return
        keeper().rebuild_index()  # a background future: not waited for
    except Exception:  # a worker starts whatever the intelligence is doing
        log.warning(IntelWorkEvent.WARM_UP_FAILED, exc_info=True)


def start_following_active_snapshot(
    settings: Settings, switch: IntelligenceSwitch, keeper: KeeperProvider
) -> threading.Thread | None:
    """Start the daemon thread that keeps this process on the active snapshot (a published one is in use
    within IntelLimits.SWITCH_CACHE_SECONDS); None with the env master switch off."""
    if not settings.external_intelligence_enabled:
        return None
    try:
        thread = threading.Thread(
            target=follow_active_snapshot,
            args=(switch, keeper, threading.Event()),
            name="evidence-follow",
            daemon=True,
        )
        thread.start()
    except Exception:  # a worker starts anyway; each search still follows the pointer itself
        log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
        return None
    return thread


def follow_active_snapshot(switch: IntelligenceSwitch, keeper: KeeperProvider, stop: threading.Event) -> None:
    """Until `stop` is set, ask the keeper for its index each interval while the switch is on (it then builds
    a newer active snapshot, or retries a failed build, in the background); never raises."""
    while not stop.wait(IntelLimits.SWITCH_CACHE_SECONDS):
        try:
            if switch.is_on():
                keeper().current_index()
        except Exception:  # the next interval asks again; the index in use keeps serving
            log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
