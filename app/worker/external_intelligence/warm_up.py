"""A worker's intelligence steps at start, only with external intelligence on: build the evidence index in the
background, and follow the active snapshot from a daemon thread. Neither blocks nor fails the start."""

import threading

import structlog

from app.core.config import get_settings
from app.core.constants import IntelLimits, IntelWorkEvent
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access

log = structlog.get_logger(__name__)


def warm_up_intelligence(access: IntelAccess | None = None) -> None:
    """Start building the evidence index in the background while the switch is on, so the first batch need
    not wait for it; never raises."""
    try:
        if not (access or get_intel_access()).is_on():
            log.info(IntelWorkEvent.WARM_UP_SKIPPED)
            return
        get_evidence_index_keeper().rebuild_index()  # a background future: not waited for
    except Exception:  # a worker starts whatever the intelligence is doing
        log.warning(IntelWorkEvent.WARM_UP_FAILED, exc_info=True)


def start_following_active_snapshot(access: IntelAccess | None = None) -> threading.Thread | None:
    """Start the daemon thread that keeps this process on the active snapshot (a published one is in use
    within IntelLimits.SWITCH_CACHE_SECONDS); None with the env master switch off."""
    if not get_settings().external_intelligence_enabled:
        return None
    try:
        thread = threading.Thread(
            target=follow_active_snapshot,
            args=(access or get_intel_access(), threading.Event()),
            name="evidence-follow",
            daemon=True,
        )
        thread.start()
    except Exception:  # a worker starts anyway; each search still follows the pointer itself
        log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
        return None
    return thread


def follow_active_snapshot(access: IntelAccess, stop: threading.Event) -> None:
    """Until `stop` is set, ask the keeper for its index each interval while the switch is on (it then builds
    a newer active snapshot, or retries a failed build, in the background); never raises."""
    while not stop.wait(IntelLimits.SWITCH_CACHE_SECONDS):
        try:
            if access.is_on():
                get_evidence_index_keeper().current_index()
        except Exception:  # the next interval asks again; the index in use keeps serving
            log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
