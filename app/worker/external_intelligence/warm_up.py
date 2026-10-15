"""A worker's intelligence steps at start: ask the index keeper to build the search index in the background,
so the first batch of scenarios does not wait for it, and keep following the active snapshot whatever the
traffic. Only with external intelligence on; never blocks the worker's start and never fails it (the first
batch then builds, or goes without evidence)."""

import threading

import structlog

from app.core.config import get_settings
from app.core.constants import IntelLimits, IntelWorkEvent
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access

log = structlog.get_logger(__name__)


def warm_up_intelligence(access: IntelAccess | None = None) -> None:
    try:
        if not (access or get_intel_access()).is_on():
            log.info(IntelWorkEvent.WARM_UP_SKIPPED)
            return
        get_evidence_index_keeper().rebuild_index()  # a background future: not waited for
    except Exception:  # noqa: BLE001 - a worker starts whatever the intelligence is doing
        log.warning(IntelWorkEvent.WARM_UP_FAILED, exc_info=True)


def start_following_active_snapshot(access: IntelAccess | None = None) -> threading.Thread | None:
    """G242: the keeper learns of a newer snapshot only when asked, and the asking search still gets the old
    index; since G238 planning no longer asks, so the writer's first batch after a reload searched old data
    (run 45b8c63b: 7 minutes after the reload). One daemon thread per process asks every
    IntelLimits.SWITCH_CACHE_SECONDS, so a published snapshot is in use within about a minute (a rebuild from
    stored vectors takes ~1 s), and a failed first build is tried again without waiting for a search. None
    with the env master switch off: nothing is read."""
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
    except Exception:  # noqa: BLE001 - a worker starts anyway; each search still follows the pointer itself
        log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
        return None
    return thread


def follow_active_snapshot(access: IntelAccess, stop: threading.Event) -> None:
    """Until `stop` is set: each interval, while the switch is on, ask the keeper for its index (it then
    builds a newer active snapshot, or retries a failed build, in the background). Never raises."""
    while not stop.wait(IntelLimits.SWITCH_CACHE_SECONDS):
        try:
            if access.is_on():
                get_evidence_index_keeper().current_index()
        except Exception:  # noqa: BLE001 - the next interval asks again; the index in use keeps serving
            log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
