"""A worker's first intelligence step: ask the index keeper to build the search index in the background,
so the first batch of scenarios does not wait for it. Only with external intelligence on; never blocks
the worker's start and never fails it (the first batch then builds, or goes without evidence)."""

import structlog

from app.core.constants import IntelWorkEvent
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
