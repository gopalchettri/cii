"""Whether external intelligence, when it is on, holds data to cite (owner, 2026-10-15).

With it on, every scenario must cite a source (G229). A run started before the first import could only retry
its evidence searches as outages until it failed, filling the worker's log. It is refused at once instead,
with the import to run named in the answer. Off (the env master or the run-time switch): nothing is read."""

from app.core.constants import ConflictReason, IntelMessage
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.services.external_intelligence.switch import get_external_intelligence_switch


def refuse_without_intel_data() -> None:
    """409 intel_no_data while the switch is on and the active snapshot indexes nothing (none built yet, or
    every source revoked); one small read, only while on."""
    if not get_external_intelligence_switch().is_enabled():
        return
    active = SnapshotPointerStore(get_mongodb()).read_active_snapshot() or {}
    if not (active.get("counts") or {}).get("indexed"):
        raise Conflict(IntelMessage.NO_DATA_YET, reason=ConflictReason.INTEL_NO_DATA)
