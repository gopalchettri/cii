"""Makes a built evidence index the active snapshot, so every process can follow it."""

import structlog

from app.core.constants import LogEvent
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.models.external_intelligence.snapshot_description import SnapshotDescription
from app.search.external_intelligence.evidence_index import EvidenceIndex

log = structlog.get_logger(__name__)


class SnapshotPublisher:
    def __init__(self, snapshot_store: SnapshotPointerStore, embedding_model: str, rerank_model: str) -> None:
        self._snapshots = snapshot_store
        self._embedding_model = embedding_model
        self._rerank_model = rerank_model

    def publish_index(self, index: EvidenceIndex) -> None:
        """Stores and activates the index's description, unless another process already published this
        corpus. An empty index is published too, under the empty checksum: other processes then drop what was
        revoked. The pointer never moves to an older build (the store refuses)."""
        active = self._snapshots.read_active_snapshot()
        if active is not None and active.get("checksum") == index.corpus.checksum:
            return
        description = SnapshotDescription(
            index.snapshot_id or "empty",
            index.built_at,
            index.source_versions,
            index.corpus.counts(),
            index.corpus.checksum,
            self._embedding_model,
            self._rerank_model,
        )
        self._snapshots.save_snapshot_description(description.as_doc())
        activated = self._snapshots.activate_snapshot(description.snapshot_id)
        event = (
            LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_ACTIVATED
            if activated
            else LogEvent.EXTERNAL_INTELLIGENCE_SNAPSHOT_SUPERSEDED
        )
        log.info(event, snapshot_id=description.snapshot_id, indexed=len(index.corpus.hits))
