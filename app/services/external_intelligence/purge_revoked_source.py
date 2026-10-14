"""A source Legal no longer approves: not approved, its records and cached vectors deleted, the index rebuilt.

Order matters: the source is first marked not approved (no refresh starts for it, one already running finds
its claim refused at the next batch, and the index is built from approved sources only), then its data goes,
and the rebuild makes every process drop it from its index (the empty index is published too when it was the
last source). A refresh that was writing in that gap deletes what it wrote itself when it sees the source is
no longer approved (SourceRefresher), so nothing of a revoked source is left behind.

With the master switch off no intelligence collection exists to be created: purge_existing_only deletes what
is there and creates and publishes nothing."""

from contextlib import suppress

from app.core.constants import IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.intel_vector_purge import IntelVectorPurge
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper


class RevokedSourcePurger:
    def __init__(
        self,
        record_store: IntelRecordStore,
        feed_store: FeedStatusStore,
        index_keeper: EvidenceIndexKeeper,
        vector_purge: IntelVectorPurge | None = None,
    ) -> None:
        self._records = record_store
        self._feeds = feed_store
        self._keeper = index_keeper
        self._vectors = vector_purge or IntelVectorPurge(get_mongodb())

    def revoke_and_purge(self, source: IntelSource) -> int:
        """The records deleted. A failed index rebuild does not undo the purge: the keeper keeps trying."""
        self._feeds.revoke_source(source)
        purged = self._records.purge_source(source)
        self._vectors.purge_source_vectors(source)
        with suppress(Exception):  # the keeper logged it and tries again after a pause
            self._keeper.rebuild_index().result()
        return purged

    def purge_existing_only(self, source: IntelSource) -> int:
        """The master switch is off: the source is marked not approved only if its registry row exists, its
        records and cached vectors are deleted, and no collection is created, no row added, no index or
        snapshot published (the first refresh after the switch is turned on rebuilds them)."""
        self._feeds.revoke_source(source, create=False)
        purged = self._records.purge_source(source)
        self._vectors.purge_source_vectors(source)
        return purged
