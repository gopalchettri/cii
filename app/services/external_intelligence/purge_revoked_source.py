"""A source Legal no longer approves: first marked not approved (so no refresh writes it again), then its
records and cached vectors deleted and the index rebuilt, so every process drops it."""

from contextlib import suppress

from app.core.constants import IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.intel_vector_purge import IntelVectorPurge
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper


class RevokedSourcePurger:
    """Revokes a source and purges its data."""

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
        """Revoke the source, purge its records and vectors and rebuild the index; return the records deleted.
        A failed rebuild does not undo the purge: the keeper keeps trying."""
        self._feeds.revoke_source(source)
        purged = self._records.purge_source(source)
        self._vectors.purge_source_vectors(source)
        with suppress(Exception):  # the keeper logged it and tries again after a pause
            self._keeper.rebuild_index().result()
        return purged

    def purge_existing_only(self, source: IntelSource) -> int:
        """With the master switch off: unapprove the source only if its row exists and delete its records and
        vectors, creating and publishing nothing; return the records deleted."""
        self._feeds.revoke_source(source, create=False)
        purged = self._records.purge_source(source)
        self._vectors.purge_source_vectors(source)
        return purged
