"""The cached vectors of external intelligence texts (tsg_embeddings, corpus external_intelligence)."""

import re

from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database

from app.core.constants import Collection, EmbeddingCorpus, IntelSource


class IntelVectorPurge:
    def __init__(self, db: Database) -> None:
        self._vectors: MongoCollection = db[Collection.EMBEDDINGS]

    def purge_source_vectors(self, source: IntelSource) -> int:
        """Deletes the vectors (and the texts stored with them) used by this source's records only; a vector
        another source also uses stays. Retired vectors go too: a revoked source is not kept as history."""
        own = re.compile(f"^{re.escape(source)}/")
        only_this_source = {
            "corpus": EmbeddingCorpus.EXTERNAL_INTELLIGENCE,
            "sources.id": own,
            "sources": {"$not": {"$elemMatch": {"id": {"$not": own}}}},
        }
        return self._vectors.delete_many(only_this_source).deleted_count
