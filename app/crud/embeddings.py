"""tsg_embeddings: the vectors of the library and of external intelligence texts."""

from datetime import datetime, timedelta

from pymongo import UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Cache, Collection, EmbeddingCorpus
from app.core.singletons import singleton
from app.crud.base import Record, VectorRepository, bulk_write


class EmbeddingRepository(VectorRepository):
    """tsg_embeddings: the library's vectors (retired, then expired) and intelligence vectors."""

    def __init__(self, collection: str | MongoCollection = Collection.EMBEDDINGS) -> None:
        super().__init__(
            collection,
            # a row's vectors now and before; the vectors made since (count_library_vectors_made_since)
            indexes=[{"keys": [("corpus", 1), ("sources.id", 1)]}, {"keys": [("created_at", 1), ("corpus", 1)]}],
            schema_version=1,
        )

    def update_library_vector_corpus(
        self, corpus: EmbeddingCorpus, in_use: dict[str, list[Record]], stored: dict[str, Record]
    ) -> int:
        """Lists each in-use vector's rows and unretires it, retires the rest; how many retired."""
        changed = [
            UpdateOne({"_id": key}, {"$set": {"sources": sources}, "$unset": {"retired_at": "", "expires_at": ""}})
            for key, sources in in_use.items()
            if key in stored and (stored[key].get("sources") != sources or "retired_at" in stored[key])
        ]
        if changed:
            bulk_write(self.collection, changed, ordered=False)
        unused = {"corpus": corpus, "_id": {"$nin": list(in_use)}, "retired_at": {"$exists": False}}
        now = utc_now()
        retired = {"retired_at": now, "expires_at": now + timedelta(days=Cache.RETIRED_VECTOR_DAYS)}
        return self.collection.update_many(unused, {"$set": retired}).modified_count

    def count_library_vectors_made_since(self, since: datetime) -> dict[str, int]:
        """{corpus: vectors embedded at or after `since`}, from the index alone."""
        made = self.collection.aggregate(
            [{"$match": {"created_at": {"$gte": since}}}, {"$group": {"_id": "$corpus", "count": {"$sum": 1}}}]
        )
        return {found["_id"]: found["count"] for found in made}


@singleton
def get_embedding_repository() -> EmbeddingRepository:
    return EmbeddingRepository()
