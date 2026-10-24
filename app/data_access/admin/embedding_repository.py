"""tsg_embeddings: the vectors of the library and of external intelligence texts."""

import re
from datetime import datetime, timedelta

from pymongo import UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core.clock import utc_now
from app.core.constants import Cache, Collection, EmbeddingCorpus, IntelSource
from app.data_access.base import Record, VectorRepository


def _retired_fields(now: datetime) -> Record:
    """A retired vector's stamp and its expiry Cache.RETIRED_VECTOR_DAYS later."""
    return {"retired_at": now, "expires_at": now + timedelta(days=Cache.RETIRED_VECTOR_DAYS)}


def _vectors_used_only_by(source: IntelSource) -> Record:
    """The cached vectors of external intelligence texts that only `source`'s records use."""
    own = re.compile(f"^{re.escape(source)}/")
    return {
        "corpus": EmbeddingCorpus.EXTERNAL_INTELLIGENCE,
        "sources.id": own,
        "sources": {"$not": {"$elemMatch": {"id": {"$not": own}}}},
    }


class EmbeddingRepository(VectorRepository):
    """tsg_embeddings: the library's vectors (one no row uses is retired, then expires) and external
    intelligence vectors (deleted with a revoked source)."""

    def __init__(self, collection: str | MongoCollection = Collection.EMBEDDINGS) -> None:
        """tsg_embeddings with its corpus indexes and the `used_only_by_source` condition."""
        super().__init__(
            collection,
            conditions={"used_only_by_source": _vectors_used_only_by},
            # a row's vectors now and before; the vectors made since (count_library_vectors_made_since)
            indexes=[
                {"keys": [("corpus", 1), ("sources.id", 1)]},
                {"keys": [("created_at", 1), ("corpus", 1)]},
            ],
            schema_version=1,
        )

    def retire_unknown_vector_corpora(self) -> int:
        """Retires (never deletes) the tsg_embeddings vectors of a corpus this code does not know: during a
        rolling update a newer process's next build brings back what it uses. How many were retired."""
        known = [corpus.value for corpus in EmbeddingCorpus]
        unknown = {"corpus": {"$exists": True, "$nin": known}, "retired_at": {"$exists": False}}
        return self.collection.update_many(unknown, {"$set": _retired_fields(utc_now())}).modified_count

    def update_library_vector_corpus(
        self, corpus: EmbeddingCorpus, in_use: dict[str, list[Record]], stored: dict[str, Record]
    ) -> int:
        """Brings one corpus of tsg_embeddings in line with the library now: a vector in use (`in_use`: key ->
        rows using it; `stored`: what was read before embedding) lists exactly its rows and is not retired;
        every other vector of the corpus is retired. How many were retired. Two processes seeing different
        library versions for a moment are safe: the next build brings back a vector still in use."""
        changed = [
            UpdateOne(
                {"_id": key}, {"$set": {"sources": sources}, "$unset": {"retired_at": "", "expires_at": ""}}
            )
            for key, sources in in_use.items()
            if key in stored and (stored[key].get("sources") != sources or "retired_at" in stored[key])
        ]
        if changed:
            self.collection.bulk_write(changed, ordered=False)
        unused = {"corpus": corpus, "_id": {"$nin": list(in_use)}, "retired_at": {"$exists": False}}
        return self.collection.update_many(unused, {"$set": _retired_fields(utc_now())}).modified_count

    def count_library_vectors_made_since(self, since: datetime) -> dict[str, int]:
        """{corpus: tsg_embeddings vectors embedded at or after `since`}: one aggregation answered from the
        (created_at, corpus) index alone."""
        made = self.collection.aggregate(
            [
                {"$match": {"created_at": {"$gte": since}}},
                {"$group": {"_id": "$corpus", "count": {"$sum": 1}}},
            ]
        )
        return {found["_id"]: found["count"] for found in made}

    def delete_vectors_used_only_by(self, source: IntelSource) -> int:
        """Deletes the external intelligence vectors only `source`'s records use; how many went."""
        return self.delete(used_only_by_source=source)
