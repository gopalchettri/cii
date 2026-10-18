"""tsg_embeddings (the library's vectors; an unused one is retired, then expires) and tsg_query_vectors (a
search query's vector by its hash, never its text)."""

from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ReplaceOne, UpdateOne
from pymongo.collection import Collection as MongoCollection
from pymongo.errors import BulkWriteError

from app.core.constants import Cache, EmbeddingCorpus
from app.core.database import expire_documents_after

Doc = dict[str, Any]

_DUPLICATE_KEY = 11000  # MongoDB's error code for an _id already stored


class _VectorStore:
    def __init__(self, collection: MongoCollection) -> None:
        self._vectors = collection

    def read(self, keys: list[str], fields: tuple[str, ...]) -> dict[str, Doc]:
        """{key: document with `fields`} for the keys stored; one query."""
        found = self._vectors.find({"_id": {"$in": list(set(keys))}}, dict.fromkeys(fields, 1))
        return {doc["_id"]: doc for doc in found}

    def store(self, documents: list[Doc]) -> None:
        """Writes each document whole (a stored vector of the wrong size is replaced). Another worker storing
        the same text at the same moment is fine (its vector is identical); any other write error is raised:
        a store that saved nothing must not look healthy while every text is paid for again."""
        if not documents:
            return
        try:
            self._vectors.bulk_write(
                [ReplaceOne({"_id": doc["_id"]}, doc, upsert=True) for doc in documents], ordered=False
            )
        except BulkWriteError as exc:
            details = exc.details
            refused = [
                error for error in details.get("writeErrors", []) if error.get("code") != _DUPLICATE_KEY
            ]
            if refused or details.get("writeConcernErrors"):
                raise


class QueryVectors(_VectorStore):
    def ensure_indexes(self) -> None:
        """Each query vector expires at its own expires_at."""
        expire_documents_after(self._vectors, "expires_at", 0)  # each document goes at its own expires_at


class LibraryVectors(_VectorStore):
    def ensure_indexes(self) -> None:
        """A retired vector's expiry, a row's vectors, the vectors made since; unknown corpora retired."""
        expire_documents_after(self._vectors, "expires_at", 0)  # a retired vector goes at its own expires_at
        self._vectors.create_index([("corpus", 1), ("sources.id", 1)])  # a row's vectors, now and before
        self._vectors.create_index([("created_at", 1), ("corpus", 1)])  # vectors made since
        self.retire_unknown_corpora()

    def retire_unknown_corpora(self) -> int:
        """The vectors of a corpus this code does not know are retired, not deleted (during a rolling update
        a newer process's next build brings back what it still uses). How many were retired."""
        now, known = datetime.now(UTC), [corpus.value for corpus in EmbeddingCorpus]
        retired = self._vectors.update_many(
            {"corpus": {"$exists": True, "$nin": known}, "retired_at": {"$exists": False}},
            {"$set": {"retired_at": now, "expires_at": now + timedelta(days=Cache.RETIRED_VECTOR_DAYS)}},
        )
        return retired.modified_count

    def count_made_since(self, since: datetime) -> dict[str, int]:
        """{corpus: vectors embedded at or after `since`}: one aggregation, answered from the (created_at,
        corpus) index alone (no vector is read)."""
        made = self._vectors.aggregate(
            [
                {"$match": {"created_at": {"$gte": since}}},
                {"$group": {"_id": "$corpus", "count": {"$sum": 1}}},
            ]
        )
        return {doc["_id"]: doc["count"] for doc in made}

    def reconcile(self, corpus: EmbeddingCorpus, in_use: dict[str, list[Doc]], stored: dict[str, Doc]) -> int:
        """Brings one corpus in line with the library now. `in_use` maps every vector the corpus uses now to
        the rows using it; `stored` is what was read before embedding. A vector in use lists exactly its rows
        and is not retired; every other vector of the corpus is retired. Returns how many were retired.

        Safe when two processes see different library versions for a moment: a vector retired by one that the
        other still uses is brought back by that one's next build, and nothing is deleted for a year."""
        changed = [
            UpdateOne(
                {"_id": key}, {"$set": {"sources": sources}, "$unset": {"retired_at": "", "expires_at": ""}}
            )
            for key, sources in in_use.items()
            if key in stored and (stored[key].get("sources") != sources or "retired_at" in stored[key])
        ]
        if changed:
            self._vectors.bulk_write(changed, ordered=False)
        now = datetime.now(UTC)
        retired = self._vectors.update_many(
            {"corpus": corpus, "_id": {"$nin": list(in_use)}, "retired_at": {"$exists": False}},
            {"$set": {"retired_at": now, "expires_at": now + timedelta(days=Cache.RETIRED_VECTOR_DAYS)}},
        )
        return retired.modified_count
