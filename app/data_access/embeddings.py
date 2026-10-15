"""The vectors in MongoDB: the only code that reads or writes them.

tsg_embeddings — the SQL library's vectors (controls, threats, threat actors, threat types). One document per
(model, corpus, text), saying what it is: `corpus`, `model`, `dimensions`, `text`, `text_hash`, `vector`,
`sources` (the library rows using this text: `{table, id, label}`) and `created_at`. A vector no row uses
any more (its text changed, its row was deleted, the model changed) is retired, not deleted: `retired_at` is
when it stopped being used, and it is deleted Cache.RETIRED_VECTOR_DAYS later (TTL on `expires_at`). So a
row's earlier texts stay findable (`{corpus, "sources.id"}`), and a text that comes back is used again
without a new AI call.

tsg_query_vectors — a search query's vector, deleted Cache.QUERY_VECTOR_DAYS after it was made (TTL on
`expires_at`). Only the query's hash is stored, never its text: a query holds an organization's asset
description."""

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
        expire_documents_after(self._vectors, "expires_at", 0)  # each document goes at its own expires_at


class LibraryVectors(_VectorStore):
    def ensure_indexes(self) -> None:
        expire_documents_after(self._vectors, "expires_at", 0)  # a retired vector goes at its own expires_at
        self._vectors.create_index([("corpus", 1), ("sources.id", 1)])  # a row's vectors, now and before
        self._vectors.create_index([("created_at", 1), ("corpus", 1)])  # vectors made since (#19 counts)
        # ponytail: documents stored before 2026-10-10 (no `corpus`: only a key and a vector) are dropped by
        # the TTL; every library text is embedded again once. Delete this line once no older store exists.
        self._vectors.update_many({"corpus": {"$exists": False}}, {"$set": {"expires_at": datetime.now(UTC)}})
        self.retire_unknown_corpora()

    def retire_unknown_corpora(self) -> int:
        """G239: the vectors of a corpus this code does not know (a renamed one: "intel" before
        "external_intelligence") are retired like any unused vector: each build retires only within the
        corpora it knows, so a renamed one stayed for ever. Retired, not deleted at once: during a rolling
        update an older process does not know a newer corpus, and the newer process's next build brings back
        what it still uses (`reconcile`). Runs at every start; a vector already retired is not written again.
        Returns how many it retired."""
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
