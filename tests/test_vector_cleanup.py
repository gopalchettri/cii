"""G239 (2026-10-14: 2,696 vectors of the renamed corpus "intel" were never cleaned): a vector of a corpus no
code knows is retired at the next start, like any unused vector (deleted RETIRED_VECTOR_DAYS later: a newer
process in a rolling update brings back what it uses); the corpora the code knows are left to their builds."""

from datetime import UTC, datetime, timedelta

from app.core.constants import Cache, EmbeddingCorpus
from app.core.database import get_mongodb
from app.data_access.admin.repository import LibraryVectorRepository


def test_a_vector_of_a_corpus_no_code_knows_is_retired_and_known_corpora_are_untouched() -> None:
    vectors = get_mongodb()["test_vector_cleanup"]
    vectors.drop()
    vectors.insert_many(
        [
            {"_id": "old", "corpus": "intel", "vector": [0.1]},
            {"_id": "control", "corpus": EmbeddingCorpus.CONTROL.value, "vector": [0.2]},
            {"_id": "intelligence", "corpus": EmbeddingCorpus.EXTERNAL_INTELLIGENCE.value, "vector": [0.3]},
        ]
    )
    store = LibraryVectorRepository(vectors)
    assert store.retire_unknown_vector_corpora() == 1
    old = vectors.find_one({"_id": "old"}) or {}
    keep = old["expires_at"].replace(tzinfo=UTC) - datetime.now(UTC)
    assert old["retired_at"] and timedelta(days=Cache.RETIRED_VECTOR_DAYS - 1) < keep  # retired, not deleted
    assert all("retired_at" not in doc for doc in vectors.find({"_id": {"$in": ["control", "intelligence"]}}))
    assert store.retire_unknown_vector_corpora() == 0  # a retired vector is not written at every start
    vectors.drop()
