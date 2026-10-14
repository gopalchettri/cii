"""One immutable evidence index: the corpus, its keyword + vector index, and the two searches the evidence
engine needs. Built once (EvidenceIndex.build), never changed afterwards, so every thread shares it.

A search ranks only the records that fit the asset's IT / OT type, chosen BEFORE the top-k cut. The embedding
of the record texts goes through the app's EmbeddingModel and its vector cache (a text is embedded once per
model, stored per batch as it arrives, so a build that stops half way resumes from what was stored). All
scores handed on are 0-100 ranking scores of the reranker, not probabilities."""

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime

import numpy as np

from app.ai import EmbeddingModel, RerankModel
from app.core.constants import EMBEDDING_SOURCE_TABLE, EmbeddingCorpus, IntelMessage
from app.core.tracing import traced
from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.search.external_intelligence.index_refused import EvidenceIndexRefused
from app.search.external_intelligence.ioc_text import remove_indicators
from app.search.indexes import HybridIndex

_EMPTY = EvidenceCorpus((), (), "")


class EvidenceIndex:
    def __init__(  # noqa: PLR0913 - the corpus, its index, the two models and the name of the reranker
        self,
        corpus: EvidenceCorpus,
        hybrid: HybridIndex | None,
        embeddings: EmbeddingModel,
        rerank: RerankModel,
        rerank_model: str = "",
    ) -> None:
        self._corpus = corpus
        self._hybrid = hybrid
        self._embeddings = embeddings
        self._rerank = rerank
        self.rerank_model = rerank_model  # the model whose 0-100 scores the threshold is cut on
        self.built_at = datetime.now(UTC)
        self._asset_types = np.array([hit.asset_type for hit in corpus.hits])

    def reuse_for(self, corpus: EvidenceCorpus) -> "EvidenceIndex | None":
        """A new index over `corpus` that shares this one's vectors, when the corpus differs only in what the
        vectors do not depend on (an EPSS value moved, say): no read, no AI call. None otherwise."""
        if self._hybrid is None or self._corpus.rows != corpus.rows:
            return None
        return EvidenceIndex(corpus, self._hybrid, self._embeddings, self._rerank, self.rerank_model)

    @property
    def snapshot_id(self) -> str | None:
        """The same for the same corpus in every process, so a stored audit names one snapshot."""
        return self._corpus.checksum[:24] if self._corpus.hits else None

    @property
    def has_records(self) -> bool:
        return bool(self._corpus.hits)

    @property
    def source_versions(self) -> dict[str, str]:
        return dict(self._corpus.source_versions)

    @property
    def corpus(self) -> EvidenceCorpus:
        return self._corpus

    @traced("search.evidence_candidates")
    def find_candidates(
        self, searches: Sequence[tuple[str, frozenset[str]]], limit: int
    ) -> list[list[IntelHit]]:
        """Per (search text, asset types): the `limit` nearest records of those types, not yet scored. ONE
        embedding call for all searches; a search no record can answer is not embedded."""
        found: list[list[IntelHit]] = [[] for _ in searches]
        if self._hybrid is None or limit < 1:
            return found
        queries = [remove_indicators(text) for text, _ in searches]
        allowed = [np.isin(self._asset_types, list(types)) for _, types in searches]
        asked = [i for i, fits in enumerate(allowed) if fits.any() and queries[i]]
        if not asked:
            return found
        vectors = self._embeddings.embed_search_queries([queries[i] for i in asked])
        for position, vector in zip(asked, vectors, strict=True):
            hits = self._hybrid.search(queries[position], vector, limit, allowed[position])
            found[position] = [self._corpus.hits[hit.position] for hit in hits]
        return found

    def score_candidates(self, query: str, hits: Sequence[IntelHit]) -> list[IntelHit]:
        """`hits` scored 0-100 by the reranker against `query` (one call), best first. Keeps every hit: the
        caller decides what a low score means."""
        if not hits:
            return []
        scores = self._rerank.score_relevance(
            remove_indicators(query), [remove_indicators(hit.text) for hit in hits]
        )
        scored = [replace(hit, score=score) for hit, score in zip(hits, scores, strict=True)]
        return sorted(scored, key=lambda hit: (-hit.score, hit.external_id))


def empty_index(embeddings: EmbeddingModel, rerank: RerankModel, rerank_model: str = "") -> EvidenceIndex:
    """No index yet: every search finds nothing and the scenarios are written as without intelligence."""
    return EvidenceIndex(_EMPTY, None, embeddings, rerank, rerank_model)


@traced("search.build_evidence_index")
def build_index(
    corpus: EvidenceCorpus, embeddings: EmbeddingModel, rerank: RerankModel, rerank_model: str = ""
) -> EvidenceIndex:
    """Embeds the record texts (the vector cache answers every text already embedded; each batch is stored as
    it arrives, so a build that stops half way resumes from what was stored)."""
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.EXTERNAL_INTELLIGENCE]
    sources = [
        {"table": table, "id": f"{hit.source}/{hit.external_id}", "label": hit.title} for hit in corpus.hits
    ]
    texts = list(corpus.search_texts)
    vectors = embeddings.embed_library_texts(EmbeddingCorpus.EXTERNAL_INTELLIGENCE, texts, sources)
    if len(vectors) != len(texts):
        raise EvidenceIndexRefused(IntelMessage.SNAPSHOT_INCONSISTENT, rows=len(texts), vectors=len(vectors))
    hybrid = HybridIndex(texts, vectors, labels=[hit.title for hit in corpus.hits])
    return EvidenceIndex(corpus, hybrid, embeddings, rerank, rerank_model)
