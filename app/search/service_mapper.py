"""Reusable hybrid index for catalog service discovery; similarity is retrieval, never dependency proof."""

import threading

from app.ai.embeddings import EmbeddingModel
from app.core.constants import EMBEDDING_SOURCE_TABLE, EmbeddingCorpus, MapperLimits
from app.models.service_mapper.catalog import CatalogService, CatalogSnapshot
from app.search.indexes import HybridIndex


class ServiceCandidateSearch:
    def __init__(self, embeddings: EmbeddingModel) -> None:
        self._embeddings = embeddings
        self._lock = threading.Lock()
        self._version = ""
        self._index: HybridIndex | None = None

    def candidates(self, catalog: CatalogSnapshot, queries: list[str]) -> list[CatalogService]:
        """Fuse semantic and keyword ranks for several operational questions across every sector."""
        if not catalog.services or not queries:
            return []
        index = self._for_catalog(catalog)
        vectors = self._embeddings.embed_search_queries(queries)
        scores: dict[int, float] = {}
        for query, vector in zip(queries, vectors, strict=True):
            hits = index.search(query, vector, MapperLimits.CANDIDATE_POOL)
            for rank, hit in enumerate(hits, start=1):
                scores[hit.position] = scores.get(hit.position, 0.0) + 1.0 / (60 + rank)
        ranked = sorted(
            scores, key=lambda position: (-scores[position], catalog.services[position].service_id)
        )
        return [catalog.services[position] for position in ranked[: MapperLimits.CANDIDATE_POOL]]

    def _for_catalog(self, catalog: CatalogSnapshot) -> HybridIndex:
        with self._lock:
            if self._index is not None and self._version == catalog.version:
                return self._index
            texts = [_describe(service) for service in catalog.services]
            table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.SERVICE]
            sources = [
                {"table": table, "id": service.service_id, "label": service.service_name}
                for service in catalog.services
            ]
            vectors = self._embeddings.embed_library_texts(EmbeddingCorpus.SERVICE, texts, sources)
            self._index = HybridIndex(texts, vectors)
            self._version = catalog.version
            return self._index


def _describe(service: CatalogService) -> str:
    groups = "; ".join(
        f"{group.sector_name} / {group.subsector_name or group.sector_name}" for group in service.sectors
    )
    return f"{service.service_name}. {service.description}. Sectors: {groups}"
