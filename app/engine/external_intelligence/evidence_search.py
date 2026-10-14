"""What the evidence engine needs from the search layer: the active snapshot's two searches."""

from collections.abc import Sequence
from typing import Protocol

from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus


class EvidenceSearch(Protocol):
    @property
    def snapshot_id(self) -> str | None:
        """The active snapshot's id; None when there is none."""
        ...

    @property
    def rerank_model(self) -> str:
        """The name of the model whose 0-100 scores the threshold is cut on; empty when it is not known."""
        ...

    @property
    def source_versions(self) -> dict[str, str]:
        """The version of each source in the active snapshot."""
        ...

    @property
    def corpus(self) -> EvidenceCorpus:
        """What the index is built from; its `groups` are the named groups behind its techniques (G230)."""
        ...

    @property
    def has_records(self) -> bool:
        """False when the snapshot holds nothing to search."""
        ...

    def find_candidates(
        self, searches: Sequence[tuple[str, frozenset[str]]], limit: int
    ) -> list[list[IntelHit]]:
        """For each (search text, asset types) the `limit` best records of those asset types, by meaning and
        keywords; one list per search, in order. Raises when the embedding service is unavailable."""
        ...

    def score_candidates(self, query: str, hits: Sequence[IntelHit]) -> list[IntelHit]:
        """The hits with the reranker's 0-100 `score`, best first. Raises when the reranker is unavailable."""
        ...
