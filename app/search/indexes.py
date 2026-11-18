"""Hybrid search in memory: keyword (BM25) and meaning (vectors) legs merged by rank, so no score scale needs
calibrating against the other."""

import math
import re
from collections import Counter
from collections.abc import Sequence

import numpy as np

from app.core.constants import Search
from app.schemas.library import SearchHit

_NOT_A_WORD = re.compile(r"[^\w\s]")


def tokenize(text: str) -> list[str]:
    """Punctuation removed, case folded, split on whitespace (v1's tokenizer)."""
    return _NOT_A_WORD.sub(" ", text).casefold().split()


def rank_best_first(scores: np.ndarray, depth: int) -> list[int]:
    """Positions best first, ties in position order; a zero score is left out, so it never votes."""
    order = np.argsort(-scores, kind="stable")
    return [int(position) for position in order[scores[order] > 0][:depth]]


def fuse_by_rank(rankings: Sequence[list[int]]) -> list[tuple[int, float]]:
    """Reciprocal-rank fusion: each ranking gives a row 1 / (RRF_K + rank); best total first."""
    fused: dict[int, float] = {}
    for ranking in rankings:
        for rank, position in enumerate(ranking, start=1):
            fused[position] = fused.get(position, 0.0) + 1.0 / (Search.RRF_K + rank)
    return sorted(fused.items(), key=lambda item: (-item[1], item[0]))


class HybridIndex:
    """One searchable list of texts: a keyword leg and a vector leg, merged by rank."""

    def __init__(self, texts: Sequence[str], vectors: np.ndarray) -> None:
        self._vectors = vectors  # L2-normalised rows, aligned with texts
        self._by_exact_text: dict[str, list[int]] = {}
        for position, text in enumerate(texts):
            self._by_exact_text.setdefault(" ".join(tokenize(text)), []).append(position)
        documents = [tokenize(text) for text in texts]
        lengths = np.array([len(document) for document in documents], dtype=np.float64)
        average = float(lengths.mean()) if documents else 0.0
        # BM25's document-only part, worked out once; an all-empty corpus has no postings to weigh.
        self._length_weight = Search.BM25_K1 * (1.0 - Search.BM25_B + Search.BM25_B * lengths / (average or 1.0))
        postings: dict[str, tuple[list[int], list[int]]] = {}
        for position, document in enumerate(documents):
            for token, count in Counter(document).items():
                ids, counts = postings.setdefault(token, ([], []))
                ids.append(position)
                counts.append(count)
        self._postings = {
            token: (np.array(ids), np.array(counts, dtype=np.float64)) for token, (ids, counts) in postings.items()
        }
        self._idf = {
            token: math.log(1.0 + (len(documents) - len(ids) + 0.5) / (len(ids) + 0.5))
            for token, (ids, _) in postings.items()
        }

    def score_keywords(self, query: str) -> np.ndarray:
        """BM25 of one query against every text; a repeated query word counts again, as in v1."""
        scores = np.zeros(len(self._length_weight))
        for token in tokenize(query):
            if (posting := self._postings.get(token)) is not None:
                ids, counts = posting
                scores[ids] += self._idf[token] * counts * (Search.BM25_K1 + 1.0) / (counts + self._length_weight[ids])
        return scores

    def search(
        self,
        query: str,
        query_vector: np.ndarray,
        top_k: int,
        allowed: np.ndarray | None = None,
        *,
        vector_floor: float | None = Search.VECTOR_FLOOR,
        leg_depth: int | None = None,
    ) -> list[SearchHit]:
        """The top_k rows for one query; `allowed` scopes the rows before each leg's cut, an exact text first."""
        keyword_scores = self.score_keywords(query)
        vector_scores = self._vectors @ query_vector if len(self._vectors) else np.zeros(0)
        if allowed is not None:
            keyword_scores = np.where(allowed, keyword_scores, 0.0)
            vector_scores = np.where(allowed, vector_scores, 0.0)
        if vector_floor is not None and (vector_scores >= vector_floor).any():
            vector_scores = np.where(vector_scores >= vector_floor, vector_scores, 0.0)
        depth = leg_depth or top_k
        meaning, keywords = rank_best_first(vector_scores, depth), rank_best_first(keyword_scores, depth)
        fused = fuse_by_rank([meaning, keywords])
        exact = [
            position
            for position in self._by_exact_text.get(" ".join(tokenize(query)), [])
            if allowed is None or allowed[position]
        ]
        hits = [SearchHit(position, 1.0) for position in exact]
        hits += [SearchHit(position, score) for position, score in fused if position not in exact]
        return hits[:top_k]
