"""Search indexes: keyword (BM25) + meaning (vectors), merged by rank method and values.

Keywords find rare exact words (product names, acronyms) that vectors blur; vectors find the same idea in
other words ("data leakage" ~ "unauthorised disclosure") that keywords miss. Merging by RANK (reciprocal-rank
fusion) means the two score scales never need calibrating against each other. Everything is in memory (~1.8k
rows): one search is a dictionary walk plus one matrix multiply."""

import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence

import numpy as np

from app.core.constants import Search
from app.core.tracing import detail_top, ranked, record_detail, step_detail_enabled
from app.models.search import SearchHit

_NOT_A_WORD = re.compile(r"[^\w\s]")


def tokenize(text: str) -> list[str]:
    """Punctuation removed, case folded, split on whitespace (v1's tokenizer)."""
    return _NOT_A_WORD.sub(" ", text).casefold().split()


class KeywordIndex:
    """BM25 over a corpus tokenized once; one query is scored against every document."""

    def __init__(self, texts: Sequence[str]) -> None:
        documents = [tokenize(text) for text in texts]
        self._size = len(documents)
        lengths = np.array([len(document) for document in documents], dtype=np.float64)
        average_length = float(lengths.mean()) if self._size else 0.0
        # The part of BM25 that depends only on the document, worked out once.
        self._length_weight = (
            Search.BM25_K1 * (1.0 - Search.BM25_B + Search.BM25_B * lengths / average_length)
            if average_length
            else None
        )
        postings: dict[str, tuple[list[int], list[int]]] = {}
        for position, document in enumerate(documents):
            for token, count in Counter(document).items():
                ids, counts = postings.setdefault(token, ([], []))
                ids.append(position)
                counts.append(count)
        self._postings = {
            token: (np.array(ids), np.array(counts, dtype=np.float64))
            for token, (ids, counts) in postings.items()
        }
        self._idf = {
            token: math.log(1.0 + (self._size - len(ids) + 0.5) / (len(ids) + 0.5))
            for token, (ids, _) in postings.items()
        }

    def score(self, query: str) -> np.ndarray:
        scores = np.zeros(self._size)
        if self._length_weight is None:
            return scores
        for token in tokenize(query):  # a repeated query word counts again, as in v1
            posting = self._postings.get(token)
            if posting is None:
                continue
            ids, counts = posting
            scores[ids] += (
                self._idf[token] * counts * (Search.BM25_K1 + 1.0) / (counts + self._length_weight[ids])
            )
        return scores

    def word_weights(self, tokens: Iterable[str]) -> dict[str, float]:
        """Each of `tokens` the corpus holds, with its idf (the step trace's matched words)."""
        return {token: round(self._idf[token], 3) for token in tokens if token in self._idf}


def rank_best_first(scores: np.ndarray, depth: int) -> list[int]:
    """Positions best first, equal scores in position order; a zero score is left out, so a leg that knows
    nothing about a row never votes for it."""
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

    def __init__(
        self, texts: Sequence[str], vectors: np.ndarray, labels: Sequence[str] | None = None
    ) -> None:
        """`labels`: each row's name in the step trace (default: its position)."""
        self._keywords = KeywordIndex(texts)
        self._vectors = vectors  # L2-normalised rows, aligned with texts
        self._labels = (
            list(labels) if labels is not None else [str(position) for position in range(len(texts))]
        )
        self._by_exact_text: dict[str, list[int]] = {}
        for position, text in enumerate(texts):
            self._by_exact_text.setdefault(" ".join(tokenize(text)), []).append(position)

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
        """The top_k rows for one query. `allowed` (one bool per row) narrows the rows BEFORE each leg is cut
        to `leg_depth` (default top_k), so rows outside the scope never take a place. The vector leg keeps
        only rows at least `vector_floor` similar when any reach it (semantic_match_threshold), else
        the best anyway. A row whose text equals the query (after tokenizing) comes first with certainty:
        two different threats once had cosine 0.969."""
        keyword_scores = self._keywords.score(query)
        vector_scores = self._vectors @ query_vector if len(self._vectors) else np.zeros(0)
        if allowed is not None:
            keyword_scores = np.where(allowed, keyword_scores, 0.0)
            vector_scores = np.where(allowed, vector_scores, 0.0)
        if step_detail_enabled():
            self._trace_legs(query, keyword_scores, vector_scores, allowed, vector_floor)
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
        if step_detail_enabled():
            self._trace_merge(query, meaning, keywords, exact, hits)
        return hits[:top_k]

    def _top(self, scores: np.ndarray) -> dict[str, float]:
        """The step trace's best rows: {"<position> <label>": score}, positive scores only."""
        return ranked((f"{p} {self._labels[p]}", scores[p]) for p in rank_best_first(scores, detail_top()))

    def _trace_legs(
        self,
        query: str,
        keyword_scores: np.ndarray,
        cosines: np.ndarray,
        allowed: np.ndarray | None,
        vector_floor: float | None,
    ) -> None:
        """The keyword leg and the vector leg of one search, the cosines before the floor drops any."""
        item = query  # whole: one category's queries share a long first part
        in_scope = int(allowed.sum()) if allowed is not None else len(self._labels)
        tokens = tokenize(query)
        record_detail(
            "words → BM25",
            item,
            given={"query": query, "tokens": " ".join(tokens), "rows_in_scope": in_scope},
            produced={"matched_words": self._keywords.word_weights(tokens), "top": self._top(keyword_scores)},
        )
        at_floor = None if vector_floor is None else int((cosines >= vector_floor).sum())
        record_detail(
            "meaning → similarity",
            item,
            given={"rows_in_scope": in_scope, "floor": vector_floor},
            produced={
                "floor_applied": bool(at_floor),
                "rows_at_or_above_floor": at_floor,
                "top": self._top(cosines),
            },
        )

    def _trace_merge(
        self, query: str, meaning: list[int], keywords: list[int], exact: list[int], hits: list[SearchHit]
    ) -> None:
        """How the two legs' rankings merged: exact-text rows first (1.0), then by reciprocal rank."""
        shown = detail_top()
        record_detail(
            "merge by rank (RRF)",
            query,
            given={
                "keyword_ranking": " | ".join(self._labels[p] for p in keywords[:shown]) or "none",
                "meaning_ranking": " | ".join(self._labels[p] for p in meaning[:shown]) or "none",
                "k": Search.RRF_K,
            },
            produced={
                "exact_text_match": " | ".join(self._labels[p] for p in exact) or "none",
                "top": ranked((f"{hit.position} {self._labels[hit.position]}", hit.score) for hit in hits),
            },
        )
