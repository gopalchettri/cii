"""One immutable evidence index (the corpus and its keyword + vector index) shared by every thread, and its
two searches: candidates of the asset's IT / OT types from approved sources, then the reranker's 0-100
scores. Indicators of compromise never reach a model."""

import re
from collections.abc import Collection, Sequence
from dataclasses import replace

import numpy as np

from app.ai import EmbeddingModel, RerankModel
from app.core.clock import utc_now
from app.core.constants import (
    EMBEDDING_SOURCE_TABLE,
    AiOutage,
    EmbeddingCorpus,
    IntelKind,
    IntelMessage,
    IntelSource,
)
from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.search.indexes import HybridIndex

_INDICATOR = re.compile(
    "|".join(
        [
            r"\b(?:https?|hxxps?|ftp)://\S+",
            r"\bwww\.\S+",
            r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            r"\b[a-f0-9]{32,128}\b",
        ]
    ),
    re.IGNORECASE,
)
_SPACES = re.compile(r"\s+")
_LABELS_TAIL = re.compile(r"\s*(?:Tactics|Platforms|Mitigations): .*$", re.DOTALL)


def remove_indicators(text: str) -> str:
    """The text without indicators, spaces collapsed."""
    return _SPACES.sub(" ", _INDICATOR.sub(" ", text)).strip()


def scoring_text(hit: IntelHit, titles: dict[tuple[IntelSource, str], str]) -> str:
    """What the reranker reads of a record: a technique's name and description only, a sub-technique's name
    after its parent's ("Unauthorized Message: Command Message" is not "Block Operational Technology Message:
    Command Message"). Its id and its Tactics / Platforms / Mitigations lists let records that share only
    those words outscore the right one (36-threat benchmark, 2026-10-19); other kinds are read whole.
    `titles`: each technique's title by (source, id)."""
    text = remove_indicators(hit.text)
    if hit.kind != IntelKind.TECHNIQUE:
        return text
    text = _LABELS_TAIL.sub("", text.removeprefix(f"{hit.external_id} "))
    parent = titles.get((hit.source, hit.external_id.partition(".")[0])) if "." in hit.external_id else None
    return f"{parent}: {text}" if parent else text


class EvidenceIndexRefused(Exception):
    """No current record, or rows and vectors out of step."""

    def __init__(self, message: IntelMessage, **facts: object) -> None:
        super().__init__(message.format(**facts))
        self.no_data = message is IntelMessage.SNAPSHOT_EMPTY  # nothing imported yet (or all of it gone)


_EMPTY = EvidenceCorpus((), (), "")
#: The snapshot id of a corpus that settled empty: searched, and nothing found.
EMPTY_SNAPSHOT_ID = "empty"


class EvidenceIndex:
    """Built once, never changed afterwards."""

    def __init__(
        self,
        corpus: EvidenceCorpus,
        hybrid: HybridIndex | None,
        embeddings: EmbeddingModel,
        rerank: RerankModel,
        rerank_model: str = "",
        *,
        settled: bool = True,
        outage: AiOutage | None = None,
    ) -> None:
        self._corpus = corpus
        self._settled = settled  # False only for the placeholder served until the first build ends
        self.outage = outage  # the placeholder's: the AI outage that stopped the first build
        self._hybrid = hybrid
        self._embeddings = embeddings
        self._rerank = rerank
        self.rerank_model = rerank_model  # the model whose 0-100 scores the threshold is cut on
        self.built_at = utc_now()
        self._asset_types = np.array([hit.asset_type for hit in corpus.hits])
        self._sources = [frozenset({hit.source, *hit.joined}) for hit in corpus.hits]
        self._titles = {
            (h.source, h.external_id): h.title for h in corpus.hits if h.kind == IntelKind.TECHNIQUE
        }

    def reuse_for(self, corpus: EvidenceCorpus) -> "EvidenceIndex | None":
        """A new index over `corpus` that shares this one's vectors, when the corpus differs only in what the
        vectors do not depend on (an EPSS value moved, say): no read, no AI call. None otherwise."""
        if self._hybrid is None or self._corpus.rows != corpus.rows:
            return None
        return EvidenceIndex(corpus, self._hybrid, self._embeddings, self._rerank, self.rerank_model)

    @property
    def snapshot_id(self) -> str | None:
        """The same for the same corpus in every process, so a stored audit names one snapshot. A corpus that
        settled empty gives EMPTY_SNAPSHOT_ID; the placeholder before the first build gives None."""
        if self._corpus.hits:
            return self._corpus.checksum[:24]
        return EMPTY_SNAPSHOT_ID if self._settled else None

    @property
    def has_records(self) -> bool:
        """False when the corpus holds nothing to search."""
        return bool(self._corpus.hits)

    @property
    def source_versions(self) -> dict[str, str]:
        """Each source's newest version in the corpus."""
        return dict(self._corpus.source_versions)

    @property
    def corpus(self) -> EvidenceCorpus:
        """The corpus the index was built from."""
        return self._corpus

    def find_candidates(
        self, searches: Sequence[tuple[str, frozenset[str]]], limit: int, approved: Collection[IntelSource]
    ) -> list[list[IntelHit]]:
        """Per (search text, asset types): the `limit` nearest records of those types whose sources (its own
        and those joined into it) are all `approved`, both filtered before the top-k cut, not yet scored; one
        embedding call for all, none for a search nothing can answer."""
        found: list[list[IntelHit]] = [[] for _ in searches]
        if self._hybrid is None or limit < 1:
            return found
        queries = [remove_indicators(text) for text, _ in searches]
        approved_sources = frozenset(approved)
        from_approved = np.array([sources <= approved_sources for sources in self._sources], dtype=bool)
        allowed = [np.isin(self._asset_types, list(types)) & from_approved for _, types in searches]
        asked = [i for i, fits in enumerate(allowed) if fits.any() and queries[i]]
        if not asked:
            return found
        vectors = self._embeddings.embed_search_queries(
            [queries[i] for i in asked], EmbeddingCorpus.EXTERNAL_INTELLIGENCE
        )
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
            remove_indicators(query), [scoring_text(hit, self._titles) for hit in hits]
        )
        scored = [replace(hit, score=score) for hit, score in zip(hits, scores, strict=True)]
        return sorted(scored, key=lambda hit: (-hit.score, hit.external_id))


def after_failed_build(index: EvidenceIndex, outage: AiOutage | None) -> EvidenceIndex:
    """The index to serve once a build failed: `index`, or, while it is the placeholder (no first build yet),
    a placeholder naming the AI outage that stopped the build (None: not the AI's)."""
    if index.snapshot_id is not None:
        return index
    return empty_index(index._embeddings, index._rerank, index.rerank_model, outage=outage)


def empty_index(
    embeddings: EmbeddingModel,
    rerank: RerankModel,
    rerank_model: str = "",
    *,
    settled: bool = False,
    outage: AiOutage | None = None,
) -> EvidenceIndex:
    """An index with nothing to search. Settled: the corpus is empty, so every search finds no evidence. Else
    the placeholder until the first build ends: it names no snapshot, so a write waits as for an outage (the
    AI outage that stopped the first build, when it was one)."""
    return EvidenceIndex(_EMPTY, None, embeddings, rerank, rerank_model, settled=settled, outage=outage)


def build_index(
    corpus: EvidenceCorpus, embeddings: EmbeddingModel, rerank: RerankModel, rerank_model: str = ""
) -> EvidenceIndex:
    """The index of `corpus`, its texts embedded through the vector cache (each batch stored as it arrives,
    so a build that stops half way resumes from what was stored)."""
    table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.EXTERNAL_INTELLIGENCE]
    sources = [
        {"table": table, "id": f"{hit.source}/{hit.external_id}", "label": hit.title} for hit in corpus.hits
    ]
    texts = list(corpus.search_texts)
    vectors = embeddings.embed_library_texts(EmbeddingCorpus.EXTERNAL_INTELLIGENCE, texts, sources)
    if len(vectors) != len(texts):
        raise EvidenceIndexRefused(IntelMessage.SNAPSHOT_INCONSISTENT, rows=len(texts), vectors=len(vectors))
    hybrid = HybridIndex(texts, vectors)
    return EvidenceIndex(corpus, hybrid, embeddings, rerank, rerank_model)
