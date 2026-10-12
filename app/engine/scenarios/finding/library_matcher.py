"""An AI proposal matched back to the library: the hybrid search's top hits, scored
0-100 against the proposal by the reranker. The caller compares the best score with
THREAT_SIMILARITY_THRESHOLD (the threat similarity threshold setting)."""

from collections.abc import Collection, Sequence

from app.ai import RerankModel
from app.core.constants import LibraryRowKind, PromotionOutcome, StrideCategory, ThreatFinding
from app.core.tracing import traced
from app.engine.shared.names import name_match_key, threat_name_without_code
from app.models.library import LibraryThreat, LibraryThreatType, ThreatLibrary
from app.search.snapshot import LibrarySnapshot

_CANDIDATES = ThreatFinding.LIBRARY_MATCH_CANDIDATES
#: What the library holds under a name: the outcome, the type id and the threat id (None when rejected).
NamedRecord = tuple[PromotionOutcome, int | None, int | None]


def library_threats_named(library: ThreatLibrary, name: str) -> NamedRecord | None:
    """What the library already holds under a threat name, compared as v1 does (normalised, library codes
    left out): a live threat, then one pending a curator (both `existing`), then a wording a curator
    rejected (never proposed again); None for a new name. In memory: only a new name reaches SQL Server."""
    key = name_match_key(threat_name_without_code(name))

    def same(other: str) -> bool:
        return name_match_key(threat_name_without_code(other)) == key

    for threat in library.threats:
        if same(threat.name):
            return PromotionOutcome.EXISTING, threat.type_id, threat.catalogue_id
    for row in library.pending:
        if row.kind == LibraryRowKind.THREAT and same(row.name):
            return PromotionOutcome.EXISTING, row.type_id, row.row_id
    if any(same(row.name) for row in library.curator_rejected):
        return PromotionOutcome.CURATOR_REJECTED, None, None
    return None


class LibraryMatcher:
    def __init__(
        self, snapshot: LibrarySnapshot, rerank: RerankModel, allowed_types: Collection[str] | None = None
    ) -> None:
        """`allowed_types`: the AssetType values the run's threats fit (G211); None = every threat."""
        self._snapshot = snapshot
        self._rerank = rerank
        self._allowed_types = allowed_types

    def closest_threat(self, text: str, category: StrideCategory) -> tuple[LibraryThreat, float] | None:
        """The category's library threat closest to `text`, compared by name (no library code): only threats
        of a type this run judged, so a proposal is never "a repeat" of a threat that was never judged."""
        (hits,) = self._snapshot.find_threats(
            [(text, category)], top_k=_CANDIDATES, allowed_types=self._allowed_types
        )
        return self._best(text, [(threat, threat_name_without_code(threat.name)) for threat, _ in hits])

    def closest_type(self, text: str, category: StrideCategory) -> tuple[LibraryThreatType, float] | None:
        """The closest of the threat types the library uses in `category`."""
        (hits,) = self._snapshot.find_threat_types([text], top_k=_CANDIDATES, category=category)
        return self._best(text, [(threat_type, threat_type.name) for threat_type, _ in hits])

    @traced("threats.library_match")
    def _best[Row](self, text: str, candidates: Sequence[tuple[Row, str]]) -> tuple[Row, float] | None:
        """The highest-scoring candidate (the first of equals, in search order), with its score."""
        if not candidates:
            return None
        scores = self._rerank.score_relevance(text, [label for _, label in candidates])
        best = max(range(len(candidates)), key=scores.__getitem__)
        return candidates[best][0], scores[best]
