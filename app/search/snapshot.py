"""One library snapshot and its searches. A run takes one snapshot and does every lookup on it, so a library
edit made while it plans never mixes two library versions into one plan (v1 loaded its library once per
round).

Many queries at once: one embedding call for all of them (each query's vector is stored in MongoDB for a
while), then in-memory ranking. No database or AI call otherwise."""

from collections.abc import Collection, Sequence
from typing import Any

import numpy as np

from app.ai import EmbeddingModel
from app.core.constants import Controls, EmbeddingCorpus, StrideCategory
from app.core.tracing import traced
from app.models.library import LibraryActor, LibraryControl, LibraryThreat, LibraryThreatType, LoadedLibraries
from app.search.indexes import HybridIndex


def threat_types_of(threats: Sequence[LibraryThreat]) -> tuple[LibraryThreatType, ...]:
    """The types the live threats use, by id."""
    return tuple(LibraryThreatType(*pair) for pair in sorted({(t.type_id, t.type_name) for t in threats}))


class LibrarySnapshot:
    """Built by app/search/service.py for each library version; never changed after that, so it is shared by
    every thread."""

    def __init__(
        self,
        library: LoadedLibraries,
        embeddings: EmbeddingModel,
        indexes: dict[EmbeddingCorpus, HybridIndex],
        threat_types: tuple[LibraryThreatType, ...],
    ) -> None:
        self.library = library
        self.threat_types = threat_types
        self._embeddings = embeddings
        self._indexes = indexes
        threats = library.threat_library.threats
        self._threats_in_category = {
            category: np.array([category in threat.categories for threat in threats], dtype=bool)
            for category in StrideCategory
        }
        used = {
            category: {t.type_id for t in threats if category in t.categories} for category in StrideCategory
        }
        self._types_in_category = {
            category: np.array(
                [threat_type.type_id in used[category] for threat_type in threat_types], dtype=bool
            )
            for category in StrideCategory
        }

    @traced("search.find_threats")
    def find_threats(
        self,
        queries: Sequence[tuple[str, StrideCategory]],
        top_k: int,
        allowed_types: Collection[str] | None = None,
    ) -> list[list[tuple[LibraryThreat, float]]]:
        """Each query ranks only its own category's threats, before the top-k cut; with `allowed_types`, only
        those whose AssetType fits too (G211), as for controls. None = every threat of the category."""
        threats = self.library.threat_library.threats
        fits = (
            np.ones(len(threats), dtype=bool)
            if allowed_types is None
            else np.array([threat.fits(allowed_types) for threat in threats], dtype=bool)
        )
        scopes = [self._threats_in_category[category] & fits for _, category in queries]
        texts = [query for query, _ in queries]
        return self._search(EmbeddingCorpus.THREAT, threats, texts, top_k, scopes)

    @traced("search.find_controls")
    def find_controls(
        self,
        queries: Sequence[str],
        top_k: int,
        allowed_types: Collection[str] | None = None,
        *,
        ai_controls: bool = True,
    ) -> list[list[tuple[LibraryControl, float]]]:
        """`allowed_types`: the only AssetType values ranked (upper case), before the top-k cut, as categories
        are for threats; a control with no AssetType always takes part. None = every control. `ai_controls`
        False: no control of Controls.AI_DOMAIN takes part (G243: a card whose threat is not about AI)."""
        controls = self.library.control_library
        if allowed_types is None and ai_controls:
            return self._search(EmbeddingCorpus.CONTROL, controls, queries, top_k)
        # ponytail: the mask is rebuilt per call (1,288 comparisons); cache it per allowed set if it shows.
        mask = np.array(
            [
                (allowed_types is None or control.fits(allowed_types))
                and (ai_controls or control.domain != Controls.AI_DOMAIN)
                for control in controls
            ],
            dtype=bool,
        )
        return self._search(EmbeddingCorpus.CONTROL, controls, queries, top_k, [mask] * len(queries))

    @traced("search.find_actors")
    def find_actors(
        self, queries: Sequence[str], top_k: int, allowed_ids: Sequence[Collection[int] | None] | None = None
    ) -> list[list[tuple[LibraryActor, float]]]:
        """`allowed_ids[i]`: the only actors query i ranks (its threat type's linked actors); None = all."""
        actors = self.library.threat_library.actors
        scopes = [
            None if ids is None else np.array([actor.actor_id in ids for actor in actors], dtype=bool)
            for ids in (allowed_ids or [None] * len(queries))
        ]
        # v1 ranks actors with hybrid_match: no similarity floor, every row in both legs.
        return self._search(
            EmbeddingCorpus.THREAT_ACTOR,
            actors,
            queries,
            top_k,
            scopes,
            vector_floor=None,
            leg_depth=len(actors),
        )

    @traced("search.find_threat_types")
    def find_threat_types(
        self, queries: Sequence[str], top_k: int, category: StrideCategory | None = None
    ) -> list[list[tuple[LibraryThreatType, float]]]:
        """The threat types closest to each query (a gap-fill proposal's type, BR-THR-03), as actors; with a
        `category`, only the types the library uses in it (v1 Library.types_for)."""
        scope = None if category is None else self._types_in_category[category]
        types = self.threat_types
        return self._search(
            EmbeddingCorpus.THREAT_TYPE,
            types,
            queries,
            top_k,
            [scope] * len(queries),
            vector_floor=None,
            leg_depth=len(types),
        )

    def _search[Row](  # noqa: PLR0913 — the corpus, its rows, the queries and how to rank them
        self,
        corpus: EmbeddingCorpus,
        rows: Sequence[Row],
        queries: Sequence[str],
        top_k: int,
        scopes: Sequence[np.ndarray | None] | None = None,
        **options: Any,
    ) -> list[list[tuple[Row, float]]]:
        if not queries:  # nothing to embed: no MongoDB read, no AI call
            return []
        index = self._indexes[corpus]
        vectors = self._embeddings.embed_search_queries(list(queries))
        return [
            [(rows[hit.position], hit.score) for hit in index.search(query, vector, top_k, scope, **options)]
            for query, vector, scope in zip(queries, vectors, scopes or [None] * len(queries), strict=True)
        ]
