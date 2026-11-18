"""One library snapshot and its searches: a run does every lookup on one, so a plan never mixes two library
versions. Many queries share one embedding call, then rank in memory."""

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.ai import EmbeddingModel
from app.core.asset_types import asset_type_fits
from app.core.constants import Controls, EmbeddingCorpus, StrideCategory
from app.schemas import library as m
from app.search.indexes import HybridIndex


def describe_control(control: m.LibraryControl) -> str:
    """The text a control is searched by: v1's "ControlName: ControlDescription"."""
    return f"{control.name}: {control.description or ''}"


def linked_actors_by_type(library: m.ThreatLibrary) -> dict[int, tuple[m.LibraryActor, ...]]:
    """The actors linked to each type id: the type's own record, else its live threats'."""
    by_threat = {threat.type_id: threat.linked_actors for threat in library.threats}
    return by_threat | {threat_type.type_id: threat_type.linked_actors for threat_type in library.types}


def threat_types_of(library: m.ThreatLibrary) -> tuple[m.LibraryThreatType, ...]:
    """The types the live threats use, by id, each with the actors the library links to it."""
    linked = linked_actors_by_type(library)
    pairs = sorted({(threat.type_id, threat.type_name) for threat in library.threats})
    return tuple(m.LibraryThreatType(*pair, linked_actors=linked.get(pair[0], ())) for pair in pairs)


@dataclass(frozen=True, eq=False)
class LibrarySnapshot:
    """One library version's searches; never changed once built, so every thread shares it."""

    library: m.LoadedLibraries
    embeddings: EmbeddingModel
    indexes: dict[EmbeddingCorpus, HybridIndex]
    threat_types: tuple[m.LibraryThreatType, ...]

    def find_threats(
        self, queries: Sequence[tuple[str, StrideCategory]], top_k: int, allowed_types: Collection[str] | None = None
    ) -> list[list[tuple[m.LibraryThreat, float]]]:
        """Each query ranks only its category's threats, and with `allowed_types` fitting ones, before top-k."""
        threats = self.library.threat_library.threats
        fits = [allowed_types is None or asset_type_fits(threat.asset_type, allowed_types) for threat in threats]
        scopes = [
            np.array(
                [fit and category in threat.categories for threat, fit in zip(threats, fits, strict=True)], dtype=bool
            )
            for _, category in queries
        ]
        texts = [query for query, _ in queries]
        return self._search(EmbeddingCorpus.THREAT, threats, texts, top_k, scopes)

    def find_controls(
        self,
        queries: Sequence[str],
        top_k: int,
        allowed_types: Collection[str] | None = None,
        *,
        ai_controls: bool = True,
    ) -> list[list[tuple[m.LibraryControl, float]]]:
        """Ranks only `allowed_types` controls (no AssetType always fits); no AI domain unless `ai_controls`."""
        controls = self.library.control_library
        if allowed_types is None and ai_controls:
            return self._search(EmbeddingCorpus.CONTROL, controls, queries, top_k)
        # ponytail: the mask is rebuilt per call (1,288 comparisons); cache it per allowed set if it shows.
        mask = np.array(
            [
                (allowed_types is None or asset_type_fits(control.asset_type, allowed_types))
                and (ai_controls or control.domain != Controls.AI_DOMAIN)
                for control in controls
            ],
            dtype=bool,
        )
        return self._search(EmbeddingCorpus.CONTROL, controls, queries, top_k, [mask] * len(queries))

    def embed_control_queries(self, queries: Sequence[str]) -> None:
        """Embed control queries in one call ahead of their searches, which then read the stored vectors."""
        self.embeddings.embed_search_queries(list(queries), EmbeddingCorpus.CONTROL)

    def embed_gap_fill_queries(self, threats: Sequence[str], threat_types: Sequence[str]) -> None:
        """Embed gap-fill threats and types in one call each ahead of their per-category searches."""
        if threats:
            self.embeddings.embed_search_queries(list(threats), EmbeddingCorpus.THREAT)
            self.embeddings.embed_search_queries(list(threat_types), EmbeddingCorpus.THREAT_TYPE)

    def find_actors(
        self, queries: Sequence[str], top_k: int, allowed_ids: Sequence[Collection[int] | None] | None = None
    ) -> list[list[tuple[m.LibraryActor, float]]]:
        """`allowed_ids[i]`: the only actors query i ranks (its threat type's linked actors); None = all."""
        actors = self.library.threat_library.actors
        scopes = [
            None if ids is None else np.array([actor.actor_id in ids for actor in actors], dtype=bool)
            for ids in (allowed_ids or [None] * len(queries))
        ]
        # v1 ranks actors with hybrid_match: no similarity floor, every row in both legs.
        return self._search(
            EmbeddingCorpus.THREAT_ACTOR, actors, queries, top_k, scopes, vector_floor=None, leg_depth=len(actors)
        )

    def find_threat_types(
        self, queries: Sequence[str], top_k: int, category: StrideCategory | None = None
    ) -> list[list[tuple[m.LibraryThreatType, float]]]:
        """The types closest to each query; with `category`, only the types the library uses in it."""
        types = self.threat_types
        used = {threat.type_id for threat in self.library.threat_library.threats if category in threat.categories}
        scope = None if category is None else np.array([kind.type_id in used for kind in types], dtype=bool)
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
        index = self.indexes[corpus]
        vectors = self.embeddings.embed_search_queries(list(queries), corpus)
        return [
            [(rows[hit.position], hit.score) for hit in index.search(query, vector, top_k, scope, **options)]
            for query, vector, scope in zip(queries, vectors, scopes or [None] * len(queries), strict=True)
        ]
