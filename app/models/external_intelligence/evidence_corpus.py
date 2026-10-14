"""What the evidence search is built from: the searchable records of the approved sources, each vulnerability
with its EPSS score and NVD detail joined in."""

from dataclasses import dataclass, field
from functools import cached_property

from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.known_groups import GroupMap


@dataclass(frozen=True)
class EvidenceCorpus:
    hits: tuple[IntelHit, ...]  # in a fixed (source, id) order, so an unchanged corpus gives the same rows
    search_texts: tuple[
        str, ...
    ]  # one per hit: its text without indicators of compromise (never embedded raw)
    checksum: str  # over every current record, whatever the order they were read in
    source_versions: dict[str, str] = field(default_factory=dict)
    scores_joined: int = 0
    scores_unmatched: int = 0
    details_joined: int = 0
    details_unmatched: int = 0

    @property
    def rows(self) -> tuple[tuple[str, str, str], ...]:
        """What the vectors were made from: when two corpora have the same rows, they share their index."""
        return tuple(
            (f"{hit.source}/{hit.external_id}", hit.title, text)
            for hit, text in zip(self.hits, self.search_texts, strict=True)
        )

    @cached_property
    def groups(self) -> GroupMap:
        """G230: the named groups behind its techniques, worked out on first use and kept (a corpus never
        changes; two threads asking at once work out the same map twice)."""
        return GroupMap.from_hits(self.hits)

    def counts(self) -> dict[str, int]:
        return {
            "indexed": len(self.hits),
            "scores_joined": self.scores_joined,
            "scores_unmatched": self.scores_unmatched,
            "details_joined": self.details_joined,
            "details_unmatched": self.details_unmatched,
        }
