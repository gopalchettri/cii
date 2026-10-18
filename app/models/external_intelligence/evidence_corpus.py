"""What the evidence search is built from (the approved sources' searchable records, EPSS scores and NVD
details joined in), and the stored description of a built index."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.constants import IntelLimits
from app.models.external_intelligence.evidence import IntelHit


@dataclass(frozen=True)
class EvidenceCorpus:
    """The searchable records and their search texts, with the checksum and join counts."""

    hits: tuple[IntelHit, ...]  # in a fixed (source, id) order, so an unchanged corpus gives the same rows
    search_texts: tuple[str, ...]  # one per hit: its text without indicators of compromise
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

    def counts(self) -> dict[str, int]:
        """How many records were indexed and how many scores and details found their vulnerability."""
        return {
            "indexed": len(self.hits),
            "scores_joined": self.scores_joined,
            "scores_unmatched": self.scores_unmatched,
            "details_joined": self.details_joined,
            "details_unmatched": self.details_unmatched,
        }


@dataclass(frozen=True)
class SnapshotDescription:
    """The stored description of a built evidence index (what the snapshot pointer carries)."""

    snapshot_id: str
    built_at: datetime
    source_versions: dict[str, str]
    counts: dict[str, int]
    checksum: str
    embedding_model: str  # a different model is a different index: it is rebuilt, never mixed
    rerank_model: str

    def as_doc(self) -> dict[str, Any]:
        """The description as the snapshot pointer store writes it."""
        return {
            "snapshot_id": self.snapshot_id,
            "built_at": self.built_at,
            "source_versions": self.source_versions,
            "counts": self.counts,
            "checksum": self.checksum,
            "parser_version": IntelLimits.PARSER_VERSION,
            "embedding_model": self.embedding_model,
            "rerank_model": self.rerank_model,
        }
