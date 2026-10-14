"""The stored description of a built evidence index (what the snapshot pointer carries)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.constants import IntelLimits


@dataclass(frozen=True)
class SnapshotDescription:
    snapshot_id: str
    built_at: datetime
    source_versions: dict[str, str]
    counts: dict[str, int]
    checksum: str
    embedding_model: str  # a different model is a different index: it is rebuilt, never mixed
    rerank_model: str

    def as_doc(self) -> dict[str, Any]:
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
