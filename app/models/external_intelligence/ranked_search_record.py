"""A threat's search audit that also names the model whose scores were cut at the threshold."""

from dataclasses import dataclass
from typing import Any

from app.models.external_intelligence.evidence import EvidenceSearchRecord


@dataclass(frozen=True)
class RankedSearchRecord(EvidenceSearchRecord):
    """Rerank scores are 0-100 ranking scores whose scale differs per model, and the threshold is a
    per-environment cut-off: the audit row is only readable next to the model that gave the scores."""

    rerank_model: str = ""

    def as_doc(self) -> dict[str, Any]:
        return super().as_doc() | {"rerank_model": self.rerank_model}
