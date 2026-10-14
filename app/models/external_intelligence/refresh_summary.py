"""What a refresh of the sources did, for the job record and the caller."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.constants import IntelSource
from app.models.external_intelligence.intel_record import SaveCounts


class RefreshResult(StrEnum):
    REFRESHED = "refreshed"  # records were stored
    UNCHANGED = "unchanged"  # the source had nothing new
    FAILED = "failed"
    SKIPPED = "skipped"  # not due, revoked, being refreshed by another worker, or nothing to ask for yet
    CLAIM_LOST = "claim_lost"  # the claim was taken over or the source revoked mid-run: the run stopped


@dataclass(frozen=True)
class SourceRefresh:
    source: IntelSource
    result: RefreshResult
    counts: SaveCounts = SaveCounts(0, 0, 0)  # noqa: RUF009 - frozen, shared safely
    retired: int = 0
    error: str | None = None  # people-readable: a message text or an exception type

    def as_doc(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "result": self.result,
            "new_versions": self.counts.new_versions,
            "unchanged": self.counts.unchanged,
            "quarantined": self.counts.quarantined,
            "retired": self.retired,
            "error": self.error,
        }


@dataclass(frozen=True)
class RefreshSummary:
    sources: tuple[SourceRefresh, ...]
    index_rebuilt: bool  # the evidence index was rebuilt after the refresh

    @property
    def failed(self) -> tuple[IntelSource, ...]:
        return tuple(item.source for item in self.sources if item.result == RefreshResult.FAILED)

    @property
    def new_versions(self) -> int:
        return sum(item.counts.new_versions for item in self.sources)

    def as_doc(self) -> dict[str, Any]:
        return {"sources": [item.as_doc() for item in self.sources], "index_rebuilt": self.index_rebuilt}
