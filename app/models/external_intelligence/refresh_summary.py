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
    """What the refresh did to one source."""

    source: IntelSource
    result: RefreshResult
    counts: SaveCounts = SaveCounts(0, 0, 0)  # frozen, so one default is shared safely
    retired: int = 0
    error: str | None = None  # people-readable: a message text or an exception type

    def as_doc(self) -> dict[str, Any]:
        """The source's outcome as the job record shows it."""
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
    """What one refresh did to every source it looked at."""

    sources: tuple[SourceRefresh, ...]
    index_rebuilt: bool  # the evidence index was rebuilt after the refresh
    index_error: dict[str, str] | None = None  # why it was not: {code, message} and an AI outage's reason

    @property
    def failed(self) -> tuple[IntelSource, ...]:
        """The sources whose refresh failed."""
        return tuple(item.source for item in self.sources if item.result == RefreshResult.FAILED)

    @property
    def new_versions(self) -> int:
        """How many new record versions every source stored together."""
        return sum(item.counts.new_versions for item in self.sources)

    def as_doc(self) -> dict[str, Any]:
        """The refresh as the job record shows it."""
        return {"sources": [item.as_doc() for item in self.sources], "index_rebuilt": self.index_rebuilt}
