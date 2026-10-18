"""The curator's API (#23 list pending threats, #24 decide them): request and answer shapes."""

from collections import Counter
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import Curation, CurationMessage, DecisionOutcome
from app.models.scenario.views import SqlId


class PendingThreat(BaseModel):
    catalogue_id: int
    threat: str
    type: str
    type_pending: bool = Field(
        description="The type is new too: it goes live with its first approved threat."
    )
    categories: list[str]
    source: str = Field(description="ai (promoted from a scenario) or manual (a hand-written scenario)")
    created_by: str | None = None
    created_at: datetime | None = None


class PendingThreatList(BaseModel):
    items: list[PendingThreat]
    total: int


class LibraryDecisions(BaseModel):
    """Body of #24. An unknown field is refused (a misspelt `aprove` must not decide nothing in silence)."""

    model_config = ConfigDict(extra="forbid")

    approve: list[SqlId] = Field(default_factory=list, examples=[[512]])
    reject: list[SqlId] = Field(default_factory=list, examples=[[513]])

    @model_validator(mode="after")
    def check_ids(self) -> Self:
        """1 to Curation.MAX_IDS_PER_CALL ids in all; each id once, in one list only."""
        ids = [*self.approve, *self.reject]
        if not ids:
            raise ValueError(CurationMessage.NO_IDS)
        if len(ids) > Curation.MAX_IDS_PER_CALL:
            raise ValueError(CurationMessage.TOO_MANY.format(limit=Curation.MAX_IDS_PER_CALL, count=len(ids)))
        if in_both := sorted(set(self.approve) & set(self.reject)):
            raise ValueError(CurationMessage.IN_BOTH.format(ids=in_both))
        if repeated := sorted(i for i, count in Counter(ids).items() if count > 1):
            raise ValueError(CurationMessage.REPEATED.format(ids=repeated))
        return self


class DecisionResult(BaseModel):
    catalogue_id: int
    outcome: DecisionOutcome


class LibraryDecisionResult(BaseModel):
    results: list[DecisionResult]
