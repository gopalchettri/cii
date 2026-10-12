"""The planner's AI answer contracts (v1 prompts.py, as they are): each item of an answer is checked against
one of these before the server's own checks (the slots and aliases it handed out)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import AnswerProblem


class RelevanceVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slot: str
    relevant: bool
    systems: list[str]
    reason: str
    impact: Literal["HIGH", "MEDIUM", "LOW"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    needs: list[str] = Field(default_factory=list)  # what the threat needs that nothing recorded mentions


class SameScenarioGroup(BaseModel):
    """One group of the same-scenario check (G213): the scenarios, by slot, that are one attack with one harm
    through different systems, and why."""

    model_config = ConfigDict(extra="forbid")
    paths: list[str]
    reason: str


class BestThreatPick(BaseModel):
    """The best-threat pick (G209): a group's best threats by slot, best first, and why."""

    model_config = ConfigDict(extra="forbid")
    best: list[str]
    reason: str


class GapFillResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applies: bool
    reason: str
    threat_type: str | None = None
    threat: str | None = None
    attacker: str | None = None
    systems: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_a_proposal_is_whole(self) -> "GapFillResponse":
        if self.applies and not all(
            value and value.strip() for value in (self.threat_type, self.threat, self.attacker)
        ):
            raise ValueError(AnswerProblem.GAP_FILL_INCOMPLETE)
        return self
