"""Request and response bodies of the review calls: accept, reject, regenerate, next set
and promote to the library."""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.core.constants import PromotionOutcome, Review, ReviewMessage, TargetProblem


def _each_once(scenario_ids: list[str]) -> list[str]:
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError(ReviewMessage.IDS_REPEATED)
    return scenario_ids


#: 1 to Review.MAX_IDS_PER_CALL scenario ids, each once and bounded in length (422 otherwise).
ScenarioIds = Annotated[
    list[Annotated[str, Field(min_length=1, max_length=Review.MAX_ID_CHARS)]],
    Field(min_length=1, max_length=Review.MAX_IDS_PER_CALL),
    AfterValidator(_each_once),
]


class AcceptRequest(BaseModel):
    """An unknown field is refused (422), never ignored: a misspelt `replace_acepted` must not
    accept without replacing."""

    model_config = ConfigDict(extra="forbid")

    scenario_ids: ScenarioIds | Literal["all"]
    replace_accepted: bool = False


class ScenarioIdsRequest(BaseModel):
    """Body of reject and regenerate: scenario ids only (no "all")."""

    model_config = ConfigDict(extra="forbid")

    scenario_ids: ScenarioIds


class TargetSkipped(BaseModel):
    scenario_id: str
    reason: TargetProblem


class AcceptResult(BaseModel):
    accepted: list[str]  # accepted now or before (a repeat lists them again)
    replaced: list[str]  # other versions sent back to pending by replace_accepted
    skipped: list[TargetSkipped]
    controls_pending: list[str]  # accepted, their controls still being mapped


class RejectResult(BaseModel):
    rejected: list[str]  # rejected now or before
    skipped: list[TargetSkipped]


class RunActionStarted(BaseModel):
    """202: the job's new epoch (messages of older epochs are ignored)."""

    epoch: int


class PromotedThreat(BaseModel):
    threat: str
    threat_type: str
    threat_type_id: int | None  # None when nothing was written (curator_rejected)
    threat_catalogue_id: int | None
    outcome: PromotionOutcome


class PromotionResult(BaseModel):
    scenario_id: str
    results: list[PromotedThreat]
