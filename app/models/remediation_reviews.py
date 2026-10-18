"""Request bodies of a plan's review and regenerate calls (`POST .../treatment-plan/review` and
`.../treatment-plan/regenerate`): an unknown field is refused (422), never ignored."""

from typing import Annotated, Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import Decision, Remediation
from app.models.remediation_requests import Blank

_Comment = Annotated[Annotated[str, Field(max_length=Remediation.COMMENT_MAX_CHARS)] | None, Blank]


class DecisionRequest(BaseModel):
    """A decision's version (default: the newest done one) and comment."""

    model_config = ConfigDict(extra="forbid")

    version: Annotated[int, Field(gt=0)] | None = Field(
        None, description="The version to decide; leave it out for the newest finished one."
    )
    comment: _Comment = Field(None, description="Why (stored with the decision; up to 2,000 characters).")


class ReviewRequest(DecisionRequest):
    """v1's one review call (owner, 2026-10-15): accept or reject a version."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"decision": "accepted"}, {"decision": "rejected", "version": 2}]},
    )

    decision: Literal[Decision.ACCEPTED, Decision.REJECTED] = Field(
        description="accepted or rejected. Accepting a version makes it THE plan: an earlier accepted "
        "version goes back to pending."
    )


class RegenerateRequest(BaseModel):
    """Nothing: the latest version's register data is reused; any field → 422."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{}]})


class DecisionChange(NamedTuple):
    """One decision on a remediation plan version as plain values; the store writes it fenced."""

    version: int
    decision: Decision
    #: decided_by, decided_by_client, decided_at and review_comment of the decided version
    stamp: dict[str, Any]
    #: the version accepted before, put back to pending with no stale stamp (None: none)
    back_to_pending: int | None
    accepted_version: int | None
    #: the record's decision after this change
    record_decision: Decision
