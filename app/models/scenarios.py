"""Request and response models of the scenarios domain."""

from datetime import datetime
from typing import Annotated, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import (
    Generation,
    Limits,
    RunActionKind,
    RunActionOutcome,
    RunKind,
    SessionMessage,
    Status,
    Step,
)

#: A SQL Server INT id: a number above 2,147,483,647 is refused here (422) instead of failing inside the
#: stored procedure (500).
SqlId = Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)]


class StartRunRequest(BaseModel):
    """Body of POST /v1/sessions: one asset and the supporting systems to assess with it. An unknown field is
    refused (422), never ignored: a misspelt `sector_idd` must not start a run without its sector."""

    # populate_by_name: code and tests build the model with the attribute name; the wire name is the alias.
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    #: Where these fields sit in the request body, for a refusal that names one (a hand-written scenario
    #: nests them under manual_scenario).
    FIELD_PREFIX: ClassVar[str] = "body"

    asset_id: SqlId
    supporting_system_ids: list[SqlId] = Field(validation_alias="supporting_system_id")
    service_id: SqlId | None = None
    sector_id: SqlId | None = None
    subsector_id: SqlId | None = None

    @field_validator("supporting_system_ids", mode="before")
    @classmethod
    def accept_a_single_id(cls, value: object) -> object:
        return [value] if isinstance(value, int) else value

    @field_validator("supporting_system_ids")
    @classmethod
    def check_supporting_systems(cls, system_ids: list[int]) -> list[int]:
        """At least one, each once, and at most Generation.MAX_SUPPORTING_SYSTEMS (0 = no upper limit)."""
        if not system_ids:
            raise ValueError(SessionMessage.SYSTEMS_REQUIRED)
        if len(set(system_ids)) != len(system_ids):
            raise ValueError(SessionMessage.SYSTEMS_REPEATED)
        limit = Generation.MAX_SUPPORTING_SYSTEMS
        if limit and len(system_ids) > limit:
            raise ValueError(SessionMessage.TOO_MANY_SYSTEMS.format(limit=limit))
        return system_ids


class SessionStatus(BaseModel):
    """A run's state as stored, read in one projected read: the API's checks (review, next set, regenerate)
    read it, and app/models/run_board.py builds the status body every caller sees from it."""

    session_id: str
    entity_id: int
    asset_id: int
    status: Status
    step: Step | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    last_action: dict[str, Any] | None = None
    error: dict[str, str] | None = None  # {code, message} once the run has failed
    updated_at: datetime
    # What the status body adds (owner 2026-10-12): who and what, times, the last next set / regenerate.
    kind: RunKind = RunKind.GENERATED
    user_id: str | None = None
    asset_name: str | None = None
    attempts: int = 0  # the job's tries so far: 0 = its stage has not started yet
    timings: dict[str, float] = Field(default_factory=dict)  # threats_s, scenarios_s, controls_s
    last_next_set: dict[str, Any] | None = None  # {outcome, requested, delivered}
    last_regen: dict[str, Any] | None = None  # {outcome, requested, replaced}
    not_assessed: list[str] = Field(default_factory=list)  # categories the plan could not assess
    cancelled: dict[str, Any] | None = None  # {at, user_id, client_id}: its owner stopped it (G214)

    #: The session fields this body reads: never the plan's threats and paths, nor the context's facts.
    RECORD_FIELDS: ClassVar[dict[str, int]] = {
        "entity_id": 1,
        "asset_id": 1,
        "status": 1,
        "step": 1,
        "counts": 1,
        "last_action": 1,
        "job.error": 1,
        "job.attempts": 1,
        "updated_at": 1,
        "kind": 1,
        "user_id": 1,
        "context.asset.name": 1,
        "timings": 1,
        "last_next_set": 1,
        "last_regen": 1,
        "plan.not_assessed": 1,
        "cancelled": 1,
    }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "SessionStatus":
        counts, job = record.get("counts") or {}, record.get("job") or {}
        step = record.get("step")
        # Stored as threats or scenarios; reads `controls` while a done run still maps its controls ("card
        # first, controls later").
        if record["status"] == Status.DONE and counts.get("controls_waiting", 0) > 0:
            step = Step.CONTROLS
        return cls(
            session_id=record["_id"],
            entity_id=record["entity_id"],
            asset_id=record["asset_id"],
            status=record["status"],
            step=step,
            counts=counts,
            last_action=record.get("last_action"),
            error=job.get("error"),
            updated_at=record["updated_at"],
            kind=record.get("kind") or RunKind.GENERATED,
            user_id=record.get("user_id"),
            asset_name=((record.get("context") or {}).get("asset") or {}).get("name"),
            attempts=job.get("attempts") or 0,
            timings=record.get("timings") or {},
            last_next_set=record.get("last_next_set"),
            last_regen=record.get("last_regen"),
            not_assessed=(record.get("plan") or {}).get("not_assessed") or [],
            cancelled=record.get("cancelled"),
        )


def running_action(kind: RunActionKind, started_at: datetime) -> dict[str, Any]:
    """A run's `last_action` as an action starts: what the reviewer asked, still running, and when it
    started (the write job times its own work from it, never from a plan frozen days earlier)."""
    return {"kind": kind, "outcome": RunActionOutcome.RUNNING, "reason": None, "started_at": started_at}
