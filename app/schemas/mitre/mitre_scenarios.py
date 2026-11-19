"""The MITRE run's shapes (ADR-010): the writer's answer for one attack path, which code then checks against
MITRE; the API shapes of POST /v1/mitre_create_session and GET /v1/mitre_sessions/{id} follow."""

from typing import Any, Literal

from pydantic import BaseModel, Field

#: A MITRE run's status as its routes show it (the POC's words).
MitreRunStatus = Literal["queued", "running", "complete", "failed", "cancelled"]


class RelevantGroup(BaseModel):
    """A MITRE group the writer chose from candidate_actors; code adds evidence_type and documented_techniques."""

    name: str = Field(min_length=1)
    mitre_id: str = Field(min_length=1)
    relevance: str = ""


class Technique(BaseModel):
    mitre_id: str
    name: str
    domain: Literal["enterprise", "ics"]
    stix_id: str


class Scenario(BaseModel):
    """What the writer returns for one path; code adds category, evidence, mitigations and prompt_version. The
    most groups a scenario names is MITRE_GROUPS_PER_SCENARIO, checked by code."""

    scenario_title: str = Field(min_length=1)
    threat_scenario_description: str = Field(min_length=1)
    threat_scenario: str = Field(min_length=1)
    risk_statement: str = Field(min_length=1)
    relevant_groups: list[RelevantGroup] = Field(min_length=1)
    attack_techniques: list[Technique] = Field(min_length=1)
    supporting_systems: list[str]
    assumptions: list[str]


class MitreSessionStarted(BaseModel):
    """POST /v1/mitre_create_session's and .../next-set's answer: the run and where to follow it."""

    session_id: str
    status: MitreRunStatus
    status_url: str


class MitreSessionStatus(BaseModel):
    """GET /v1/mitre_sessions/{session_id}: the run's stage, its scenarios so far, and the result once done.
    Each scenario is the MITRE scenario with the CII library controls mapped to it."""

    session_id: str
    status: MitreRunStatus
    stage: str | None
    elapsed_seconds: float
    written: int
    run_target: int
    scenarios_left: int
    partial_scenarios: list[dict[str, Any]] | None
    result: dict[str, Any] | None
    error: dict[str, str] | None
    status_url: str
    next_set_url: str
