"""The MITRE run's shapes (ADR-010): the writer's answer for one attack path, which code then checks against
MITRE; the API shapes of POST /v1/mitre_create_session and GET /v1/mitre_sessions/{id} follow."""

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.scenarios import RunBoard

#: A MITRE run's status as its routes show it (the POC's words).
MitreRunStatus = Literal["queued", "running", "complete", "failed", "cancelled"]


class RelevantGroup(BaseModel):
    """A MITRE group the writer chose from candidate_actors; code adds evidence_type, documented_techniques and
    relevance, in MITRE's words only (any relevance the writer sends is replaced)."""

    name: str = Field(min_length=1)
    mitre_id: str = Field(min_length=1)
    relevance: str = ""


class Technique(BaseModel):
    mitre_id: str
    name: str
    domain: Literal["enterprise", "ics"]
    stix_id: str


class Scenario(BaseModel):
    """What the writer returns for one path; code adds category, evidence, mitigations, prompt_version and the
    attack.mitre.org page (url) of each technique and group, as MITRE's own reference gives it. The
    most groups a scenario names is MITRE_GROUPS_PER_SCENARIO, checked by code."""

    scenario_title: str = Field(min_length=1)
    threat_scenario_description: str = Field(min_length=1)
    threat_scenario: str = Field(min_length=1)
    risk_statement: str = Field(min_length=1)
    relevant_groups: list[RelevantGroup] = Field(min_length=1)
    attack_techniques: list[Technique] = Field(min_length=1)
    supporting_systems: list[str]
    assumptions: list[str]
    threat_type: str = ""  # copied from the library's threat_types; checked by code (none when it has none)


class MitreRunDetails(BaseModel):
    """The `mitre` block of GET /v1/mitre_sessions/{session_id}: the MITRE stage, its counts, the scenarios so
    far (`partial_scenarios`) and once complete `result` (`scenarios` with their CII library controls, `metadata`)."""

    stage: str | None
    elapsed_seconds: float
    written: int
    run_target: int
    scenarios_left: int
    partial_scenarios: list[dict[str, Any]] | None
    result: dict[str, Any] | None
    status_url: str
    next_set_url: str


class MitreSessionStatus(RunBoard):
    """GET /v1/mitre_sessions/{session_id}: the same board as GET /v1/sessions/{session_id}, plus `mitre`."""

    mitre: MitreRunDetails
