"""Scenario writing: the brief the writer reads, the AI answer contracts, a draft,
its findings and the written scenario. Frozen, so the paths written at once share nothing mutable."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from app.core.constants import (
    FINDING_SEVERITIES,
    AnswerProblem,
    ErrorCode,
    FindingCode,
    FindingSeverity,
    PlanCheckStatus,
    Route,
    StrideCategory,
)
from app.models.library import ThreatLibrary


@dataclass(frozen=True)
class LiveLibrary:
    """What the library holds active now (it reloads within a minute of a curator's edit): a path whose
    threat or acting attacker was retired since the plan was made is not written."""

    threat_ids: frozenset[int]
    type_ids: frozenset[int]  # an AI-proposed threat stays writable while its library type is active
    actor_ids: frozenset[int]

    @classmethod
    def of(cls, library: ThreatLibrary) -> "LiveLibrary":
        return cls(
            frozenset(threat.catalogue_id for threat in library.threats),
            frozenset(threat.type_id for threat in library.threats),
            frozenset(actor.actor_id for actor in library.actors),
        )


@dataclass(frozen=True)
class WriterBrief:
    """Everything the writer and the plan check read about one path (approved prompts): names and recorded
    facts only, never a database id."""

    asset: dict[str, Any]  # name, type, description, sector ...: recorded facts only, cleaned for a prompt
    asset_name: str
    critical_service: str | None
    category: StrideCategory
    attacker: str  # the acting attacker (search ranking), always described as a type of attacker
    threat_type: str
    threat: str
    why_it_applies: str  # the relevance check's reason, systems by name
    systems: tuple[dict[str, Any], ...]  # the threat's systems, each its name plus recorded facts
    other_systems: tuple[str, ...]  # the run's other systems, by name: never part of this scenario
    other_scenarios: tuple[str, ...] = ()  # the statements of the path's other versions (regenerate only)

    @property
    def entry_point_options(self) -> tuple[str, ...]:
        """The threat's systems; none = the attack reaches the asset itself."""
        return tuple(system["name"] for system in self.systems)


@dataclass(frozen=True)
class ScenarioDraft:
    title: str
    statement: str
    risk: str
    assumptions: tuple[str, ...]
    entry_point: str  # one of the brief's entry_point_options; "" = the asset itself

    def to_answer(self) -> dict[str, Any]:
        """The draft as the writer's answer reads: the assistant turn the one rewrite follows."""
        return {
            "scenario_title": self.title,
            "scenario_statement": self.statement,
            "risk_statement": self.risk,
            "assumptions": list(self.assumptions),
            "entry_point": self.entry_point,
        }


@dataclass(frozen=True)
class Finding:
    code: FindingCode
    message: str

    @property
    def severity(self) -> FindingSeverity:
        return FINDING_SEVERITIES[self.code]

    def to_record(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity, "message": self.message}


@dataclass(frozen=True)
class PlanCheck:
    status: PlanCheckStatus
    problems: tuple[str, ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {"status": self.status, "problems": list(self.problems)}


@dataclass(frozen=True)
class WrittenScenario:
    """The draft kept (the original or its one rewrite) with what was found in it."""

    draft: ScenarioDraft
    findings: tuple[Finding, ...]  # the code rules' findings and the plan check's notes
    plan_check: PlanCheck
    route: Route
    rewritten: bool  # the rewrite was kept
    title_qualifier: str = ""  # the threat's name as a title carries it, to tell two same titles apart

    @property
    def blocked(self) -> bool:
        return any(finding.severity == FindingSeverity.BLOCKER for finding in self.findings)


@dataclass(frozen=True)
class PathFailure:
    """Why one path got a failure card instead of a scenario."""

    code: ErrorCode
    message: str
    final: bool = False  # no retry can help (the frozen plan lacks a fact): the path is abandoned at once


class ScenarioAnswer(BaseModel):
    """The writer's answer (approved prompts). Whether entry_point is one of the brief's options is checked
    by the writer, which knows them."""

    scenario_title: str
    scenario_statement: str
    risk_statement: str
    assumptions: list[str]
    entry_point: str

    @field_validator("scenario_title", "scenario_statement", "risk_statement")
    @classmethod
    def check_the_text_is_given(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(AnswerProblem.TEXT_REQUIRED)
        return value


class PlanCheckAnswer(BaseModel):
    consistent: bool
    problems: list[str]

    @model_validator(mode="after")
    def check_an_inconsistency_says_why(self) -> "PlanCheckAnswer":
        if not self.consistent and not any(problem.strip() for problem in self.problems):
            raise ValueError(AnswerProblem.PROBLEMS_REQUIRED)
        return self
