"""Scenario writing: the brief the writer reads, the AI answer contracts, a draft,
its findings and the written scenario. Frozen, so the paths written at once share nothing mutable."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from app.core.constants import (
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    STORY_FINDING_SEVERITIES,
    AnswerProblem,
    ErrorCode,
    EvidenceMode,
    FindingCode,
    FindingSeverity,
    PlanCheckStatus,
    Route,
    StoryFindingCode,
    StrideCategory,
    WriterStyle,
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
class BriefSystem:
    """One supporting system of the run as a scenario's brief lists it (G216): applicable when the scenario's
    route goes through it. Its id never reaches the prompt (brief_text writes the name and the flag only)."""

    id: int
    name: str
    applicable: bool


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
    # How this scenario is written (the batch's decision). The evidence is read only by an evidence story: the
    # threat's evidence docs (Evidence.as_doc) in the plan's order, entry n of the markers [n] is
    # evidence[n - 1].
    style: WriterStyle = WriterStyle.ORIGINAL
    evidence: tuple[dict[str, Any], ...] = ()
    # Every supporting system of the run, in its order, applicable or not: the writer gives each a reason.
    supporting_systems: tuple[BriefSystem, ...] = ()

    @property
    def evidence_mode(self) -> EvidenceMode:
        return EvidenceMode.SOURCE_DOCUMENTED if self.evidence else EvidenceMode.INFERRED

    @property
    def entry_point_options(self) -> tuple[str, ...]:
        """The threat's systems; none = the attack reaches the asset itself."""
        return tuple(system["name"] for system in self.systems)


@dataclass(frozen=True)
class Anatomy:
    """A scenario's parts as its writer states them (G229, owner 2026-10-13: "An independent reviewer must be
    able to identify the target, attack mechanism, relevant preconditions, and potential consequence")."""

    target: str
    entry_point: str
    preconditions: tuple[str, ...]  # () when none is needed
    mechanism: str
    consequence: str

    def as_doc(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "entry_point": self.entry_point,
            "preconditions": list(self.preconditions),
            "mechanism": self.mechanism,
            "consequence": self.consequence,
        }


@dataclass(frozen=True)
class ScenarioDraft:
    title: str
    statement: str
    risk: str
    assumptions: tuple[str, ...]
    entry_point: str  # one of the brief's entry_point_options; "" = the asset itself
    # (system name as the brief spells it, its one-sentence reason), in the brief's order (G216)
    system_reasons: tuple[tuple[str, str], ...] = ()
    # An evidence story's citations (G229): (marker n, the claim in the text that entry n supports).
    evidence_links: tuple[tuple[int, str], ...] = ()
    anatomy: Anatomy | None = None  # G229: None when the answer gave none usable (a final finding)

    def to_answer(self) -> dict[str, Any]:
        """The draft as the writer's answer reads: the assistant turn the one rewrite follows (system_reasons
        only when the brief listed systems, evidence_links only when it cited)."""
        answer: dict[str, Any] = {
            "scenario_title": self.title,
            "scenario_statement": self.statement,
            "risk_statement": self.risk,
            "assumptions": list(self.assumptions),
            "entry_point": self.entry_point,
        }
        if self.evidence_links:
            answer["evidence_links"] = [{"n": n, "claim": claim} for n, claim in self.evidence_links]
        if self.anatomy is not None:
            answer["anatomy"] = self.anatomy.as_doc()
        return answer | ({"system_reasons": dict(self.system_reasons)} if self.system_reasons else {})


@dataclass(frozen=True)
class Finding:
    code: FindingCode | StoryFindingCode
    message: str

    @property
    def severity(self) -> FindingSeverity:
        if isinstance(self.code, StoryFindingCode):
            return STORY_FINDING_SEVERITIES[self.code]
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

    @property
    def final(self) -> bool:
        """Blocked by a rule no new attempt is asked to fix (G229): its path is given up at once."""
        return any(finding.code in FINAL_FINDINGS for finding in self.findings)

    @property
    def blocker(self) -> str:
        """The code of the finding that blocks it, a final one first: why its path is given up ("": none)."""
        blockers = [finding for finding in self.findings if finding.severity == FindingSeverity.BLOCKER]
        first = min(blockers, key=lambda finding: finding.code not in FINAL_FINDINGS, default=None)
        return str(first.code) if first else ""


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
    # One sentence per supporting system, by name; that every system has one is checked by the writer.
    system_reasons: dict[str, str] = {}
    # G229: read leniently by the writer (a bad one is a finding, never a re-ask: no AI call is added).
    evidence_links: Any = None
    anatomy: Any = None

    @field_validator("scenario_title", "scenario_statement", "risk_statement")
    @classmethod
    def check_the_text_is_given(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(AnswerProblem.TEXT_REQUIRED)
        return value


class PlanCheckAnswer(BaseModel):
    consistent: bool
    problems: list[str]
    unsupported_citations: Any = None  # an evidence story's markers its entries do not support (G229)

    @model_validator(mode="after")
    def check_an_inconsistency_says_why(self) -> "PlanCheckAnswer":
        if not self.consistent and not any(problem.strip() for problem in self.problems):
            raise ValueError(AnswerProblem.PROBLEMS_REQUIRED)
        return self
