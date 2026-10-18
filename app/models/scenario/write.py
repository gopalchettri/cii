"""Scenario writing: the writer's brief, its AI answer contracts, a draft, its findings and the written
scenario. Frozen, so the paths written at once share nothing mutable."""

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
    """What the library holds active now: a path whose threat or attacker was retired since is not written."""

    threat_ids: frozenset[int]
    type_ids: frozenset[int]  # an AI-proposed threat stays writable while its library type is active
    actor_ids: frozenset[int]

    @classmethod
    def of(cls, library: ThreatLibrary) -> "LiveLibrary":
        """The active ids of `library`."""
        return cls(
            frozenset(threat.catalogue_id for threat in library.threats),
            frozenset(threat.type_id for threat in library.threats),
            frozenset(actor.actor_id for actor in library.actors),
        )


@dataclass(frozen=True)
class BriefSystem:
    """One supporting system on a brief: applicable when the route goes through it. Its id never reaches
    the prompt."""

    id: int
    name: str
    applicable: bool


@dataclass(frozen=True)
class WriterBrief:
    """Everything the writer and the plan check read about one path: names and recorded facts, never an id."""

    asset: dict[str, Any]  # name, type, description, sector ...: recorded facts only, cleaned for a prompt
    asset_name: str
    critical_service: str | None
    category: StrideCategory
    attacker: str  # the acting attacker, always described as a type of attacker
    threat_type: str
    threat: str
    why_it_applies: str  # the relevance check's reason, systems by name
    systems: tuple[dict[str, Any], ...]  # the threat's systems, each its name plus recorded facts
    other_systems: tuple[str, ...]  # the run's other systems, by name: never part of this scenario
    other_scenarios: tuple[str, ...] = ()  # the statements of the path's other versions (regenerate only)
    style: WriterStyle = WriterStyle.ORIGINAL
    # Evidence docs in the plan's order: marker [n] cites evidence[n - 1]. Read by an evidence story only.
    evidence: tuple[dict[str, Any], ...] = ()
    # Every supporting system of the run, applicable or not: the writer gives each a reason.
    supporting_systems: tuple[BriefSystem, ...] = ()

    @property
    def evidence_mode(self) -> EvidenceMode:
        """Source-documented when the brief carries evidence, else inferred."""
        return EvidenceMode.SOURCE_DOCUMENTED if self.evidence else EvidenceMode.INFERRED

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
    system_reasons: tuple[tuple[str, str], ...] = ()  # (system name, its one-sentence reason), brief order
    evidence_links: tuple[tuple[int, str], ...] = ()  # (marker n, the claim entry n supports)
    why_applies: str = ""  # the writer's own sentence on why the threat applies ("" when it gave none)

    def to_answer(self) -> dict[str, Any]:
        """The draft as the writer's answer reads, for the one rewrite to follow."""
        answer: dict[str, Any] = {
            "scenario_title": self.title,
            "scenario_statement": self.statement,
            "risk_statement": self.risk,
            "assumptions": list(self.assumptions),
            "entry_point": self.entry_point,
        }
        if self.evidence_links:
            answer["evidence_links"] = [{"n": n, "claim": claim} for n, claim in self.evidence_links]
        if self.why_applies:
            answer["why_applies"] = self.why_applies
        return answer | ({"system_reasons": dict(self.system_reasons)} if self.system_reasons else {})


@dataclass(frozen=True)
class Finding:
    code: FindingCode | StoryFindingCode
    message: str

    @property
    def severity(self) -> FindingSeverity:
        """How serious the finding's code is."""
        if isinstance(self.code, StoryFindingCode):
            return STORY_FINDING_SEVERITIES[self.code]
        return FINDING_SEVERITIES[self.code]

    def to_record(self) -> dict[str, str]:
        """The finding as the scenario stores it."""
        return {"code": self.code, "severity": self.severity, "message": self.message}


@dataclass(frozen=True)
class PlanCheck:
    status: PlanCheckStatus
    problems: tuple[str, ...] = ()
    # The reviewer's verdicts on meaning; True when the check could not be made (stored as None then).
    same_threat: bool = True  # the statement, and the cause its risk gives, carry the plan's threat
    same_impact: bool = True  # the risk is the consequence of that same scenario's impact
    unsupported: tuple[int, ...] = ()  # markers whose entries do not support their sentences

    def to_record(self) -> dict[str, Any]:
        """The check as stored: a check not made records no verdict, never a pass nobody judged."""
        made = self.status is not PlanCheckStatus.UNCHECKED
        verdicts = {
            "same_threat": self.same_threat if made else None,
            "same_impact": self.same_impact if made else None,
        }
        reviewed = {"problems": list(self.problems), "unsupported": list(self.unsupported)}
        return {"status": self.status, **reviewed, **verdicts}


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
        """True when any finding is a blocker."""
        return any(finding.severity == FindingSeverity.BLOCKER for finding in self.findings)

    @property
    def final(self) -> bool:
        """Blocked by a rule no new attempt is asked to fix: its path is given up at once."""
        return any(finding.code in FINAL_FINDINGS for finding in self.findings)

    @property
    def blocker(self) -> str:
        """The code of the finding that blocks it, a final one first ("": none)."""
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
    """The writer's answer; the writer checks entry_point against the brief's options."""

    scenario_title: str
    scenario_statement: str
    risk_statement: str
    assumptions: list[str]
    entry_point: str
    system_reasons: dict[str, str] = {}  # one sentence per supporting system, by name
    evidence_links: Any = None  # read leniently: a malformed link is left out, never a re-ask
    why_applies: str | None = ""  # one sentence; none given (null too) is never a re-ask

    @field_validator("scenario_title", "scenario_statement", "risk_statement")
    @classmethod
    def check_the_text_is_given(cls, value: str) -> str:
        """The title, statement and risk are not blank."""
        if not value.strip():
            raise ValueError(AnswerProblem.TEXT_REQUIRED)
        return value


class PlanCheckAnswer(BaseModel):
    """The reviewer's answer: per numbered rule "holds" or 'broken: "<exact words>" - <reason>'."""

    rules: dict[str, str]
    same_threat: bool  # required, so a reviewer that leaves them out is re-asked, never assumed
    same_impact: bool
    unsupported_citations: Any = None  # an evidence story's markers its entries do not support

    @model_validator(mode="after")
    def check_every_rule_has_a_verdict(self) -> "PlanCheckAnswer":
        """Every rule holds or is broken."""
        verdicts = [verdict.strip().casefold() for verdict in self.rules.values()]
        if not verdicts or not all(v == "holds" or v.startswith("broken") for v in verdicts):
            raise ValueError(AnswerProblem.RULE_VERDICTS_REQUIRED)
        return self
