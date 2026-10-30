"""Scenario writing: the writer's brief, its AI answer contracts, a draft, its findings and the written
scenario. Frozen, so the paths written at once share nothing mutable."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from app.core.constants import (
    AiOutage,
    AnswerProblem,
    ErrorCode,
    FindingCode,
    PlanCheckStatus,
    Route,
    StoryFindingCode,
    StrideCategory,
    WriterStyle,
)


@dataclass(frozen=True)
class LiveLibrary:
    """What the library holds active now: a path whose threat or attacker was retired since is not written."""

    threat_ids: frozenset[int]
    type_ids: frozenset[int]  # an AI-proposed threat stays writable while its library type is active
    actor_ids: frozenset[int]


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
    threat_actions: tuple[str, ...] = ()  # the actions the threat's name states; (): the writer splits it
    style: WriterStyle = WriterStyle.ORIGINAL
    # Evidence docs in the plan's order, best first: the writer's grounding; the first citable one is [1].
    evidence: tuple[dict[str, Any], ...] = ()
    # Every supporting system of the run, applicable or not: each gets a reason (the writer's only for "yes").
    supporting_systems: tuple[BriefSystem, ...] = ()
    entry_system: str = ""  # the system the path gets in through, by its name in `systems` ("" = any of them)


@dataclass(frozen=True)
class ScenarioDraft:
    title: str
    statement: str
    risk: str
    assumptions: tuple[str, ...]
    entry_point: str  # one of the brief's entry_point_options; "" = the asset itself
    system_reasons: tuple[tuple[str, str], ...] = ()  # (system name, its one-sentence reason), brief order
    evidence_statement: str = ""  # a story's closing sentence code built from its step ("" when none)
    evidence_step: str = ""  # the writer's step of its story that the cited entry is about


@dataclass(frozen=True)
class Finding:
    code: FindingCode | StoryFindingCode
    message: str


@dataclass(frozen=True)
class PlanCheck:
    status: PlanCheckStatus
    problems: tuple[str, ...] = ()
    # The reviewer's verdicts on meaning; True when the check could not be made (stored as None then).
    same_threat: bool = True  # the statement, and the cause its risk gives, carry the plan's threat
    same_impact: bool = True  # the risk is the consequence of that same scenario's impact
    actions_not_carried_out: tuple[str, ...] = ()  # the brief's listed actions not judged "carried out"


@dataclass(frozen=True)
class WrittenScenario:
    """The draft written with what was found in it."""

    draft: ScenarioDraft
    findings: tuple[Finding, ...]  # the code rules' findings and the plan check's notes
    plan_check: PlanCheck
    route: Route
    title_qualifier: str = ""  # the threat's name as a title carries it, to tell two same titles apart
    rewritten: bool = False  # the draft is the writer's repair (_repaired), kept over its first draft


@dataclass(frozen=True)
class PathFailure:
    """Why one path got a failure card instead of a scenario."""

    code: ErrorCode
    message: str
    final: bool = False  # no retry can help (the frozen plan lacks a fact): the path is abandoned at once
    reason: AiOutage | None = None  # the AI outage that cost the path: what the card and the UI are told


class ScenarioAnswer(BaseModel):
    """The writer's answer; code settles entry_point against the brief's options."""

    scenario_title: str
    scenario_statement: str
    risk_statement: str
    assumptions: list[str]
    entry_point: str
    system_reasons: dict[str, str] = {}  # one sentence per "yes" supporting system, by name
    action_sentences: dict[str, Any] = {}  # per listed action, the number of its statement's sentence
    evidence_step: str | None = ""  # none given is never a re-ask: code cites its own sentence

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
    threat_actions: dict[str, str] = {}  # per listed action: "carried out", "only named" or "missing"
    same_threat: bool  # required, so a reviewer that leaves them out is re-asked, never assumed
    same_impact: bool

    @model_validator(mode="after")
    def check_every_rule_has_a_verdict(self) -> "PlanCheckAnswer":
        """Every rule holds or is broken."""
        verdicts = [verdict.strip().casefold() for verdict in self.rules.values()]
        if not verdicts or not all(v == "holds" or v.startswith("broken") for v in verdicts):
            raise ValueError(AnswerProblem.RULE_VERDICTS_REQUIRED)
        return self
