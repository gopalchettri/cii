"""Scenario writing's shapes: the brief, the writer's answer contract, a draft, its findings, the card."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, field_validator

from app.core.constants import (
    FINAL_FINDINGS,
    FINDING_SEVERITIES,
    STORY_FINDING_SEVERITIES,
    AiOutage,
    AnswerProblem,
    ErrorCode,
    EvidenceMode,
    FindingCode,
    FindingSeverity,
    StoryFindingCode,
)
from app.models.library.library import ThreatLibrary


@dataclass(frozen=True)
class LiveLibrary:
    """What the library holds active now: a path whose threat or attacker was retired is not written."""

    threat_ids: frozenset[int]
    type_ids: frozenset[int]  # an AI-proposed threat stays writable while its library type is active
    actor_ids: frozenset[int]

    @classmethod
    def from_library(cls, library: ThreatLibrary) -> "LiveLibrary":
        """The active threat, type and actor ids of `library`."""
        return cls(
            frozenset(threat.catalogue_id for threat in library.threats),
            frozenset(threat.type_id for threat in library.threats),
            frozenset(actor.actor_id for actor in library.actors),
        )


@dataclass(frozen=True)
class BriefSystem:
    """One supporting system on a brief, applicable when the route goes through it."""

    id: int
    name: str
    applicable: bool


@dataclass(frozen=True)
class WriterBrief:
    """Everything the writer reads about one path: names and recorded facts, never an id."""

    asset: dict[str, Any]  # name, type, description, sector ...: recorded facts only, cleaned for a prompt
    systems: tuple[dict[str, Any], ...]  # the path's systems, each its name plus recorded facts
    facts: dict[str, Any]  # the path's own BRIEF fields: category, attacker, threat, entry point options ...
    threat: str  # the threat's name without its code: copied back by the writer, a title's qualifier
    threat_actions: tuple[str, ...]  # the actions the threat's name states; (): the writer splits it
    supporting_systems: tuple[BriefSystem, ...]  # every supporting system of the run, applicable or not
    entry_options: tuple[str, ...]  # the systems the path may get in through; (): the asset itself
    # Evidence docs in the plan's order, best first, only for an evidence story: the cited one is [1].
    evidence: tuple[dict[str, Any], ...] = ()
    cleaned_evidence: tuple[
        tuple[str, tuple[str, ...]], ...
    ] = ()  # each entry's (title, stated facts), cleaned
    cited_index: int | None = None  # the index in `evidence` of the entry a story cites; None: not a story
    cited_claim: str = ""  # code's own sentence about the cited entry
    brief_text: str = ""  # the whole brief as JSON, casefolded: what a scenario may take a label or word from

    def get_evidence_mode(self) -> EvidenceMode:
        """Returns the brief's evidence mode: inferred, nearest or source-documented."""
        if not self.evidence:
            return EvidenceMode.INFERRED
        if all(entry.get("nearest") for entry in self.evidence):
            return EvidenceMode.NEAREST
        return EvidenceMode.SOURCE_DOCUMENTED


@dataclass(frozen=True)
class ScenarioDraft:
    title: str
    statement: str
    risk: str
    assumptions: tuple[str, ...]
    entry_point: str  # one of the brief's entry_options; "" = the asset itself
    system_reasons: tuple[tuple[str, str], ...] = ()  # (system name, its one-sentence reason), brief order
    evidence_statement: str = ""  # a story's closing sentence code built from its step ("" when none)
    evidence_problem: str = ""  # why the writer's step could not open that sentence ("" when it could)


@dataclass(frozen=True)
class Finding:
    code: FindingCode | StoryFindingCode
    message: str

    def get_severity(self) -> FindingSeverity:
        """How serious the finding's code is."""
        if isinstance(self.code, StoryFindingCode):
            return STORY_FINDING_SEVERITIES[self.code]
        return FINDING_SEVERITIES[self.code]

    def build_record(self) -> dict[str, str]:
        """The finding as the scenario stores it."""
        return {"code": self.code, "severity": self.get_severity(), "message": self.message}


@dataclass(frozen=True)
class WrittenScenario:
    """The draft with what the exact checks found in it."""

    draft: ScenarioDraft
    findings: tuple[Finding, ...]

    def list_blocking_codes(self) -> list[str]:
        """The codes of the findings that block it, sorted, each once."""
        return sorted(
            {finding.code for finding in self.findings if finding.get_severity() == FindingSeverity.BLOCKER}
        )

    def find_blocking_code(self) -> str:
        """The code of the finding that blocks it, a final one first ("": none)."""
        blockers = [finding for finding in self.findings if finding.get_severity() == FindingSeverity.BLOCKER]
        first = min(blockers, key=lambda finding: finding.code not in FINAL_FINDINGS, default=None)
        return str(first.code) if first else ""


@dataclass(frozen=True)
class PathFailure:
    """Why one path got a failure card instead of a scenario."""

    code: ErrorCode
    message: str
    final: bool = False  # no retry can help (the frozen plan lacks a fact): the path is abandoned at once
    reason: AiOutage | None = None  # the AI outage that cost the path: what the card and the UI are told


class ScenarioAnswer(BaseModel):
    """The writer's answer for one slot; code settles entry_point against the brief's options."""

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
