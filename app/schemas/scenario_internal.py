"""Scenario logic's internal shapes: the asset context, the plan, the control mapping and the writer's."""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, fields
from typing import Any, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core import constants as c
from app.schemas.library import LibraryActor, ThreatLibrary

Row = dict[str, Any]


@dataclass(frozen=True)
class AssetContextRows:
    """tsg_GetAssetContext's answer, one field per result set."""

    asset: Row | None  # None: the entity does not own the asset
    services: list[Row]  # the asked service, else every service linked to the asset; each with `linked`
    sector: Row | None  # the asked (sub-)sector with its parent's id and name
    systems: list[Row]  # every linked, not deleted system of the asset, the asked ones among them
    options: list[Row]  # {code, value or id, name}: the dropdown names, keyed as the procedure returns them


@dataclass(frozen=True)
class FrozenContext:
    """What a run knows about its asset, frozen at its start (tsg_sessions.context)."""

    asset: dict[str, Any]  # id, name, category_code: what names, cards and the control pool need
    asset_context: dict[str, Any]  # every other column of the asset row: the facts the prompts get
    systems: list[dict[str, Any]]  # aliased SYS1..n in request order: id, alias, name, category_code + facts
    asset_systems: list[dict[str, Any]] = field(default_factory=list)  # id, name, category of each linked

    def to_record(self) -> dict[str, Any]:
        return asdict(self)

    def linked_systems(self) -> list[dict[str, Any]]:
        """Every supporting system of the asset as {id, name, category_code}; an older run: its own."""
        own = [{"id": s["id"], "name": s["name"], "category_code": s.get("category_code")} for s in self.systems]
        return self.asset_systems or own

    def system_categories(self) -> dict[int, str | None]:
        """Each supporting system's category code (IT, OT ...), the run's own as frozen; None when unknown."""
        return {system["id"]: system.get("category_code") for system in [*self.asset_systems, *self.systems]}

    def own_and_organisation_facts(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """This asset's own facts and the organisation's: an entity_... column describes the whole entity."""
        prefix = c.ContextProperties.ORGANISATION_PREFIX
        own = {key: value for key, value in self.asset_context.items() if not key.startswith(prefix)}
        return own, {key: value for key, value in self.asset_context.items() if key.startswith(prefix)}

    @staticmethod
    def read_system_facts(system: dict[str, Any]) -> dict[str, Any]:
        """A system's recorded facts, its category as its asset type; not yet safe for a prompt."""
        facts = {
            "asset_type" if key == "category_name" else key: value
            for key, value in system.items()
            if key not in c.ContextProperties.ALWAYS_USED
        }
        return {"name": system["name"], **facts}

    def find_systems(self, system_ids: Iterable[int]) -> list[dict[str, Any]]:
        """The run's frozen supporting systems with these ids, in the run's order."""
        wanted = set(system_ids)
        return [system for system in self.systems if system["id"] in wanted]

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "FrozenContext":
        """A stored context; the top-level copies a run frozen before 2026-10-11 still holds are not read."""
        return cls(**{name: record[name] for name in _FIELDS if name in record})


_FIELDS = tuple(f.name for f in fields(FrozenContext))


@dataclass(frozen=True)
class ControlQuery:
    """One scenario's control query."""

    text: str
    is_about_ai: bool = False  # the threat is about AI: only then may an AI control be searched


class ControlView(BaseModel):
    """A mapped control as the API shows it."""

    control_id: int
    control_code: str | None
    itot: str | None  # Control_Library.AssetType: IT, OT, IT\OT
    domain: str | None
    control_name: str | None
    control_description: str | None
    map_rank: int | None
    score: float | None  # the reranker's 0-100; None for a control the scenario's author named
    mapping_relevance: float | None  # v1's second name for the score
    match_type: str  # EXACT, NEAREST or GIVEN
    match_reason: str
    tier: str  # strong, fallback or given


def control_view(item: dict[str, Any]) -> ControlView:
    """A stored control item as the API shows it."""
    match = item.get("match")
    return ControlView(
        control_id=item["control_id"],
        control_code=item.get("code"),
        itot=item.get("asset_type"),
        domain=item.get("domain"),
        control_name=item.get("name"),
        control_description=item.get("description"),
        map_rank=item.get("rank"),
        score=item.get("score"),
        mapping_relevance=item.get("score"),
        match_type=str(match).upper(),
        match_reason=item.get("rationale") or c.CONTROL_MATCH_REASONS.get(str(match), ""),
        tier=item.get("tier") or c.CONTROL_TIERS.get(str(match), ""),
    )


@dataclass(frozen=True)
class ActorPick:
    """The gate's pick for one threat: the most plausible listed attacker, and why."""

    name: str | None  # as the library spells it; None: no listed attacker plausibly could, or none named
    reason: str  # one sentence: the access, skill and motive the threat needs


@dataclass(frozen=True)
class Verdict:
    """The relevance gate's one answer for a candidate threat, for all its own categories."""

    named_categories: dict[c.StrideCategory, tuple[int, str]]
    refusal: tuple[str, str] | None  # (CandidateRejection, detail) when it does not apply; None: it applies
    systems: tuple[int, ...]  # supporting system ids; () = the asset itself
    entry_points: tuple[int, ...]  # the systems among `systems` an attacker could get in through
    confidence: float  # 0-100; 0 when not relevant
    likelihood: int  # ThreatFinding.LIKELIHOOD_RANK; 0 when not relevant
    actor_pick: ActorPick | None  # None when not relevant
    actions: tuple[str, ...]  # the acts its name states, as the gate split them


@dataclass(frozen=True)
class AttackPlace:
    """Where the threat's one attack path goes: its main category's systems, ways in and confidence."""

    systems: tuple[int, ...] = ()  # () = the asset itself
    entry_points: tuple[int, ...] = ()  # its ways in among `systems`; () = the asset itself
    confidence: float = 0.0


@dataclass(frozen=True)
class PlannedActor:
    actor_id: int
    name: str
    role: c.ActorRole


@dataclass(frozen=True)
class PlannedThreat:
    """One threat that applies to the asset, one record from the gate to the plan: library or gap fill."""

    key: str  # "lib:<catalogue id>" or "ai:<normalised raw name>": one threat under two categories is one
    catalogue_id: int | None  # None: an AI threat
    type_id: int  # always a library type
    type_name: str
    name: str
    categories: tuple[c.StrideCategory, ...]
    reasons: dict[c.StrideCategory, str] = field(default_factory=dict)  # the gate's reason per category
    main_place: AttackPlace = AttackPlace()  # where its main category's attack path goes
    systems: tuple[int, ...] = ()  # every system it involves
    impact: int = 0  # the highest of its categories: what ranks it
    confidence: float = 0.0
    likelihood: int = 0  # how likely a listed attacker would attempt it; the higher on a merge
    actor_pick: ActorPick | None = None  # the gate's pick, until code decides
    actions: tuple[str, ...] = ()  # the acts its name states, systems by name: the plan's threats[].actions
    linked_actors: tuple[LibraryActor, ...] = ()  # those the library links to it (an AI threat: to its type)
    asset_type: str | None = None  # a library threat's AssetType
    actors: tuple[PlannedActor, ...] = ()  # the acting actor
    attacker_check: c.AttackerCheck | None = None
    attacker_check_reason: str = ""

    def to_record(self, category_ids: dict[str, int]) -> dict[str, Any]:
        """The threat as the plan stores it, its main category's library id from `category_ids`."""
        main = self.categories[0]
        return {
            "key": self.key,
            "library_id": self.catalogue_id,
            "ai_generated": self.catalogue_id is None,
            "type": {"id": self.type_id, "name": self.type_name},
            "name": self.name,
            "category": main,
            "categories": list(self.categories),
            "systems": list(self.systems),
            "reason": self.reasons[main],
            "reasons": {str(category): self.reasons[category] for category in self.categories},
            "impact": self.impact,
            "confidence": self.confidence,
            "likelihood": self.likelihood,
            "actors": [
                {"id": actor.actor_id, "name": actor.name, "role": actor.role, "closest": False}
                for actor in self.actors
            ],
            "attacker_check": self.attacker_check,
            "attacker_check_reason": self.attacker_check_reason or None,
            "actions": list(self.actions),
            "category_id": category_ids.get(main.lower()),
        }


class Drop(NamedTuple):
    """One candidate that left the plan, as planning found it; its trace entry is written from it."""

    threat_key: str
    threat_name: str  # as planned: a library name with its code, an AI name with system names
    kind: c.StrideCategory | None  # None: the whole threat
    stage: c.PlanStage
    reason: str  # PlanLoss, CandidateRejection or AttackerCheck
    detail: str = ""  # system names, never aliases


@dataclass(frozen=True)
class Landscape:
    """The asset and its supporting systems as one text for the AI, each system by alias, never by id."""

    text: str
    system_ids: dict[str, int]  # alias -> supporting system id
    system_names: dict[str, str]  # alias -> name, to turn an alias the AI still wrote back into the name
    is_cut: bool = False  # facts were shortened to fit the prompt (every system kept its name)


@dataclass(frozen=True)
class ThreatFindings:
    threats: list[PlannedThreat]
    landscape: Landscape  # the text the threats were judged against
    category_ids: dict[str, int] = field(default_factory=dict)
    drops: list[Drop] = field(default_factory=list)  # every candidate that left the plan
    library_threats: int = 0  # library threats looked at
    gate_asked: int = 0  # library threat and own category pairs the gate was asked about
    ai_threats: int = 0  # gap-fill threats proposed and accepted, one per category


class GapFillResponse(BaseModel):
    """The gap-fill answer: whether a threat applies, and the one it proposes."""

    model_config = ConfigDict(extra="forbid")
    applies: bool
    reason: str
    threat_type: str | None = None
    threat: str | None = None
    systems: list[str] = Field(default_factory=list)


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
    evidence: tuple[dict[str, Any], ...] = ()
    cleaned_evidence: tuple[tuple[str, tuple[str, ...]], ...] = ()  # each entry's (title, stated facts), cleaned
    cited_index: int | None = None  # the index in `evidence` of the entry a story cites; None: not a story
    cited_claim: str = ""  # code's own sentence about the cited entry
    brief_text: str = ""  # the whole brief as JSON, casefolded: what a scenario may take a label or word from

    def get_evidence_mode(self) -> c.EvidenceMode:
        """Returns the brief's evidence mode: inferred, nearest or source-documented."""
        if not self.evidence:
            return c.EvidenceMode.INFERRED
        if all(entry.get("nearest") for entry in self.evidence):
            return c.EvidenceMode.NEAREST
        return c.EvidenceMode.SOURCE_DOCUMENTED


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
    code: c.FindingCode | c.StoryFindingCode
    message: str

    def get_severity(self) -> c.FindingSeverity:
        """How serious the finding's code is: a removed citation warns, every other code blocks."""
        is_warning = self.code == c.FindingCode.CITATION_REMOVED
        return c.FindingSeverity.WARNING if is_warning else c.FindingSeverity.BLOCKER

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
            {finding.code for finding in self.findings if finding.get_severity() == c.FindingSeverity.BLOCKER}
        )

    def find_blocking_code(self) -> str:
        """The code of the finding that blocks it, a final one first ("": none)."""
        blockers = [finding for finding in self.findings if finding.get_severity() == c.FindingSeverity.BLOCKER]
        first = min(blockers, key=lambda finding: finding.code != c.FindingCode.NEAR_DUPLICATE, default=None)
        return str(first.code) if first else ""


@dataclass(frozen=True)
class PathFailure:
    """Why one path got a failure card instead of a scenario."""

    code: c.ErrorCode
    message: str
    reason: c.AiOutage | None = None  # the AI outage that cost the path: what the card and the UI are told


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
            raise ValueError(c.AnswerProblem.TEXT_REQUIRED)
        return value
