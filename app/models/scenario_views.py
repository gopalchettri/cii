"""A scenario as the API shows it, in v1's layout (owner 2026-10-12): what it says, the threat it is about
(the threat block v1 tracked), its attackers, its controls and its review. Built from the stored scenario
alone: the category id and each control's description were kept when it was written and mapped, so a read
never needs the library (or SQL Server). No database call here."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.core.constants import (
    CONTROL_MATCH_REASONS,
    Decision,
    FindingSeverity,
    GroundingStatus,
    LibraryStatus,
    RunKind,
    ScenarioDisplay,
    ScenarioStatus,
    Status,
    ValidationStatus,
)
from app.models.run_board import Progress


class SystemInvolved(BaseModel):
    supporting_system_id: int
    supporting_system: str
    is_entry_point: bool


class ScenarioText(BaseModel):
    """None on a failure card: the path could not be written."""

    threat_category: str | None
    contributing_categories: list[str]
    threat_type: str | None
    threat_name: str | None
    supporting_systems_involved: list[SystemInvolved]
    scenario_title: str | None
    scenario_statement: str | None  # the statement, then "Why this threat applies: ..."
    risk_statement: str | None
    assumptions: list[str]
    # STANDALONE: no link between systems claimed; UNKNOWN: it relies on a link the platform does not record.
    route_status: str | None
    also_applies: list[
        str
    ]  # the other threats of the same kind of attack on the same system, strongest first


class ThreatBlock(BaseModel):
    threat_id: str | None  # the plan's key: "lib:<catalogue id>" or "ai:<name>"
    threat_category: str | None
    threat_category_id: int | None
    threat_type: str | None
    threat_name: str | None
    threat_type_id: int | None
    library_threat_type: str | None
    library_threat_name: str | None  # None for a threat the library does not hold
    grounding_status: GroundingStatus | None
    threat_catalogue_id: int | None
    is_threat_type_ai_generated: (
        bool  # never: the AI's threats are of library types (G108); a person's are theirs
    )
    is_threat_ai_generated: bool | None
    grounding_score: float | None  # the relevance check's confidence, 0-100
    score: float | None
    scope_rank: int | None  # the path's rank in the plan, 1 = most relevant


class ActorView(BaseModel):
    actor_id: int | None
    actor_name: str | None
    role: str | None  # acting, or alternate
    closest_match: bool  # no actor is linked to the threat's type: the nearest library actor acts
    below_threshold: bool  # that nearest actor scored below ACTOR_SIMILARITY_THRESHOLD


class ControlView(BaseModel):
    control_id: int
    control_code: str | None
    itot: str | None  # Control_Library.AssetType: IT, OT, IT\OT
    domain: str | None
    control_name: str | None
    control_description: str | None
    map_rank: int | None
    score: float | None  # the reranker's 0-100; None for a control the scenario's author named
    match_type: str  # EXACT, NEAREST or GIVEN
    match_reason: str


class ScenarioView(BaseModel):
    scenario_id: str
    session_id: str
    version: int
    status: ScenarioStatus  # done, or failed: a failure card says why in `failure`
    scenario: ScenarioText
    threat: ThreatBlock
    actors: list[ActorView]
    controls_status: Status | None  # queued, running, done or failed; None on a failure card
    controls: list[ControlView]
    accepted: bool
    accepted_by: str | None
    accepted_at: datetime | None
    rejected_by: str | None
    rejected_at: datetime | None
    validation_status: ValidationStatus
    validation_errors: list[str]  # warnings: shown, never blocking an accept
    validation_notes: list[str]  # the plan check's words: information only
    scenario_source: RunKind
    replaced_scenarios: list[str]  # the version this one replaced
    replaced_by: str | None  # the newer version, when this one was regenerated
    failure: dict[str, Any] | None
    regenerate_error: dict[str, Any] | None  # why the last regenerate kept this version
    created_at: datetime

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "ScenarioView":
        content, controls = record.get("content") or {}, record.get("controls") or {}
        findings = record.get("findings") or []
        return cls(
            scenario_id=record["_id"],
            session_id=record["session_id"],
            version=record["version"],
            status=record["status"],
            scenario=_scenario_text(content),
            threat=_threat_block(content),
            actors=[_actor(actor) for actor in content.get("actors") or []],
            controls_status=controls.get("status"),
            controls=[_control(item) for item in controls.get("items") or []],
            **_review(record),
            validation_status=_validation_status(findings),
            validation_errors=_messages(findings, FindingSeverity.WARNING),
            validation_notes=_messages(findings, FindingSeverity.NOTE),
            scenario_source=record["source"],
            replaced_scenarios=[record["replaces"]] if record.get("replaces") else [],
            replaced_by=record.get("superseded_by"),
            failure=record.get("failure"),
            regenerate_error=record.get("regenerate_error"),
            created_at=record["created_at"],
        )


class ScenarioList(BaseModel):
    scenarios: list[ScenarioView]
    total: int  # every match, for paging (offset + limit)


class RunResults(ScenarioList):
    """GET /v1/sessions/{id}/results: the run, its progress (as its status shows it), then its scenarios."""

    session_id: str
    entity_id: int
    asset_id: int
    asset_name: str | None
    user_id: str | None
    progress: Progress


def _scenario_text(content: dict[str, Any]) -> ScenarioText:
    threat, route = content.get("threat") or {}, content.get("route") or {}
    statement, why = content.get("statement"), content.get("why_applies")
    shown = f"{statement}{ScenarioDisplay.WHY_APPLIES_JOIN}{why}" if statement and why else statement
    systems = [
        SystemInvolved(
            supporting_system_id=system["id"],
            supporting_system=system["name"],
            is_entry_point=bool(system.get("entry_point")),
        )
        for system in content.get("systems") or []
    ]
    return ScenarioText(
        threat_category=content.get("category"),
        contributing_categories=content.get("contributing_categories") or [],
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        supporting_systems_involved=systems,
        scenario_title=content.get("title"),
        scenario_statement=shown,
        risk_statement=content.get("risk_statement"),
        assumptions=content.get("assumptions") or [],
        route_status=str(route["status"]).upper() if route.get("status") else None,
        also_applies=content.get("also_applies") or [],
    )


def _grounding(threat: dict[str, Any]) -> GroundingStatus | None:
    """A library threat, one the AI proposed (gap-fill), or one a person named in a hand-written scenario:
    new, or proposed and still waiting for a curator (it has a library id while pending)."""
    if not threat:
        return None
    if threat.get("library_id") is not None and threat.get("library_status") != LibraryStatus.PENDING:
        return GroundingStatus.VERIFIED
    return GroundingStatus.AI_PROPOSED if threat.get("ai_generated") else GroundingStatus.PERSON_PROPOSED


def _threat_block(content: dict[str, Any]) -> ThreatBlock:
    threat, category = content.get("threat") or {}, content.get("category")
    library_id, confidence = threat.get("library_id"), threat.get("confidence")
    return ThreatBlock(
        threat_id=threat.get("key"),
        threat_category=category,
        threat_category_id=content.get("category_id"),
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        threat_type_id=threat.get("type_id"),
        # The same names where the library holds them (without a framework code, as every card shows them); a
        # type or threat a person named and the library does not hold yet has none.
        library_threat_type=threat.get("type") if threat.get("type_id") is not None else None,
        library_threat_name=threat.get("name") if library_id is not None else None,
        grounding_status=_grounding(threat),
        threat_catalogue_id=library_id,
        is_threat_type_ai_generated=False,
        is_threat_ai_generated=threat.get("ai_generated"),
        grounding_score=confidence,
        score=confidence,
        scope_rank=threat.get("rank"),
    )


def _actor(actor: dict[str, Any]) -> ActorView:
    return ActorView(
        actor_id=actor.get("id"),
        actor_name=actor.get("name"),
        role=actor.get("role"),
        closest_match=bool(actor.get("closest")),
        below_threshold=bool(actor.get("below_threshold")),
    )


def _control(item: dict[str, Any]) -> ControlView:
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
        match_type=str(match).upper(),
        match_reason=CONTROL_MATCH_REASONS.get(str(match), ""),
    )


def _review(record: dict[str, Any]) -> dict[str, Any]:
    """The decision as v1 showed it: accepted, and who decided which way, when."""
    decision, by, at = record.get("decision"), record.get("decided_by"), record.get("decided_at")
    accepted, rejected = decision == Decision.ACCEPTED, decision == Decision.REJECTED
    return {
        "accepted": accepted,
        "accepted_by": by if accepted else None,
        "accepted_at": at if accepted else None,
        "rejected_by": by if rejected else None,
        "rejected_at": at if rejected else None,
    }


def _validation_status(findings: list[dict[str, Any]]) -> ValidationStatus:
    """`warning` when any finding is a warning (it never blocks an accept), else `ok`: notes are information,
    and a blocked scenario is never served (a blocker is never shown as a warning)."""
    warned = any(finding.get("severity") == FindingSeverity.WARNING for finding in findings)
    return ValidationStatus.WARNING if warned else ValidationStatus.OK


def _messages(findings: list[dict[str, Any]], severity: FindingSeverity) -> list[str]:
    return [str(finding.get("message")) for finding in findings if finding.get("severity") == severity]
