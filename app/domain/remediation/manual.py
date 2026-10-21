"""A hand-written scenario: request checks, run and scenario records, library threat, controls, attacker."""

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.constants import (
    ActorRole,
    ConflictReason,
    ControlMatch,
    Decision,
    ErrorCode,
    Header,
    LibraryRowKind,
    LibraryStatus,
    PlanMessage,
    RemediationMessage,
    Route,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
    StrideCategory,
)
from app.core.exceptions import Conflict, Forbidden, Invalid, Unavailable
from app.core.redaction import redact
from app.domain.remediation.plan import describe_ref, resolve_control_refs
from app.domain.shared.names import name_match_key, threat_name_without_code
from app.models.admin.api_clients import Principal
from app.models.library.library import LibraryActor, LibraryControl, ThreatLibrary
from app.models.remediation.requests import ManualScenario, PlanRequest
from app.models.scenario.asset_context import FrozenContext
from app.search.snapshot import LibrarySnapshot, linked_actors_by_type

#: A hand-written scenario's path: one per manual run.
MANUAL_PATH = "manual"
Errors = list[dict[str, str]]


def check_manual_request(principal: Principal, body: PlanRequest, key: str | None) -> ManualScenario:
    """The hand-written scenario asked for: 422 without an Idempotency-Key, 403 for another entity's."""
    if not key:
        message = RemediationMessage.IDEMPOTENCY_KEY_REQUIRED
        raise Invalid(message, errors=[{"field": f"header.{Header.IDEMPOTENCY_KEY}", "message": message}])
    manual = body.manual_scenario
    assert manual is not None  # PlanRequest: is_manual=true
    if manual.entity_id != principal.entity_id:
        raise Forbidden(SessionMessage.ENTITY_MISMATCH_BODY)
    return manual


def manual_request_fingerprint(body: PlanRequest) -> str:
    """SHA-256 of the whole request, so a key replays only the request it first named."""
    return hashlib.sha256(json.dumps(body.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def check_same_manual_request(earlier: dict[str, Any], fingerprint: str) -> None:
    """409 idempotency_key_conflict when the key's earlier run is not this hand-written request."""
    if earlier.get("kind") != RunKind.MANUAL or earlier.get("request_hash") != fingerprint:
        raise Conflict(
            SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT
        )


def check_actor_library(actors: Sequence[LibraryActor]) -> None:
    """503 while the threat library has no attacker for the plan job to name."""
    if not actors:
        raise Unavailable(PlanMessage.ACTOR_LIBRARY_EMPTY, reason=ErrorCode.ACTOR_LIBRARY_EMPTY)


def manual_ids(entity_id: int, idempotency_key: str) -> tuple[str, str]:
    """(the run's id, the scenario's id), the same for every retry with this key."""
    base = f"{entity_id}:{idempotency_key}"
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{base}:run").hex, uuid.uuid5(
        uuid.NAMESPACE_URL, f"{base}:scenario"
    ).hex


def manual_run_record(
    principal: Principal,
    scenario: ManualScenario,
    run_id: str,
    idempotency_key: str,
    request_hash: str,
    context: FrozenContext,
    now: datetime,
) -> dict[str, Any]:
    """The manual run, born done and inactive so it never holds the asset's one active run."""
    return {
        "_id": run_id,
        "kind": RunKind.MANUAL,
        "entity_id": principal.entity_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "client_id": principal.client_id,
        "asset_id": scenario.asset_id,
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "context": context.to_record(),
        "status": Status.DONE,
        "step": Step.SCENARIOS,
        "active": False,
        "plan_note": None,
        "last_action": None,
        "counts": {},  # counted from its scenario once saved (scenarios.update_scenario_session_counts)
        "created_at": now,
        "updated_at": now,
        "finished_at": now,
    }


def manual_scenario_record(
    principal: Principal,
    scenario: ManualScenario,
    ids: tuple[str, str],
    threat: dict[str, Any],
    context: FrozenContext,
    controls: dict[str, Any],
    by: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """The scenario as saved, accepted by its writer; `by` is the audit actor of its library proposal."""
    run_id, scenario_id = ids
    return {
        "_id": scenario_id,
        "session_id": run_id,
        "entity_id": principal.entity_id,
        "asset_id": scenario.asset_id,
        "path_id": MANUAL_PATH,
        "version": 1,
        "source": RunKind.MANUAL,
        "status": ScenarioStatus.DONE,
        "decision": Decision.ACCEPTED,  # the person who wrote it
        "decided_by": principal.user_id,
        "decided_by_client": principal.client_id,
        "decided_at": now,
        "replaces": None,
        "superseded_by": None,
        "content": _content(scenario, threat, context),
        # What its plan job completes first; removed once done.
        "pending": {"actors": True, "proposal": threat["status"] is None, "by": by},
        "findings": [],  # the code checks are for AI text only
        "plan_check": None,
        "controls": controls,
        "created_at": now,
        "updated_at": now,
    }


def _content(scenario: ManualScenario, threat: dict[str, Any], context: FrozenContext) -> dict[str, Any]:
    """The scenario's content as written, its threat as the library knows it, the first system the entry."""
    names = {system["id"]: system["name"] for system in context.systems}
    return {
        "title": None,
        "statement": scenario.threat_scenario,
        "risk_statement": scenario.risk_statement,
        "why_applies": None,
        "assumptions": [],
        "category": threat["category"],
        "category_id": threat["category_id"],
        "contributing_categories": [],
        "threat": {
            "type": threat["type_name"],
            "type_id": threat["type_id"],
            "name": threat["threat_name"],
            "library_id": threat["catalogue_id"],
            "library_status": threat["status"],
            "ai_generated": False,
        },
        "actors": [],
        "systems": [
            {"id": system_id, "name": names[system_id], "entry_point": i == 0}
            for i, system_id in enumerate(scenario.supporting_system_ids)
        ],
        # One system: nothing links; more: any link between them is one the platform does not record.
        "route": {"status": Route.STANDALONE if len(names) == 1 else Route.UNKNOWN, "note": None},
        "prompt_version": None,
    }


def resolve_mapped_controls(
    manual: ManualScenario, controls: Sequence[LibraryControl]
) -> list[LibraryControl]:
    """The library rows the scenario's own controls name; any unknown one is refused (422)."""
    rows, unresolved = resolve_control_refs(manual.mapped_controls or [], controls)
    if unresolved:
        errors = [
            {
                "field": f"{ManualScenario.FIELD_PREFIX}.mapped_controls[{position}]",
                "message": RemediationMessage.CONTROL_UNKNOWN.format(reference=describe_ref(ref)),
            }
            for position, ref in unresolved
        ]
        raise Invalid(RemediationMessage.REFERENCES_INVALID, errors=errors)
    return rows


def given_controls(controls: Sequence[LibraryControl], now: datetime) -> dict[str, Any]:
    """The person's own controls in the order given; none given waits for the plan job to map them."""
    if not controls:
        return {"status": Status.QUEUED, "attempts": 0, "queued_at": now}
    items = [
        {
            "control_id": control.control_id,
            "code": control.code,
            "name": control.name,
            "domain": control.domain,
            "asset_type": control.asset_type,
            "description": control.description,
            "rank": rank,
            "score": None,
            "match": ControlMatch.GIVEN,
        }
        for rank, control in enumerate(controls, start=1)
    ]
    return {"status": Status.DONE, "items": items, "mapped_at": now}


def pick_manual_attacker(search_snapshot: LibrarySnapshot, scenario: dict[str, Any]) -> list[dict[str, Any]]:
    """The stored acting attacker: best of the threat's actors, else its type's, else the library's."""
    content, library = scenario["content"], search_snapshot.library.threat_library
    threat = content.get("threat") or {}
    by_threat = {row.catalogue_id: row.linked_actors for row in library.threats}
    active = threat.get("library_status") == LibraryStatus.ACTIVE
    own = by_threat.get(threat.get("library_id") or 0, ()) if active else ()
    linked = own or linked_actors_by_type(library).get(threat.get("type_id") or 0, ())  # 0: a new type
    candidates = linked or library.actors
    if not candidates:
        return []
    type_name, name = redact(threat.get("type") or ""), redact(threat.get("name") or "")
    query = f"{type_name}: {name}. {redact(content.get('statement') or '')}".strip()
    allowed = {actor.actor_id for actor in candidates}
    (found,) = search_snapshot.find_actors([query], top_k=len(library.actors), allowed_ids=[allowed])
    acting = found[0][0] if found else candidates[0]
    return [{"id": acting.actor_id, "name": acting.name, "role": ActorRole.ACTING, "closest": not linked}]


@dataclass(frozen=True)
class _Known:
    """One library row a reference may name: a type or a threat, live, pending or curator-rejected."""

    row_id: int
    name: str
    status: LibraryStatus
    type_id: int | None = None  # a threat's type
    categories: tuple[StrideCategory, ...] = ()  # a live threat's, in STRIDE order
    category: StrideCategory | None = None  # a live type's own


def resolve_threat(library: ThreatLibrary, scenario: ManualScenario) -> dict[str, Any]:
    """The scenario's category, type and threat as the library knows them; every fault in one 422."""
    errors: Errors = []
    types, threats = _library_rows(library)
    threat_type = _named(types, scenario.threat_type_id, scenario.threat_type_name, "threat_type", errors)
    threat = _named(threats, scenario.threat_id, scenario.threat_name, "threat", errors)
    in_library = threat is not None and threat.status != LibraryStatus.CURATOR_REJECTED
    reason: ConflictReason | None = None
    if threat is not None and in_library:  # threat names are unique across the library: its type decides
        type_id = threat.type_id
        library_type = next((row for row in types if row.row_id == type_id), None)
        if threat_type is None or threat_type.row_id != type_id:
            shown = library_type.name if library_type else str(type_id)
            message = RemediationMessage.TYPE_MISMATCH.format(threat=threat.name, library_type=shown)
            part = "threat_type_id" if scenario.threat_type_id is not None else "threat_type_name"
            errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}", "message": message})
            reason = ConflictReason.TYPE_MISMATCH
        threat_type = library_type
    named_category = (scenario.threat_category_id, scenario.threat_category_name)
    category = _category(library, named_category, threat, threat_type, errors)
    if errors:
        raise Invalid(RemediationMessage.THREAT_REFS_INVALID, errors=errors, reason=reason)
    folded = category.casefold() if category is not None else None
    return {
        "category": category,
        "category_id": next(
            (row_id for row_id, name in library.category_ids if name.casefold() == folded), None
        ),
        "type_name": threat_type.name if threat_type else str(scenario.threat_type_name),
        "type_id": threat_type.row_id if threat_type else None,
        "threat_name": threat.name if threat is not None else str(scenario.threat_name),
        "catalogue_id": threat.row_id if threat is not None and in_library else None,
        "status": threat.status if threat is not None else None,
    }


def _library_rows(library: ThreatLibrary) -> tuple[list[_Known], list[_Known]]:
    """Types (live, pending) and threats (live, pending, curator-rejected); a name twice is the earlier's."""
    types = [_Known(t.type_id, t.name, LibraryStatus.ACTIVE, category=t.category) for t in library.types]
    threats = [
        _Known(t.catalogue_id, t.name, LibraryStatus.ACTIVE, t.type_id, t.categories) for t in library.threats
    ]
    for row in library.pending:
        if row.kind == LibraryRowKind.TYPE:
            types.append(_Known(row.row_id, row.name, LibraryStatus.PENDING))
        elif row.kind == LibraryRowKind.THREAT:
            threats.append(_Known(row.row_id, row.name, LibraryStatus.PENDING, row.type_id))
    threats += [
        _Known(row.catalogue_id, row.name, LibraryStatus.CURATOR_REJECTED, row.type_id)
        for row in library.curator_rejected
    ]
    return types, threats


def _named(
    rows: Sequence[_Known], row_id: int | None, name: str | None, part: str, errors: Errors
) -> _Known | None:
    """The row the scenario names by id, name or both; None for a new name. An unknown id, or an id and a
    name that disagree, is an error."""
    named: _Known | None = None
    if name:  # names compared normalised, any library code left out
        wanted = name_match_key(threat_name_without_code(name))
        named = next(
            (row for row in rows if name_match_key(threat_name_without_code(row.name)) == wanted), None
        )
    if row_id is None:
        return named
    by_id = next((row for row in rows if row.row_id == row_id), None)
    if by_id is None:
        message = RemediationMessage.UNKNOWN_ID.format(id=row_id)
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}_id", "message": message})
        return None
    if name and named is not by_id:
        message = RemediationMessage.ID_NAME_DISAGREE.format(id=row_id, library_name=by_id.name, name=name)
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.{part}_name", "message": message})
    return by_id


def _category(
    library: ThreatLibrary,
    given: tuple[int | None, str | None],
    threat: _Known | None,
    threat_type: _Known | None,
    errors: Errors,
) -> StrideCategory | None:
    """The STRIDE category given (one the threat is filed under), else the threat's first, else the type's."""
    filed = threat.categories if threat is not None else ()
    given_id, given_name = given
    if given_id is None and not given_name:
        return filed[0] if filed else (threat_type.category if threat_type else None)
    name = dict(library.category_ids).get(given_id, "") if given_id is not None else str(given_name)
    category = next((c for c in StrideCategory if c.value.casefold() == name.casefold()), None)
    part = "threat_category_id" if given_id is not None else "threat_category_name"
    field = f"{ManualScenario.FIELD_PREFIX}.{part}"
    if (
        given_id is not None and given_name and name and given_name.casefold() != name.casefold()
    ):  # both agree
        message = RemediationMessage.ID_NAME_DISAGREE.format(id=given_id, library_name=name, name=given_name)
        errors.append({"field": f"{ManualScenario.FIELD_PREFIX}.threat_category_name", "message": message})
    elif category is None:
        message = RemediationMessage.CATEGORY_UNKNOWN.format(name=name or given_id)
        errors.append({"field": field, "message": message})
    elif threat is not None and filed and category not in filed:
        message = RemediationMessage.CATEGORY_NOT_OF_THREAT.format(
            threat=threat.name, categories=", ".join(filed), category=category
        )
        errors.append({"field": field, "message": message})
    return category
