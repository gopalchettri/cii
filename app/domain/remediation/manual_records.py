"""A hand-written scenario saved as a run and a scenario (BLUEPRINT M11 R2 step 6; BUILD_PLAN S55), under ids
derived from the entity and the Idempotency-Key, so a retry after a crash lands on the same documents. The
scenario carries every field a generated one does (lists and views read them alike), is accepted by the
person who wrote it, and has no title (A-11). Its attackers, and the library proposal of a new wording, are
its plan job's (`pending`, G262): a request makes no AI call. Pure."""

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from app.core.constants import (
    ConflictReason,
    ControlMatch,
    Decision,
    ErrorCode,
    Header,
    PlanMessage,
    RemediationMessage,
    Route,
    RunKind,
    ScenarioStatus,
    SessionMessage,
    Status,
    Step,
)
from app.core.exceptions import Conflict, Forbidden, Invalid, Unavailable
from app.models.admin.api_clients import Principal
from app.models.library.library import LibraryActor, LibraryControl
from app.models.remediation.plan import ThreatIdentity
from app.models.remediation.requests import ManualScenario, PlanRequest
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.plan import PlannedActor

#: A hand-written scenario's path: one per manual run.
MANUAL_PATH = "manual"


def check_manual_request(principal: Principal, body: PlanRequest, key: str | None) -> ManualScenario:
    """The hand-written scenario a plan is requested for: 422 without an Idempotency-Key, 403 when the body
    names another entity (v1 sends the entity in the body: the caller's only)."""
    if not key:
        message = RemediationMessage.IDEMPOTENCY_KEY_REQUIRED
        raise Invalid(message, errors=[{"field": f"header.{Header.IDEMPOTENCY_KEY}", "message": message}])
    manual = body.manual_scenario
    assert manual is not None  # PlanRequest: is_manual=true
    if manual.entity_id != principal.entity_id:
        raise Forbidden(SessionMessage.ENTITY_MISMATCH_BODY)
    return manual


def manual_request_fingerprint(body: PlanRequest) -> str:
    """SHA-256 of the whole request (scenario and register): a key replays only the request it first named."""
    return hashlib.sha256(json.dumps(body.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def check_same_manual_request(earlier: dict[str, Any], manual: ManualScenario, fingerprint: str) -> None:
    """409 idempotency_key_conflict when the key's earlier run is not this hand-written request."""
    same = (
        earlier.get("kind") == RunKind.MANUAL
        and earlier["asset_id"] == manual.asset_id
        and earlier.get("request_hash") == fingerprint
    )
    if not same:
        raise Conflict(
            SessionMessage.IDEMPOTENCY_KEY_CONFLICT, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT
        )


def check_actor_library(actors: tuple[LibraryActor, ...]) -> None:
    """503 while the threat library has no attacker: its plan job could never name one."""
    if not actors:
        raise Unavailable(PlanMessage.ACTOR_LIBRARY_EMPTY, reason=ErrorCode.ACTOR_LIBRARY_EMPTY)


def manual_ids(entity_id: int, idempotency_key: str) -> tuple[str, str]:
    """(the run's id, the scenario's id), the same for every retry with this key."""
    base = f"{entity_id}:{idempotency_key}"
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{base}:run").hex, uuid.uuid5(
        uuid.NAMESPACE_URL, f"{base}:scenario"
    ).hex


def manual_run_record(  # noqa: PLR0913 — one record, whole
    principal: Principal,
    scenario: ManualScenario,
    run_id: str,
    idempotency_key: str,
    request_hash: str,
    context: FrozenContext,
    now: datetime,
) -> dict[str, Any]:
    """Born done and inactive: it plans nothing, and never holds the asset's one active run."""
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


def manual_scenario_record(  # noqa: PLR0913 — one record, whole
    principal: Principal,
    scenario: ManualScenario,
    ids: tuple[str, str],
    identity: ThreatIdentity,
    context: FrozenContext,
    controls: dict[str, Any],
    by: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """`by`: who asked (the audit actor of the library proposal its plan job may make)."""
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
        "content": _content(scenario, identity, context),
        # What its plan job finds first (app/worker/remediation/plan_inputs.py); removed once found.
        "pending": {"actors": True, "proposal": identity.status is None, "by": by},
        "findings": [],  # the code checks are for AI text only (W5)
        "plan_check": None,
        "controls": controls,
        "created_at": now,
        "updated_at": now,
    }


def actor_records(planned: tuple[PlannedActor, ...], closest: bool) -> list[dict[str, Any]]:
    """The acting attacker as a generated scenario's, flagged when it is only the closest match."""
    return [
        {
            "id": actor.actor_id,
            "name": actor.name,
            "role": actor.role,
            "closest": closest and i == 0,
        }
        for i, actor in enumerate(planned)
    ]


def _content(scenario: ManualScenario, identity: ThreatIdentity, context: FrozenContext) -> dict[str, Any]:
    """The scenario as the person wrote it, with its threat as the library knows it and its systems (the first
    is the entry point); its attackers come from its plan job."""
    names = {system["id"]: system["name"] for system in context.systems}
    return {
        "title": None,
        "statement": scenario.threat_scenario,
        "risk_statement": scenario.risk_statement,
        "why_applies": None,
        "assumptions": [],
        "category": identity.category,
        "category_id": identity.category_id,
        "contributing_categories": [],
        "threat": {
            "type": identity.type_name,
            "type_id": identity.type_id,
            "name": identity.threat_name,
            "library_id": identity.catalogue_id,
            "library_status": identity.status,
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


def given_controls(controls: tuple[LibraryControl, ...], now: datetime) -> dict[str, Any]:
    """The person's own controls, in the order given; none given → waiting for its plan job (G262)."""
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
