"""A plan for a hand-written scenario (`POST /v1/remediation` with `manual_scenario`): saved, planned and
replayed with no AI in the request; its plan job picks the attacker and proposes a new wording once. The
asset from the SQL test database; the library, the search, the proposal, the mapping and the chat faked."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ConflictReason,
    ErrorCode,
    Header,
    LibraryStatus,
    RemediationMessage,
    ResolveOutcome,
    RunKind,
    StrideCategory,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.data_access.scenario.asset_repository import AssetRepository
from app.domain.remediation.manual import manual_ids, manual_request_fingerprint
from app.models.library.library import LibraryControl
from app.models.remediation.requests import PlanRequest
from app.services.remediation.remediation_plan_service import RemediationPlanService
from tests.plan_addresses import plan_url
from tests.plan_job_fakes import (  # noqa: F401 — api_key_fixture and world_fixture are fixtures
    CONTROLS,
    api_key_fixture,
    deliver,
    fake_library,
    plan_answer,
    remediation_plan_job,
    remediation_plan_service,
    world_fixture,
)

IDENTITY = {Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}
#: v1's hand-written request: is_manual, the entity and the threat's flat fields (asset 103 is entity 86's).
BODY = {
    "is_manual": True,
    "all_supporting_systems_applicable": 1,
    "existing_controls_all_supporting_system_applicable": 1,
    "manual_scenario": {
        "asset_id": 103,
        "entity_id": 86,
        "supporting_system_id": [321, 322],
        "subsector_id": 11,
        "threat_type_name": "Malware",
        "threat_name": "Firmware tampering",
        "threat_scenario": "A cybercriminal could push unsigned firmware to the RTU; tell ops@example.com.",
        "risk_statement": "Loss of trusted control could interrupt electricity transmission.",
        "mapped_controls": ["CII-CID-1"],
    },
    "risk_level": "High",
}


def _manual_service(
    world: dict[str, Any], engine: Engine, controls: tuple[LibraryControl, ...]
) -> RemediationPlanService:
    """The remediation service on the SQL test database's assets, a library of `controls` and the world's
    send and publish fakes."""
    return remediation_plan_service(
        library=fake_library(controls),
        assets=AssetRepository(StoredProcedureClient(engine)),
        send_job=lambda *args: world["sent"].append(args),
        publish_remediation_status=world["published"].append,
    )


@pytest.fixture
def manual(client: TestClient, world: dict[str, Any], sql_test_engine: Engine) -> Iterator[dict[str, Any]]:
    """`world` with its service on the SQL test database's asset 103 (entity 86), and that `engine`."""
    world["engine"] = sql_test_engine
    built = _manual_service(world, sql_test_engine, tuple(CONTROLS.values()))
    client.app.dependency_overrides[container.get_remediation_plan_service] = lambda: built  # type: ignore[attr-defined]
    yield world
    client.app.dependency_overrides.pop(container.get_remediation_plan_service, None)  # type: ignore[attr-defined]


def _post(client: TestClient, key: str, body: dict[str, Any], idempotency_key: str | None) -> Any:
    headers = IDENTITY | {Header.API_KEY: key}
    if idempotency_key:
        headers[Header.IDEMPOTENCY_KEY] = idempotency_key
    return client.post("/v1/remediation", json=body, headers=headers)


def _planned(client: TestClient, key: str, body: dict[str, Any], manual: dict[str, Any]) -> dict[str, Any]:
    """A hand-written request answered 202, then its plan job run."""
    answer = _post(client, key, body, uuid.uuid4().hex)
    assert answer.status_code == 202, answer.text
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(answer.json()["remediation_id"])
    return answer.json()


def _with(**changes: Any) -> dict[str, Any]:
    return BODY | {"manual_scenario": BODY["manual_scenario"] | changes}


def _scenario(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})


def _plan(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def _runs_with_key(key: str) -> int:
    return get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key})


def _on(*system_ids: int) -> dict[str, Any]:
    """BODY sending the SCADA master station (321) alone, CII-CID-1 in the register on `system_ids`."""
    return _with(supporting_system_id=[321]) | {
        "existing_controls_all_supporting_system_applicable": 0,
        "existing_controls": [{"control_code": "CII-CID-1", "supporting_system_ids": list(system_ids)}],
    }


def test_existing_controls_name_the_assets_systems_and_a_refusal_saves_nothing(
    client: TestClient, api_key: str, manual: dict[str, Any]
) -> None:
    """Asset 103 has the SCADA master station (321) and the Process historian (322): a control on 323 (not
    the asset's) is a 422 that saves nothing, so the same key then works; one on the historian, which the
    request did not send, is accepted, and the risk on every system covers both of them."""
    key = uuid.uuid4().hex
    refused = _post(client, api_key, _on(323), key)
    assert refused.status_code == 422, refused.text
    assert [error["message"] for error in refused.json()["errors"]] == [
        RemediationMessage.SYSTEM_NOT_OF_ASSET.format(system_id=323, known="321, 322")
    ]
    assert _runs_with_key(key) == 0
    answer = _post(client, api_key, _on(322), key)
    assert answer.status_code == 202, answer.text
    extending = plan_answer("CII-CID-1")
    extending["controls_to_be_implemented"]["controls"][0]["description"] = "Extends signed firmware."
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, extending)
    deliver(answer.json()["remediation_id"])
    snapshot = _plan(answer.json()["remediation_id"])["versions"][0]["snapshot"]
    assert [system["name"] for system in snapshot["risk_scope"]["affected_systems"]] == [
        "SCADA master station",
        "Process historian",
    ]


def test_a_hand_written_scenario_is_saved_planned_and_replayed(
    client: TestClient, api_key: str, manual: dict[str, Any]
) -> None:
    """No AI in the request: the scenario is saved accepted, its ids from the key, and replayed (200) under
    the same key; its plan job picks the attacker on the person's words redacted, then plans."""
    key = uuid.uuid4().hex
    first = _post(client, api_key, BODY, key)
    assert first.status_code == 202, first.text
    planned = first.json()
    assert (planned["is_manual"], planned["replayed"]) == (True, False)
    assert (planned["session_id"], planned["scenario_id"]) == manual_ids(86, key)
    scenario = _scenario(planned["scenario_id"])
    assert (scenario["content"]["actors"], scenario["pending"]["actors"], manual["search"].queries) == (
        [],
        True,
        [],
    )
    assert _plan(planned["remediation_id"])["versions"][0]["snapshot"] is None
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": planned["session_id"]})
    assert (run["kind"], run["active"], run["counts"]["accepted"]) == (RunKind.MANUAL, False, 1)
    content = scenario["content"]
    # Two systems: any link between them is one the platform does not record.
    found = (scenario["source"], scenario["decision"], content["route"]["status"])
    assert found == (RunKind.MANUAL, "accepted", "unknown")
    threat = content["threat"]
    found = (threat["library_id"], threat["library_status"], content["category"])
    assert found == (10, LibraryStatus.ACTIVE, StrideCategory.TAMPERING) and content["category_id"] == 2
    item = scenario["controls"]["items"][0]
    assert (scenario["controls"]["status"], item["code"], item["match"]) == ("done", "CII-CID-1", "given")
    assert item["description"] == CONTROLS[1].description
    assert manual["sent"] == [(TaskName.WRITE_PLAN, planned["remediation_id"], 1)]
    again = _post(client, api_key, BODY, key)
    assert (again.status_code, again.json()) == (200, planned | {"replayed": True})
    other_entity = _with(entity_id=87)  # v1 sends the entity in the body: only the caller's
    assert _post(client, api_key, other_entity, uuid.uuid4().hex).status_code == 403
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(planned["remediation_id"])
    scenario = _scenario(planned["scenario_id"])
    actors = [(a["name"], a["role"], a["closest"]) for a in scenario["content"]["actors"]]
    assert actors == [("Organised crime group", "acting", False)] and "pending" not in scenario
    words = "A cybercriminal could push unsigned firmware to the RTU; tell [REDACTED]."
    assert manual["search"].queries == [f"Malware: Firmware tampering. {words}"]  # the address redacted
    version = _plan(planned["remediation_id"])["versions"][0]
    assert version["status"] == "done" and version["snapshot"]["threat"]["actors"][0]["role"] == "acting"
    given = (
        version["snapshot"]["existing_controls"]["library_mapped"][0],
        version["plan"]["control_assessment"][0],
    )
    assert [row["match"] for row in given] == ["given", "given"]  # as the scenario shows it
    assert (
        '"match":"exact"' in manual["chat"].asked(AiTask.REMEDIATION_PLAN)[-1]
    )  # the AI knows exact, nearest
    assert manual["mapper"].asked == [] and manual["proposals"] == []  # its controls given, its threat live
    listed = client.get("/v1/entities/86/scenarios", headers=IDENTITY | {Header.API_KEY: api_key})
    assert planned["scenario_id"] in [row["scenario_id"] for row in listed.json()["scenarios"]]
    # The writer has no plan path for it: regenerating it is refused by name, never a 500.
    url = f"/v1/sessions/{planned['session_id']}/regenerate/scenarios"
    regenerate = client.post(
        url, json={"scenario_ids": [planned["scenario_id"]]}, headers=IDENTITY | {Header.API_KEY: api_key}
    )
    assert (regenerate.status_code, regenerate.json()["errors"][0]["reason"]) == (409, "hand_written")
    next_set = client.post(
        f"/v1/sessions/{planned['session_id']}/scenarios/next-set",
        headers=IDENTITY | {Header.API_KEY: api_key},
    )
    assert next_set.status_code == 409


def test_the_key_is_required_and_names_one_request(
    client: TestClient, api_key: str, manual: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No key: 422. The key with another body, a generated run's key (even with this body's fingerprint), or
    a parallel request whose upsert met the first's run: 409, nothing proposed."""
    assert _post(client, api_key, BODY, None).status_code == 422
    key = uuid.uuid4().hex
    assert _post(client, api_key, BODY, key).status_code == 202
    another = _with(threat_scenario="Another attack, written differently.")
    other = _post(client, api_key, another, key)
    assert (other.status_code, other.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    generated, new_wording = uuid.uuid4().hex, _with(threat_name="Logic bomb")
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": uuid.uuid4().hex, "entity_id": 86, "asset_id": 103, "kind": RunKind.GENERATED,
         "idempotency_key": generated, "status": "done", "updated_at": datetime.now(UTC),
         "request_hash": manual_request_fingerprint(PlanRequest.model_validate(new_wording))}
    )  # fmt: skip
    taken = _post(client, api_key, new_wording, generated)
    assert (taken.status_code, taken.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    sessions = container.get_threat_scenario_session_repository()
    real_get = sessions.get
    monkeypatch.setattr(
        sessions,
        "get",
        lambda fields=None, **where: None if fields == "replay" else real_get(fields, **where),
    )  # the parallel request looked for the key before the first saved
    parallel = _post(client, api_key, another, key)
    assert (parallel.status_code, parallel.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    assert manual["proposals"] == []


def test_a_new_wording_is_proposed_once_by_the_plan_job_and_a_rejected_one_never(
    client: TestClient, api_key: str, manual: dict[str, Any]
) -> None:
    """A new threat of a live type: proposed with no actor links, once (a regenerate proposes nothing). A new
    type: linked to the closest attacker it was given (flagged). A curator-rejected wording: never proposed,
    saved without a library id. All by the plan job, as the person who asked."""
    request = _post(client, api_key, _with(threat_name="Logic bomb"), uuid.uuid4().hex).json()
    assert manual["proposals"] == []  # the request saved it; its plan job proposes it
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(request["remediation_id"])
    threat = _scenario(request["scenario_id"])["content"]["threat"]
    assert (threat["library_id"], threat["library_status"]) == (901, LibraryStatus.PENDING)
    proposal = manual["proposals"][0]
    found = (proposal.category, proposal.type_name, proposal.actor_ids, proposal.source, proposal.created_by)
    assert found == (StrideCategory.TAMPERING, "Malware", (), "manual", "u1")
    audit = get_mongodb()[Collection.AUDIT].find_one(
        {"action": AuditAction.LIBRARY_PROPOSED, "target.id": "901"}
    )
    assert audit is not None and audit["actor"]["user_id"] == "u1"
    headers = IDENTITY | {Header.API_KEY: api_key}
    url = plan_url(request["remediation_id"], "regenerate")
    assert client.post(url, json={}, headers=headers).status_code == 202
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(request["remediation_id"], 2)
    assert _plan(request["remediation_id"])["status"] == "done" and len(manual["proposals"]) == 1
    new_wording = _with(threat_type_name="Insider sabotage", threat_name="Logic bomb")
    new_type = _planned(client, api_key, new_wording, manual)
    actors = _scenario(new_type["scenario_id"])["content"]["actors"]
    assert [(a["name"], a["closest"]) for a in actors] == [("Organised crime group", True)]
    assert (manual["proposals"][1].actor_ids, manual["proposals"][1].category) == ((3,), None)
    rejected = _planned(client, api_key, _with(threat_name="Rogue USB"), manual)
    threat = _scenario(rejected["scenario_id"])["content"]["threat"]
    found = (threat["library_id"], threat["library_status"], len(manual["proposals"]))
    assert found == (None, LibraryStatus.CURATOR_REJECTED, 2)


def test_an_unknown_mapped_control_is_refused_and_none_given_are_mapped_by_the_plan_job(
    client: TestClient, api_key: str, manual: dict[str, Any]
) -> None:
    key = uuid.uuid4().hex
    unknown = _post(client, api_key, _with(mapped_controls=["CII-CID-1", "cii-cid-1", "CII-CID-77"]), key)
    assert unknown.status_code == 422  # a repeat is no fault, and the 422 names the entry's own place
    assert unknown.json()["errors"][0]["field"] == "body.manual_scenario.mapped_controls[2]"
    assert _runs_with_key(key) == 0  # nothing saved
    answer = _post(client, api_key, _with(mapped_controls=None), uuid.uuid4().hex)
    assert answer.status_code == 202 and manual["mapper"].asked == []  # never inside the request
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(answer.json()["remediation_id"])
    assert manual["mapper"].asked == [answer.json()["scenario_id"]]
    controls = _scenario(answer.json()["scenario_id"])["controls"]
    assert (controls["status"], [item["code"] for item in controls["items"]]) == ("done", ["CII-CID-1"])
    assert _plan(answer.json()["remediation_id"])["status"] == "done"


def test_nothing_is_saved_when_a_property_is_missing_or_the_control_library_is_empty(
    client: TestClient, api_key: str, manual: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hand-written scenario is held to a run's required properties (the refusal names the field where the
    request put it), and an empty control library is 409 before the first write: a retry under the same key
    is then a first request, never a 409 against an orphaned scenario."""
    key = uuid.uuid4().hex
    with monkeypatch.context() as required:
        required.setattr(get_settings(), "system_properties_required", "description")
        refused = _post(client, api_key, BODY, key)
    assert (refused.status_code, refused.json()["reason"]) == (422, "required_facts_missing")
    assert refused.json()["errors"][0]["field"] == "body.manual_scenario.supporting_system_id.1"
    assert _runs_with_key(key) == 0 and manual["proposals"] == []
    empty = _manual_service(manual, manual["engine"], ())
    client.app.dependency_overrides[container.get_remediation_plan_service] = lambda: empty  # type: ignore[attr-defined]
    refused = _post(client, api_key, _with(mapped_controls=None), key)
    assert (refused.status_code, refused.json()["reason"]) == (409, ErrorCode.CONTROL_LIBRARY_EMPTY)
    assert _runs_with_key(key) == 0


def test_a_deleted_runs_key_reused_with_another_wording_proposes_the_new_one(
    client: TestClient, api_key: str, manual: dict[str, Any]
) -> None:
    """The scenario id comes from the key, so it is the same again after its run's delete: the delete removes
    its operation records too, and the new wording reaches the library, never the old answer replayed."""
    asked: list[str] = []

    def resolve_threat(procedure: Any, **parameters: Any) -> list[list[dict[str, Any]]]:
        asked.append(parameters["ThreatName"])
        row = {"threat_type_id": 1, "threat_catalogue_id": 900 + len(asked)}
        return [[row | {"outcome": ResolveOutcome.CREATED_PENDING}]]

    procedures = SimpleNamespace(execute_procedure=resolve_threat)
    threats = ThreatRepository(procedures, SqlOperationRepository(procedures))  # type: ignore[arg-type]
    manual["job"] = remediation_plan_job(manual["chat"], manual, threats=threats)
    key, headers = uuid.uuid4().hex, IDENTITY | {Header.API_KEY: api_key}
    first = _post(client, api_key, _with(threat_name="Logic bomb"), key).json()
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(first["remediation_id"])
    assert client.delete(f"/v1/sessions/{first['session_id']}", headers=headers).status_code == 200
    again = _post(client, api_key, _with(threat_name="Time bomb"), key)
    assert again.status_code == 202 and again.json()["scenario_id"] == first["scenario_id"]
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(again.json()["remediation_id"])
    assert asked == ["Logic bomb", "Time bomb"]
    assert _scenario(first["scenario_id"])["content"]["threat"]["library_id"] == 902
