"""A plan for a hand-written scenario (#11 with `manual_scenario`; BLUEPRINT M11 R2; BUILD_PLAN S55): saved
and planned, replayed, key conflicts, strict control references; then its plan job (G262: the request makes no
AI call) ranks its attackers, proposes a new wording pending (a new type linked to its closest attacker),
never a curator-rejected one, and maps its controls when none were given. The asset from the SQL test
database; the library, the search, the proposal, the mapping and the chat faked."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ConflictReason,
    ErrorCode,
    Header,
    LibraryStatus,
    ResolveOutcome,
    RunKind,
    StrideCategory,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.library.repository import SqlServerRepository
from app.data_access.scenario.repository import scenario_sessions
from app.domain.remediation.manual_records import manual_request_fingerprint
from app.models.library import LoadedLibraries
from app.models.remediation_requests import PlanRequest
from app.services.remediation.manual import ManualPlans, get_manual_plans
from app.services.remediation.manual_scenarios import ManualScenarios
from app.worker.tasks import remediation as plan_job
from tests.test_remediation_planner import _answer, _control
from tests.test_remediation_requests import (  # noqa: F401 — api_key and world are fixtures
    _deliver,
    _service,
    api_key,
    world,
)
from tests.test_remediation_snapshot import LIBRARY as CONTROLS
from tests.test_threat_identity import LIBRARY as THREATS

IDENTITY = {Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}
#: v1's hand-written request (owner, 2026-10-15): is_manual, the entity and the threat's flat fields.
BODY = {
    "is_manual": True,
    "manual_scenario": {
        "asset_id": 103,
        "entity_id": 86,
        "supporting_system_id": [321, 322],
        "subsector_id": 11,
        "threat_type_name": "Malware",
        "threat_name": "Firmware tampering",
        "threat_scenario": "A cybercriminal could push unsigned firmware to the RTU during maintenance.",
        "risk_statement": "Loss of trusted control could interrupt electricity transmission.",
        "mapped_controls": ["CII-CID-1"],
    },
    "risk_level": "High",
}


@pytest.fixture
def manual(
    client: TestClient,
    world: dict[str, Any],  # noqa: F811
    sql_test_engine: Engine,
) -> Iterator[dict[str, Any]]:
    """ManualPlans on the SQL test database's asset 103 (entity 86) and the fakes; the plan job's fakes
    (world: mapper, search, proposals, chat)."""
    library = SimpleNamespace(
        check_library_once=lambda: None,
        get_loaded_libraries=lambda: LoadedLibraries((), THREATS, tuple(CONTROLS.values())),
    )
    scenarios = ManualScenarios(
        SqlServerRepository(StoredProcedureClient(sql_test_engine)),
        library,  # type: ignore[arg-type]
    )
    built = ManualPlans(scenario_sessions, scenarios, _service())
    client.app.dependency_overrides[get_manual_plans] = lambda: built  # type: ignore[attr-defined]
    yield world
    client.app.dependency_overrides.pop(get_manual_plans, None)  # type: ignore[attr-defined]


def _post(client: TestClient, key: str, body: dict[str, Any], idempotency_key: str | None) -> Any:
    headers = IDENTITY | {Header.API_KEY: key}
    if idempotency_key:
        headers[Header.IDEMPOTENCY_KEY] = idempotency_key
    return client.post("/v1/remediation", json=body, headers=headers)


def _planned(client: TestClient, key: str, body: dict[str, Any], manual: dict[str, Any]) -> dict[str, Any]:
    """A hand-written request answered 202, then its plan job run (input completed, plan written)."""
    answer = _post(client, key, body, uuid.uuid4().hex)
    assert answer.status_code == 202, answer.text
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(answer.json()["remediation_id"])
    return answer.json()


def _with(**changes: Any) -> dict[str, Any]:
    return BODY | {"manual_scenario": BODY["manual_scenario"] | changes}


def _scenario(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})


def test_a_hand_written_scenario_is_saved_planned_and_replayed(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    key = uuid.uuid4().hex
    first = _post(client, api_key, BODY, key)
    assert first.status_code == 202, first.text
    planned = first.json()
    assert (planned["is_manual"], planned["replayed"]) == (True, False)
    scenario = _scenario(planned["scenario_id"])
    # G262: no AI in the request: its attackers wait for its plan job, the snapshot with them.
    assert (scenario["content"]["actors"], scenario["pending"]["actors"], manual["search"].queries) == (
        [],
        True,
        [],
    )
    record = get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": planned["remediation_id"]})
    assert record["versions"][0]["snapshot"]["pending"] is True
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
    assert item["description"] == next(c.description for c in CONTROLS.values() if c.code == "CII-CID-1")
    assert manual["sent"] == [(TaskName.WRITE_PLAN, planned["remediation_id"], 1)]
    again = _post(client, api_key, BODY, key)  # v1: the same key and body replay the first answer
    assert (again.status_code, again.json()) == (200, planned | {"replayed": True})
    other_entity = _with(entity_id=87)  # v1 sends the entity in the body: only the caller's
    assert _post(client, api_key, other_entity, uuid.uuid4().hex).status_code == 403
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(planned["remediation_id"])  # its plan job: the attackers, then the snapshot, then the plan
    scenario = _scenario(planned["scenario_id"])
    actors = [(a["name"], a["role"], a["closest"]) for a in scenario["content"]["actors"]]
    assert actors == [("Organised crime group", "acting", False)] and "pending" not in scenario
    version = get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": planned["remediation_id"]})["versions"][
        0
    ]
    shown = version["snapshot"]["existing_controls"]["library_mapped"][0]
    assert (shown["match"], shown["mapping_relevance"]) == ("exact", None)  # the prompt knows exact, nearest
    assert version["status"] == "done" and version["snapshot"]["threat"]["actors"][0]["role"] == "acting"
    assert (
        manual["mapper"].asked == [] and manual["proposals"] == []
    )  # its controls were given; its threat live
    listed = client.get("/v1/entities/86/scenarios", headers=IDENTITY | {Header.API_KEY: api_key})
    assert planned["scenario_id"] in [row["scenario_id"] for row in listed.json()["scenarios"]]
    # The writer has no plan path for it: regenerating it is refused by name, never a 500 (no write job).
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


def test_a_required_property_not_recorded_saves_nothing(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G197 (owner 2026-10-11): a hand-written scenario is held to the same required properties as a run;
    the refusal names the field where the request put it, and nothing is proposed or saved."""
    monkeypatch.setattr(get_settings(), "system_properties_required", "description")
    key = uuid.uuid4().hex
    refused = _post(client, api_key, BODY, key)
    assert (refused.status_code, refused.json()["reason"]) == (422, "required_facts_missing")
    assert refused.json()["errors"][0]["field"] == "body.manual_scenario.supporting_system_id.1"
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0
    assert manual["proposals"] == []


def test_the_key_is_required_and_names_one_request(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    assert _post(client, api_key, BODY, None).status_code == 422
    key = uuid.uuid4().hex
    assert _post(client, api_key, BODY, key).status_code == 202
    other = _post(client, api_key, _with(threat_scenario="Another attack, written differently."), key)
    assert (other.status_code, other.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    # A generated run's key, even with this very body's fingerprint: refused before anything is saved.
    generated, new_wording = uuid.uuid4().hex, _with(threat_name="Logic bomb")
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": uuid.uuid4().hex, "entity_id": 86, "asset_id": 103, "kind": RunKind.GENERATED,
         "idempotency_key": generated, "status": "done", "updated_at": datetime.now(UTC),
         "request_hash": manual_request_fingerprint(PlanRequest.model_validate(new_wording))}
    )  # fmt: skip
    taken = _post(client, api_key, new_wording, generated)
    assert (taken.status_code, taken.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    assert manual["proposals"] == []


def test_a_parallel_request_with_the_key_and_another_body_is_refused(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both looked for the key before either saved: the second's upsert keeps the first's run, so it is 409,
    never planned from (or replayed as) the first's scenario."""
    key = uuid.uuid4().hex
    assert _post(client, api_key, BODY, key).status_code == 202
    real_get = scenario_sessions.get
    monkeypatch.setattr(
        scenario_sessions,
        "get",
        lambda fields=None, **where: None if fields == "replay" else real_get(fields, **where),
    )
    other = _post(client, api_key, _with(threat_scenario="Another attack, written differently."), key)
    assert (other.status_code, other.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)


def test_new_wordings_are_proposed_pending_by_the_plan_job_and_a_rejected_one_is_not(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    """A new threat of a live type: proposed with no actor links. A new type: linked to the closest attacker
    it was given (flagged). A curator-rejected wording: never proposed, saved without a library id. All by the
    plan job, as the person who asked (G262: the request proposes nothing, it calls no AI)."""
    request = _post(client, api_key, _with(threat_name="Logic bomb"), uuid.uuid4().hex).json()
    assert manual["proposals"] == []  # the request saved it; its plan job proposes it
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(request["remediation_id"])
    threat = _scenario(request["scenario_id"])["content"]["threat"]
    assert (threat["library_id"], threat["library_status"]) == (901, LibraryStatus.PENDING)
    proposal = manual["proposals"][0]
    found = (proposal.category, proposal.type_name, proposal.actor_ids, proposal.source, proposal.created_by)
    assert found == (StrideCategory.TAMPERING, "Malware", (), "manual", "u1")
    audit = get_mongodb()[Collection.AUDIT].find_one(
        {"action": AuditAction.LIBRARY_PROPOSED, "target.id": "901"}
    )
    assert audit is not None and audit["actor"]["user_id"] == "u1"
    body = _with(threat_type_name="Insider sabotage", threat_name="Logic bomb")
    new_type = _planned(client, api_key, body, manual)
    actors = _scenario(new_type["scenario_id"])["content"]["actors"]
    assert [(a["name"], a["closest"]) for a in actors] == [("Organised crime group", True)]
    assert (manual["proposals"][1].actor_ids, manual["proposals"][1].category) == ((3,), None)
    rejected = _planned(client, api_key, _with(threat_name="Rogue USB"), manual)
    threat = _scenario(rejected["scenario_id"])["content"]["threat"]
    found = (threat["library_id"], threat["library_status"], len(manual["proposals"]))
    assert found == (None, LibraryStatus.CURATOR_REJECTED, 2)


def test_controls_named_strictly_else_mapped_by_the_plan_job(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    key = uuid.uuid4().hex
    unknown = _post(client, api_key, _with(mapped_controls=["CII-CID-1", "CII-CID-77"]), key)
    assert unknown.status_code == 422
    assert unknown.json()["errors"][0]["field"] == "body.manual_scenario.mapped_controls[1]"
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0  # nothing saved
    answer = _post(client, api_key, _with(mapped_controls=None), uuid.uuid4().hex)
    assert answer.status_code == 202 and manual["mapper"].asked == []  # G262: not inside the request
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(answer.json()["remediation_id"])
    assert manual["mapper"].asked == [answer.json()["scenario_id"]]
    controls = _scenario(answer.json()["scenario_id"])["controls"]
    assert (controls["status"], [item["code"] for item in controls["items"]]) == ("done", ["CII-CID-1"])


def test_a_refused_register_saves_nothing_and_the_persons_words_are_redacted(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    """Review S56: the register is checked before the run and the scenario are saved, so a corrected retry
    under the same key is a first request, never a 409 against an orphan; the person's text goes to the
    embedding model redacted (by the plan job, G262)."""
    key = uuid.uuid4().hex
    wording = _with(threat_name="Logic bomb", threat_scenario="Mail ops@example.com a bad image.")
    refused = wording | {"existing_controls": [{"control_id": 1, "control_code": "CII-CID-2"}]}
    assert _post(client, api_key, refused, key).status_code == 422
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0
    assert manual["proposals"] == []
    answer = _post(client, api_key, wording, key)
    assert answer.status_code == 202
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(answer.json()["remediation_id"])
    assert manual["search"].queries[-1] == "Malware: Logic bomb. Mail [REDACTED] a bad image."


def test_a_deleted_runs_key_reused_with_another_wording_proposes_the_new_one(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scenario id comes from the key, so it is the same again after its run's delete: the delete removes
    its operation records too, and the new wording reaches the library, never the old answer replayed."""
    asked: list[str] = []

    def resolve_threat(procedure: Any, **parameters: Any) -> list[list[dict[str, Any]]]:
        asked.append(parameters["ThreatName"])
        row = {"threat_type_id": 1, "threat_catalogue_id": 900 + len(asked)}
        return [[row | {"outcome": ResolveOutcome.CREATED_PENDING}]]

    procedures = SimpleNamespace(execute_procedure=resolve_threat)
    monkeypatch.setattr(plan_job.get_plan_inputs(), "_proposals", SqlServerRepository(procedures))  # type: ignore[arg-type]
    key, headers = uuid.uuid4().hex, IDENTITY | {Header.API_KEY: api_key}
    first = _post(client, api_key, _with(threat_name="Logic bomb"), key).json()
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(first["remediation_id"])
    assert client.delete(f"/v1/sessions/{first['session_id']}", headers=headers).status_code == 200
    again = _post(client, api_key, _with(threat_name="Time bomb"), key)
    assert again.status_code == 202 and again.json()["scenario_id"] == first["scenario_id"]
    manual["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(again.json()["remediation_id"])
    assert asked == ["Logic bomb", "Time bomb"]
    assert _scenario(first["scenario_id"])["content"]["threat"]["library_id"] == 902


def test_an_empty_control_library_refuses_a_hand_written_request_before_anything_is_saved(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
    sql_test_engine: Engine,
) -> None:
    """409 control_library_empty before the first write, so a retry under the same key once the library is
    back is a first request, never a 409 against an orphaned scenario."""
    library = SimpleNamespace(
        check_library_once=lambda: None,
        get_loaded_libraries=lambda: LoadedLibraries((), THREATS, ()),
    )
    scenarios = ManualScenarios(SqlServerRepository(StoredProcedureClient(sql_test_engine)), library)  # type: ignore[arg-type]
    built = ManualPlans(scenario_sessions, scenarios, _service())
    client.app.dependency_overrides[get_manual_plans] = lambda: built  # type: ignore[attr-defined]
    key = uuid.uuid4().hex
    refused = _post(client, api_key, _with(mapped_controls=None), key)
    assert (refused.status_code, refused.json()["reason"]) == (409, ErrorCode.CONTROL_LIBRARY_EMPTY)
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0
