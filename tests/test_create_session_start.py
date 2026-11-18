"""POST /v1/create_session: the start of a run the AI writes from MITRE ATT&CK. The same body, checks, answers
and Idempotency-Key rules as POST /v1/sessions, on the SQL test database (entity 86: OT asset 103 with systems
321 and 322; IT asset 105 with system 323); and POST /v1/sessions still stores what it always stored."""

import dataclasses
import re
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.api import deps
from app.core.config import get_settings
from app.core.constants import (
    AiApi,
    AttackMessage,
    AttackRecord,
    AuditAction,
    Collection,
    ConflictReason,
    Header,
    IntelSource,
    RunPipeline,
    Status,
    Step,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.crud import admin as admin_crud
from app.crud import scenarios as scenario_crud
from app.crud.attack import attack_doc_id, get_attack_repository
from app.crud.jobs import JobRepository
from app.domain.scenario import attack, write
from app.domain.scenario import runs as scenario_runs
from app.domain.scenario.attack_prompt import build_attack_prompt
from app.domain.scenario.plan import describe_asset_for_ai
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import FrozenContext
from app.schemas.scenarios import StartRunRequest
from tests.planner_samples import ACTORS, THREATS

URL = "/v1/create_session"
START = {"asset_id": 103, "supporting_system_id": [321, 322], "subsector_id": 11}
#: The IT asset of the SQL test database, with its IT system.
BILLING = {"asset_id": 105, "supporting_system_id": [323], "sector_id": 10}
DATA_HANDLED = "Customer names, meter readings and payment records"
GRID_DATA_HANDLED = "Telemetry and switching commands"  # asset 103's, as tsg_GetAssetContext returns it
LIBRARY, ROOM = ThreatLibrary(THREATS, ACTORS), 20_000
ICS, ENTERPRISE = IntelSource.ATTACK_ICS, IntelSource.ATTACK_ENTERPRISE


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = admin_crud.create_api_client(get_mongodb(), f"create-session-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture(autouse=True)
def world(client: TestClient, sql_test_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Asset facts from the SQL test database, MITRE ATT&CK imported, each job sent recorded (`sent`), and both
    assets free of earlier runs."""
    state: dict[str, Any] = {"sent": []}
    monkeypatch.setattr(scenario_crud, "get_stored_procedure_client", lambda: StoredProcedureClient(sql_test_engine))
    _import_attack(ICS, ENTERPRISE)
    monkeypatch.setattr(scenario_runs, "send_job", lambda *sent: state["sent"].append(sent))
    get_mongodb()[Collection.SESSIONS].delete_many({"entity_id": 86, "asset_id": {"$in": [103, 105]}})
    return state


def _forget_attack_import() -> None:
    get_mongodb()[Collection.ATTACK].delete_many({})


def _import_attack(*sources: IntelSource) -> None:
    """Only these sources hold ATT&CK data: one object each, enough for a start, which asks no more."""
    _forget_attack_import()
    for source in sources:
        imported = {"_id": attack_doc_id(source, "intrusion-set--sandworm"), "record": AttackRecord.OBJECT}
        get_attack_repository().replace_source(source, [imported], "v1")


def _identity(api_key: str) -> dict[str, str]:
    return {Header.API_KEY: api_key, Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}


def _start(client: TestClient, api_key: str, body: dict[str, Any] = START, url: str = URL, **headers: str) -> Any:
    """A start with a new Idempotency-Key, unless `headers` name one."""
    new_key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    return client.post(url, json=body, headers=_identity(api_key) | new_key | headers)


def _run(session_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SESSIONS].find_one({"_id": session_id})


def _stored_runs() -> int:
    return get_mongodb()[Collection.SESSIONS].count_documents({"entity_id": 86, "asset_id": {"$in": [103, 105]}})


def test_a_start_stores_the_attack_run_with_its_starting_plan_and_queues_the_write_job(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """202 with the status board; the record carries pipeline attack at step scenarios, the starting plan
    built from the frozen context at the run's own time, and a write job a worker can claim at once.
    Mutation: leave `pipeline` out and the worker writes the run as a library run."""
    response = _start(client, api_key)
    assert response.status_code == 202, response.text
    body = response.json()
    assert (body["entity_id"], body["asset_id"], body["asset_name"]) == (86, 103, "Grid control centre")
    assert (body["session_status"], body["user_id"]) == ("active", "u1") and "client_id" not in body
    run = _run(body["session_id"])
    assert (run["pipeline"], run["kind"], run["status"], run["step"]) == (
        RunPipeline.ATTACK,
        "generated",
        Status.QUEUED,
        Step.SCENARIOS,
    )
    built = attack.build_starting_plan(FrozenContext.from_record(run["context"]), run["created_at"])
    assert (run["plan"], run["plan_trace"], run["counts"]) == (built["plan"], built["plan_trace"], built["counts"])
    assert run["plan"]["paths"] and run["plan"]["frozen_at"] == run["created_at"]
    job = run["job"]
    assert (job["task"], job["epoch"], job["batch"], job["set"]) == (
        TaskName.WRITE_SCENARIOS,
        1,
        built["batch"],
        built["set"],
    )
    assert (job["attempts"], job["due_at"], job["request_id"]) == (
        0,
        run["created_at"],
        response.headers[Header.REQUEST_ID],
    )
    client_id = admin_crud.get_active_client_id(get_mongodb(), api_key)
    assert job["origin"] == {"api": AiApi.CREATE_SESSION, "client_id": client_id, "entity_id": 86}
    assert (run["client_id"], run["user_id"], run["tenant_id"]) == (client_id, "u1", "DESC")
    assert run["last_action"] == {
        "kind": "start",
        "outcome": "running",
        "reason": None,
        "started_at": run["created_at"],
    }
    request = StartRunRequest.model_validate(START)
    assert run["request"] == request.model_dump(exclude={"asset_id"})
    assert run["request_hash"] == f"attack:{request.fingerprint()}"
    assert [(system["alias"], system["id"]) for system in run["context"]["systems"]] == [("SYS1", 321), ("SYS2", 322)]
    assert world["sent"] == [(TaskName.WRITE_SCENARIOS, run["_id"], 1)]
    audited = get_mongodb()[Collection.AUDIT].find_one({"target.id": run["_id"]})
    assert (audited["action"], audited["after"]) == (
        AuditAction.RUN_STARTED,
        {"asset_id": 103, "supporting_system_ids": [321, 322]},
    )
    lease = JobRepository(get_mongodb()[Collection.SESSIONS]).claim_job(run["_id"], 1, TaskName.WRITE_SCENARIOS, "w1")
    assert lease is not None


def test_a_started_run_holds_its_first_set_and_reads_like_any_other_run(client: TestClient, api_key: str) -> None:
    """With the real starting plan: the first set is INITIAL_SET_SIZE slots (TOTAL_SCENARIO_COUNT when that is
    smaller and not 0), every one in the job's set; the status and the plan trace read at once."""
    settings = get_settings()
    wanted = min(settings.initial_set_size, settings.total_scenario_count or settings.initial_set_size)
    session_id = _start(client, api_key).json()["session_id"]
    run = _run(session_id)
    selected = [path["path_id"] for path in run["plan"]["paths"] if path["selected"]]
    assert len(selected) == wanted and run["job"]["set"] == selected
    assert [item["path_id"] for item in run["job"]["batch"]] == selected[: len(run["job"]["batch"])] != []
    assert (run["counts"]["planned"], run["counts"]["remaining"]) == (wanted, wanted)
    assert run["plan"]["frozen_at"] == run["created_at"]
    headers = _identity(api_key)
    status = client.get(f"/v1/sessions/{session_id}", headers=headers)
    assert status.status_code == 200 and status.json()["progress"]["scenario_count"]["total"] == wanted
    trace = client.get(f"/v1/sessions/{session_id}/plan-trace", headers=headers)
    assert trace.status_code == 200, trace.text
    assert trace.json()["counts"]["selected"] == wanted


def test_the_same_key_replays_the_run_and_another_request_or_route_is_refused(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """The same key and body: 200 with the same run, no second job. The key with another body, or on the
    other start route, is 409: one key never answers with the other route's run."""
    key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    first, again = _start(client, api_key, **key), _start(client, api_key, **key)
    assert (first.status_code, again.status_code) == (202, 200), again.text
    assert again.json()["session_id"] == first.json()["session_id"] and len(world["sent"]) == 1
    reordered = _start(client, api_key, START | {"supporting_system_id": [322, 321]}, **key)
    assert (reordered.status_code, reordered.json()["session_id"]) == (200, first.json()["session_id"])
    for other in (
        _start(client, api_key, START | {"supporting_system_id": [321]}, **key),
        _start(client, api_key, url="/v1/sessions", **key),
    ):
        assert (other.status_code, other.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    library_key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    assert _start(client, api_key, url="/v1/sessions", **library_key).status_code == 202
    crossed = _start(client, api_key, **library_key)
    assert (crossed.status_code, crossed.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    assert _stored_runs() == 2


def test_a_keyless_repeat_is_refused_naming_the_first_run(
    client: TestClient, api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No Idempotency-Key: the server derives one from the caller, route, body and minute, so the same start
    again is 409 duplicate_request naming the run; the same body on POST /v1/sessions is another request."""
    monkeypatch.setattr(deps, "epoch_seconds", lambda: 1_800_000_000.0)  # one window for every request
    first = client.post(URL, json=START, headers=_identity(api_key))
    again = client.post(URL, json=START, headers=_identity(api_key))
    assert first.status_code == 202, first.text
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.DUPLICATE_REQUEST), again.text
    assert again.json()["details"]["session_id"] == first.json()["session_id"]
    assert first.headers[Header.IDEMPOTENCY_KEY].startswith("derived-")
    assert client.post("/v1/sessions", json=START, headers=_identity(api_key)).status_code == 202


def test_a_start_without_attack_data_is_refused_before_the_asset_is_read(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing imported: 409 intel_no_data naming the import API, no SQL read, no run, no job. A replay of a
    run started before the data went is still answered."""
    key = {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex}
    started = _start(client, api_key, **key)
    _forget_attack_import()
    monkeypatch.setattr(scenario_runs, "get_asset_context", lambda *args: pytest.fail("the asset was read"))
    refused = _start(client, api_key)
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.INTEL_NO_DATA), refused.text
    assert refused.json()["detail"] == AttackMessage.NO_DATA and "POST /v1/tsg/intel/refresh" in AttackMessage.NO_DATA
    assert (_stored_runs(), len(world["sent"])) == (1, 1)
    assert _start(client, api_key, **key).json()["session_id"] == started.json()["session_id"]


def test_a_start_is_refused_while_the_matrix_its_asset_needs_is_not_imported(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Enterprise for IT, ICS for OT, both for an OT asset with an IT system: a start whose matrix holds no data
    is 409 intel_no_data once its asset is read, with no run and no job.
    Mutation: ask only whether anything is imported, and an OT run starts while ICS is missing: every scenario
    it writes is refused after a paid re-ask."""
    ot_only = START | {"supporting_system_id": [321]}
    _import_attack(ENTERPRISE)
    assert _start(client, api_key, BILLING).status_code == 202
    for body in (ot_only, START):
        refused = _start(client, api_key, body)
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.INTEL_NO_DATA), refused.text
        assert refused.json()["detail"] == AttackMessage.NO_DATA
    assert (_stored_runs(), len(world["sent"])) == (1, 1)
    _import_attack(ICS)
    assert _start(client, api_key, ot_only).status_code == 202
    for body in (START, BILLING):
        assert _start(client, api_key, body).json().get("reason") == ConflictReason.INTEL_NO_DATA
    assert (_stored_runs(), len(world["sent"])) == (2, 2)


def test_a_hybrid_asset_needs_both_matrices_imported_whatever_its_systems_are(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    r"""The procedure gives asset 105 the category IT\OT: with its IT system it still needs Enterprise and ICS,
    409 intel_no_data while either is missing. Mutation: map IT\OT to itself only, and it starts without ICS."""
    read = scenario_runs.get_asset_context

    def read_as_hybrid(*args: Any) -> Any:
        rows = read(*args)
        return dataclasses.replace(rows, asset=rows.asset | {"category_code": "IT\\OT"})

    monkeypatch.setattr(scenario_runs, "get_asset_context", read_as_hybrid)
    for imported in (ENTERPRISE, ICS):
        _import_attack(imported)
        refused = _start(client, api_key, BILLING)
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.INTEL_NO_DATA), refused.text
    assert (_stored_runs(), world["sent"]) == (0, [])
    _import_attack(ENTERPRISE, ICS)
    started = _frozen_context(_start(client, api_key, BILLING))
    assert started.asset["category_code"] == "IT\\OT" and len(world["sent"]) == 1
    assert "the MITRE ATT&CK Enterprise and ICS matrices" in _attack_prompt(started)


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"asset_id": 103}, "body.supporting_system_id"),
        (START | {"supporting_system_id": []}, "body.supporting_system_id"),
        (START | {"asset_id": 0}, "body.asset_id"),
        (START | {"asset_id": "grid"}, "body.asset_id"),
        (START | {"sector_idd": 5}, "body.sector_idd"),
        (START | {"data_handled": "Grid telemetry"}, "body.data_handled"),  # an asset fact, never a field
    ],
)
def test_a_bad_body_is_refused_naming_the_field(
    client: TestClient, api_key: str, world: dict[str, Any], body: dict[str, Any], field: str
) -> None:
    response = _start(client, api_key, body)
    assert response.status_code == 422, response.text
    assert [error["field"] for error in response.json()["errors"]] == [field]
    assert (_stored_runs(), world["sent"]) == (0, [])


@pytest.mark.parametrize(
    ("body", "status", "reason"),
    [
        (START | {"asset_id": 104}, 403, "asset_not_owned"),
        (START | {"supporting_system_id": [321, 323]}, 403, "system_not_linked"),
        (START | {"sector_id": 99}, 422, None),  # not the sub-sector's parent
        (START | {"service_id": 77}, 404, None),
    ],
)
def test_what_the_asset_facts_refuse_for_a_run_they_refuse_here(
    client: TestClient, api_key: str, world: dict[str, Any], body: dict[str, Any], status: int, reason: str | None
) -> None:
    response = _start(client, api_key, body)
    assert (response.status_code, response.json().get("reason")) == (status, reason), response.text
    assert (_stored_runs(), world["sent"]) == (0, [])


def _frozen_context(response: Any) -> FrozenContext:
    assert response.status_code == 202, response.text
    return FrozenContext.from_record(_run(response.json()["session_id"])["context"])


def _attack_prompt(context: FrozenContext) -> str:
    return "\n".join(build_attack_prompt(context, [{"slot": "SC1"}], [], True, LIBRARY, ROOM))


def test_the_data_an_asset_handles_comes_from_the_procedure_and_reaches_both_routes_prompts(
    client: TestClient, api_key: str
) -> None:
    """data_handled is a column of tsg_GetAssetContext, so both routes freeze each asset's own value and both
    show it to the AI."""
    for url in (URL, "/v1/sessions"):
        billing = _frozen_context(_start(client, api_key, BILLING, url=url))
        grid = _frozen_context(_start(client, api_key, url=url))
        assert (billing.asset_context["data_handled"], grid.asset_context["data_handled"]) == (
            DATA_HANDLED,
            GRID_DATA_HANDLED,
        )
        shown = f'"data_handled": "{DATA_HANDLED}"'
        assert shown in _attack_prompt(billing) and "Data Handled" in _attack_prompt(billing)
        assert "Use the asset type, the sector and the data handled to judge" in _attack_prompt(billing)
        assert shown in describe_asset_for_ai(billing, ROOM).text  # what POST /v1/sessions' threat finding reads
        writer_facts, _ = write.shorten_facts_to_fit(billing, billing.systems, False, ROOM)  # and its writer
        assert writer_facts["data_handled"] == DATA_HANDLED
        assert f"data_handled: {DATA_HANDLED}" in write.build_control_query({}, billing).text  # and its control search
        assert f'"data_handled": "{GRID_DATA_HANDLED}"' in _attack_prompt(grid)
        assert f'"data_handled": "{GRID_DATA_HANDLED}"' in describe_asset_for_ai(grid, ROOM).text


def test_a_stored_runs_prompt_names_its_own_matrix_and_inputs_and_no_database_id(
    client: TestClient, api_key: str
) -> None:
    """From the procedure's own rows: the IT asset with an IT system names Enterprise only, the OT asset with
    its OT system ICS only, with its IT system too both; a start that sent only a sector never has a
    sub-sector named; and no asset, system or entity id is in any of them."""
    billing = _attack_prompt(_frozen_context(_start(client, api_key, BILLING)))
    assert "the MITRE ATT&CK Enterprise matrix" in billing and "ICS" not in billing
    assert "Sector" in billing and "sub-sector" not in billing.lower() and "sub_sector" not in billing
    grid = _attack_prompt(_frozen_context(_start(client, api_key, START | {"supporting_system_id": [321]})))
    assert "the MITRE ATT&CK ICS matrix" in grid and "Enterprise" not in grid
    assert "Sector, Sub-sector, Asset Description, Data Handled, Supporting Systems and Type given below." in grid
    both = _attack_prompt(_frozen_context(_start(client, api_key)))
    assert "the MITRE ATT&CK Enterprise and ICS matrices" in both
    for prompt in (billing, grid, both):
        assert not re.search(r"\b(86|103|105|321|322|323)\b", prompt) and "SYS1" not in prompt


def test_post_sessions_stores_the_record_it_always_stored(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """The two starts share their steps: POST /v1/sessions still stores these fields, these values and nothing
    else, sends tsg_find_threats and never asks whether ATT&CK is imported."""
    _forget_attack_import()
    key = uuid.uuid4().hex
    response = _start(client, api_key, url="/v1/sessions", **{Header.IDEMPOTENCY_KEY: key})
    assert response.status_code == 202, response.text
    run = _run(response.json()["session_id"])
    assert list(run) == [
        "_id",
        "kind",
        "entity_id",
        "tenant_id",
        "user_id",
        "client_id",
        "asset_id",
        "request",
        "request_hash",
        "context",
        "status",
        "step",
        "last_action",
        "counts",
        "job",
        "created_at",
        "updated_at",
        "idempotency_key",
        "schema_version",
    ]
    client_id, at = admin_crud.get_active_client_id(get_mongodb(), api_key), run["created_at"]
    request = StartRunRequest.model_validate(START)
    context = run.pop("context")
    assert run == {
        "_id": response.json()["session_id"],
        "kind": "generated",
        "entity_id": 86,
        "tenant_id": "DESC",
        "user_id": "u1",
        "client_id": client_id,
        "asset_id": 103,
        "request": {"supporting_system_ids": [321, 322], "service_id": None, "sector_id": None, "subsector_id": 11},
        "request_hash": request.fingerprint(),
        "status": "queued",
        "step": "threats",
        "last_action": {"kind": "start", "outcome": "running", "reason": None, "started_at": at},
        "counts": {},
        "job": {
            "task": "tsg_find_threats",
            "epoch": 1,
            "request_id": response.headers[Header.REQUEST_ID],
            "origin": {"api": "create_scenario", "client_id": client_id, "entity_id": 86},
            "task_id": None,
            "attempts": 0,
            "due_at": at,
            "lease_until": None,
            "resends": 0,
            "error": None,
        },
        "created_at": at,
        "updated_at": at,
        "idempotency_key": key,
        "schema_version": 1,
    }
    assert list(context) == ["asset", "asset_context", "systems", "asset_systems"]
    assert context["asset"] == {"id": 103, "name": "Grid control centre", "category_code": "OT"}
    assert [(system["alias"], system["id"]) for system in context["systems"]] == [("SYS1", 321), ("SYS2", 322)]
    assert world["sent"] == [(TaskName.FIND_THREATS, run["_id"], 1)]
