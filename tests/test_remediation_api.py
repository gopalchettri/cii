"""The remediation API on the test database: a plan requested, written by its job, regenerated, decided and
read; every refusal and race; the store's guarded writes; a record stored before the rebuild. The library,
the mapping, the search and the chat faked (tests/plan_job_fakes.py)."""

import dataclasses
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiOutage,
    AiTask,
    AuditAction,
    BoardMessage,
    Collection,
    ConflictReason,
    Controls,
    Decision,
    ErrorCode,
    ErrorMessage,
    Header,
    Lease,
    PlanWarning,
    PromptVersion,
    Remediation,
    RemediationMessage,
    RunKind,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import ControlsNotMapped, DuplicateRecord, LeaseLost, Unavailable
from app.core.lease_signal import raise_if_lease_lost
from app.data_access.jobs.job_repository import new_job
from app.data_access.scenario.threat_scenario_session_repository import (
    DELETING_MARK,
    ThreatScenarioSessionRepository,
)
from app.domain.remediation.rules import check_regenerable, decision_change
from app.models.remediation.requests import SYSTEM_LISTS, PlanRequest
from app.models.scenario.asset_context import FrozenContext
from app.worker import jobs
from tests.plan_addresses import generated, plan_url
from tests.plan_job_fakes import (  # noqa: F401 — api_key_fixture and world_fixture are fixtures
    CONTROLS,
    SCENARIO_CONTENT,
    api_key_fixture,
    deliver,
    fake_library,
    plan_answer,
    remediation_plan_service,
    world_fixture,
)
from tests.planner_samples import CONTEXT

ENTITY = 186  # its own entity: nothing here shows in another test's entity-wide list
MAPPED = [{"control_id": 1, "code": "CII-CID-1", "score": 87.4, "match": "exact"}]
UNMAPPED = {"status": Status.QUEUED, "attempts": 0}
REGISTER = {"risk_level": "High", "risk_owner": "Head of Grid Operations", "likelihood_rating": "4.47"}
BROKEN = plan_answer("CII-CID-1", applicable_to_all_subsystems="Maybe")  # fails the answer contract
DECIDED_BY = {"decided_by": "u1", "decided_by_client": "c1"}
NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


def _identity(api_key: str, entity_id: int = ENTITY) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _run(context: FrozenContext = CONTEXT) -> str:
    """A run of ENTITY with its frozen asset context."""
    run_id = uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": run_id, "entity_id": ENTITY, "asset_id": 1179, "status": Status.DONE,
         "updated_at": datetime.now(UTC), "context": context.to_record()}
    )  # fmt: skip
    return run_id


def _scenario(run_id: str | None = None, **fields: Any) -> str:
    """An accepted scenario of a run of ENTITY (a new run unless `run_id`), its controls mapped; `fields`
    override any of it."""
    scenario_id = uuid.uuid4().hex
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": run_id or _run(), "entity_id": ENTITY, "asset_id": 1179,
         "path_id": scenario_id, "source": RunKind.GENERATED, "status": ScenarioStatus.DONE,
         "decision": Decision.ACCEPTED, "content": SCENARIO_CONTENT,
         "controls": {"status": Status.DONE, "items": MAPPED}} | fields
    )  # fmt: skip
    return scenario_id


def _request(client: TestClient, api_key: str, body: dict[str, Any], entity_id: int = ENTITY) -> Any:
    return client.post("/v1/remediation", json=body, headers=_identity(api_key, entity_id))


def _status(client: TestClient, api_key: str, remediation_id: str, entity_id: int = ENTITY) -> Any:
    return client.get(plan_url(remediation_id, "status"), headers=_identity(api_key, entity_id))


def _result(client: TestClient, api_key: str, remediation_id: str, **params: Any) -> Any:
    return client.get(plan_url(remediation_id), params=params, headers=_identity(api_key))


#: v1's one review call takes the decision in its body.
_REVIEWS = {"accept": Decision.ACCEPTED, "reject": Decision.REJECTED}


def _post(client: TestClient, key: str, remediation_id: str, action: str, body: dict[str, Any]) -> Any:
    """`accept` / `reject` → POST .../treatment-plan/review with that decision; `regenerate` as it is."""
    if action in _REVIEWS:
        action, body = "review", body | {"decision": _REVIEWS[action]}
    return client.post(plan_url(remediation_id, action), json=body, headers=_identity(key))


def _record(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def _scenario_controls(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]


def _settled(outcome: str) -> float:
    return REGISTRY.get_sample_value("tsg_plans_total", {"outcome": outcome}) or 0.0


def _audits(remediation_id: str, action: AuditAction) -> int:
    return get_mongodb()[Collection.AUDIT].count_documents({"target.id": remediation_id, "action": action})


def _done_plan(client: TestClient, key: str, world: dict[str, Any], **body: Any) -> str:
    """A plan whose version 1 is written; `body` adds register fields to its request."""
    remediation_id = _request(client, key, generated(_scenario(), **body)).json()["remediation_id"]
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    return remediation_id


def _mapped_codes(version: dict[str, Any]) -> list[str]:
    return [control["control_code"] for control in version["snapshot"]["existing_controls"]["library_mapped"]]


# --- a plan requested and written


def test_a_plan_is_requested_written_and_its_status_read(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """202 with version 1 queued and no snapshot yet; sent, published, audited with the risk owner masked;
    the job builds the snapshot, writes the plan (the gap stamped from the library), counts and audits it."""
    scenario_id, done_before = _scenario(), _settled("done")
    answer = _request(client, api_key, generated(scenario_id, **REGISTER))
    assert answer.status_code == 202, answer.text
    started = answer.json()
    remediation_id = started["remediation_id"]
    found = (started["scenario_id"], started["version"], started["status"], started["is_manual"])
    assert found == (scenario_id, 1, "queued", False) and started["replayed"] is False
    assert world["sent"] == [(TaskName.WRITE_PLAN, remediation_id, 1)] and world["mapper"].asked == []
    assert remediation_id in world["published"]
    record = _record(remediation_id)
    stored = (record["decision_seq"], record["register"]["likelihood_rating"], record["risk_level"])
    assert stored == (0, "4.47", "High") and record["versions"][0]["snapshot"] is None
    audit = {"target.id": remediation_id, "action": AuditAction.PLAN_REQUESTED}
    assert get_mongodb()[Collection.AUDIT].find_one(audit)["after"]["register"]["risk_owner"] == "[REDACTED]"
    assert _status(client, api_key, remediation_id).json()["progress"]["overall"] == "generating"
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    version = _record(remediation_id)["versions"][0]
    assert (version["status"], version["prompt_version"]) == (Status.DONE, PromptVersion.REMEDIATION)
    assert _mapped_codes(version) == ["CII-CID-1"]
    assert version["warnings"] == [PlanWarning.NO_WINDOW.format(total=20)]
    shown = _result(client, api_key, remediation_id).json()
    assert (shown["latest_status"], shown["progress"]["overall"]) == ("done", "awaiting_review")
    plan = shown["plan"]
    control = plan["controls_to_be_implemented"][0]
    assert (plan["control_coverage"], control["control_id"], control["implementation_status"]) == (
        "gaps",
        1,
        "not_implemented",
    )
    assert plan["control_assessment"] == [
        {"control_id": 1, "control_code": "CII-CID-1", "control_name": "Firmware integrity verification",
         "domain": "Integrity", "match": "exact", "implementation_status": "not_implemented",
         "recommended": True,
         "protected_systems": [],
         "validation": "retained", "validation_reason": "It reduces the firmware tampering risk.",
         "replaced_by": None, "replaces": [],
         "required_systems": [{"supporting_system_id": 321, "name": "SCADA server"},
                              {"supporting_system_id": 322, "name": "Historian"}]}
    ]  # fmt: skip
    assert control["required_systems"] == plan["control_assessment"][0]["required_systems"]
    assert _settled("done") == done_before + 1
    completed = {"target.id": remediation_id, "action": AuditAction.PLAN_COMPLETED}
    assert get_mongodb()[Collection.AUDIT].find_one(completed)["after"] == {"version": 1, "warnings": 1}


def test_every_request_refusal(client: TestClient, api_key: str, world: dict[str, Any]) -> None:
    accepted, pending = _scenario(), _scenario(decision=Decision.PENDING)
    assert _request(client, api_key, generated("nope")).status_code == 404
    assert _request(client, api_key, generated(accepted), entity_id=ENTITY + 1).status_code == 403
    refused = _request(client, api_key, generated(pending))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    first = _request(client, api_key, generated(accepted)).json()["remediation_id"]
    second = _request(client, api_key, generated(accepted))
    assert (second.status_code, second.json()["reason"]) == (409, ConflictReason.PLAN_ALREADY_EXISTS)
    assert second.json()["details"] == {"remediation_id": first}
    assert _request(client, api_key, generated(accepted, risk_levl="High")).status_code == 422
    old_flag = _request(client, api_key, generated(accepted, all_supporting_systems_applicable=1))
    assert [error["field"] for error in old_flag.json().get("errors", [])] == [
        "body.all_supporting_systems_applicable"
    ]
    manual = {
        "is_manual": True,
        "manual_scenario": {
            "asset_id": 1,
            "entity_id": ENTITY,
            "supporting_system_ids": [1],
            "threat_type_name": "Malware",
            "threat_name": "Firmware tampering",
            "threat_scenario": "A cybercriminal could tamper with firmware.",
            "risk_statement": "Control could be lost.",
        },
    }
    assert _request(client, api_key, manual).status_code == 422  # no Idempotency-Key
    run = generated(accepted)["session_id"]
    nowhere = client.get(
        f"/v1/sessions/{run}/scenarios/nope/treatment-plan/status", headers=_identity(api_key)
    )
    assert nowhere.status_code == 404
    other_run = generated(accepted) | {"session_id": "another-run"}
    assert _request(client, api_key, other_run).status_code == 404  # not a scenario of that run
    elsewhere = plan_url(first, "status").replace(run, "another-run")
    assert client.get(elsewhere, headers=_identity(api_key)).status_code == 404
    empty = remediation_plan_service(
        library=fake_library(()), send_job=lambda *args: world["sent"].append(args)
    )
    client.app.dependency_overrides[container.get_remediation_plan_service] = lambda: empty  # type: ignore[attr-defined]
    refused = _request(client, api_key, generated(_scenario()))
    assert (refused.status_code, refused.json()["reason"]) == (409, ErrorCode.CONTROL_LIBRARY_EMPTY)
    assert world["sent"] == [(TaskName.WRITE_PLAN, first, 1)]  # nothing sent for the refused one


def _on(*system_ids: int) -> dict[str, Any]:
    """Register fields: CII-CID-1 an existing control, the existing controls on `system_ids`."""
    on = {"supporting_systems_applicable_to_existing_controls": list(system_ids)}
    return {"existing_controls": ["CII-CID-1"]} | on


def test_a_listed_system_the_run_lacks_is_a_422_and_the_systems_set_its_status(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """A run stored before its asset's systems were kept: both lists name the run's systems (321, 322): 999 in
    either is refused by field and position as sent (a repeat counted) before anything is saved; the
    existing controls on the SCADA server alone, the risk on both, CII-CID-1 is partially implemented."""
    scenario_id = _scenario()
    risk_on = {"supporting_systems_applicable_to_risk": [321, 321, 999]}
    for wrong, field in ((_on(321, 321, 999), "existing_controls[2]"), (risk_on | _on(321), "risk[2]")):
        refused = _request(client, api_key, generated(scenario_id, **wrong))
        assert refused.status_code == 422, refused.text
        assert refused.json()["errors"] == [
            {
                "field": f"body.supporting_systems_applicable_to_{field}",
                "message": RemediationMessage.SYSTEM_NOT_OF_ASSET.format(system_id=999, known="321, 322"),
            }
        ]
    assert not get_mongodb()[Collection.REMEDIATIONS].count_documents({"scenario_id": scenario_id})
    answer = _request(client, api_key, generated(scenario_id, **_on(321)))
    assert answer.status_code == 202, answer.text
    extending = plan_answer("CII-CID-1")
    extending["controls_to_be_implemented"]["controls"][0]["description"] = (
        "Extends signed firmware to the Historian."
    )
    world["chat"].queue(AiTask.REMEDIATION_PLAN, extending)
    deliver(answer.json()["remediation_id"])
    (assessed,) = _result(client, api_key, answer.json()["remediation_id"]).json()["plan"][
        "control_assessment"
    ]
    assert assessed["implementation_status"] == "partially_implemented"
    names = (
        [s["name"] for s in assessed["protected_systems"]],
        [s["name"] for s in assessed["required_systems"]],
    )
    assert names == (["SCADA server"], ["Historian"])


@pytest.mark.parametrize("none", [None, "", []], ids=["null", "blank", "empty"])
def test_a_list_naming_no_system_is_accepted_and_sets_the_status(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch, none: Any
) -> None:
    """Both lists naming none: accepted without reading the run; the risk is on the asset itself, so
    CII-CID-1, an existing control, is implemented on no system and the plan's actions name none. The risk on
    both systems, the existing controls on none: CII-CID-1 is still needed on both."""
    reads: list[str] = []
    read_context = ThreatScenarioSessionRepository.get_scenario_session_context

    def counted(sessions: ThreatScenarioSessionRepository, session_id: str) -> dict[str, Any]:
        reads.append(session_id)
        return read_context(sessions, session_id)

    monkeypatch.setattr(ThreatScenarioSessionRepository, "get_scenario_session_context", counted)
    nowhere = generated(_scenario(), existing_controls=["CII-CID-1"], **dict.fromkeys(SYSTEM_LISTS, none))
    answer = _request(client, api_key, nowhere)
    assert (answer.status_code, reads) == (202, []), answer.text
    covered = {"control_coverage": "covered", "controls": []}
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer(controls_to_be_implemented=covered))
    deliver(answer.json()["remediation_id"])
    plan = _result(client, api_key, answer.json()["remediation_id"]).json()["plan"]
    (assessed,) = plan["control_assessment"]
    found = [assessed[key] for key in ("implementation_status", "protected_systems", "required_systems")]
    assert found == ["implemented", [], []]
    assert [action["supporting_systems"] for action in plan["actions"]] == [[], []]
    on_none = {"supporting_systems_applicable_to_existing_controls": none}
    answer = _request(client, api_key, generated(_scenario(), existing_controls=["CII-CID-1"], **on_none))
    assert answer.status_code == 202, answer.text
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(answer.json()["remediation_id"])
    (assessed,) = _result(client, api_key, answer.json()["remediation_id"]).json()["plan"][
        "control_assessment"
    ]
    names = [[s["name"] for s in assessed[key]] for key in ("protected_systems", "required_systems")]
    assert (assessed["implementation_status"], names) == (
        "not_implemented",
        [[], ["SCADA server", "Historian"]],
    )


def test_existing_controls_on_a_system_outside_the_risk_count_only_where_the_risk_is(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """The risk on the SCADA server, the existing controls on the Historian: accepted, and CII-CID-1 is not
    implemented, still needed on the SCADA server alone."""
    scenario_id = _scenario()
    body = generated(scenario_id, supporting_systems_applicable_to_risk=[321], **_on(322))
    answer = _request(client, api_key, body)
    assert answer.status_code == 202, answer.text
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(answer.json()["remediation_id"])
    (assessed,) = _result(client, api_key, answer.json()["remediation_id"]).json()["plan"][
        "control_assessment"
    ]
    names = [[s["name"] for s in assessed[key]] for key in ("protected_systems", "required_systems")]
    assert (assessed["implementation_status"], names) == ("not_implemented", [[], ["SCADA server"]])


def test_an_existing_control_on_an_asset_system_the_run_was_not_started_on_counts(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """The asset has an OT engineering workstation (324) and an IT billing server (325) the run was not
    started on: existing controls on 324 are the asset's, so accepted, and with the risk on every system
    CII-CID-1 is partial, still needed on the other OT systems but never on the IT server (an OT control);
    999 is still refused."""
    systems = [
        {"id": s["id"], "name": s["name"], "category_code": s["category_code"]} for s in CONTEXT.systems
    ]
    others = [
        {"id": 324, "name": "Engineering workstation", "category_code": "OT"},
        {"id": 325, "name": "Billing server", "category_code": "IT"},
    ]
    wide = dataclasses.replace(CONTEXT, asset_systems=[*systems, *others])
    scenario_id = _scenario(_run(wide))
    risk_on_all = {"supporting_systems_applicable_to_risk": [321, 322, 324, 325]}
    refused = _request(client, api_key, generated(scenario_id, **risk_on_all, **_on(324, 999)))
    assert refused.status_code == 422, refused.text
    assert [error["message"] for error in refused.json()["errors"]] == [
        RemediationMessage.SYSTEM_NOT_OF_ASSET.format(system_id=999, known="321, 322, 324, 325")
    ]
    answer = _request(client, api_key, generated(scenario_id, **risk_on_all, **_on(324)))
    assert answer.status_code == 202, answer.text
    extending = plan_answer("CII-CID-1")
    extending["controls_to_be_implemented"]["controls"][0]["description"] = "Extends signed firmware."
    world["chat"].queue(AiTask.REMEDIATION_PLAN, extending)
    deliver(answer.json()["remediation_id"])
    plan = _result(client, api_key, answer.json()["remediation_id"]).json()["plan"]
    (assessed,) = plan["control_assessment"]
    names = [[s["name"] for s in assessed[key]] for key in ("protected_systems", "required_systems")]
    assert (assessed["implementation_status"], names) == (
        "partially_implemented",
        [["Engineering workstation"], ["SCADA server", "Historian"]],
    )


def test_an_identified_control_replaced_by_a_library_alternative_shows_both_through_the_api(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """The plan job offers the scenario's next-best library controls as alternatives; the AI replaces
    CII-CID-1 with CII-CID-5; the result recommends 5 and traces 1 replaced by 5."""
    world["mapper"].alternatives = [(CONTROLS[5], 66.0)]
    answer = _request(client, api_key, generated(_scenario()))
    assert answer.status_code == 202, answer.text
    replacing = plan_answer("CII-CID-5")
    replacing["control_validation"] = [
        {
            "control_code": "CII-CID-1",
            "validation": "replaced",
            "replacement_code": "CII-CID-5",
            "reason": "Fits better.",
        }
    ]
    world["chat"].queue(AiTask.REMEDIATION_PLAN, replacing)
    remediation_id = answer.json()["remediation_id"]
    deliver(remediation_id)
    snapshot = _record(remediation_id)["versions"][0]["snapshot"]
    assert [row["control_code"] for row in snapshot["existing_controls"]["library_alternatives"]] == [
        "CII-CID-5"
    ]
    plan = _result(client, api_key, remediation_id).json()["plan"]
    assert [control["control_code"] for control in plan["controls_to_be_implemented"]] == ["CII-CID-5"]
    rows = {row["control_code"]: row for row in plan["control_assessment"]}
    assert (rows["CII-CID-1"]["validation"], rows["CII-CID-1"]["replaced_by"]) == ("replaced", "CII-CID-5")
    assert (rows["CII-CID-5"]["match"], rows["CII-CID-5"]["replaces"]) == ("alternative", ["CII-CID-1"])


def test_a_request_made_at_the_same_moment_gets_409_with_the_winner(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unique scenario_id index decides: this request saw no plan, the winner's insert landed first."""
    scenario_id = _scenario()
    remediations = container.get_remediation_repository()
    real_create = remediations.create
    winners: list[str] = []

    def the_winner_inserts_first(record: dict[str, Any]) -> Any:
        winner = record | {"_id": uuid.uuid4().hex}
        real_create(winner)
        winners.append(winner["_id"])
        return real_create(record)

    monkeypatch.setattr(remediations, "create", the_winner_inserts_first)
    refused = _request(client, api_key, generated(scenario_id))
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.PLAN_ALREADY_EXISTS)
    assert refused.json()["details"] == {"remediation_id": winners[0]} and world["sent"] == []


def test_many_plan_requests_at_once_all_answer_202_and_their_jobs_write_every_plan(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Every request answers at once whatever the AI is doing: each mapping waits (a busy AI) while 12
    requests run in parallel; then their 12 jobs map and plan."""
    world["mapper"].release = threading.Event()
    scenarios = [_scenario(controls=UNMAPPED) for _ in range(12)]
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=12) as pool:
        answers = list(pool.map(lambda sid: _request(client, api_key, generated(sid)), scenarios))
    assert [answer.status_code for answer in answers] == [202] * 12
    assert time.monotonic() - started < 10 and world["mapper"].asked == []  # no request waited on the AI
    world["mapper"].release.set()
    for answer in answers:
        world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
        deliver(answer.json()["remediation_id"])
    assert sorted(world["mapper"].asked) == sorted(scenarios)
    assert [_record(answer.json()["remediation_id"])["status"] for answer in answers] == [Status.DONE] * 12


@pytest.mark.parametrize("deleted", ["meanwhile", "being_deleted"])
def test_a_plan_never_outlives_its_run(
    client: TestClient,
    api_key: str,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    deleted: str,
) -> None:
    """The run deleted between the scenario's read and the insert: 404; its delete under way: 409
    run_being_deleted. Either way no plan is left and no job is sent."""
    scenario_id = _scenario()
    if deleted == "meanwhile":
        remediations = container.get_remediation_repository()
        real_create = remediations.create

        def create_after_the_delete(record: dict[str, Any]) -> Any:
            get_mongodb()[Collection.SCENARIOS].delete_one({"_id": scenario_id})
            return real_create(record)

        monkeypatch.setattr(remediations, "create", create_after_the_delete)
    else:
        run = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["session_id"]
        marked = {"$set": {DELETING_MARK: datetime.now(UTC)}}
        get_mongodb()[Collection.SESSIONS].update_one({"_id": run}, marked)
    refused = _request(client, api_key, generated(scenario_id, **REGISTER))
    if deleted == "meanwhile":
        assert refused.status_code == 404, refused.text
    else:
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    assert get_mongodb()[Collection.REMEDIATIONS].count_documents({"scenario_id": scenario_id}) == 0
    assert world["sent"] == []


# --- the plan job's controls


@pytest.mark.parametrize(
    "controls",
    [
        UNMAPPED,
        {
            "status": Status.DONE,
            "items": [{"control_id": 77, "code": "CII-CID-77", "score": 90.0, "match": "exact"}],
        },
        {
            "status": Status.FAILED,
            "attempts": Controls.MAX_ATTEMPTS,
            "error": {"code": ErrorCode.UNAVAILABLE, "message": "Busy.", "reason": AiOutage.BUSY},
        },
    ],
    ids=["never_mapped", "every_one_retired", "failed_after_every_busy_try"],
)
def test_missing_controls_are_mapped_by_the_plan_job_never_the_request(
    client: TestClient, api_key: str, world: dict[str, Any], controls: dict[str, Any]
) -> None:
    """The request answers 202 and calls no AI; the job maps the controls under the scenario's own lease,
    saves them on the scenario, then plans."""
    scenario_id = _scenario(controls=controls)
    answer = _request(client, api_key, generated(scenario_id))
    assert answer.status_code == 202 and world["mapper"].asked == []
    remediation_id = answer.json()["remediation_id"]
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    assert world["mapper"].asked == [scenario_id]
    version = _record(remediation_id)["versions"][0]
    assert version["status"] == Status.DONE and _mapped_codes(version) == ["CII-CID-1"]
    saved = _scenario_controls(scenario_id)
    assert (saved["status"], [item["code"] for item in saved["items"]]) == (Status.DONE, ["CII-CID-1"])
    assert world["mapper"].mapped["items"] == saved["items"]  # the alternatives see the record just mapped
    assert _request(client, api_key, generated(scenario_id)).status_code == 409
    assert world["mapper"].asked == [scenario_id]  # refused before any control was mapped


def test_the_run_board_sends_failed_controls_to_a_plan_not_to_a_later_retry() -> None:
    """Nothing maps controls again by itself after their last try; a plan request or a regenerate does."""
    shown = BoardMessage.CONTROLS_FAILED.format(failed=2)
    assert "tried again later" not in shown and "regenerate" in shown


@pytest.mark.parametrize("blocked", ["held_by_another_job", "ai_outage"])
def test_controls_held_or_an_outage_while_mapping_give_the_job_back_and_the_retry_plans(
    client: TestClient, api_key: str, world: dict[str, Any], blocked: str
) -> None:
    """No wait: the job is given back for its normal retry. Controls another job holds: the retry plans on
    that job's mapping (never mapped twice). An outage while mapping frees the controls, saying why, and the
    retry maps and plans."""
    held = {"status": Status.RUNNING, "attempts": 1, "task_id": "controls-job",
            "lease_until": datetime.now(UTC) + timedelta(seconds=60)}  # fmt: skip
    scenario_id = _scenario(controls=held if blocked == "held_by_another_job" else UNMAPPED)
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    if blocked == "ai_outage":
        world["mapper"].failure = Unavailable("The reranker is busy.", reason=AiOutage.BUSY)
    deliver(remediation_id)
    record = _record(remediation_id)
    assert record["status"] == Status.QUEUED  # the job retries after its back-off
    if blocked == "held_by_another_job":  # waiting for that job uses none of this job's attempts
        assert record["job"]["attempts"] == 0 and record["versions"][0]["snapshot"] is None
        mapped = [{"control_id": 1, "code": "CII-CID-1", "score": 80.0, "match": "exact"}]
        get_mongodb()[Collection.SCENARIOS].update_one(
            {"_id": scenario_id}, {"$set": {"controls.status": Status.DONE, "controls.items": mapped}}
        )  # the controls job finished
    else:
        controls = _scenario_controls(scenario_id)
        found = (controls["status"], controls["error"]["code"], controls["error"]["reason"])
        assert found == (Status.QUEUED, ErrorCode.UNAVAILABLE, AiOutage.BUSY)  # the card can say why
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"job.due_at": datetime.now(UTC) - timedelta(seconds=1)}}
    )  # the back-off over: the next delivery may claim the job
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    record = _record(remediation_id)
    assert (record["status"], _mapped_codes(record["versions"][0])) == (Status.DONE, ["CII-CID-1"])
    assert world["mapper"].asked == ([] if blocked == "held_by_another_job" else [scenario_id, scenario_id])


@pytest.mark.parametrize("cancelled", ["plan", "run"])
def test_a_plan_cancel_ends_the_job_and_a_run_cancel_retries_it(
    client: TestClient,
    api_key: str,
    world: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    cancelled: str,
) -> None:
    """The mapping's next AI call sees either lease lost. A plan cancel ends the delivery as stopped by its
    owner; a run cancel (the scenario's control lease lost) gives the plan job back to wait, not to retry."""
    monkeypatch.setattr(jobs.Lease, "RENEW_EVERY_SECONDS", 0.02)
    scenario_id = _scenario(controls=UNMAPPED)
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    stopped_by: list[str] = []

    def map_until_stopped(*_args: Any) -> None:
        if cancelled == "plan":
            plans = get_mongodb()[Collection.REMEDIATIONS]
            plans.update_one({"_id": remediation_id}, {"$set": {"status": Status.CANCELLED}})
        else:  # a run cancel stops the controls being mapped
            cards = get_mongodb()[Collection.SCENARIOS]
            cards.update_one({"_id": scenario_id}, {"$set": {"controls.status": Status.CANCELLED}})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:  # every AI call checks the signal first
            try:
                raise_if_lease_lost()
            except LeaseLost as exc:
                stopped_by.append(str(exc))
                raise
            time.sleep(0.01)

    monkeypatch.setattr(world["mapper"], "map_controls", map_until_stopped)
    with capture_logs() as logs:
        deliver(remediation_id)
    events = [entry["event"] for entry in logs]
    record = _record(remediation_id)
    assert "job.lease_lost" not in events
    if cancelled == "plan":
        assert stopped_by == [remediation_id] and "job.stopped_by_owner" in events
        assert record["status"] == Status.CANCELLED
        assert _scenario_controls(scenario_id).get("error") is None  # stopped, never told as an outage
    else:
        assert stopped_by == [scenario_id] and "job.waiting" in events and "job.retry_scheduled" not in events
        assert (record["status"], record["job"]["attempts"]) == (Status.QUEUED, 0)  # no attempt used


@pytest.mark.parametrize(
    ("failure", "code", "snapshot_saved"),
    [
        ("unusable", "generation_failed", True),
        ("no_action", "invalid_plan", True),
        ("library_empty", "control_library_empty", False),
    ],
)
def test_a_failed_version_keeps_its_code_and_its_snapshot(
    client: TestClient,
    api_key: str,
    world: dict[str, Any],
    failure: str,
    code: str,
    snapshot_saved: bool,
) -> None:
    """Unusable twice, a plan without action, or a mapping no retry changes: failed with its code, never a
    run-only last_action, the snapshot kept once built, and counted wherever in the job it failed."""
    failed_before = _settled("failed")
    scenario_id = _scenario(controls=UNMAPPED) if failure == "library_empty" else _scenario()
    remediation_id = _request(client, api_key, generated(scenario_id)).json()["remediation_id"]
    if failure == "unusable":
        world["chat"].queue(AiTask.REMEDIATION_PLAN, BROKEN, BROKEN)
    elif failure == "no_action":
        world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1", remediation_action_plan=[]))
    else:
        failed = ControlsNotMapped(ErrorCode.CONTROL_LIBRARY_EMPTY, ErrorMessage.CONTROL_LIBRARY_EMPTY)
        world["mapper"].failure = failed
    deliver(remediation_id)
    record = _record(remediation_id)
    assert (record["status"], record["job"]["error"]["code"]) == (Status.FAILED, code)
    assert "last_action" not in record
    assert (record["versions"][0]["snapshot"] is not None) is snapshot_saved
    shown = _status(client, api_key, remediation_id).json()
    assert (shown["progress"]["overall"], shown["error"]["code"]) == ("failed", code)
    assert _settled("failed") == failed_before + 1


# --- regenerate and review


def test_a_regenerate_writes_a_new_version_from_the_scenario_as_it_is_now(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    remediation_id = _done_plan(client, api_key, world)
    scenario_id = _record(remediation_id)["scenario_id"]
    remapped = [{"control_id": 2, "code": "CII-CID-2", "score": 70.0, "match": "exact"}]
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": scenario_id}, {"$set": {"controls.items": remapped}}
    )
    answer = _post(client, api_key, remediation_id, "regenerate", {})
    assert (answer.status_code, answer.json()["version"]) == (202, 2), answer.text
    assert (TaskName.WRITE_PLAN, remediation_id, 2) in world["sent"]
    record = _record(remediation_id)
    assert [(v["version"], v["status"]) for v in record["versions"]] == [(1, Status.DONE), (2, Status.QUEUED)]
    assert record["versions"][1]["snapshot"] is None  # its job builds it
    again = _post(client, api_key, remediation_id, "regenerate", {})
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)
    assert _post(client, api_key, remediation_id, "regenerate", {"note": "x"}).status_code == 422
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-2"))
    deliver(remediation_id, 2)
    versions = _record(remediation_id)["versions"]
    assert (_mapped_codes(versions[0]), _mapped_codes(versions[1])) == (["CII-CID-1"], ["CII-CID-2"])
    status = _status(client, api_key, remediation_id).json()
    assert (status["latest_version"], status["latest_status"], status["decision"]) == (2, "done", "pending")
    assert _audits(remediation_id, AuditAction.PLAN_REGENERATED) == 1


def test_every_review_and_regenerate_refusal_and_a_read_only_plan(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Each refusal writes nothing; a regenerate as its run is being deleted is 409 with nothing sent or
    audited; a plan whose scenario is no longer accepted is read-only."""
    remediation_id = _done_plan(client, api_key, world)
    missing = _post(client, api_key, remediation_id, "accept", {"version": 9})
    assert (missing.status_code, missing.json()["reason"]) == (404, ConflictReason.VERSION_NOT_FOUND)
    _post(client, api_key, remediation_id, "regenerate", {})
    queued = _post(client, api_key, remediation_id, "accept", {"version": 2})
    assert (queued.status_code, queued.json()["reason"]) == (409, ConflictReason.NOT_COMPLETE)
    url, review = plan_url(remediation_id, "review"), {"version": 1, "decision": "accepted"}
    assert client.post(url, json=review, headers=_identity(api_key, 1)).status_code == 403
    nowhere = "/v1/sessions/none/scenarios/nope/treatment-plan/review"
    assert client.post(nowhere, json={"decision": "rejected"}, headers=_identity(api_key)).status_code == 404
    unknown_field = {"version": 1, "decision": "accepted", "note": "x"}
    assert client.post(url, json=unknown_field, headers=_identity(api_key)).status_code == 422
    last = get_settings().regenerations_max_version_count
    limited = _done_plan(client, api_key, world)
    assert check_regenerable({"job": {"epoch": last - 1}, "status": Status.DONE}, limited, last) == last
    get_mongodb()[Collection.REMEDIATIONS].update_one({"_id": limited}, {"$set": {"job.epoch": last}})
    full = _post(client, api_key, limited, "regenerate", {})
    assert (full.status_code, full.json()["reason"]) == (409, ConflictReason.VERSION_LIMIT_REACHED)
    assert str(last) in full.json()["detail"] and _audits(limited, AuditAction.PLAN_REGENERATED) == 0
    deleting = _done_plan(client, api_key, world)
    marked = {"$set": {DELETING_MARK: datetime.now(UTC)}}
    get_mongodb()[Collection.SESSIONS].update_one({"_id": _record(deleting)["session_id"]}, marked)
    refused = _post(client, api_key, deleting, "regenerate", {})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    record = _record(deleting)
    assert (record["job"]["epoch"], record["status"], len(record["versions"])) == (1, Status.DONE, 1)
    assert (TaskName.WRITE_PLAN, deleting, 2) not in world["sent"]
    assert _audits(deleting, AuditAction.PLAN_REGENERATED) == 0
    scenario_id = _record(remediation_id)["scenario_id"]
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": scenario_id}, {"$set": {"decision": Decision.PENDING}}
    )
    for action in ("accept", "reject", "regenerate"):
        body = {} if action == "regenerate" else {"version": 1}
        refused = _post(client, api_key, remediation_id, action, body)
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    assert _result(client, api_key, remediation_id).status_code == 200


def _failed_for_outage(world: dict[str, Any], remediation_id: str, version: int = 1) -> None:
    """The plan job's last try of `version` meets a busy AI: the plan fails for the outage."""
    plans = get_mongodb()[Collection.REMEDIATIONS]
    plans.update_one({"_id": remediation_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    busy = Unavailable("Every AI slot stayed busy.", reason=AiOutage.BUSY)
    world["chat"].queue(AiTask.REMEDIATION_PLAN, busy)
    deliver(remediation_id, version)
    record = _record(remediation_id)
    error = record["job"]["error"]
    assert (record["status"], error["code"], error["reason"]) == (
        Status.FAILED,
        ErrorCode.UNAVAILABLE,
        AiOutage.BUSY,
    )


def test_a_regenerate_after_an_outage_writes_the_failed_version_again_in_place(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Busy on the job's last try: regenerate queues version 1 again with a fresh job (no new version, no
    failed history item), a second click is 409, and the next good answer leaves one done version."""
    remediation_id = _request(client, api_key, generated(_scenario())).json()["remediation_id"]
    _failed_for_outage(world, remediation_id)
    assert _record(remediation_id)["versions"][0]["snapshot"] is not None  # built before the AI was asked
    answer = _post(client, api_key, remediation_id, "regenerate", {})
    assert answer.status_code == 202, answer.text
    assert (answer.json()["version"], answer.json()["status"]) == (1, "queued")
    assert world["sent"] == [(TaskName.WRITE_PLAN, remediation_id, 1)] * 2
    record = _record(remediation_id)
    job = record["job"]
    assert (record["status"], record["active"], job["attempts"], job["error"]) == (
        Status.QUEUED,
        True,
        0,
        None,
    )
    assert len(record["versions"]) == 1 and record["versions"][0]["snapshot"] is None
    assert "finished_at" not in record
    again = _post(client, api_key, remediation_id, "regenerate", {})
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id)
    versions = _record(remediation_id)["versions"]
    assert [(v["version"], v["status"]) for v in versions] == [(1, Status.DONE)]
    status = _status(client, api_key, remediation_id).json()
    assert (status["latest_version"], status["latest_status"], status["error"]) == (1, "done", None)
    assert _audits(remediation_id, AuditAction.PLAN_REGENERATED) == 1


def test_at_the_version_limit_an_outage_is_still_retried_and_another_failure_is_final(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """An outage retry uses no version, so the last version is retried (202); a generation failure there is
    final as before (409 version_limit_reached)."""
    last = get_settings().regenerations_max_version_count
    remediation_id = _request(client, api_key, generated(_scenario())).json()["remediation_id"]
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"job.epoch": last, "versions.0.version": last}}
    )  # every version used
    _failed_for_outage(world, remediation_id, last)
    retried = _post(client, api_key, remediation_id, "regenerate", {})
    assert (retried.status_code, retried.json()["version"]) == (202, last), retried.text
    world["chat"].queue(AiTask.REMEDIATION_PLAN, BROKEN, BROKEN)
    deliver(remediation_id, last)
    assert _record(remediation_id)["job"]["error"]["code"] == ErrorCode.GENERATION_FAILED
    full = _post(client, api_key, remediation_id, "regenerate", {})
    assert (full.status_code, full.json()["reason"]) == (409, ConflictReason.VERSION_LIMIT_REACHED)


def test_an_outage_retry_that_meets_its_runs_delete_is_put_back_failed_for_the_outage(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run's delete marks it just after the in-place write: 409 run_being_deleted and nothing sent; the
    last version is failed for the outage again (not cancelled), so once the delete stops it is retried."""
    last = get_settings().regenerations_max_version_count
    remediation_id = _request(client, api_key, generated(_scenario())).json()["remediation_id"]
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"job.epoch": last, "versions.0.version": last}}
    )  # every version used
    _failed_for_outage(world, remediation_id, last)
    plans, runs = container.get_remediation_repository(), get_mongodb()[Collection.SESSIONS]
    run, real_retry = _record(remediation_id)["session_id"], plans.retry_remediation_plan_version

    def retried_then_the_delete_marks(*args: Any) -> bool:
        retried = real_retry(*args)
        runs.update_one({"_id": run}, {"$set": {DELETING_MARK: datetime.now(UTC)}})
        return retried

    with monkeypatch.context() as raced:
        raced.setattr(plans, "retry_remediation_plan_version", retried_then_the_delete_marks)
        refused = _post(client, api_key, remediation_id, "regenerate", {})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.RUN_BEING_DELETED)
    record = _record(remediation_id)
    assert (record["status"], record["active"], record["job"]["error"]["code"]) == (
        Status.FAILED,
        False,
        ErrorCode.UNAVAILABLE,
    )
    assert world["sent"] == [(TaskName.WRITE_PLAN, remediation_id, 1)]
    runs.update_one({"_id": run}, {"$unset": {DELETING_MARK: ""}})  # the delete found work left and stopped
    retried = _post(client, api_key, remediation_id, "regenerate", {})
    assert (retried.status_code, retried.json()["version"]) == (202, last), retried.text


def test_one_accepted_version_at_a_time_and_the_records_decision(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Accept v1, then v2 (v1 back to pending, no stale stamp); a repeat changes and audits nothing;
    rejecting the accepted v2 clears it (v1 still waits); rejecting v1 too → rejected. No version given =
    the newest done."""
    remediation_id = _done_plan(client, api_key, world)
    _post(client, api_key, remediation_id, "regenerate", {})
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id, 2)
    first = _post(client, api_key, remediation_id, "accept", {"version": 1, "comment": "Fits the window."})
    assert (first.status_code, first.json()["accepted_version"], first.json()["decision"]) == (
        200,
        1,
        "accepted",
    )
    assert _post(client, api_key, remediation_id, "accept", {}).json()["accepted_version"] == 2
    record = _record(remediation_id)
    assert [version["decision"] for version in record["versions"]] == [Decision.PENDING, Decision.ACCEPTED]
    demoted = record["versions"][0]
    assert (demoted["decided_by"], demoted["decided_at"], demoted["review_comment"]) == (None, None, None)
    repeat = _post(client, api_key, remediation_id, "accept", {"version": 2})
    assert (repeat.status_code, repeat.json()["accepted_version"]) == (200, 2)
    assert _audits(remediation_id, AuditAction.PLAN_ACCEPTED) == 2  # the repeat: nothing written or audited
    # decision_seq: one for the regenerate's append and one per decision written, none for the repeat.
    assert _record(remediation_id)["decision_seq"] == record["decision_seq"] == 3
    rejected = _post(client, api_key, remediation_id, "reject", {"version": 2}).json()
    assert (rejected["accepted_version"], rejected["decision"]) == (None, "pending")
    assert _post(client, api_key, remediation_id, "reject", {"version": 1}).json()["decision"] == "rejected"
    item = _record(remediation_id)["versions"][0]
    assert (item["decided_by"], item["review_comment"]) == ("u1", None)


def test_a_decision_raced_by_another_reads_again_once_then_409(
    client: TestClient, api_key: str, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another decision lands between this one's read and its write: this one reads again and applies on the
    new read; when one lands every time, 409 changed_concurrently."""
    remediation_id = _done_plan(client, api_key, world)
    remediations = container.get_remediation_repository()
    decide = remediations.update_remediation_plan_decision
    raced: list[bool] = []

    def another_decision_first(*args: Any, **kwargs: Any) -> bool:
        if not raced:
            raced.append(True)
            get_mongodb()[Collection.REMEDIATIONS].update_one(
                {"_id": remediation_id}, {"$inc": {"decision_seq": 1}}
            )
        return decide(*args, **kwargs)

    monkeypatch.setattr(remediations, "update_remediation_plan_decision", another_decision_first)
    accepted = _post(client, api_key, remediation_id, "accept", {"version": 1})
    assert (accepted.status_code, accepted.json()["accepted_version"], raced) == (200, 1, [True])
    monkeypatch.setattr(remediations, "update_remediation_plan_decision", lambda *args, **kwargs: False)
    refused = _post(client, api_key, remediation_id, "reject", {"version": 1})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.CHANGED_CONCURRENTLY)


# --- reads


def test_reads_show_the_accepted_else_the_newest_done_version_and_the_history_without_snapshots(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """A failed latest version's status and error come from the record; the history never holds a snapshot
    and only comes when asked for; an accepted older version is the one shown."""
    remediation_id = _done_plan(client, api_key, world, **REGISTER)
    _post(client, api_key, remediation_id, "regenerate", {})
    world["chat"].queue(AiTask.REMEDIATION_PLAN, BROKEN, BROKEN)
    deliver(remediation_id, 2)
    answer = _result(client, api_key, remediation_id, include_history="true")
    shown = answer.json()
    assert "snapshot" not in answer.text and "requested_by_client" not in answer.text
    assert [(v["version"], v["status"]) for v in shown["versions"]] == [(1, "done"), (2, "failed")]
    assert (
        shown["versions"][1]["error"]["code"] == "generation_failed" and shown["versions"][1]["plan"] is None
    )
    assert (shown["shown_version"], shown["latest_status"]) == (1, "failed")
    assert shown["register_data"]["risk_owner"] == "Head of Grid Operations"
    _post(client, api_key, remediation_id, "regenerate", {})
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id, 3)
    newest = _result(client, api_key, remediation_id).json()
    assert (newest["shown_version"], newest["versions"]) == (3, None)
    assert newest["plan"]["actions"][0]["start_date"] is None  # no mitigation window
    assert newest["plan"]["treatment_strategy"] == Remediation.STRATEGY
    _post(client, api_key, remediation_id, "accept", {"version": 1})
    assert _result(client, api_key, remediation_id).json()["shown_version"] == 1
    queued = _request(client, api_key, generated(_scenario())).json()["remediation_id"]
    nothing = _result(client, api_key, queued).json()
    assert (nothing["shown_version"], nothing["plan"]) == (None, None)


def test_each_list_filter_newest_first(client: TestClient, api_key: str, world: dict[str, Any]) -> None:
    run = _run()

    def planned(answers: tuple[dict[str, Any], ...], created_at: datetime, **body: Any) -> str:
        remediation_id = _request(client, api_key, generated(_scenario(run), **body)).json()["remediation_id"]
        world["chat"].queue(AiTask.REMEDIATION_PLAN, *answers)
        deliver(remediation_id)
        get_mongodb()[Collection.REMEDIATIONS].update_one(
            {"_id": remediation_id}, {"$set": {"created_at": created_at}}
        )
        return remediation_id

    older = planned((plan_answer("CII-CID-1"),), NOW - timedelta(days=1), risk_level="Low")
    failed = planned((BROKEN, BROKEN), NOW - timedelta(hours=1))
    newer = planned((plan_answer("CII-CID-1"),), NOW)
    assert _post(client, api_key, newer, "accept", {}).status_code == 200

    def listed(**params: Any) -> list[str]:
        answer = client.get(f"/v1/sessions/{run}/treatment-plans", params=params, headers=_identity(api_key))
        assert answer.status_code == 200, answer.text
        return [item["remediation_id"] for item in answer.json()["items"]]

    assert listed() == [newer, failed, older]
    assert listed(decision="accepted") == [newer]
    assert listed(status="failed") == [failed]
    assert listed(risk_level="Low") == [older]
    page = client.get(f"/v1/sessions/{run}/treatment-plans", params={"limit": 1}, headers=_identity(api_key))
    assert (page.json()["total"], page.json()["items"][0]["latest_version"]) == (3, 1)
    assert "versions" not in page.text
    register = client.get(
        f"/v1/entities/{ENTITY}/treatment-plans", params={"limit": 500}, headers=_identity(api_key)
    )
    assert {newer, failed, older} <= {item["remediation_id"] for item in register.json()["items"]}


def test_another_entity_sees_nothing(client: TestClient, api_key: str, world: dict[str, Any]) -> None:
    remediation_id = _done_plan(client, api_key, world)
    other = _identity(api_key, ENTITY + 1)
    assert client.get(plan_url(remediation_id), headers=other).status_code == 403
    assert client.get(plan_url(remediation_id, "status"), headers=other).status_code == 403
    run = _record(remediation_id)["session_id"]
    assert client.get(f"/v1/sessions/{run}/scenarios/nope/treatment-plan", headers=other).status_code == 404
    assert client.get(f"/v1/sessions/{run}/treatment-plans", headers=other).status_code == 403
    assert client.get(f"/v1/entities/{ENTITY}/treatment-plans", headers=other).status_code == 403


# --- the store's guarded writes


def _job(epoch: int) -> dict[str, Any]:
    return {"task": TaskName.WRITE_PLAN, "epoch": epoch, "attempts": 0, "due_at": NOW, "error": None}


def _item(version: int, statement: str = "A statement.") -> dict[str, Any]:
    return {
        "version": version,
        "status": Status.QUEUED,
        "snapshot": {"scenario": {"statement": statement}},
        "plan": None,
        "decision": Decision.PENDING,
        "requested_at": NOW,
    }


def _stored_plan() -> str:
    record = {
        "_id": uuid.uuid4().hex,
        "scenario_id": uuid.uuid4().hex,
        "session_id": "run1",
        "entity_id": 135,
        "versions": [_item(1)],
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "status": Status.QUEUED,
        "active": True,
        "job": _job(1),
        "created_at": NOW,
        "updated_at": NOW,
    }
    container.get_remediation_repository().create(record)
    return record["_id"]


def test_a_version_is_appended_only_on_the_finished_latest_read() -> None:
    """One plan per scenario; refused while the latest is queued; on a failed latest its outcome is frozen
    onto its item in the same write; refused again on the same stale read; a "$" text stays text; a decision
    worked out before the append reads again."""
    plans = container.get_remediation_repository()
    remediation_id = _stored_plan()
    with pytest.raises(DuplicateRecord) as clash:
        plans.create(_record(remediation_id) | {"_id": uuid.uuid4().hex})
    assert clash.value.index_name == "scenario_id_1"
    assert plans.create_remediation_plan_version(remediation_id, 1, _item(2), _job(2), NOW) is False
    error = {"code": "generation_failed", "message": "The AI could not write a usable remediation plan."}
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"status": Status.FAILED, "job.error": error, "finished_at": NOW}}
    )
    stale = _record(remediation_id)
    assert plans.create_remediation_plan_version(
        remediation_id, 1, _item(2, "$status costs $5"), _job(2), NOW
    )
    record = _record(remediation_id)
    found = [(v["version"], v["status"]) for v in record["versions"]]
    assert found == [(1, Status.FAILED), (2, Status.QUEUED)] and record["versions"][0]["error"] == error
    assert record["versions"][1]["snapshot"]["scenario"]["statement"] == "$status costs $5"
    assert (record["status"], record["active"], record["job"]["epoch"]) == (Status.QUEUED, True, 2)
    assert "finished_at" not in record and record["job"]["error"] is None
    assert plans.create_remediation_plan_version(remediation_id, 1, _item(3), _job(3), NOW) is False
    assert (record["decision_seq"], record["decision"]) == (1, Decision.PENDING)
    change = decision_change(stale, 1, Decision.REJECTED, DECIDED_BY, None, NOW)
    assert change is not None
    assert plans.update_remediation_plan_decision(remediation_id, stale["decision_seq"], change) is False


def test_only_a_latest_version_failed_for_an_outage_is_queued_again_in_place() -> None:
    """Refused while queued, done, failed for another reason, or for a version that is not the latest; once
    on an outage failure: a fresh job, queued and active, its snapshot cleared, no version added."""
    plans, records = container.get_remediation_repository(), get_mongodb()[Collection.REMEDIATIONS]
    remediation_id = _stored_plan()

    def retry(version: int = 1) -> bool:
        return plans.retry_remediation_plan_version(remediation_id, version, _job(version), NOW)

    def settle(status: Status, error: dict[str, str] | None) -> None:
        settled = {
            "status": status,
            "active": False,
            "job.attempts": 5,
            "job.error": error,
            "finished_at": NOW,
        }
        records.update_one({"_id": remediation_id}, {"$set": settled})

    assert retry() is False
    settle(Status.DONE, None)
    assert retry() is False
    settle(Status.FAILED, {"code": "generation_failed", "message": "No usable plan."})
    assert retry() is False
    settle(Status.FAILED, {"code": ErrorCode.UNAVAILABLE, "message": "Busy.", "reason": AiOutage.BUSY})
    assert retry(2) is False
    assert retry() is True
    record = _record(remediation_id)
    job = record["job"]
    assert (record["status"], record["active"], job["attempts"], job["error"]) == (
        Status.QUEUED,
        True,
        0,
        None,
    )
    assert [v["version"] for v in record["versions"]] == [1] and record["versions"][0]["snapshot"] is None
    assert "finished_at" not in record and record["decision_seq"] == 0
    assert retry() is False


# --- a record stored before the rebuild

#: A version 1 plan as the previous planner stored it: no implementation status, no control assessment.
OLD_PLAN = {
    "title": "Firmware Integrity Hardening",
    "controls_to_be_implemented": {
        "control_coverage": "gaps",
        "controls": [
            {"control_type": "preventive", "control_name": "Firmware integrity verification",
             "description": "Stops unsigned firmware reaching the RTU.", "priority": "High",
             "control_code": "CII-CID-1", "control_id": 1, "domain": "Integrity"}
        ],
    },
    "remediation_action_plan": [
        {"action_id": "A1", "action": "Do A1", "owner": "OT Security", "priority": "High",
         "dependencies": "None", "depends_on": [], "duration_days": 10, "implements_controls": ["CII-CID-1"],
         "success_criteria": "Shown by a signing test.", "start_date": None, "end_date": None,
         "timeline": "10 days"}
    ],
    "action_plan": "A1.",
    "mitigation_owner": "OT Security",
    "applicable_to_all_subsystems": "Yes",
    "treatment_strategy": "Mitigate",
    "risk_identification_date": None,
    "risk_owner": "Head of Grid Operations",
    "impacted_business_division": None,
    "critical_path": ["A1"],
    "mitigation_timeline": "10 days in total (critical path A1)",
    "mitigation_timeline_days": 10,
    "mitigation_end_date_planned": None,
}  # fmt: skip


def test_a_plan_stored_before_the_rebuild_reads_and_its_pending_version_is_written_by_the_new_job(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Version 1 done with the old plan shape and its old snapshot, version 2 queued with the old pending
    snapshot: the result reads (new fields at their defaults), and the new job ignores the old snapshot and
    writes version 2 from the scenario and the stored register."""
    scenario_id, now = _scenario(), datetime.now(UTC)
    run = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["session_id"]
    register = PlanRequest.model_validate(generated(scenario_id, **REGISTER)).register()
    old_mapped = [{"control_code": "CII-CID-1", "covered_by_register": False}]
    old_snapshot = {
        "existing_controls": {"library_mapped": old_mapped, "register_controls": []},
        "warnings": [],
    }
    old_register = {"register_controls": [], "warnings": []}
    pending = {"pending": True, "scenario_id": scenario_id, "register_part": old_register}
    stamp = {
        "decision": Decision.PENDING,
        "requested_by": "u1",
        "requested_by_client": "c1",
        "requested_at": now,
    }
    versions = [
        {"version": 1, "status": Status.DONE, "snapshot": old_snapshot, "plan": OLD_PLAN, "warnings": [],
         "prompt_version": "remediation-1", "error": None, "completed_at": now} | stamp,
        {"version": 2, "status": Status.QUEUED, "snapshot": pending, "plan": None, "warnings": [],
         "prompt_version": None, "error": None} | stamp,
    ]  # fmt: skip
    remediation_id = uuid.uuid4().hex
    container.get_remediation_repository().create(
        {"_id": remediation_id, "scenario_id": scenario_id, "session_id": run, "entity_id": ENTITY,
         "asset_id": 1179, "source": RunKind.GENERATED, "title": "Loss of control integrity",
         "register": register, "versions": versions, "accepted_version": None, "decision": Decision.PENDING,
         "decision_seq": 1, "risk_level": "High", "status": Status.QUEUED, "active": True,
         "job": new_job(TaskName.WRITE_PLAN, 2, now), "created_at": now, "updated_at": now}
    )  # fmt: skip
    old = _result(client, api_key, remediation_id, include_history="true")
    assert old.status_code == 200, old.text
    shown = old.json()
    assert (shown["shown_version"], shown["latest_status"], shown["plan"]["control_assessment"]) == (
        1,
        "queued",
        [],
    )
    assert shown["plan"]["controls_to_be_implemented"][0]["implementation_status"] == "not_implemented"
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(remediation_id, 2)
    record = _record(remediation_id)
    written = record["versions"][1]
    assert (record["status"], written["prompt_version"]) == (Status.DONE, PromptVersion.REMEDIATION)
    assert "pending" not in written["snapshot"] and _mapped_codes(written) == ["CII-CID-1"]
    assert record["versions"][0]["plan"] == OLD_PLAN
    newest = _result(client, api_key, remediation_id).json()
    assert newest["shown_version"] == 2 and len(newest["plan"]["control_assessment"]) == 1
