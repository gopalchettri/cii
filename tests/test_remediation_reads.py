"""Reading remediation plans (#16, #17; BLUEPRINT M11 R10; BUILD_PLAN S53): the shown-version rule, the
history without snapshots (the latest version's status from the record), each list filter newest first,
another entity. The test database."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.constants import Collection, Decision, Header, Status
from app.core.database import get_mongodb
from app.data_access.remediation_reads import RemediationReads
from app.domain.remediation.planner import finish
from app.models.remediation import PlanDraft
from app.models.remediation_views import RemediationResult
from app.services.api_clients import get_api_client_service
from tests.plan_addresses import plan_url
from tests.test_remediation_planner import _answer, _control, _snapshot

ENTITY = 286  # its own entity: these plans never show in another test's list
NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"reads-{uuid.uuid4().hex[:8]}", None, "test")
    return key


def _identity(api_key: str, entity_id: int = ENTITY) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _version(number: int, done: bool = True, decision: Decision = Decision.PENDING) -> dict[str, Any]:
    snapshot = _snapshot()
    finished = finish(PlanDraft.model_validate(_answer(_control("CII-CID-1"))), snapshot) if done else None
    return {
        "version": number,
        "status": Status.DONE if done else Status.QUEUED,
        "snapshot": snapshot,
        "plan": None if finished is None else finished.plan,
        "warnings": [] if finished is None else [f"warning of version {number}"],
        "prompt_version": None if finished is None else finished.prompt_version,
        "decision": decision,
        "requested_by": "u1",
        "requested_by_client": "c1",
        "requested_at": NOW,
    }


def _plan(*versions: dict[str, Any], **fields: Any) -> str:
    """A plan of ENTITY whose latest version is the last given; `fields` override the record's."""
    latest = versions[-1]
    record = {
        "_id": uuid.uuid4().hex,
        "scenario_id": uuid.uuid4().hex,
        "session_id": "run-reads",
        "entity_id": ENTITY,
        "asset_id": 1179,
        "source": "generated",
        "title": "Loss of control integrity",
        "register": {"risk_owner": "Head of Grid Operations", "risk_level": "High"},
        "versions": list(versions),
        "accepted_version": None,
        "decision": Decision.PENDING,
        "decision_seq": 0,
        "risk_level": "High",
        "status": latest["status"],
        "active": latest["status"] != Status.DONE,
        "job": {"task": "tsg_write_plan", "epoch": latest["version"], "error": None},
        "created_at": NOW,
        "updated_at": NOW,
    } | fields
    get_mongodb()[Collection.REMEDIATIONS].insert_one(record)
    return record["_id"]


def _result(client: TestClient, api_key: str, remediation_id: str, **params: Any) -> Any:
    return client.get(plan_url(remediation_id), params=params, headers=_identity(api_key))


def _run(session_id: str) -> str:
    """A run of ENTITY (a run's list checks the run first: 404 unknown, 403 another entity's)."""
    get_mongodb()[Collection.SESSIONS].replace_one(
        {"_id": session_id},
        {"entity_id": ENTITY, "asset_id": 1179, "status": Status.DONE, "updated_at": NOW},
        upsert=True,
    )
    return session_id


def test_the_accepted_version_is_shown_else_the_newest_done(client: TestClient, api_key: str) -> None:
    """v3 is still being written: the newest done is v2; once v1 is accepted, v1 is shown (as in v1, where
    approving an old version made it the active one)."""
    versions = (_version(1), _version(2), _version(3, done=False))
    newest = _result(client, api_key, _plan(*versions)).json()
    shown = (newest["shown_version"], newest["warnings"], newest["latest_status"])
    assert shown == (2, ["warning of version 2"], "queued")
    plan = newest["plan"]
    table = (plan["control_coverage"], plan["controls_to_be_implemented"][0]["control_code"])
    assert table == ("gaps", "CII-CID-1")
    assert plan["actions"][0]["start_date"] == "2026-10-15" and plan["treatment_strategy"] == "Mitigate"
    assert _result(client, api_key, _plan(*versions, accepted_version=1)).json()["shown_version"] == 1
    nothing = _result(client, api_key, _plan(_version(1, done=False))).json()
    assert (nothing["shown_version"], nothing["plan"]) == (None, None)


def test_the_history_never_holds_a_snapshot(client: TestClient, api_key: str) -> None:
    """A failed latest version's status and error come from the record (R3); an older one's from its item."""
    error = {"code": "generation_failed", "message": "The AI could not write a usable remediation plan."}
    remediation_id = _plan(
        _version(1), _version(2, done=False), status=Status.FAILED, job={"epoch": 2, "error": error}
    )
    answer = _result(client, api_key, remediation_id, include_history="true")
    shown = answer.json()
    assert "snapshot" not in answer.text and "requested_by_client" not in answer.text
    scenario_id = get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})["scenario_id"]
    stored = RemediationReads(get_mongodb()).find_result_of_scenario(scenario_id)
    assert "snapshot" not in stored["versions"][0]  # IO
    assert [(v["version"], v["status"]) for v in shown["versions"]] == [(1, "done"), (2, "failed")]
    assert shown["versions"][1]["error"] == error and shown["versions"][1]["plan"] is None
    assert shown["register_data"]["risk_owner"] == "Head of Grid Operations"
    assert _result(client, api_key, remediation_id).json()["versions"] is None


def test_each_list_filter_newest_first(client: TestClient, api_key: str) -> None:
    session = _run(uuid.uuid4().hex)
    older = _plan(_version(1), session_id=session, created_at=NOW - timedelta(days=1), risk_level="Low")
    failed = _plan(
        _version(1, done=False), session_id=session, status=Status.FAILED, created_at=NOW - timedelta(hours=1)
    )
    newer = _plan(_version(1), session_id=session, decision=Decision.ACCEPTED, accepted_version=1)

    def listed(**params: Any) -> list[str]:
        answer = client.get(
            f"/v1/sessions/{session}/treatment-plans", params=params, headers=_identity(api_key)
        )
        assert answer.status_code == 200, answer.text
        return [item["remediation_id"] for item in answer.json()["items"]]

    assert listed() == [newer, failed, older]
    assert listed(decision="accepted") == [newer]
    assert listed(status="failed") == [failed]
    assert listed(risk_level="Low") == [older]
    page = client.get(
        f"/v1/sessions/{session}/treatment-plans", params={"limit": 1}, headers=_identity(api_key)
    ).json()
    assert (
        page["total"] == 3 and page["items"][0]["latest_version"] == 1 and "versions" not in json.dumps(page)
    )
    register = client.get(
        f"/v1/entities/{ENTITY}/treatment-plans", params={"limit": 500}, headers=_identity(api_key)
    )
    assert {newer, failed, older} <= {item["remediation_id"] for item in register.json()["items"]}


def test_another_entity_sees_nothing(client: TestClient, api_key: str) -> None:
    remediation_id = _plan(_version(1))
    other = _identity(api_key, ENTITY + 1)
    assert client.get(plan_url(remediation_id), headers=other).status_code == 403
    assert client.get(plan_url(remediation_id, "status"), headers=other).status_code == 403
    nowhere = "/v1/sessions/run-reads/scenarios/nope/treatment-plan"
    assert client.get(nowhere, headers=other).status_code == 404
    assert client.get(f"/v1/sessions/{_run('run-reads')}/treatment-plans", headers=other).status_code == 403
    assert client.get(f"/v1/entities/{ENTITY}/treatment-plans", headers=other).status_code == 403


def test_only_the_shown_version_is_built_without_the_history() -> None:
    """Review S56: a result builds its shown version alone; the others only when the history is asked for
    (a malformed older plan proves it is never read)."""
    record = {
        "_id": "r", "entity_id": ENTITY, "scenario_id": "s", "session_id": "run", "status": Status.DONE,
        "decision": Decision.PENDING, "accepted_version": None, "job": {"epoch": 2, "error": None},
        "updated_at": NOW, "versions": [_version(1) | {"plan": {"not": "a plan"}}, _version(2)],
    }  # fmt: skip
    result = RemediationResult.from_records(record, None, include_history=False)
    assert (result.shown_version, result.versions) == (2, None)
    with pytest.raises(KeyError):  # the malformed plan is read only for the history
        RemediationResult.from_records(record, None, include_history=True)


def test_the_old_v2_addresses_are_gone(client: TestClient, api_key: str) -> None:
    """Owner, 2026-10-15: v1's addresses replace /v1/remediation/{id}/... (no legacy code)."""
    remediation_id = _plan(_version(1))
    for path in ("status", "result", "events"):
        assert (
            client.get(f"/v1/remediation/{remediation_id}/{path}", headers=_identity(api_key)).status_code
            == 404
        )
    for action in ("accept", "reject", "regenerate", "cancel"):
        old = client.post(f"/v1/remediation/{remediation_id}/{action}", json={}, headers=_identity(api_key))
        assert old.status_code == 404
    assert client.get("/v1/remediation", headers=_identity(api_key)).status_code == 405  # POST only now
