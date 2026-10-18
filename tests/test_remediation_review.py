"""Regenerating a remediation plan and deciding its versions (#12, #13, #14; BLUEPRINT M11 R8-R9;
BUILD_PLAN S54): v1 → v2 (the outcome frozen on v1, a lost control warned about, a second regenerate
refused while v2 is written), accept v1 then v2 (v1 back to pending), rejects and the record's decision, a
decision raced by another, every refusal, a read-only plan. The test database; the library, the top-up and
the chat faked."""

import contextlib
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ConflictReason,
    Decision,
    SnapshotWarning,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.data_access.remediation_reads import RemediationReads
from app.data_access.remediation_versions import RemediationVersions
from app.data_access.remediations import RemediationRepository
from app.data_access.scenario.runs import SessionRepository
from app.models.remediation_reviews import DecisionRequest
from app.services.remediation import regenerate as regenerate_module
from app.services.remediation.decisions import PlanDecisions
from app.services.remediation.regenerate import PlanRegeneration, get_plan_regeneration
from app.services.remediation.snapshots import SnapshotMaker
from app.worker import jobs
from app.worker.tasks import remediation as plan_job
from tests.plan_addresses import generated, plan_url
from tests.test_remediation_planner import _answer, _control
from tests.test_remediation_requests import (  # noqa: F401 — api_key and world are fixtures
    FAKE_LIBRARY,
    _identity,
    _request,
    _scenario,
    api_key,
    world,
)


@pytest.fixture
def plans(
    client: TestClient,
    world: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[dict[str, Any]]:
    """`world` and a regenerate service on the same fakes; what a regenerate sends."""
    db = get_mongodb()
    snapshots = SnapshotMaker(SessionRepository(db), FAKE_LIBRARY)  # type: ignore[arg-type]
    built = PlanRegeneration(RemediationRepository(db), RemediationVersions(db), snapshots)
    client.app.dependency_overrides[get_plan_regeneration] = lambda: built  # type: ignore[attr-defined]
    monkeypatch.setattr(regenerate_module, "send_job", lambda *args: world["sent"].append(args))
    yield world
    client.app.dependency_overrides.pop(get_plan_regeneration, None)  # type: ignore[attr-defined]


def _deliver(remediation_id: str, version: int) -> None:
    task: Any = SimpleNamespace(
        name=TaskName.WRITE_PLAN, request=SimpleNamespace(id=uuid.uuid4().hex), retry=None
    )
    with contextlib.suppress(Exception):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(task, Collection.REMEDIATIONS, remediation_id, version, plan_job.write_version)


def _done_plan(client: TestClient, key: str, state: dict[str, Any]) -> str:
    """A plan whose version 1 is written."""
    remediation_id = _request(client, key, generated(_scenario())).json()["remediation_id"]
    state["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id, 1)
    return remediation_id


#: v1's one review call takes the decision in its body (owner, 2026-10-15).
_REVIEWS = {"accept": Decision.ACCEPTED, "reject": Decision.REJECTED}


def _post(client: TestClient, key: str, remediation_id: str, action: str, body: dict[str, Any]) -> Any:
    """`accept` / `reject` → POST .../treatment-plan/review with that decision; `regenerate` as it is."""
    if action in _REVIEWS:
        action, body = "review", body | {"decision": _REVIEWS[action]}
    return client.post(plan_url(remediation_id, action), json=body, headers=_identity(key))


def _record(remediation_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": remediation_id})


def _decisions(remediation_id: str) -> list[str]:
    return [version["decision"] for version in _record(remediation_id)["versions"]]


def _audits(remediation_id: str, action: AuditAction) -> int:
    return get_mongodb()[Collection.AUDIT].count_documents({"target.id": remediation_id, "action": action})


def test_a_new_version_is_written_from_the_scenario_as_it_is_now(
    client: TestClient,
    api_key: str,  # noqa: F811
    plans: dict[str, Any],
) -> None:
    remediation_id = _done_plan(client, api_key, plans)
    scenario_id = _record(remediation_id)["scenario_id"]
    remapped = [{"control_id": 2, "code": "CII-CID-2", "score": 70.0, "match": "exact"}]
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": scenario_id}, {"$set": {"controls.items": remapped}}
    )
    answer = _post(client, api_key, remediation_id, "regenerate", {})
    assert (answer.status_code, answer.json()["version"]) == (202, 2), answer.text
    assert (TaskName.WRITE_PLAN, remediation_id, 2) in plans["sent"]
    record = _record(remediation_id)
    assert [(v["version"], v["status"]) for v in record["versions"]] == [(1, Status.DONE), (2, Status.QUEUED)]
    lost = SnapshotWarning.CONTROL_NO_LONGER_MAPPED.format(code="CII-CID-1", version=1)
    assert lost in record["versions"][1]["snapshot"]["warnings"]
    again = _post(client, api_key, remediation_id, "regenerate", {})
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)
    assert _post(client, api_key, remediation_id, "regenerate", {"note": "x"}).status_code == 422
    plans["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-2")))
    _deliver(remediation_id, 2)
    status = client.get(plan_url(remediation_id, "status"), headers=_identity(api_key)).json()
    assert (status["latest_version"], status["latest_status"], status["decision"]) == (2, "done", "pending")
    assert _audits(remediation_id, AuditAction.PLAN_REGENERATED) == 1


def test_one_accepted_version_at_a_time_and_the_records_decision(
    client: TestClient,
    api_key: str,  # noqa: F811
    plans: dict[str, Any],
) -> None:
    """Accept v1, then v2 (v1 back to pending); a repeat changes and audits nothing; rejecting the accepted v2
    clears it (v1 still waits: pending); rejecting v1 too → rejected. No version given = the newest done."""
    remediation_id = _done_plan(client, api_key, plans)
    _post(client, api_key, remediation_id, "regenerate", {})
    plans["chat"].queue(AiTask.REMEDIATION_PLAN, _answer(_control("CII-CID-1")))
    _deliver(remediation_id, 2)
    first = _post(client, api_key, remediation_id, "accept", {"version": 1, "comment": "Fits the window."})
    assert (first.status_code, first.json()["accepted_version"], first.json()["decision"]) == (
        200,
        1,
        "accepted",
    )
    assert _post(client, api_key, remediation_id, "accept", {}).json()["accepted_version"] == 2  # newest done
    assert _decisions(remediation_id) == [Decision.PENDING, Decision.ACCEPTED]
    demoted = _record(remediation_id)["versions"][0]  # review S56: back to pending, with no stale stamp
    assert (demoted["decided_by"], demoted["decided_at"], demoted["review_comment"]) == (None, None, None)
    seq = _record(remediation_id)["decision_seq"]
    repeat = _post(client, api_key, remediation_id, "accept", {"version": 2})
    assert (repeat.status_code, repeat.json()["accepted_version"]) == (200, 2)
    assert _audits(remediation_id, AuditAction.PLAN_ACCEPTED) == 2  # the repeat: nothing written or audited
    assert _record(remediation_id)["decision_seq"] == seq
    rejected = _post(client, api_key, remediation_id, "reject", {"version": 2}).json()
    assert (rejected["accepted_version"], rejected["decision"]) == (None, "pending")
    assert _post(client, api_key, remediation_id, "reject", {"version": 1}).json()["decision"] == "rejected"
    item = _record(remediation_id)["versions"][0]
    assert (item["decided_by"], item["review_comment"]) == ("u1", None)


def test_every_refusal_and_a_read_only_plan(
    client: TestClient,
    api_key: str,  # noqa: F811
    plans: dict[str, Any],
) -> None:
    remediation_id = _done_plan(client, api_key, plans)
    missing = _post(client, api_key, remediation_id, "accept", {"version": 9})
    assert (missing.status_code, missing.json()["reason"]) == (404, ConflictReason.VERSION_NOT_FOUND)
    _post(client, api_key, remediation_id, "regenerate", {})
    queued = _post(client, api_key, remediation_id, "accept", {"version": 2})
    assert (queued.status_code, queued.json()["reason"]) == (409, ConflictReason.NOT_COMPLETE)
    # v1 rejected while v2 is still being written: the plan still waits for a decision on v2.
    assert _post(client, api_key, remediation_id, "reject", {"version": 1}).json()["decision"] == "pending"
    url, review = plan_url(remediation_id, "review"), {"version": 1, "decision": "accepted"}
    assert client.post(url, json=review, headers=_identity(api_key, 1)).status_code == 403
    nowhere = "/v1/sessions/none/scenarios/nope/treatment-plan/review"
    assert client.post(nowhere, json={"decision": "rejected"}, headers=_identity(api_key)).status_code == 404
    assert (
        client.post(url, json={"version": 1, "decision": "pending"}, headers=_identity(api_key)).status_code
        == 422
    )
    scenario_id = _record(remediation_id)["scenario_id"]
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": scenario_id}, {"$set": {"decision": Decision.PENDING}}
    )
    for action in ("accept", "reject", "regenerate"):
        refused = _post(
            client, api_key, remediation_id, action, {} if action == "regenerate" else {"version": 1}
        )
        assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.SCENARIO_NOT_ACCEPTED)
    assert client.get(plan_url(remediation_id), headers=_identity(api_key)).status_code == 200


def test_a_decision_raced_by_another_reads_again_once(
    client: TestClient,
    api_key: str,  # noqa: F811
    plans: dict[str, Any],
) -> None:
    """Another decision lands between this one's read and its write: this one reads again and applies on the
    new read; when one lands every time, 409 changed_concurrently."""
    remediation_id = _done_plan(client, api_key, plans)
    db = get_mongodb()
    versions = RemediationVersions(db)
    decide = versions.decide
    raced: list[bool] = []

    def another_decision_first(*args: Any) -> bool:
        if not raced:
            raced.append(True)
            db[Collection.REMEDIATIONS].update_one({"_id": remediation_id}, {"$inc": {"decision_seq": 1}})
        return decide(*args)

    versions.decide = another_decision_first  # type: ignore[method-assign]
    service = PlanDecisions(RemediationRepository(db), versions, RemediationReads(db))
    owner = _record(remediation_id)["entity_id"]
    principal: Any = SimpleNamespace(entity_id=owner, user_id="u1", client_id="c1")
    assert service.accept(principal, remediation_id, DecisionRequest(version=1)).accepted_version == 1
    versions.decide = lambda *args: False  # type: ignore[method-assign]
    with pytest.raises(Conflict) as clash:
        service.reject(principal, remediation_id, DecisionRequest(version=1))
    assert clash.value.reason == ConflictReason.CHANGED_CONCURRENTLY


def test_a_regenerate_is_never_refused_for_a_library_change_since(
    client: TestClient,
    api_key: str,  # noqa: F811
    plans: dict[str, Any],
) -> None:
    """Review S56: the stored register's control id and code name two rows only since a curator changed a
    code; the caller cannot fix what it did not send now, so the new version notes it and goes ahead."""
    remediation_id = _done_plan(client, api_key, plans)
    changed = [{"control_id": 1, "control_code": "CII-CID-2", "control_name": None}]
    get_mongodb()[Collection.REMEDIATIONS].update_one(
        {"_id": remediation_id}, {"$set": {"register.existing_controls": changed}}
    )
    answer = _post(client, api_key, remediation_id, "regenerate", {})
    assert answer.status_code == 202, answer.text
    warnings = _record(remediation_id)["versions"][1]["snapshot"]["warnings"]
    assert SnapshotWarning.REGISTER_REF_CHANGED.format(reference="CII-CID-2") in warnings
