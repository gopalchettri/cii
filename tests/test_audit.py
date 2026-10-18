"""The audit trail: key mint and revoke are recorded, once, with who and which request; an audit outage never
fails the action."""

import contextlib
from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from pymongo.errors import ServerSelectionTimeoutError

from app import container
from app.core.constants import Audit, AuditAction, AuditTarget, Collection, Timeouts
from app.core.database import get_mongodb
from app.data_access.admin import audit_repository
from app.data_access.admin.audit_repository import AuditRepository
from app.domain.shared import audit
from tests.conftest import ADMIN

URL = "/v1/tsg/api-clients"


def _audit_records(client_id: str) -> list[dict]:
    return list(get_mongodb()[Collection.AUDIT].find({"target.id": client_id}, {"_id": 0}).sort("at", 1))


def _failures() -> float:
    return REGISTRY.get_sample_value("tsg_audit_failures_total") or 0.0


def test_mint_is_recorded_with_the_admin_user_and_the_request_id(client: TestClient) -> None:
    response = client.post(
        URL,
        json={"name": "audit-a"},
        headers={**ADMIN, "X-User-Id": "admin-1", "X-Request-Id": "req-audit-a"},
    )
    assert response.status_code == 201, response.text
    client_id = response.json()["client_id"]
    [record] = _audit_records(client_id)
    assert record["action"] == AuditAction.KEY_MINTED
    assert record["actor"] == {"admin": True, "user_id": "admin-1"}
    assert record["target"] == {"type": "api_client", "id": client_id}
    assert record["after"]["name"] == "audit-a" and record["after"]["active"] is True
    assert record["request_id"] == "req-audit-a"
    assert response.json()["api_key"] not in str(record)  # the secret is never audited


def test_an_admin_without_a_user_header_is_recorded_as_admin(client: TestClient) -> None:
    minted = client.post(URL, json={"name": "audit-b"}, headers=ADMIN).json()
    assert minted["created_by"] == Audit.ADMIN_USER
    assert _audit_records(minted["client_id"])[0]["actor"]["user_id"] == Audit.ADMIN_USER


def test_revoking_twice_is_recorded_once(client: TestClient) -> None:
    client_id = client.post(URL, json={"name": "audit-c"}, headers=ADMIN).json()["client_id"]
    for _ in range(2):
        assert client.post(f"{URL}/{client_id}/revoke", headers=ADMIN).status_code == 200
    revokes = [r for r in _audit_records(client_id) if r["action"] == AuditAction.KEY_REVOKED]
    assert len(revokes) == 1
    assert revokes[0]["before"] == {"active": True} and revokes[0]["after"] == {"active": False}


def test_an_audit_outage_never_fails_the_action_and_is_counted(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MongoIsDown:
        def insert_one(self, _record: dict) -> None:
            raise ServerSelectionTimeoutError("audit store down")

    monkeypatch.setattr(container.get_audit_repository(), "_collection", MongoIsDown())
    failures_before = _failures()
    response = client.post(URL, json={"name": "audit-d"}, headers=ADMIN)
    assert response.status_code == 201, response.text
    assert _failures() == failures_before + 1


def test_audit_indexes_and_365_day_retention_are_made_at_start_up(client: TestClient) -> None:
    indexes = get_mongodb()[Collection.AUDIT].index_information()  # the client fixture ran the start-up
    keys = {tuple(index["key"]): index for index in indexes.values()}
    assert (("actor.entity_id", 1), ("at", -1)) in keys
    assert (("target.id", 1), ("at", -1)) in keys
    assert keys[(("at", 1),)]["expireAfterSeconds"] == timedelta(days=Audit.KEEP_DAYS).total_seconds()


def test_an_audit_record_is_one_insert_no_index_work() -> None:
    """Before: the first record of every process also ran three index commands inside its 5 s budget, and a
    failing one (e.g. a login without collMod) dropped every record, though the insert alone would work."""
    calls: list[str] = []

    class Store:
        def insert_one(self, _record: dict) -> None:
            calls.append("insert_one")

        def __getattr__(self, name: str) -> object:
            calls.append(name)
            return lambda *_a, **_k: None

    AuditRepository(collection=Store()).create_audit_record(  # type: ignore[arg-type]
        AuditAction.KEY_MINTED, audit.admin_actor("t"), audit.audit_target(AuditTarget.API_CLIENT, "x")
    )
    assert calls == ["insert_one"]


def test_an_audit_write_is_bounded_so_a_slow_store_cannot_hold_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: the insert could wait the 30 s socket timeout after the action had already happened."""
    deadlines: list[float] = []
    inside: list[bool] = []
    inserted_inside: list[bool] = []

    @contextlib.contextmanager
    def timeout(seconds: float) -> Iterator[None]:
        deadlines.append(seconds)
        inside.append(True)
        yield
        inside.pop()

    class Store:
        def insert_one(self, _record: dict) -> None:
            # Recorded, not asserted here: a failed write is only logged, so an assert would be lost.
            inserted_inside.append(bool(inside))

    monkeypatch.setattr(audit_repository.pymongo, "timeout", timeout)
    AuditRepository(collection=Store()).create_audit_record(  # type: ignore[arg-type]
        AuditAction.KEY_MINTED, audit.admin_actor("t"), audit.audit_target(AuditTarget.API_CLIENT, "x")
    )
    assert deadlines == [Timeouts.RECORD_WRITE_SECONDS] and inserted_inside == [True]
