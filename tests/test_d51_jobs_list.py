"""GET /v1/jobs lists every leased job the caller's organisation has queued or running: its runs, its
remediation plans and its service mappings being generated. Mappings are written straight into the test
MongoDB."""

import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import AiOutage, Collection, Header, Status, TaskName
from app.core.database import get_mongodb

NOW = datetime.now(UTC)
TENANT = "T"


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = container.get_admin_service().create_api_client(f"jobs-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def entity() -> int:
    """An organisation of this test alone: other tests' work never shows in its list."""
    return random.randint(10_000_000, 99_999_999)  # noqa: S311 - test data, not security


def _who(api_key: str, entity_id: int) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: TENANT,
    }


def _mapping(entity_id: int, status: Status, tenant_id: str = TENANT, **fields: Any) -> str:
    """A service mapping of the entity, its generation's job in `status`."""
    mapping_id = uuid.uuid4().hex
    record = {
        "_id": mapping_id, "tenant_id": tenant_id, "entity_id": entity_id, "created_by": "u7",
        "client_id": "c1", "status": status, "generation": 1, "created_at": NOW, "updated_at": NOW,
        "job": {"task": TaskName.MAP_SERVICES, "epoch": 1, "attempts": 2, "due_at": NOW},
    }  # fmt: skip
    get_mongodb()[Collection.SERVICE_MAPPINGS].insert_one(record | fields)
    return mapping_id


def test_the_list_shows_my_service_mapping_being_generated(
    client: TestClient, api_key: str, entity: int
) -> None:
    """A mapping queued or running is my work in progress, with its outage notice; a finished one and
    another organisation's are not."""
    notice = {"reason": AiOutage.BUSY, "message": "The AI service is busy.", "attempt": 1,
              "max_attempts": 5, "retry_at": NOW}  # fmt: skip
    queued = _mapping(entity, Status.QUEUED, created_at=NOW - timedelta(minutes=5))
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one({"_id": queued}, {"$set": {"job.retry": notice}})
    running = _mapping(entity, Status.RUNNING, created_at=NOW - timedelta(minutes=2))
    _mapping(entity, Status.DONE)  # finished: not work in progress
    _mapping(entity + 1, Status.RUNNING)  # another entity's
    _mapping(entity, Status.RUNNING, tenant_id="other")  # another tenant's
    listed = client.get("/v1/jobs", headers=_who(api_key, entity)).json()
    assert listed["total"] == 2
    assert [(job["kind"], job.get("mapping_id")) for job in listed["jobs"]] == [
        ("service_mapping", queued),
        ("service_mapping", running),
    ]
    first = listed["jobs"][0]
    assert (first["status"], first["user_id"], first["attempts"]) == (Status.QUEUED, "u7", 2)
    assert first["retrying"]["reason"] == AiOutage.BUSY
    assert listed["jobs"][1]["retrying"] is None


def test_the_mappings_in_the_list_are_one_indexed_read(entity: int) -> None:
    """Every poll reads only the entity's mappings at work, never a walk over every mapping it made."""
    for _ in range(30):
        _mapping(entity, Status.DONE)
    _mapping(entity, Status.RUNNING)
    query = {"tenant_id": TENANT, "entity_id": entity, "status": {"$in": [Status.QUEUED, Status.RUNNING]}}
    explained = get_mongodb()[Collection.SERVICE_MAPPINGS].find(query).sort("created_at", 1).explain()
    assert explained["executionStats"]["totalDocsExamined"] == 1
    assert "tenant_id_1_entity_id_1_status_1_created_at_1" in str(explained["queryPlanner"]["winningPlan"])
