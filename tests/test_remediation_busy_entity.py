"""A busy entity's plans wait behind other entities' new work: with 2 of its plans queued or running, its next
plan or version is sent at Worker.BUSY_ENTITY_PRIORITY, a broker list of its own that workers read last."""

import base64
import json
import random
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    AiTask,
    Collection,
    Decision,
    Header,
    Queue,
    RunKind,
    ScenarioStatus,
    Status,
    Worker,
)
from app.core.database import get_mongodb
from app.worker.celery_app import celery_app
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

MAPPED = [{"control_id": 1, "code": "CII-CID-1", "score": 87.4, "match": "exact"}]


def _identity(api_key: str, entity_id: int) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _scenario(entity_id: int) -> str:
    """An accepted scenario of a new run of `entity_id`, its controls mapped."""
    run_id, scenario_id = uuid.uuid4().hex, uuid.uuid4().hex
    database = get_mongodb()
    database[Collection.SESSIONS].insert_one(
        {"_id": run_id, "entity_id": entity_id, "asset_id": 1179, "status": Status.DONE,
         "updated_at": datetime.now(UTC), "context": CONTEXT.to_record()}
    )  # fmt: skip
    database[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": run_id, "entity_id": entity_id, "asset_id": 1179,
         "path_id": scenario_id, "source": RunKind.GENERATED, "status": ScenarioStatus.DONE,
         "decision": Decision.ACCEPTED, "content": SCENARIO_CONTENT,
         "controls": {"status": Status.DONE, "items": MAPPED}}
    )  # fmt: skip
    return scenario_id


def _plan(client: TestClient, api_key: str, entity_id: int) -> str:
    answer = client.post(
        "/v1/remediation", json=generated(_scenario(entity_id)), headers=_identity(api_key, entity_id)
    )
    assert answer.status_code == 202, answer.text
    return answer.json()["remediation_id"]


def _steps_holding(remediation_id: str, version: int) -> list[int]:
    """The priority steps whose tsg_remediation list holds this version's job, as a worker reads them."""
    with celery_app.connection_for_read() as connection:
        channel = connection.default_channel
        lists = {
            step: channel.global_keyprefix + channel._q_for_pri(Queue.REMEDIATION, step)
            for step in channel.priority_steps
        }
        return [
            step
            for step, key in lists.items()
            for raw in channel.client.lrange(key, 0, -1)  # kombu prefixes LRANGE's key for no one
            if json.loads(base64.b64decode(json.loads(raw)["body"]))[0] == [remediation_id, version]
        ]


def test_a_busy_entitys_plans_wait_behind_another_entitys_new_work(
    client: TestClient, api_key: str, world: dict[str, Any]
) -> None:
    """Its first two plans at new work's step, its third and a new version (2 others waiting) at the busy one;
    another entity's first plan at new work's."""
    busy = random.randint(10_000_000, 99_999_999)  # noqa: S311 - test data, drawn per run: a rerun starts empty
    other_entity = busy + 1
    sending = remediation_plan_service(library=fake_library(tuple(CONTROLS.values())))  # the real send_job
    client.app.dependency_overrides[container.get_remediation_plan_service] = lambda: sending  # type: ignore[attr-defined]
    first, second, third = (_plan(client, api_key, busy) for _ in range(3))
    other = _plan(client, api_key, other_entity)
    world["chat"].queue(AiTask.REMEDIATION_PLAN, plan_answer("CII-CID-1"))
    deliver(first)
    regenerated = client.post(plan_url(first, "regenerate"), json={}, headers=_identity(api_key, busy))
    assert (regenerated.status_code, regenerated.json()["version"]) == (202, 2), regenerated.text
    steps = [_steps_holding(plan, 1) for plan in (first, second, third, other)] + [_steps_holding(first, 2)]
    normal, busy = [Worker.NEW_WORK_PRIORITY], [Worker.BUSY_ENTITY_PRIORITY]
    assert steps == [normal, normal, busy, normal, busy]


def test_the_busy_priority_is_its_own_step_of_every_workers_lists() -> None:
    """kombu files a priority under the highest step at or below it: without a step of its own, the busy
    priority would share new work's list."""
    with celery_app.connection_for_read() as connection:
        channel = connection.default_channel
        assert channel.priority(Worker.BUSY_ENTITY_PRIORITY) == Worker.BUSY_ENTITY_PRIORITY
        assert channel.priority_steps == sorted(channel.priority_steps)  # read in order: 0 first, busy last
        assert channel.priority_steps[-1] == Worker.BUSY_ENTITY_PRIORITY > Worker.NEW_WORK_PRIORITY
