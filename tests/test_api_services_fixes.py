"""Admin jobs carry the request that queued them and log their failure; the job list finds a request's jobs,
shows each lease and survives Redis being down; a long admin job is not failed for its queued time; an
intelligence change stands when its refresh cannot be queued; a mapping replay tells its real status."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from structlog.contextvars import bound_contextvars
from structlog.testing import capture_logs

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AdminJobKind,
    AdminJobs,
    Collection,
    ErrorCode,
    IntelRefreshMessage,
    IntelSource,
    LogEvent,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.domain.service_mapper.reconcile import reconcile
from app.models.external_intelligence.intel_admin import IntelSourceApproved, IntelSwitchOut
from app.services.admin.admin_service import queue_admin_job
from tests.conftest import ADMIN
from tests.external_intelligence.fakes import intelligence_service
from tests.external_intelligence.switch.test_switch_admin import Flags
from tests.test_job_monitor import _mapping
from tests.test_service_mapper import PRINCIPAL, _answer, _catalog, _request
from tests.test_service_mapper_outage_retry import _mapper


def _queue(job_id: str, kind: str, sent: bool = True) -> None:
    """Queue an admin job of `kind` through the one function every admin job is queued by."""
    job = {"_id": job_id, "kind": kind, "status": Status.QUEUED}
    queue_admin_job(
        container.get_admin_job_repository(),
        lambda _task, _job_id: sent,
        TaskName.BUILD_LIBRARY_INDEXES,
        job,
        "busy",
        "not sent",
    )


def _clear_active(kind: str) -> None:
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({"kind": kind, "active": True})


def test_an_admin_job_keeps_the_request_that_queued_it() -> None:
    job_id = uuid.uuid4().hex
    with bound_contextvars(request_id="req-admin-3"):
        _queue(job_id, uuid.uuid4().hex)
    assert container.get_admin_job_repository().get_any_admin_job(job_id)["request_id"] == "req-admin-3"


def test_the_job_list_finds_a_requests_jobs_with_their_lease(client: TestClient) -> None:
    request_id, admin_job = uuid.uuid4().hex, uuid.uuid4().hex
    with bound_contextvars(request_id=request_id):
        _queue(admin_job, uuid.uuid4().hex)
    lease_until = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=5)
    leased = _mapping(Status.RUNNING, request_id=request_id, lease_until=lease_until, resends=2)
    _mapping(Status.RUNNING, request_id="another-request")
    body = client.get("/v1/admin/jobs", params={"request_id": request_id}, headers=ADMIN).json()
    by_id = {job["id"]: job for job in body["jobs"]}
    assert set(by_id) == {admin_job, leased}
    assert by_id[admin_job]["request_id"] == by_id[leased]["request_id"] == request_id
    assert by_id[leased]["resends"] == 2  # a lease long past: its worker is gone
    assert datetime.fromisoformat(by_id[leased]["lease_until"]).replace(tzinfo=UTC) == lease_until


def test_the_job_list_answers_when_the_worker_count_cannot_be_read(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def redis_down(_queues: Any) -> dict[str, int]:
        raise ConnectionError("redis down")

    monitor = container.get_job_monitor_service()
    monkeypatch.setattr(monitor, "_count_workers", redis_down)
    monkeypatch.setattr(monitor, "_count_waiting", lambda _queue: 0)
    response = client.get("/v1/admin/jobs", headers=ADMIN)
    assert response.status_code == 200
    assert {state["workers_online"] for state in response.json()["queues"].values()} == {None}


def test_an_admin_job_that_fails_writes_its_job_failed_line() -> None:
    _clear_active(AdminJobKind.EMBEDDINGS_BUILD)
    with capture_logs() as logs, pytest.raises(Unavailable):
        _queue(uuid.uuid4().hex, AdminJobKind.EMBEDDINGS_BUILD, sent=False)
    failed = [line for line in logs if line["event"] == LogEvent.JOB_FAILED]
    assert [(line["task"], line["module"], line["code"], line["message"]) for line in failed] == [
        (TaskName.BUILD_LIBRARY_INDEXES, "library_embeddings", ErrorCode.UNAVAILABLE, "not sent")
    ]


def test_a_long_running_admin_job_is_not_failed_for_its_time_in_the_queue() -> None:
    jobs = container.get_admin_job_repository()
    now = datetime.now(UTC)
    long_ago = now - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS + 600)
    started_late, never_started = uuid.uuid4().hex, uuid.uuid4().hex
    for job_id in (started_late, never_started):
        kind = uuid.uuid4().hex
        assert jobs.create_admin_job(
            {"_id": job_id, "kind": kind, "status": Status.QUEUED, "created_at": long_ago}
        )
    assert jobs.update_admin_job_running(started_late, now - timedelta(minutes=5))
    failed = {job["_id"] for job in jobs.fail_stale_admin_jobs(now)}
    assert never_started in failed and started_late not in failed
    assert jobs.get_any_admin_job(started_late)["status"] == Status.RUNNING
    kind = jobs.get_any_admin_job(started_late)["kind"]
    newer = {"_id": uuid.uuid4().hex, "kind": kind, "status": Status.QUEUED, "created_at": now}
    assert jobs.create_admin_job(newer) == started_late  # still the active one: not taken over


class _ApprovedFeeds:
    """Every source approved; an approval only noted."""

    def update_intel_feed_approval(self, source: IntelSource, approved: bool, **_: Any) -> None:
        return None

    def count(self, **_: Any) -> int:
        return 1


def _intel_with_no_job_queue(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The intelligence admin with the switch on and a job queue that is unreachable."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    _clear_active(AdminJobKind.INTEL_REFRESH)
    switch = IntelligenceSwitch(Flags(), lambda: True)  # type: ignore[arg-type]
    return intelligence_service(switch=switch, feeds=_ApprovedFeeds(), index_keeper=None)


def test_turning_intelligence_on_stands_when_its_refresh_cannot_be_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = IntelSwitchOut.model_validate(
        _intel_with_no_job_queue(monkeypatch).update_intelligence_switch_state(True, "op")
    )
    assert state.runtime_enabled and state.refresh_not_queued == IntelRefreshMessage.NOT_SENT


def test_an_approval_stands_when_its_refresh_cannot_be_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    approved = IntelSourceApproved.model_validate(
        _intel_with_no_job_queue(monkeypatch).approve_intelligence_source(IntelSource.CISA_KEV, "op")
    )
    assert approved.refresh_job_id is None and approved.refresh_not_queued == IntelRefreshMessage.NOT_SENT


def test_a_mapping_replay_answers_its_generations_real_status() -> None:
    create_key = uuid.uuid4().hex
    mapper, _sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    records = get_mongodb()[Collection.SERVICE_MAPPINGS]
    records.update_one({"_id": mapping_id}, {"$set": {"status": Status.RUNNING}})
    assert mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].status == Status.RUNNING
    result = reconcile(mapping_id, 1, _request(), _answer(), _catalog(), 20, 20)
    records.update_one({"_id": mapping_id}, {"$set": {"status": Status.DONE, "result": result}})
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid.uuid4().hex)  # generation 2: queued
    replayed, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
    assert (replayed.generation, replayed.status, created) == (1, Status.DONE, False)
