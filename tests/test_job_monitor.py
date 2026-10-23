"""Seeing every job: GET /v1/admin/jobs, the worker that runs each one, the API request that sent it, the
start/finish log lines, and the reaper failing an admin job left running."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import structlog
from celery import states
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import container
from app.core.constants import AdminJobKind, AdminJobs, Collection, ErrorCode, LogEvent, Status, TaskName
from app.core.database import get_mongodb
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.jobs.job_repository import JobRepository
from app.worker import celery_app, lifecycle, reaper
from app.worker.celery_app import REQUEST_ID_HEADER, send_job
from tests.conftest import ADMIN


def _mapping(status: Status, **job: object) -> str:
    record_id = uuid.uuid4().hex
    now = datetime.now(UTC)
    get_mongodb()[Collection.SERVICE_MAPPINGS].insert_one(
        {
            "_id": record_id,
            "tenant_id": "t1",
            "entity_id": 86,
            "generation": 1,
            "status": status,
            "created_at": now,
            "updated_at": now,
            "job": {"task": TaskName.MAP_SERVICES, "epoch": 1, "attempts": 0, "due_at": now, **job},
        }
    )
    return record_id


def test_every_job_its_queue_and_its_worker_in_one_call(client: TestClient, monkeypatch) -> None:
    monitor = container.get_job_monitor_service()
    monkeypatch.setattr(monitor, "_count_waiting", lambda queue: 3 if queue == "tsg_servicemapper" else 0)
    monkeypatch.setattr(monitor, "_count_workers", lambda queues: dict.fromkeys(queues, 1))
    queued = _mapping(Status.QUEUED)
    error = {"code": "ai_unavailable", "message": "The AI is down."}
    failed = _mapping(Status.FAILED, error=error)
    claimed = JobRepository(get_mongodb()[Collection.SERVICE_MAPPINGS]).claim_job(
        queued, 1, TaskName.MAP_SERVICES, "task-9", worker="mapper@uat"
    )
    assert claimed is not None
    admin_jobs = container.get_admin_job_repository()
    new_refresh = {"_id": uuid.uuid4().hex, "kind": "monitor_test", "status": Status.QUEUED}
    refresh = admin_jobs.create_admin_job(new_refresh | {"created_at": datetime.now(UTC)})
    assert refresh is not None
    assert admin_jobs.update_admin_job_running(refresh, datetime.now(UTC), "t-1", "maint@uat")
    try:
        body = client.get("/v1/admin/jobs", headers=ADMIN).json()
        by_id = {job["id"]: job for job in body["jobs"]}
        assert (by_id[queued]["status"], by_id[queued]["worker"], by_id[queued]["task_id"]) == (
            Status.RUNNING,
            "mapper@uat",
            "task-9",
        )
        assert by_id[queued]["started_at"] is not None and by_id[queued]["kind"] == TaskName.MAP_SERVICES
        assert by_id[queued]["module"] == "service_mapper"
        assert by_id[failed]["error"] == error
        assert (by_id[refresh]["status"], by_id[refresh]["worker"]) == (Status.RUNNING, "maint@uat")
        assert body["queues"]["tsg_servicemapper"] == {"waiting": 3, "workers_online": 1}

        failures = client.get("/v1/admin/jobs", params={"status": "failed"}, headers=ADMIN).json()["jobs"]
        assert {job["status"] for job in failures} == {Status.FAILED}
        mapper = client.get("/v1/admin/jobs", params={"module": "service_mapper"}, headers=ADMIN).json()[
            "jobs"
        ]
        assert {job["module"] for job in mapper} == {"service_mapper"} and refresh not in {
            j["id"] for j in mapper
        }
        assert client.get("/v1/admin/jobs", headers={"X-Admin-Key": "wrong"}).status_code == 401
    finally:
        admin_jobs.update_admin_job_finished(refresh, datetime.now(UTC), result={})


def test_the_api_request_id_travels_with_the_job_and_its_start_and_finish_are_logged(monkeypatch) -> None:
    sent: list[dict] = []
    monkeypatch.setattr(celery_app, "send_task", lambda task, args, headers: sent.append(headers))
    structlog.contextvars.bind_contextvars(request_id="req-42")
    try:
        send_job(TaskName.MAP_SERVICES, "mapping-1", 1)
    finally:
        structlog.contextvars.clear_contextvars()
    send_job(TaskName.MAP_SERVICES, "mapping-2", 1)  # the reaper's re-send: no API request
    assert sent == [{REQUEST_ID_HEADER: "req-42"}, {}]

    request = SimpleNamespace(hostname="mapper@uat", tsg_request_id="req-42")
    task = SimpleNamespace(name=TaskName.MAP_SERVICES, request=request)
    with capture_logs() as logs:
        lifecycle.start_job_clock("task-7", task, args=("mapping-1", 1))
        context = structlog.contextvars.get_contextvars()
        lifecycle.record_job_outcome("task-7", task, state=states.SUCCESS)
    assert {key: context[key] for key in ("request_id", "record_id", "worker", "module")} == {
        "request_id": "req-42",
        "record_id": "mapping-1",
        "worker": "mapper@uat",
        "module": "service_mapper",
    }
    events = [line for line in logs if line["event"] in (LogEvent.JOB_STARTED, LogEvent.JOB_FINISHED)]
    assert [line["event"] for line in events] == [LogEvent.JOB_STARTED, LogEvent.JOB_FINISHED]
    assert events[1]["outcome"] == "success" and events[1]["seconds"] is not None


def test_the_reaper_fails_an_admin_job_left_running_and_leaves_a_fresh_one(monkeypatch) -> None:
    monkeypatch.setattr(reaper, "_queue_sizes_read_once", lambda: lambda _queue: True)
    jobs = AdminJobRepository()
    long_ago = datetime.now(UTC) - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS + 60)
    stuck, fresh = uuid.uuid4().hex, uuid.uuid4().hex
    jobs.collection.delete_many({"kind": {"$in": [AdminJobKind.INTEL_REFRESH, "fresh_kind"]}})
    base = {"status": Status.RUNNING, "active": True}
    jobs.create(base | {"_id": stuck, "kind": AdminJobKind.INTEL_REFRESH, "created_at": long_ago})
    jobs.create(base | {"_id": fresh, "kind": "fresh_kind", "created_at": datetime.now(UTC)})
    failures = {"task": TaskName.REFRESH_EXTERNAL_INTELLIGENCE, "outcome": "failure"}
    before = REGISTRY.get_sample_value("tsg_jobs_total", failures) or 0.0
    try:
        with capture_logs() as logs:
            reaper.reap_jobs()
        assert jobs.get(None, _id=stuck)["error"]["code"] == ErrorCode.JOB_ABANDONED
        assert jobs.get(None, _id=stuck)["status"] == Status.FAILED
        assert jobs.get(None, _id=fresh)["status"] == Status.RUNNING
        lines = [line for line in logs if line["event"] == LogEvent.JOB_FAILED]
        [failed] = [line for line in lines if line.get("record_id") == stuck]
        # The import's own task and module, not the reaper's: the dashboard groups failed jobs by them.
        assert (failed["task"], failed["module"], failed["reason"], failed["code"]) == (
            TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
            "external_intelligence",
            "abandoned",
            ErrorCode.JOB_ABANDONED,
        )
        assert failed["message"] and REGISTRY.get_sample_value("tsg_jobs_total", failures) == before + 1
    finally:
        jobs.collection.delete_many({"_id": {"$in": [stuck, fresh]}})


def test_one_job_is_read_by_id_and_an_import_or_build_can_be_cancelled(client: TestClient) -> None:
    jobs = container.get_admin_job_repository()
    jobs.collection.delete_many({"kind": "cancel_test"})
    job_id = jobs.create_admin_job(
        {
            "_id": uuid.uuid4().hex,
            "kind": "cancel_test",
            "status": Status.QUEUED,
            "created_at": datetime.now(UTC),
        }
    )
    mapping = _mapping(Status.QUEUED)
    try:
        assert client.get(f"/v1/admin/jobs/{job_id}", headers=ADMIN).json()["status"] == Status.QUEUED
        assert client.get(f"/v1/admin/jobs/{mapping}", headers=ADMIN).json()["module"] == "service_mapper"
        assert client.get("/v1/admin/jobs/no-such-job", headers=ADMIN).status_code == 404

        cancelled = client.post(f"/v1/admin/jobs/{job_id}/cancel", headers=ADMIN)
        assert cancelled.status_code == 200 and cancelled.json()["status"] == Status.CANCELLED
        # A queued job cancelled never starts, and a new one of its kind can start at once.
        assert jobs.update_admin_job_running(job_id, datetime.now(UTC)) is False
        assert not jobs.is_admin_job_active(job_id)
        again = client.post(f"/v1/admin/jobs/{job_id}/cancel", headers=ADMIN)
        assert (again.status_code, again.json()["reason"]) == (409, "nothing_to_cancel")
        other = client.post(f"/v1/admin/jobs/{mapping}/cancel", headers=ADMIN)
        assert other.status_code == 409 and "service_mapper" in other.json()["detail"]
        assert client.post(f"/v1/admin/jobs/{job_id}/cancel", headers={"X-Admin-Key": "x"}).status_code == 401
    finally:
        jobs.collection.delete_many({"kind": "cancel_test"})
