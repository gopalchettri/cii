"""Embeddings build on request (#18 start, #19 read; BLUEPRINT AD3 for embeddings_build): one build at a time,
a stale one replaced, an unreachable queue failing the build at once, and the job recording its counts. The
job queue is faked; the job itself runs on fakes of the library and its search."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import Collection, EmbeddingCorpus, ErrorMessage, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.services.admin.admin_service import AdminService
from app.worker.admin.library_indexes import run_embeddings_job
from tests.conftest import ADMIN

URL = "/v1/embeddings"


def _sending_with(client: TestClient, send: Callable[[str, str], bool]) -> AdminService:
    """The admin service on the app's own repositories, queueing through `send`, as the API's service."""
    service = AdminService(
        container.get_api_client_repository(),
        container.get_admin_job_repository(),
        container.get_audit_repository(),
        send,
    )
    client.app.dependency_overrides[container.get_admin_service] = lambda: service  # type: ignore[attr-defined]
    return service


@pytest.fixture(autouse=True)
def fresh_jobs(client: TestClient) -> Iterator[list[tuple[str, str]]]:
    """No admin job left by another test; every send recorded and accepted."""
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({})
    sent: list[tuple[str, str]] = []

    def send(task: str, job_id: str) -> bool:
        sent.append((task, job_id))
        return True

    _sending_with(client, send)
    yield sent
    client.app.dependency_overrides.pop(container.get_admin_service, None)  # type: ignore[attr-defined]


def _start(client: TestClient, **headers: str) -> Any:
    return client.post(URL, headers=ADMIN | headers)


def _job(client: TestClient, job_id: str) -> dict[str, Any]:
    return client.get(f"{URL}/{job_id}", headers=ADMIN).json()


def _run(job_id: str, library: Any, search: Any) -> None:
    jobs, audit = container.get_admin_job_repository(), container.get_audit_repository()
    run_embeddings_job(job_id, jobs, library, search, _Vectors(), audit)  # type: ignore[arg-type]


def test_a_build_is_queued_once_at_a_time(client: TestClient, fresh_jobs: list[tuple[str, str]]) -> None:
    started = _start(client, **{"X-User-Id": "operator-1"})
    assert started.status_code == 202 and started.json()["status"] == "queued"
    job_id = started.json()["job_id"]
    assert fresh_jobs == [(TaskName.BUILD_LIBRARY_INDEXES, job_id)]
    again = _start(client)
    assert again.status_code == 409
    assert (again.json()["reason"], again.json()["details"]) == ("job_in_progress", {"job_id": job_id})
    job = _job(client, job_id)
    assert (job["kind"], job["status"], job["requested_by"]) == ("embeddings_build", "queued", "operator-1")
    audit = get_mongodb()[Collection.AUDIT].find_one({"target.id": job_id})
    assert audit["action"] == "admin.job_started" and audit["actor"]["user_id"] == "operator-1"


def test_a_build_unfinished_for_an_hour_is_replaced(client: TestClient) -> None:
    """Its worker died or its message was lost: it must not block every later build."""
    old = datetime.now(UTC) - timedelta(hours=2)
    container.get_admin_job_repository().create(
        {
            "active": True,
            "_id": "old-job",
            "kind": "embeddings_build",
            "status": "running",
            "requested_by": "x",
            "created_at": old,
        }
    )
    started = _start(client)
    assert started.status_code == 202 and started.json()["job_id"] != "old-job"
    old_job = _job(client, "old-job")
    assert (old_job["status"], old_job["error"]["code"]) == ("failed", "job_abandoned")


def test_an_unreachable_queue_fails_the_build_at_once(client: TestClient) -> None:
    """No reaper re-sends an admin job: it is failed, never left queued; the next request may start one."""
    _sending_with(client, lambda task, job_id: False)
    assert _start(client).status_code == 503
    failed = get_mongodb()[Collection.ADMIN_JOBS].find_one({})
    assert failed["status"] == "failed" and "active" not in failed
    _sending_with(client, lambda task, job_id: True)
    assert _start(client).status_code == 202


class _Library:
    def __init__(self, fails: bool = False) -> None:
        self.fails, self.checked = fails, 0

    def reload_if_library_changed(self) -> None:
        self.checked += 1
        if self.fails:
            raise Unavailable(ErrorMessage.SQL_UNREACHABLE)


class _Search:
    def __init__(self, fails: bool = False) -> None:
        self.fails, self.builds = fails, 0

    def snapshot(self, *, wait: bool) -> Any:
        assert wait  # the job waits for the build, unlike a search
        self.builds += 1
        if self.fails:
            raise RuntimeError("embedding provider down")
        threat_library = SimpleNamespace(threats=[1, 2, 3], actors=[1])
        library = SimpleNamespace(threat_library=threat_library, control_library=[1, 2])
        return SimpleNamespace(library=library, threat_types=(1,))


class _Vectors:
    def count_library_vectors_made_since(self, since: datetime) -> dict[str, int]:
        return {EmbeddingCorpus.THREAT: 2, EmbeddingCorpus.CONTROL: 1}


def test_the_build_reads_the_library_now_and_records_its_counts(client: TestClient) -> None:
    job_id = _start(client).json()["job_id"]
    library, search = _Library(), _Search()
    _run(job_id, library, search)
    job = _job(client, job_id)
    assert job["status"] == "done" and library.checked == 1
    assert job["result"] == {
        "counts": {"threats": 3, "threat_types": 1, "actors": 1, "controls": 2},
        "newly_embedded": {"threats": 2, "threat_types": 0, "actors": 0, "controls": 1},
    }
    assert job["started_at"] and job["finished_at"]
    finished = get_mongodb()[Collection.AUDIT].find_one({"target.id": job_id, "action": "admin.job_finished"})
    assert finished["after"]["status"] == "done"
    _run(job_id, library, search)
    assert search.builds == 1  # a repeated message builds nothing
    assert _start(client).status_code == 202  # the slot is free again


def test_a_failed_build_is_recorded_then_raised(client: TestClient) -> None:
    job_id = _start(client).json()["job_id"]
    with pytest.raises(RuntimeError):
        _run(job_id, _Library(), _Search(fails=True))
    job = _job(client, job_id)
    assert job["status"] == "failed" and job["error"] == {"code": "internal_error", "message": "RuntimeError"}
    assert _start(client).status_code == 202


def test_an_unreadable_library_fails_the_build_never_done_on_the_old_one(client: TestClient) -> None:
    """Review 2026-10-11: SQL Server unreachable while the job reads the library: the job fails with the
    reason, instead of reporting the last loaded library as built."""
    job_id = _start(client).json()["job_id"]
    search = _Search()
    with pytest.raises(Unavailable):
        _run(job_id, _Library(fails=True), search)
    job = _job(client, job_id)
    assert (job["status"], job["error"]["code"]) == ("failed", "unavailable") and search.builds == 0


def test_any_failure_to_queue_a_build_frees_the_slot(client: TestClient) -> None:
    """Review 2026-10-11: not only an unreachable broker (an encode error, a Redis refusal): the build no
    worker will run is failed, so it never blocks the next one for an hour."""

    def broken_send(task: str, job_id: str) -> bool:
        raise RuntimeError("encode error")

    with pytest.raises(RuntimeError):
        _sending_with(client, broken_send).create_embeddings_build("operator-1")
    failed = get_mongodb()[Collection.ADMIN_JOBS].find_one({})
    assert failed["status"] == "failed" and "active" not in failed
    _sending_with(client, lambda task, job_id: True)
    assert _start(client).status_code == 202


def test_a_build_taken_over_while_running_keeps_its_abandoned_outcome(client: TestClient) -> None:
    """Review 2026-10-11: a build that outlived the stale limit and was replaced finishes late: its record
    keeps job_abandoned and no "done" audit is written for it."""
    job_id = _start(client).json()["job_id"]

    class _TakenOverWhileBuilding(_Search):
        def snapshot(self, *, wait: bool) -> Any:
            error = {"code": "job_abandoned", "message": "taken over"}
            container.get_admin_job_repository().update_admin_job_finished(
                job_id, datetime.now(UTC), error=error
            )
            return super().snapshot(wait=wait)

    _run(job_id, _Library(), _TakenOverWhileBuilding())
    assert _job(client, job_id)["error"]["code"] == "job_abandoned"
    assert (
        get_mongodb()[Collection.AUDIT].find_one({"target.id": job_id, "action": "admin.job_finished"})
        is None
    )


def test_an_unknown_build_is_404_and_both_endpoints_need_the_admin_key(client: TestClient) -> None:
    assert client.get(f"{URL}/no-such-job", headers=ADMIN).status_code == 404
    assert client.post(URL).status_code == 401 and client.get(f"{URL}/x").status_code == 401


def test_another_kinds_job_is_404_here(client: TestClient) -> None:
    """An intelligence refresh's job id is not a build."""
    container.get_admin_job_repository().create(
        {"_id": "intel-job", "kind": "intel_refresh", "status": "done", "requested_by": "x"}
    )
    assert client.get(f"{URL}/intel-job", headers=ADMIN).status_code == 404


def test_new_vectors_are_counted_by_library_since_a_moment() -> None:
    vectors = get_mongodb()[Collection.EMBEDDINGS]
    since = datetime.now(UTC)
    vectors.insert_many(
        [
            {"_id": "count-test-1", "corpus": "threat", "created_at": since + timedelta(seconds=1)},
            {"_id": "count-test-2", "corpus": "threat", "created_at": since + timedelta(seconds=2)},
            {"_id": "count-test-3", "corpus": "control", "created_at": since - timedelta(days=1)},
        ]
    )
    try:
        assert EmbeddingRepository(vectors).count_library_vectors_made_since(since) == {"threat": 2}
    finally:
        vectors.delete_many({"_id": {"$regex": "^count-test-"}})


def test_a_redelivered_build_message_never_runs_a_second_build(client: TestClient) -> None:
    """Before: any active record was marked running, so a redelivered copy of a running build built again."""
    job_id = _start(client).json()["job_id"]
    jobs = container.get_admin_job_repository()
    assert jobs.update_admin_job_running(job_id, datetime.now(UTC)) is True
    assert jobs.update_admin_job_running(job_id, datetime.now(UTC)) is False  # the redelivered copy
