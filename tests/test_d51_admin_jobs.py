"""Admin jobs (an embeddings build, an intelligence import): a heartbeat while they run, so a crashed one
fails in minutes; a failed feed fails its import; an outcome saved meanwhile (a cancel, the reaper) stands;
the switch answers the id of the import it queued; a cancel that comes too late names how the job ended."""

import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from celery.exceptions import Ignore
from fastapi.testclient import TestClient

from app import container
from app.core.config import get_settings
from app.core.constants import AdminJobKind, Collection, ErrorCode, IntelSource, Lease, Status
from app.core.database import get_mongodb
from app.models.external_intelligence.refresh_summary import RefreshResult, RefreshSummary, SourceRefresh
from app.worker import reaper
from app.worker.admin.library_indexes import run_embeddings_job
from app.worker.external_intelligence.refresh_task import run_refresh_job
from tests.conftest import ADMIN
from tests.external_intelligence.api.test_intel_admin_api import Api

_SNAPSHOT = SimpleNamespace(
    library=SimpleNamespace(threat_library=SimpleNamespace(threats=[], actors=[]), control_library=[]),
    threat_types=(),
)


@pytest.fixture(autouse=True)
def intelligence_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env master switch on, so an admin import runs."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)


def _jobs() -> Any:
    return container.get_admin_job_repository()


def _queued(kind: str, created_at: datetime | None = None, **fields: Any) -> str:
    """A new queued admin job of `kind`, the only active one of its kind."""
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({"kind": kind, "active": True})
    job = {"_id": uuid.uuid4().hex, "kind": kind, "status": Status.QUEUED, **fields}
    job_id = _jobs().create_admin_job(job | {"created_at": created_at or datetime.now(UTC)})
    assert job_id == job["_id"]
    return job_id


def _run_build(job_id: str, work: Callable[[], None]) -> None:
    """The embeddings build of `job_id`, `work` running as its build."""
    search = SimpleNamespace(snapshot=lambda *, wait: (work(), _SNAPSHOT)[1])
    library = SimpleNamespace(reload_if_library_changed=lambda: None)
    vectors = SimpleNamespace(count_library_vectors_made_since=lambda since: {})
    run_embeddings_job(job_id, _jobs(), library, search, vectors, container.get_audit_repository())  # type: ignore[arg-type]


def _run_import(job_id: str, work: Callable[[], None]) -> None:
    """The intelligence import of `job_id`, `work` running as its refresh."""

    def refresh(*_: Any) -> RefreshSummary:
        work()
        return RefreshSummary((), True)

    refresher = SimpleNamespace(refresh_due_sources=refresh, refresh_one_source=refresh)
    run_refresh_job(job_id, _jobs(), lambda: refresher)  # type: ignore[arg-type,return-value]


RUNNERS = {AdminJobKind.EMBEDDINGS_BUILD: _run_build, AdminJobKind.INTEL_REFRESH: _run_import}


def test_the_reaper_fails_a_running_admin_job_whose_heartbeat_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its worker crashed 3 min after starting: failed now, not an hour after it started."""
    monkeypatch.setattr(reaper, "_queue_sizes_read_once", lambda: lambda _queue: True)
    now = datetime.now(UTC)
    job_id = _queued(AdminJobKind.INTEL_REFRESH)
    assert _jobs().update_admin_job_running(job_id, now - timedelta(seconds=Lease.SECONDS + 60))
    reaper.reap_jobs()
    job = _jobs().get_any_admin_job(job_id)
    assert (job["status"], job["error"]["code"]) == (Status.FAILED, ErrorCode.JOB_ABANDONED)


def test_a_new_request_takes_over_a_job_whose_heartbeat_stopped() -> None:
    now = datetime.now(UTC)
    dead = _queued(AdminJobKind.EMBEDDINGS_BUILD, created_at=now - timedelta(minutes=10))
    assert _jobs().update_admin_job_running(dead, now - timedelta(seconds=Lease.SECONDS + 60))
    newer = {"_id": uuid.uuid4().hex, "kind": AdminJobKind.EMBEDDINGS_BUILD, "status": Status.QUEUED}
    assert _jobs().create_admin_job(newer | {"created_at": now}) == newer["_id"]
    assert _jobs().get_any_admin_job(dead)["error"]["code"] == ErrorCode.JOB_ABANDONED


def test_a_job_with_a_live_heartbeat_is_never_failed_for_its_age() -> None:
    """A long build that still beats keeps running, however long ago it was created and started."""
    now = datetime.now(UTC)
    long_ago = now - timedelta(hours=3)
    job_id = _queued(AdminJobKind.EMBEDDINGS_BUILD, created_at=long_ago)
    assert _jobs().update_admin_job_running(job_id, long_ago)
    assert _jobs().renew_admin_job(job_id, now)
    assert job_id not in {job["_id"] for job in _jobs().fail_stale_admin_jobs(now)}
    assert _jobs().get_any_admin_job(job_id)["status"] == Status.RUNNING


@pytest.mark.parametrize("kind", list(RUNNERS))
def test_a_running_admin_job_beats_its_heartbeat_past_the_job_time_limit(
    kind: AdminJobKind, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A healthy build beats until it ends: an hour-long one is never taken for a crashed one."""
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.01)
    monkeypatch.setattr(Lease, "STALL_SECONDS", 0.05)
    job_id = _queued(kind)
    beats: list[bool] = []

    def work() -> None:
        time.sleep(0.2)  # past the time limit
        first = _jobs().get_any_admin_job(job_id)["lease_until"]
        deadline = time.monotonic() + 5
        while _jobs().get_any_admin_job(job_id)["lease_until"] == first and time.monotonic() < deadline:
            time.sleep(0.01)
        beats.append(_jobs().get_any_admin_job(job_id)["lease_until"] > first)

    RUNNERS[kind](job_id, work)
    assert beats == [True] and _jobs().get_any_admin_job(job_id)["status"] == Status.DONE


def test_an_import_with_a_failed_feed_ends_failed_and_names_the_feed() -> None:
    """The other feeds' data stands; the job says which feed could not be imported."""
    job_id = _queued(AdminJobKind.INTEL_REFRESH, source=IntelSource.CISA_KEV)
    failed_feed = SourceRefresh(IntelSource.CISA_KEV, RefreshResult.FAILED, error="HTTPError")
    refresher = SimpleNamespace(refresh_one_source=lambda source, now: RefreshSummary((failed_feed,), True))
    run_refresh_job(job_id, _jobs(), lambda: refresher)  # type: ignore[arg-type,return-value]
    job = _jobs().get_any_admin_job(job_id)
    assert (job["status"], job["error"]["code"]) == (Status.FAILED, ErrorCode.UNAVAILABLE)
    assert IntelSource.CISA_KEV in job["error"]["message"] and job["result"] == {"source": "cisa_kev"}


def _cancel(job_id: str) -> None:
    assert _jobs().cancel_admin_job(job_id, datetime.now(UTC), "op-1")


def _abandon(job_id: str) -> None:
    error = {"code": ErrorCode.JOB_ABANDONED, "message": "its worker stopped"}
    assert _jobs().update_admin_job_finished(job_id, datetime.now(UTC), error=error)


@pytest.mark.parametrize("ended_meanwhile", [_cancel, _abandon])
@pytest.mark.parametrize("kind", list(RUNNERS))
def test_a_job_ended_meanwhile_that_then_fails_ends_quietly(
    kind: AdminJobKind, ended_meanwhile: Callable[[str], None]
) -> None:
    """Its cancel or the reaper's failure stands: the delivery is neither a failure nor counted twice."""
    job_id = _queued(kind)
    ended = _jobs().get_any_admin_job

    def work() -> None:
        ended_meanwhile(job_id)
        raise RuntimeError("the build broke after its job ended")

    before = ended(job_id)
    with pytest.raises(Ignore):
        RUNNERS[kind](job_id, work)
    after = ended(job_id)
    assert before["status"] == Status.QUEUED and after["status"] in (Status.CANCELLED, Status.FAILED)
    assert after.get("error", {}).get("code") in (None, ErrorCode.JOB_ABANDONED)
    finished = {"target.id": job_id, "action": "admin.job_finished"}
    assert get_mongodb()[Collection.AUDIT].find_one(finished) is None


@pytest.fixture
def intel_api(client: TestClient) -> Iterator[Api]:
    """The intelligence service over the API test's fakes, every send accepted."""
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({"kind": AdminJobKind.INTEL_REFRESH, "active": True})
    api = Api()
    client.app.dependency_overrides[container.get_external_intelligence_service] = lambda: api.service  # type: ignore[attr-defined]
    yield api
    client.app.dependency_overrides.pop(container.get_external_intelligence_service, None)  # type: ignore[attr-defined]


def test_turning_the_switch_on_answers_the_id_of_the_import_it_queued(
    client: TestClient, intel_api: Api
) -> None:
    intel_api.switch.runtime = False
    on = client.put("/v1/tsg/intel/switch", json={"enabled": True}, headers=ADMIN)
    again = client.put("/v1/tsg/intel/switch", json={"enabled": True}, headers=ADMIN)  # one already queued
    [(_task, job_id)] = intel_api.sent
    assert on.status_code == 200 and on.json()["refresh_job_id"] == job_id
    assert _jobs().get_any_admin_job(job_id)["kind"] == AdminJobKind.INTEL_REFRESH
    assert again.status_code == 200 and again.json()["refresh_job_id"] is None


def test_a_cancel_that_finds_the_job_just_ended_names_how_it_ended(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_id = _queued("cancel_race_test")
    jobs = container.get_job_monitor_service()._admin_jobs
    cancel = jobs.cancel_admin_job

    def finished_first(*args: Any) -> bool:
        jobs.update_admin_job_finished(job_id, datetime.now(UTC), result={})
        return cancel(*args)

    monkeypatch.setattr(jobs, "cancel_admin_job", finished_first)
    refused = client.post(f"/v1/admin/jobs/{job_id}/cancel", headers=ADMIN)
    assert refused.status_code == 409 and f"is already {Status.DONE}" in refused.json()["detail"]
